"""
FastAPI Backend and REST API for CyberSecurityBot.
Provides endpoints for automated SAST & DAST scans, LLM remediation, and PR generation.
"""

import asyncio
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import httpx

from ai.remediation_engine import RemediationEngine, RemediationResult
from core.config import settings
from core.pr_creator import PullRequestCreator
from core.verifier import OwnershipVerifier
from scanners.dast_scanner import DASTScanner
from scanners.models import DASTScanResult, SASTScanResult, VulnerabilityFinding
from scanners.sast_scanner import SASTScanner

logger = logging.getLogger("cybersecuritybot.api")

app = FastAPI(
    title=settings.app_name,
    description="Autonomous Local & Hybrid AI Pentester, SAST/DAST Security Scanner & Auto-Remediation Engine",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for future dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan jobs: scan_id -> dict
SCAN_STORE: Dict[str, Dict[str, Any]] = {}


# --- Request & Response Models ---
class HealthResponse(BaseModel):
    status: str
    app_name: str
    environment: str
    llm_provider: str
    ollama_model: str
    ollama_online: bool
    gemini_configured: bool


class SASTScanRequest(BaseModel):
    repo_url: Optional[str] = Field(None, description="GitHub repository URL or 'owner/repo'")
    github_token: Optional[str] = Field(None, description="GitHub PAT with repo scope for private repos / PRs")
    local_path: Optional[str] = Field(None, description="Local folder path to audit (if running locally)")


class DASTScanRequest(BaseModel):
    target_url: str = Field(..., description="Target website or API base URL")
    additional_endpoints: List[str] = Field(
        default_factory=lambda: ["/api", "/login", "/health"],
        description="Extra endpoints to probe"
    )


class RemediationRequest(BaseModel):
    finding: VulnerabilityFinding = Field(..., description="Vulnerability finding model")
    code_context: Optional[str] = Field(None, description="Source code snippet or file excerpt")


class PRCreateRequest(BaseModel):
    repo_url: str = Field(..., description="Target repository (e.g. owner/repo)")
    github_token: str = Field(..., description="GitHub PAT with repo write permissions")
    file_path: str = Field(..., description="Relative path of file to patch")
    finding: VulnerabilityFinding
    remediation: RemediationResult


# --- Routes ---
@app.get("/", tags=["General"])
async def root():
    return {
        "app": settings.app_name,
        "status": "online",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "sast_scan": "/api/v1/scan/sast",
            "dast_scan": "/api/v1/scan/dast",
            "remediation": "/api/v1/remediate",
            "create_pr": "/api/v1/pr"
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
async def health_check():
    """Verify system health, LLM connectivity, and configuration."""
    ollama_online = False
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags")
            ollama_online = (resp.status_code == 200)
    except Exception:
        ollama_online = False

    return HealthResponse(
        status="healthy",
        app_name=settings.app_name,
        environment=settings.environment,
        llm_provider=settings.llm_provider.value,
        ollama_model=settings.ollama_model,
        ollama_online=ollama_online,
        gemini_configured=bool(settings.gemini_api_key),
    )


@app.post("/api/v1/scan/sast", response_model=SASTScanResult, tags=["Scanners"])
async def trigger_sast_scan(req: SASTScanRequest):
    """Execute SAST security scan on local folder or GitHub repository."""
    scanner = SASTScanner()

    # 1. Local path scan
    if req.local_path:
        target = Path(req.local_path)
        if not target.exists():
            raise HTTPException(status_code=404, detail=f"Local path does not exist: {req.local_path}")
        return await scanner.scan(target)

    # 2. Remote GitHub repository scan
    if not req.repo_url:
        raise HTTPException(
            status_code=400, detail="Either 'repo_url' or 'local_path' must be provided."
        )

    repo_name = OwnershipVerifier.parse_github_repo(req.repo_url)
    if not repo_name:
        raise HTTPException(status_code=400, detail="Invalid GitHub repository format.")

    token = req.github_token or settings.github_token
    if token:
        is_owner, msg = await OwnershipVerifier.verify_github_access(token, repo_name)
        if not is_owner:
            raise HTTPException(status_code=403, detail=f"Proof of Ownership failed: {msg}")

    # Clone into temporary directory
    scan_id = str(uuid.uuid4())[:8]
    temp_dir = settings.temp_clone_dir / f"api_scan_{scan_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    clone_url = (
        f"https://x-access-token:{token}@github.com/{repo_name}.git"
        if token
        else f"https://github.com/{repo_name}.git"
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", clone_url, str(temp_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)

        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Git clone failed: {stderr.decode('utf-8', errors='replace')[:200]}"
            )

        result = await scanner.scan(temp_dir)
        SCAN_STORE[scan_id] = {"result": result, "repo_name": repo_name}
        return result

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/v1/scan/dast", response_model=DASTScanResult, tags=["Scanners"])
async def trigger_dast_scan(req: DASTScanRequest):
    """Execute dynamic security audit (Headers, CORS, Cookies) on live URL."""
    dast = DASTScanner()
    result = await dast.scan_url(
        target_url=req.target_url,
        additional_paths=req.additional_endpoints
    )
    return result


@app.post("/api/v1/remediate", response_model=RemediationResult, tags=["AI Remediation"])
async def remediate_vulnerability(req: RemediationRequest):
    """Generate root-cause explanation and secure code patch via local/cloud LLM."""
    engine = RemediationEngine()
    remediation = await engine.analyze_and_remediate(
        finding=req.finding,
        code_context=req.code_context
    )
    return remediation


@app.post("/api/v1/pr", tags=["Pull Requests"])
async def create_pull_request(req: PRCreateRequest):
    """Apply remediated code and open a GitHub Pull Request."""
    success, msg, pr_url = await PullRequestCreator.create_remediation_pr(
        token=req.github_token,
        repo_identifier=req.repo_url,
        file_path=req.file_path,
        fixed_content=req.remediation.fixed_code,
        finding=req.finding,
        remediation=req.remediation,
    )

    if not success:
        raise HTTPException(status_code=400, detail=msg)

    return {
        "success": True,
        "message": msg,
        "pull_request_url": pr_url
    }
