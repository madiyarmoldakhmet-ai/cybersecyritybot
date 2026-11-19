"""
FastAPI Backend and REST API for Aegis.
Provides endpoints for automated SAST & DAST scans, LLM remediation, and PR generation.
"""

import asyncio
import logging
import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import httpx

from aegis.ai.offline_chat import probe_ai_status
from aegis.ai.remediation_engine import RemediationEngine, RemediationResult
from aegis.core.config import settings
from aegis.core.logging_config import setup_logging
from aegis.core.pr_creator import PullRequestCreator
from aegis.core.queue_manager import ollama_limiter, task_queue
from aegis.core.verifier import OwnershipVerifier
from aegis.scanners.dast_scanner import DASTScanner
from aegis.scanners.models import DASTScanResult, SASTScanResult, ScannerType, VulnerabilityFinding
from aegis.scanners.sast_scanner import SASTScanner
from web.dashboard import router as dashboard_router
from web.webhook import router as webhook_router

setup_logging()
logger = logging.getLogger("aegis.api")

app = FastAPI(
    title=settings.app_name,
    description="Autonomous Local & Hybrid AI Pentester, SAST/DAST Security Scanner & Auto-Remediation Engine",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

api_router = APIRouter()

# CORS: explicit origins only (a wildcard combined with credentials would let any site call the API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
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
    air_gapped: bool
    cloud_llm_allowed: bool


class SASTScanRequest(BaseModel):
    repo_url: Optional[str] = Field(None, description="GitHub repository URL or 'owner/repo'")
    github_token: Optional[str] = Field(None, description="GitHub PAT with repo scope for private repos / PRs")
    proof_token: Optional[str] = Field(None, description="Signed authorship proof token returned by /api/v1/verify/ownership")
    require_ownership: bool = Field(False, description="Require verified authorship even on public repositories")
    local_path: Optional[str] = Field(None, description="Local folder path to audit (if running locally)")


class DASTScanRequest(BaseModel):
    target_url: str = Field(..., description="Target website or API base URL")
    proof_token: Optional[str] = Field(None, description="Signed domain ownership proof token")
    require_ownership: bool = Field(False, description="Require verified domain DNS TXT ownership before active DAST probes")
    additional_endpoints: List[str] = Field(
        default_factory=lambda: ["/api", "/login", "/health"],
        description="Extra endpoints to probe"
    )


class VerifyChallengeRequest(BaseModel):
    target: str = Field(..., description="GitHub repository URL/slug or target domain")
    target_type: Literal["auto", "github", "domain"] = "auto"


class VerifyOwnershipRequest(BaseModel):
    target: str = Field(..., description="GitHub repository URL/slug or domain")
    method: Literal["token", "challenge", "dns_txt"] = "token"
    github_token: Optional[str] = Field(None, description="GitHub PAT for strict permission verification")
    challenge_code: Optional[str] = Field(None, description="Challenge code for commit, verify.txt, or DNS TXT check")


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
            "dashboard": "/dashboard",
            "metrics": "/api/v1/metrics",
            "github_webhook": "/api/v1/webhook/github",
            "sast_scan": "/api/v1/scan/sast",
            "dast_scan": "/api/v1/scan/dast",
            "verify_challenge": "/api/v1/verify/challenge",
            "verify_ownership": "/api/v1/verify/ownership",
            "remediation": "/api/v1/remediate",
            "create_pr": "/api/v1/pr"
        }
    }


@api_router.get("/api/v1/metrics", tags=["General"])
async def get_system_metrics():
    """Retrieve operational queue and concurrency metrics."""
    return task_queue.get_metrics()


@api_router.get("/health", response_model=HealthResponse, tags=["General"])
async def health_check():
    """Verify system health, LLM connectivity, and configuration."""
    _, ai_online, _ = await probe_ai_status(timeout_seconds=1.5)
    ollama_online = ai_online if settings.air_gapped else False

    return HealthResponse(
        status="healthy",
        app_name=settings.app_name,
        environment=settings.environment,
        llm_provider=settings.llm_provider.value,
        ollama_model=settings.ollama_model,
        ollama_online=ollama_online,
        gemini_configured=bool(settings.gemini_api_key),
        air_gapped=settings.air_gapped,
        cloud_llm_allowed=settings.allow_cloud_llm,
    )


@api_router.post("/api/v1/scan/sast", response_model=SASTScanResult, tags=["Scanners"])
async def trigger_sast_scan(req: SASTScanRequest):
    """Execute SAST security scan on local folder or GitHub repository."""
    scanner = SASTScanner()

    # 1. Local path scan (disabled in production to prevent server filesystem exposure)
    if req.local_path:
        if settings.environment.lower() == "production":
            raise HTTPException(
                status_code=403,
                detail="Local path scanning is disabled in production; use repo_url or ZIP upload.",
            )
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

    token = (req.github_token or settings.github_token or "").strip()
    proof = OwnershipVerifier.verify_proof_token(req.proof_token, repo_name)
    if proof:
        can_create_pr = bool(token)
    else:
        if req.require_ownership and not req.github_token:
            raise HTTPException(
                status_code=403,
                detail="Требуется подтверждение авторства: передайте GitHub Token или proof_token из /api/v1/verify/ownership.",
            )
        if req.require_ownership:
            strict_res = await OwnershipVerifier.verify_repo_ownership_strict(token, repo_name)
            if not strict_res.get("verified"):
                raise HTTPException(status_code=403, detail=strict_res.get("message", "Авторство не подтверждено."))
            can_create_pr = bool(strict_res.get("can_create_pr"))
        else:
            is_accessible, msg, can_create_pr = await OwnershipVerifier.verify_github_access(token, repo_name)
            if not is_accessible:
                raise HTTPException(status_code=403, detail=f"Access verification failed: {msg}")

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

        # 1. Run Aegis Deep Agentic Scanner
        from aegis.scanners.aegis_runner import AegisEngine
        aegis_engine = AegisEngine()
        aegis_res_task = asyncio.create_task(aegis_engine.scan(temp_dir))

        # 2. Run AST rule scanner
        sast_res_task = asyncio.create_task(scanner.scan(temp_dir))

        aegis_res, sast_res = await asyncio.gather(aegis_res_task, sast_res_task)

        # Merge findings
        all_findings = list(aegis_res.findings)
        seen_keys = {f"{f.file_path}:{f.line_start}:{f.title}" for f in aegis_res.findings}

        for sf in sast_res.findings:
            key = f"{sf.file_path}:{sf.line_start}:{sf.title}"
            if key not in seen_keys:
                all_findings.append(sf)
                seen_keys.add(key)

        total_duration = round(aegis_res.duration_seconds + sast_res.duration_seconds, 2)
        severity_counts = {}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        result = SASTScanResult(
            target_path=str(temp_dir),
            total_findings=len(all_findings),
            findings_by_severity=severity_counts,
            findings=all_findings,
            duration_seconds=total_duration,
            scanners_run=[ScannerType.STRIX, ScannerType.SEMGREP, ScannerType.BANDIT],
            errors=aegis_res.errors + sast_res.errors,
        )

        SCAN_STORE[scan_id] = {"result": result, "repo_name": repo_name}
        return result

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@api_router.post("/api/v1/verify/challenge", tags=["Authorship Verification"])
async def create_verification_challenge(req: VerifyChallengeRequest):
    """Issue a time-bound authorship verification challenge for a GitHub repo or domain."""
    try:
        return OwnershipVerifier.issue_challenge(req.target, req.target_type)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))


@api_router.post("/api/v1/verify/ownership", tags=["Authorship Verification"])
async def verify_asset_ownership(req: VerifyOwnershipRequest):
    """Verify repository or domain authorship via GitHub Token, Commit Challenge, or DNS TXT record."""
    if req.method == "token":
        token = (req.github_token or "").strip()
        res = await OwnershipVerifier.verify_repo_ownership_strict(token, req.target)
        proof_token = (
            OwnershipVerifier.create_proof_token(req.target, "github_token", res.get("username") or "owner")
            if res.get("verified")
            else None
        )
        return {
            **res,
            "target": OwnershipVerifier.parse_github_repo(req.target) or req.target,
            "target_type": "github",
            "method": "token",
            "proof_token": proof_token,
        }

    if req.method == "challenge":
        code = (req.challenge_code or "").strip()
        if not code:
            raise HTTPException(status_code=400, detail="Укажите challenge_code из /api/v1/verify/challenge.")
        ok, msg = await OwnershipVerifier.verify_commit_challenge(req.target, code)
        repo = OwnershipVerifier.parse_github_repo(req.target) or req.target
        proof_token = (
            OwnershipVerifier.create_proof_token(repo, "commit_challenge", repo.split("/")[0])
            if ok
            else None
        )
        return {
            "verified": ok,
            "target": repo,
            "target_type": "github",
            "method": "challenge",
            "username": repo.split("/")[0] if ok and "/" in repo else "",
            "repo_owner": repo.split("/")[0] if "/" in repo else "",
            "role": "VerifiedAuthor" if ok else "Unverified",
            "can_create_pr": False,
            "message": msg,
            "proof_token": proof_token,
        }

    # method == "dns_txt"
    code = (req.challenge_code or "").strip()
    if not code:
        raise HTTPException(status_code=400, detail="Укажите challenge_code для проверки DNS TXT-записи.")
    host = OwnershipVerifier.normalize_domain(req.target)
    if not host:
        raise HTTPException(status_code=400, detail=f"Неверный формат домена: '{req.target}'.")
    ok, msg = await OwnershipVerifier.verify_domain_txt_record(host, code)
    proof_token = OwnershipVerifier.create_proof_token(host, "dns_txt", host) if ok else None
    return {
        "verified": ok,
        "target": host,
        "target_type": "domain",
        "method": "dns_txt",
        "username": host if ok else "",
        "repo_owner": host,
        "role": "DomainOwner" if ok else "Unverified",
        "can_create_pr": False,
        "message": msg,
        "proof_token": proof_token,
    }


@api_router.post("/api/v1/scan/dast", response_model=DASTScanResult, tags=["Scanners"])
async def trigger_dast_scan(req: DASTScanRequest):
    """Execute dynamic security audit (Headers, CORS, Cookies) on live URL."""
    if req.require_ownership:
        host = OwnershipVerifier.normalize_domain(req.target_url)
        if not host or not OwnershipVerifier.verify_proof_token(req.proof_token, host):
            raise HTTPException(
                status_code=403,
                detail="Требуется подтверждение владения доменом через DNS TXT (/api/v1/verify/ownership).",
            )
    dast = DASTScanner()
    result = await dast.scan_url(
        target_url=req.target_url,
        additional_paths=req.additional_endpoints
    )
    return result


@api_router.post("/api/v1/remediate", response_model=RemediationResult, tags=["AI Remediation"])
async def remediate_vulnerability(req: RemediationRequest):
    """Generate root-cause explanation and secure code patch via local/cloud LLM."""
    engine = RemediationEngine()
    remediation = await engine.analyze_and_remediate(
        finding=req.finding,
        code_context=req.code_context
    )
    return remediation


@api_router.post("/api/v1/pr", tags=["Pull Requests"])
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


_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


@api_router.get("/api/v1/reports/{repo_slug}/{filename}", tags=["Reports"])
async def download_audit_report(repo_slug: str, filename: str):
    """Serve a persisted Markdown or PDF compliance audit report safely."""
    if not _SAFE_SEGMENT_RE.match(repo_slug) or not _SAFE_SEGMENT_RE.match(filename):
        raise HTTPException(status_code=400, detail="Invalid report path segment.")
    if ".." in repo_slug or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid report path segment.")

    ext = Path(filename).suffix.lower()
    if ext not in {".pdf", ".md"}:
        raise HTTPException(status_code=400, detail="Only .pdf and .md compliance reports are downloadable.")

    base_dir = Path(settings.scan_output_dir).resolve()
    target = (base_dir / repo_slug / filename).resolve()
    if not target.is_relative_to(base_dir) or not target.is_file():
        raise HTTPException(status_code=404, detail="Audit report not found.")

    media_type = "application/pdf" if ext == ".pdf" else "text/markdown; charset=utf-8"
    return FileResponse(path=target, media_type=media_type, filename=target.name)


app.include_router(webhook_router)
app.include_router(dashboard_router)
app.include_router(api_router)
