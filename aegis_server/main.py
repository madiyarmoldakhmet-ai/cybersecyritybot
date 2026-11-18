import asyncio
import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from openai import AsyncOpenAI

from aegis.core.archive_utils import safe_extract_zip
from aegis.core.audit_pipeline import AuditArtifacts, finalize_scan_audit
from aegis.core.event_bus import ScanEventBus
from aegis.core.verifier import OwnershipVerifier
from aegis.scanners.models import SASTScanResult
from aegis.scanners.sast_scanner import SASTScanner
from aegis.core.config import LLMProvider, settings
from aegis.core.logging_config import setup_logging
from aegis.core.queue_manager import ollama_limiter
from bot.main import run_bot
from web.api import api_router
from web.dashboard import router as dashboard_router
from web.webhook import router as webhook_router

setup_logging()
logger = logging.getLogger("aegis_server")


def log_security_posture() -> None:
    """Log the effective security configuration once at startup."""
    logger.info(f"Starting {settings.app_name} API v2.0 (environment: {settings.environment})")
    if settings.air_gapped:
        logger.info(f"AI mode: local-only, Ollama {settings.ollama_model} at {settings.ollama_base_url}")
    for notice in settings.llm_policy_notices:
        logger.warning(notice)
    if not settings.github_webhook_secret:
        logger.warning("GITHUB_WEBHOOK_SECRET is not set: webhook signatures are not verified"
                       + (" and all webhooks will be rejected in production." if settings.environment == "production" else "."))
    logger.info(f"Audit reports: {settings.scan_output_dir.resolve()} · metrics DB: {settings.metrics_db_path.resolve()}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_security_posture()
    bot_task = asyncio.create_task(run_bot())
    yield
    logger.info("Shutting down Telegram bot")
    bot_task.cancel()
    try:
        await bot_task
    except asyncio.CancelledError:
        pass

app = FastAPI(title="Commit Guardian Security API", version="2.0", lifespan=lifespan)

DEMO_TARGET_DIR = Path(__file__).resolve().parent.parent / "demo_targets" / "fintech_demo"


def _build_scan_payload(result: SASTScanResult, repo_name: str, artifacts: AuditArtifacts) -> Dict[str, Any]:
    """Serialize SAST scan results, security score, and report URLs for the web console."""
    return {
        "status": "success",
        "repo_name": repo_name,
        "total_findings": result.total_findings,
        "security_score": artifacts.score,
        "grade": artifacts.grade,
        "recommendation": artifacts.recommendation,
        "summary": artifacts.summary.text if artifacts.summary else "",
        "summary_ai_generated": bool(artifacts.summary and artifacts.summary.ai_generated),
        "report_pdf_url": artifacts.report_pdf_url,
        "report_md_url": artifacts.report_md_url,
        "vulnerabilities": [f.model_dump() for f in result.findings],
        "scan_result": result.model_dump(),
    }

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Commit Guardian: GitHub webhook audits, observability dashboard & REST API
app.include_router(webhook_router)
app.include_router(dashboard_router)
app.include_router(api_router)

@app.exception_handler(Exception)
async def global_error(request: Request, exc: Exception):
    # Full details go to the log only; clients get an opaque reference
    error_id = uuid.uuid4().hex[:12]
    logger.exception(f"Unhandled server error {error_id} on {request.method} {request.url.path}")
    return JSONResponse(status_code=500, content={"error": "Internal server error", "error_id": error_id})

SCANS_DIR = Path("/tmp/aegis_scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

class ScanRequest(BaseModel):
    github_url: str

async def clone_repo(repo_url: str, dest_dir: Path) -> bool:
    """Clones a validated public GitHub repository into the specified directory."""
    repo_name = OwnershipVerifier.parse_github_repo(repo_url)
    if not repo_name:
        logger.warning(f"Rejected invalid or non-GitHub clone URL: {repo_url}")
        return False

    safe_url = f"https://github.com/{repo_name}.git"
    logger.info(f"Cloning {safe_url} into {dest_dir}...")
    try:
        process = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--", safe_url, str(dest_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, _ = await asyncio.wait_for(process.communicate(), timeout=45.0)
        if process.returncode != 0:
            logger.error(f"Failed to clone repository: {safe_url}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error during git clone: {e}")
        return False

@app.post("/api/scan/demo")
async def scan_demo():
    """Run a 1-click live demo audit against the built-in fintech/GovTech target."""
    if not DEMO_TARGET_DIR.is_dir():
        return JSONResponse(status_code=404, content={"error": "Demo target directory is missing."})

    scan_uuid = uuid.uuid4().hex[:12]
    scanner = SASTScanner(event_bus=ScanEventBus(scan_id=scan_uuid))
    result = await scanner.scan(DEMO_TARGET_DIR)
    repo_name = "demo/kz-fintech-app"
    artifacts = await finalize_scan_audit(
        result,
        repo_name=repo_name,
        commit_sha=scan_uuid,
        branch="demo",
        author="stage-demo",
    )
    return _build_scan_payload(result, repo_name, artifacts)


@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        return JSONResponse(status_code=400, content={"error": "Только ZIP-архивы разрешены"})
    
    scan_uuid = str(uuid.uuid4())
    repo_dir = SCANS_DIR / scan_uuid
    zip_path = repo_dir / "upload.zip"
    extract_dir = repo_dir / "code"
    
    repo_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            return JSONResponse(status_code=400, content={"error": "Файл слишком большой (максимум 50MB)"})
        
        with open(zip_path, "wb") as f:
            f.write(content)

        try:
            safe_extract_zip(zip_path, extract_dir)
        except Exception as zip_err:
            return JSONResponse(status_code=400, content={"error": f"Некорректный или опасный ZIP-архив: {zip_err}"})
        
        event_bus = ScanEventBus(scan_id=scan_uuid)
        scanner = SASTScanner(event_bus=event_bus)
        
        result = await scanner.scan(extract_dir)
        archive_label = Path(file.filename).stem or "archive"
        repo_name = f"upload/{archive_label}"
        artifacts = await finalize_scan_audit(
            result,
            repo_name=repo_name,
            commit_sha=scan_uuid[:12],
            branch="zip-upload",
            author="web-upload",
        )
        return _build_scan_payload(result, repo_name, artifacts)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
        logger.info("Код удалён с сервера")

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    scan_uuid = str(uuid.uuid4())
    repo_dir = SCANS_DIR / scan_uuid
    
    try:
        data = await websocket.receive_json()
        repo_url = (data.get("github_url") or "").strip()
        repo_name = OwnershipVerifier.parse_github_repo(repo_url)
        if not repo_name:
            await websocket.send_json({"event_type": "SystemError", "message": "Invalid GitHub URL or owner/repo format."})
            await websocket.close()
            return
            
        await websocket.send_json({"event_type": "SystemLog", "message": f"Cloning repository {repo_name}..."})
        success = await clone_repo(repo_name, repo_dir)
        
        if not success:
            await websocket.send_json({"event_type": "SystemError", "message": "Failed to clone repository."})
            await websocket.close()
            return
            
        event_bus = ScanEventBus(scan_id=scan_uuid)
        scanner = SASTScanner(event_bus=event_bus)

        async def _run_and_finish():
            try:
                return await scanner.scan(repo_dir)
            finally:
                if not event_bus._completed:
                    await event_bus.complete(total_findings=0, duration_seconds=0.0)

        scan_task = asyncio.create_task(_run_and_finish())
        
        async for event in event_bus.subscribe():
            await websocket.send_json(event.model_dump(mode="json"))
            
        result = await scan_task
        artifacts = await finalize_scan_audit(
            result,
            repo_name=repo_name,
            commit_sha=scan_uuid[:12],
            branch="main",
            author="web-console",
        )
        await websocket.send_json({
            "event_type": "ScanResult",
            "repo_name": repo_name,
            "total_findings": result.total_findings,
            "security_score": artifacts.score,
            "grade": artifacts.grade,
            "recommendation": artifacts.recommendation,
            "summary": artifacts.summary.text if artifacts.summary else "",
            "summary_ai_generated": bool(artifacts.summary and artifacts.summary.ai_generated),
            "report_pdf_url": artifacts.report_pdf_url,
            "report_md_url": artifacts.report_md_url,
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "duration_seconds": result.duration_seconds,
        })
        await websocket.send_json({"event_type": "SystemLog", "message": "Scan completely finished."})
        
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_uuid}")
    except Exception as e:
        logger.error(f"Error in websocket handler: {e}")
        try:
            await websocket.send_json({"event_type": "SystemError", "message": "Scan failed due to an internal error."})
        except:
            pass
    finally:
        if repo_dir.exists():
            shutil.rmtree(repo_dir, ignore_errors=True)
            logger.info("Код удалён с сервера")
        try:
            await websocket.close()
        except:
            pass


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()
    
    # Enforce local-LLM policy consistently with settings.enforce_local_llm_policy()
    if not settings.air_gapped and settings.llm_provider == LLMProvider.OPENROUTER and settings.openrouter_api_key:
        client = AsyncOpenAI(base_url="https://openrouter.ai/api/v1", api_key=settings.openrouter_api_key)
        model = settings.openrouter_model
    elif not settings.air_gapped and settings.llm_provider == LLMProvider.GEMINI and settings.gemini_api_key:
        client = AsyncOpenAI(base_url="https://generativelanguage.googleapis.com/v1beta/openai/", api_key=settings.gemini_api_key)
        model = settings.gemini_model
    else:
        client = AsyncOpenAI(base_url=settings.ollama_base_url.rstrip("/") + "/v1", api_key="ollama")
        model = settings.ollama_model
    
    chat_history = [
        {"role": "system", "content": "You are Commit Guardian, an on-premise AI AppSec assistant. Help developers analyze GitHub repositories, understand vulnerabilities, and verify on-premise privacy (no code leaves the server). Reply concisely in Russian."}
    ]
    
    try:
        while True:
            data = await websocket.receive_text()
            chat_history.append({"role": "user", "content": data})
            
            # Trigger scan when a GitHub URL or owner/repo + scan intent is sent
            if "github.com/" in data:
                url = [word for word in data.split() if "github.com" in word][0]
                await websocket.send_json({"type": "action", "action": "SCAN", "github_url": url})
                chat_history.append({"role": "assistant", "content": f"Запустил локальное сканирование для {url}."})
                await websocket.send_json({"type": "chunk", "content": f"Запустил аудит репозитория {url}. Результаты и отчёт появятся в консоли справа."})
                await websocket.send_json({"type": "done"})
                continue
                
            try:
                stream = await client.chat.completions.create(
                    model=model,
                    messages=chat_history,
                    stream=True,
                )
                full_response = ""
                async for chunk in stream:
                    if chunk.choices and chunk.choices[0].delta.content:
                        content = chunk.choices[0].delta.content
                        full_response += content
                        await websocket.send_json({"type": "chunk", "content": content})
            except Exception as llm_err:
                logger.warning(f"Local LLM chat unavailable, serving offline fallback: {llm_err}")
                full_response = (
                    f"Локальная модель Ollama ({settings.ollama_model}) на этом хосте сейчас не запущена — "
                    "и это нормально для демо-режима: весь статический движок (SAST, Taint, Secrets, PDF-отчёты и AI-фиксы) "
                    "работает полностью автономно без интернета. Отправьте ссылку на GitHub, перетащите ZIP-архив или нажмите «Демо-аудит»."
                )
                await websocket.send_json({"type": "chunk", "content": full_response})

            await websocket.send_json({"type": "done"})
            chat_history.append({"role": "assistant", "content": full_response})
            
    except WebSocketDisconnect:
        logger.info("Chat WebSocket disconnected")
    except Exception as e:
        logger.error(f"Chat Error: {e}")
        try:
            await websocket.close()
        except:
            pass

# Mounted last so it never shadows API routes; optional so the API runs without a frontend build
FRONTEND_DIR = Path("aegis_web/out")
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")
else:
    logger.warning(f"Frontend build not found at {FRONTEND_DIR}; serving API and /dashboard only")
