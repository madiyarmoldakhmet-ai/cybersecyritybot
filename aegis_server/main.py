import asyncio
import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
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

SCANS_DIR = settings.temp_clone_dir / "web_scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)


class ScanRequest(BaseModel):
    github_url: str


async def clone_repo(repo_url: str, dest_dir: Path, token: Optional[str] = None) -> bool:
    """Clones a validated GitHub repository into the specified directory."""
    repo_name = OwnershipVerifier.parse_github_repo(repo_url)
    if not repo_name:
        logger.warning(f"Rejected invalid or non-GitHub clone URL: {repo_url}")
        return False

    clean_token = (token or "").strip()
    safe_url = (
        f"https://x-access-token:{clean_token}@github.com/{repo_name}.git"
        if clean_token
        else f"https://github.com/{repo_name}.git"
    )
    logger.info(f"Cloning {repo_name} into {dest_dir}...")
    try:
        process = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--", safe_url, str(dest_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(process.communicate(), timeout=45.0)
        if process.returncode != 0:
            err_msg = stderr.decode("utf-8", errors="replace")[:200]
            if clean_token:
                err_msg = err_msg.replace(clean_token, "***")
            logger.error(f"Failed to clone repository {repo_name}: {err_msg}")
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

async def _authorize_ws_scan(
    repo_name: str,
    user_token: Optional[str],
    proof_token: Optional[str],
    require_ownership: bool,
) -> tuple[bool, bool, str, str, bool, str]:
    """
    Authorize a WebSocket repository audit and compute authorship metadata.
    Returns (allowed, verified, status_label, actor, can_create_pr, message).
    """
    clean_user_token = (user_token or "").strip()
    effective_token = clean_user_token or (settings.github_token or "").strip()
    proof = OwnershipVerifier.verify_proof_token(proof_token, repo_name)
    if proof:
        method = proof.get("method", "challenge")
        actor = proof.get("actor", "verified-author")
        return (
            True,
            True,
            f"Подтверждён автор ({method}: {actor})",
            actor,
            bool(clean_user_token),
            f"Авторство {repo_name} подтверждено ({actor}).",
        )

    if clean_user_token:
        strict = await OwnershipVerifier.verify_repo_ownership_strict(clean_user_token, repo_name)
        verified = bool(strict.get("verified"))
        role = strict.get("role", "None")
        actor = strict.get("username") or repo_name.split("/")[0]
        if verified:
            return (
                True,
                True,
                f"Подтверждён ({role}: @{actor})",
                actor,
                bool(strict.get("can_create_pr")),
                strict.get("message", ""),
            )
        return (
            False,
            False,
            f"Доступ запрещён ({role})",
            actor,
            False,
            strict.get("message", "Недостаточно прав в репозитории."),
        )

    if require_ownership:
        return (
            False,
            False,
            "Авторство не подтверждено",
            "unverified",
            False,
            "Включена строгая проверка авторства: подтвердите владение репозиторием через Token или Commit Challenge.",
        )

    accessible, msg, can_pr = await OwnershipVerifier.verify_github_access(effective_token, repo_name)
    if not accessible:
        return False, False, "Закрытый репозиторий", "unverified", False, msg
    return True, False, "Публичный доступ (Read-Only)", "public-readonly", can_pr, msg


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    scan_uuid = str(uuid.uuid4())
    repo_dir = SCANS_DIR / scan_uuid
    
    try:
        data = await websocket.receive_json()
        repo_url = (data.get("github_url") or "").strip()
        user_token = (data.get("github_token") or "").strip()
        proof_token = (data.get("proof_token") or "").strip()
        require_ownership = bool(data.get("require_ownership", False))

        repo_name = OwnershipVerifier.parse_github_repo(repo_url)
        if not repo_name:
            await websocket.send_json({"event_type": "SystemError", "message": "Неверный формат GitHub URL или owner/repo."})
            await websocket.close()
            return

        allowed, auth_verified, auth_status, auth_actor, can_create_pr, auth_msg = await _authorize_ws_scan(
            repo_name, user_token, proof_token, require_ownership
        )
        if not allowed:
            await websocket.send_json({"event_type": "SystemError", "message": auth_msg})
            await websocket.close()
            return

        await websocket.send_json({"event_type": "SystemLog", "message": f"Проверка доступа: {auth_status}"})
        await websocket.send_json({"event_type": "SystemLog", "message": f"Клонирование репозитория {repo_name}..."})
        clone_token = user_token or (settings.github_token or "")
        success = await clone_repo(repo_name, repo_dir, token=clone_token)
        
        if not success:
            await websocket.send_json({"event_type": "SystemError", "message": f"Не удалось клонировать репозиторий {repo_name}."})
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
            author=auth_actor,
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
            "authorship_verified": auth_verified,
            "authorship_status": auth_status,
            "authorship_actor": auth_actor,
            "can_create_pr": can_create_pr,
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
        except Exception as send_err:
            logger.debug(f"Could not emit WebSocket SystemError: {send_err}")
    finally:
        if repo_dir.exists():
            shutil.rmtree(repo_dir, ignore_errors=True)
            logger.info("Код удалён с сервера")
        try:
            await websocket.close()
        except Exception as close_err:
            logger.debug(f"WebSocket close skipped: {close_err}")


def _parse_chat_payload(raw_data: str) -> tuple[bool, str, str]:
    """Parse plain text or structured JSON chat payload with optional active scan context."""
    stripped = raw_data.strip()
    if not stripped.startswith("{"):
        return False, stripped, ""
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return False, stripped, ""
    if not isinstance(payload, dict):
        return False, stripped, ""
    if payload.get("reset"):
        return True, "", ""

    user_text = str(payload.get("message") or "").strip()
    ctx = payload.get("scan_context")
    if not isinstance(ctx, dict) or not ctx.get("repo_name"):
        return False, user_text, ""

    findings = ctx.get("findings") or []
    top_lines = []
    for item in findings[:8]:
        if isinstance(item, dict):
            sev = item.get("severity", "INFO")
            title = item.get("title", "Vulnerability")
            loc = f"{item.get('file_path', '?')}:{item.get('line_start') or 1}"
            cwe = ", ".join(item.get("cwe") or [])
            top_lines.append(f"- [{sev}] {title} ({loc}" + (f", {cwe}" if cwe else "") + ")")

    summary_note = (
        f"[Контекст текущего аудита в консоли] Репозиторий: {ctx.get('repo_name')}; "
        f"Score: {ctx.get('security_score', '-')}/100 ({ctx.get('grade', '-')}); "
        f"Всего находок: {ctx.get('total_findings', len(findings))}."
    )
    if top_lines:
        summary_note += "\nКлючевые уязвимости:\n" + "\n".join(top_lines)
    return False, user_text, summary_note


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
    
    system_prompt = (
        "You are Commit Guardian, an on-premise AI AppSec assistant. Help developers analyze GitHub repositories, "
        "explain vulnerabilities concisely with safe fixes, and verify on-premise privacy (no code leaves the server). "
        "Reply clearly in Russian."
    )
    chat_history = [{"role": "system", "content": system_prompt}]
    
    try:
        while True:
            raw_data = await websocket.receive_text()
            should_reset, data, scan_context_note = _parse_chat_payload(raw_data)
            if should_reset:
                chat_history = [{"role": "system", "content": system_prompt}]
                await websocket.send_json({"type": "done"})
                continue
            if not data:
                await websocket.send_json({"type": "done"})
                continue

            # Trigger scan when a GitHub URL is sent
            if "github.com/" in data:
                url = next((word for word in data.split() if "github.com/" in word), data)
                chat_history.append({"role": "user", "content": data})
                await websocket.send_json({"type": "action", "action": "SCAN", "github_url": url})
                reply = f"Запустил аудит репозитория {url}. Результаты и отчёт появятся в консоли справа."
                chat_history.append({"role": "assistant", "content": f"Запустил локальное сканирование для {url}."})
                await websocket.send_json({"type": "chunk", "content": reply})
                await websocket.send_json({"type": "done"})
                continue

            user_content = f"{scan_context_note}\n\nВопрос пользователя: {data}" if scan_context_note else data
            chat_history.append({"role": "user", "content": user_content})
            # Cap history to system prompt + recent 16 turns to keep local inference fast
            if len(chat_history) > 17:
                chat_history = [chat_history[0]] + chat_history[-16:]

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
                if scan_context_note:
                    full_response = (
                        f"Локальная модель Ollama ({settings.ollama_model}) на этом хосте сейчас не запущена, "
                        "поэтому отвечаю по детерминированным результатам текущего скана:\n\n"
                        f"{scan_context_note}\n\n"
                        "Нажми **«Патч»** напротив любой строки в таблице справа — офлайн-движок сформирует готовое исправление кода."
                    )
                else:
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
        except Exception as close_err:
            logger.debug(f"Chat WebSocket close skipped: {close_err}")

# Mounted last so it never shadows API routes; optional so the API runs without a frontend build
FRONTEND_DIR = Path("aegis_web/out")
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")
else:
    logger.warning(f"Frontend build not found at {FRONTEND_DIR}; serving API and /dashboard only")
