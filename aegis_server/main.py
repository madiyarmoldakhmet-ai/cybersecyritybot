import asyncio
import json
import logging
import os
import re
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

from aegis.ai.offline_chat import (
    build_offline_appsec_reply,
    format_scan_context_note,
    parse_chat_payload,
)
from aegis.core.archive_utils import safe_extract_zip
from aegis.core.audit_pipeline import AuditArtifacts, finalize_scan_audit
from aegis.core.demo_history import materialize_demo_repo
from aegis.core.event_bus import ScanEventBus
from aegis.core.git_clone import clone_repo_resilient, extract_git_metadata
from aegis.core.llm_runtime import (
    build_openai_client,
    chat_completion,
    get_runtime_status,
    reset_runtime_override,
    resolve_active_llm,
    set_runtime_override,
)
from aegis.core.pr_creator import PullRequestCreator
from aegis.core.self_heal import SelfHealer
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


async def _extract_git_metadata(
    repo_dir: Path,
    fallback_sha: str,
    fallback_branch: str = "main",
    fallback_author: str = "unknown",
    repo_name: Optional[str] = None,
    token: Optional[str] = None,
) -> tuple[str, str, str, List[Dict[str, str]]]:
    """Read real branch, HEAD commit SHA/author, and recent commit log from a cloned git directory."""
    return await extract_git_metadata(
        repo_dir,
        fallback_sha=fallback_sha,
        fallback_branch=fallback_branch,
        fallback_author=fallback_author,
        repo_name=repo_name,
        token=token,
    )


def _build_scan_payload(
    result: SASTScanResult,
    repo_name: str,
    artifacts: AuditArtifacts,
    commit_sha: Optional[str] = None,
    branch: str = "main",
    author: str = "unknown",
    commits: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Serialize SAST scan results, security score, real commits, and report URLs for the web console."""
    sev_counts = {sev.value: count for sev, count in result.findings_by_severity.items()}
    return {
        "status": "success",
        "repo_name": repo_name,
        "commit_sha": commit_sha or "",
        "branch": branch,
        "author": author,
        "commits": commits or [],
        "duration_seconds": result.duration_seconds,
        "severity_counts": sev_counts,
        "total_findings": result.total_findings,
        "security_score": artifacts.score,
        "grade": artifacts.grade,
        "recommendation": artifacts.recommendation,
        "summary": artifacts.summary.text if artifacts.summary else "",
        "summary_ai_generated": bool(artifacts.summary and artifacts.summary.ai_generated),
        "report_pdf_url": artifacts.report_pdf_url,
        "report_md_url": artifacts.report_md_url,
        "financial_risk": (
            {**artifacts.risk.model_dump(), "headline": artifacts.risk.headline} if artifacts.risk else None
        ),
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
    github_token: Optional[str] = None
    proof_token: Optional[str] = None
    require_ownership: bool = True


async def clone_repo(repo_url: str, dest_dir: Path, token: Optional[str] = None) -> bool:
    """Clones a validated GitHub repository with smart sparse fallback for large repos / slow links."""
    outcome = await clone_repo_resilient(repo_url, dest_dir, token=token)
    return outcome.success


@app.post("/api/scan/repo")
async def scan_repo_http(req: ScanRequest):
    """HTTP repository audit endpoint (identical pipeline to Telegram bot & WebSocket scanner)."""
    repo_name = OwnershipVerifier.parse_github_repo(req.github_url.strip())
    if not repo_name:
        return JSONResponse(status_code=400, content={"error": "Неверный формат GitHub URL или owner/repo."})

    allowed, auth_verified, auth_status, auth_actor, can_create_pr, auth_msg, challenge_info = await _authorize_ws_scan(
        repo_name, req.github_token, req.proof_token, req.require_ownership
    )
    if not allowed:
        err_body: Dict[str, Any] = {
            "error": auth_msg,
            "code": "OWNERSHIP_REQUIRED",
            "repo_name": repo_name,
        }
        if challenge_info:
            err_body.update(challenge_info)
        return JSONResponse(status_code=403, content=err_body)

    scan_uuid = uuid.uuid4().hex[:12]
    repo_dir = SCANS_DIR / f"repo_{scan_uuid}"
    try:
        clone_token = (req.github_token or "").strip() or (settings.github_token or "")
        outcome = await clone_repo_resilient(repo_name, repo_dir, token=clone_token)
        if not outcome.success:
            return JSONResponse(
                status_code=502,
                content={"error": outcome.error or f"Не удалось клонировать репозиторий {repo_name}."},
            )

        commit_sha, branch, author, commits = await _extract_git_metadata(
            repo_dir,
            fallback_sha=scan_uuid,
            fallback_branch="main",
            fallback_author=auth_actor,
            repo_name=repo_name,
            token=clone_token,
        )
        scanner = SASTScanner(event_bus=ScanEventBus(scan_id=scan_uuid))
        result = await scanner.scan(repo_dir)
        artifacts = await finalize_scan_audit(
            result,
            repo_name=repo_name,
            commit_sha=commit_sha,
            branch=branch,
            author=author,
            commit_url=f"https://github.com/{repo_name}/commit/{commit_sha}" if len(commit_sha) == 40 else None,
        )
        payload = _build_scan_payload(
            result, repo_name, artifacts, commit_sha=commit_sha, branch=branch, author=author, commits=commits
        )
        payload.update({
            "authorship_verified": auth_verified,
            "authorship_status": auth_status,
            "authorship_actor": auth_actor,
            "can_create_pr": can_create_pr,
        })
        return payload
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
        logger.info("Код удалён с сервера")


@app.post("/api/scan/demo")
async def scan_demo():
    """Run a 1-click live demo audit against the built-in fintech/GovTech target with real git history."""
    if not DEMO_TARGET_DIR.is_dir():
        return JSONResponse(status_code=404, content={"error": "Demo target directory is missing."})

    scan_uuid = uuid.uuid4().hex[:12]
    work_dir = SCANS_DIR / f"demo_{scan_uuid}"
    try:
        target = await asyncio.to_thread(materialize_demo_repo, DEMO_TARGET_DIR, work_dir / "kz-fintech-app")
        commit_sha, branch, author, commits = await _extract_git_metadata(
            target, fallback_sha=scan_uuid, fallback_branch="demo", fallback_author="stage-demo"
        )
        scanner = SASTScanner(event_bus=ScanEventBus(scan_id=scan_uuid))
        result = await scanner.scan(target)
        repo_name = "demo/kz-fintech-app"
        artifacts = await finalize_scan_audit(
            result,
            repo_name=repo_name,
            commit_sha=commit_sha,
            branch=branch,
            author=author,
        )
        return _build_scan_payload(
            result, repo_name, artifacts, commit_sha=commit_sha, branch=branch, author=author, commits=commits
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


@app.post("/api/scan/demo/heal")
async def heal_demo():
    """Self-Healing demo: patch the demo app in a sandbox, re-scan, and return verified diffs + before/after."""
    if not DEMO_TARGET_DIR.is_dir():
        return JSONResponse(status_code=404, content={"error": "Demo target directory is missing."})
    work_dir = SCANS_DIR / f"heal_{uuid.uuid4().hex[:12]}"
    try:
        target = await asyncio.to_thread(materialize_demo_repo, DEMO_TARGET_DIR, work_dir / "kz-fintech-app")
        report = await SelfHealer().heal(target)
        return {
            "status": "success",
            "repo_name": "demo/kz-fintech-app",
            "fixed_count": report.fixed_count,
            **report.model_dump(),
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


class RepoAutoFixRequest(BaseModel):
    github_url: str
    proof_token: Optional[str] = None
    github_token: Optional[str] = None
    commit_to_github: bool = True
    direct_commit: bool = False
    commit_message: Optional[str] = None
    require_ownership: bool = True


_GH_TOKEN_CREATE_URL = (
    "https://github.com/settings/tokens/new?scopes=repo&description=Commit+Guardian+Auto-Commit"
)


@app.post("/api/repo/autofix")
async def autofix_and_commit_repo(req: RepoAutoFixRequest):
    """
    Claude-Code-style Auto-Fix & Atomic GitHub Commit/PR pipeline for a verified GitHub repository:
    1. Strictly verifies repository ownership (proof_token or github_token).
    2. Clones repo into isolated temp dir, runs SelfHealer (AST/JS/TS/Python/Dart fixers + SAST re-scan).
    3. If verified patches exist and github_token is provided, pushes 1 atomic commit (new branch + PR, or direct commit).
    4. Always deletes cloned source code immediately after completion.
    """
    repo_name = OwnershipVerifier.parse_github_repo(req.github_url.strip())
    if not repo_name:
        return JSONResponse(status_code=400, content={"error": "Неверный формат GitHub URL или owner/repo."})

    allowed, _, _, _, _, auth_msg, challenge_info = await _authorize_ws_scan(
        repo_name, req.github_token, req.proof_token, req.require_ownership
    )
    if not allowed:
        err_body: Dict[str, Any] = {
            "error": auth_msg,
            "code": "OWNERSHIP_REQUIRED",
            "repo_name": repo_name,
        }
        if challenge_info:
            err_body.update(challenge_info)
        return JSONResponse(status_code=403, content=err_body)

    work_dir = SCANS_DIR / f"autofix_{uuid.uuid4().hex[:12]}"
    repo_dir = work_dir / "repo"
    try:
        user_token = (req.github_token or "").strip()
        clone_token = user_token or (settings.github_token or "")
        outcome = await clone_repo_resilient(repo_name, repo_dir, token=clone_token)
        if not outcome.success:
            return JSONResponse(
                status_code=502,
                content={"error": outcome.error or f"Не удалось клонировать репозиторий {repo_name}."},
            )

        report = await SelfHealer(enable_llm_fallback=True).heal(repo_dir)
        verified_fixes = [f for f in report.fixes if f.verified and f.patched_content is not None]

        commit_result: Dict[str, Any] = {
            "committed": False,
            "needs_token": False,
            "direct_commit": req.direct_commit,
            "branch_name": None,
            "base_branch": None,
            "commit_sha": None,
            "commit_url": None,
            "pull_request_url": None,
            "files_committed": [],
            "token_create_url": _GH_TOKEN_CREATE_URL,
            "commit_message": "",
        }

        if not verified_fixes:
            commit_result["commit_message"] = (
                "Авто-фиксер проверил код: безопасных автоматических патчей не найдено "
                "(оставшиеся пункты требуют ручного ревью — смотри детали ниже)."
            )
        elif req.commit_to_github and user_token:
            file_updates = [(f.file_path, f.patched_content or "") for f in verified_fixes]
            summary_lines = [
                f"{f.file_path}: {', '.join(f.fixers)} ({len(f.fixed_findings)} испр.)"
                for f in verified_fixes
            ]
            gh_res = await PullRequestCreator.commit_multi_file_fixes(
                token=user_token,
                repo_identifier=repo_name,
                file_updates=file_updates,
                summary_lines=summary_lines,
                before_score=report.before_score,
                after_score=report.after_score,
                before_grade=report.before_grade,
                after_grade=report.after_grade,
                fixed_count=report.fixed_count,
                direct_commit=req.direct_commit,
                commit_message=req.commit_message,
            )
            commit_result.update({
                "committed": bool(gh_res.get("committed")),
                "needs_token": not bool(gh_res.get("committed")),
                "direct_commit": bool(gh_res.get("direct_commit", req.direct_commit)),
                "branch_name": gh_res.get("branch_name"),
                "base_branch": gh_res.get("base_branch"),
                "commit_sha": gh_res.get("commit_sha"),
                "commit_url": gh_res.get("commit_url"),
                "pull_request_url": gh_res.get("pull_request_url"),
                "files_committed": gh_res.get("files_committed") or [],
                "commit_message": gh_res.get("message") or "",
            })
        else:
            commit_result["needs_token"] = True
            commit_result["commit_message"] = (
                f"Найдено и подтверждено пересканированием {report.fixed_count} исправлений "
                f"в {len(verified_fixes)} файл(ах). Вставь GitHub Token (scope repo) — "
                f"я сама запушу атомарный коммит в `{repo_name}`!"
            )

        return {
            "status": "success",
            "repo_name": repo_name,
            "fixed_count": report.fixed_count,
            **report.model_dump(),
            **commit_result,
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        logger.info("Код удалён с сервера (autofix)")


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
        return _build_scan_payload(
            result,
            repo_name,
            artifacts,
            commit_sha=scan_uuid[:12],
            branch="zip-upload",
            author="web-upload",
        )
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
        logger.info("Код удалён с сервера")

async def _authorize_ws_scan(
    repo_name: str,
    user_token: Optional[str],
    proof_token: Optional[str],
    require_ownership: bool,
) -> tuple[bool, bool, str, str, bool, str, Optional[Dict[str, Any]]]:
    """
    Authorize a WebSocket repository audit and compute authorship metadata.
    Returns (allowed, verified, status_label, actor, can_create_pr, message, challenge_info).
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
            None,
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
                None,
            )
        return (
            False,
            False,
            f"Доступ запрещён ({role})",
            actor,
            False,
            strict.get("message", "Недостаточно прав в репозитории."),
            None,
        )

    enforce_ownership = True if settings.environment.lower() == "production" else bool(require_ownership)
    if enforce_ownership:
        challenge_info: Optional[Dict[str, Any]] = None
        try:
            ch = await OwnershipVerifier.issue_challenge_async(repo_name, "github", token=effective_token)
            challenge_info = {
                "challenge_code": ch["challenge_code"],
                "verify_url": ch.get("verify_url"),
                "default_branch": ch.get("default_branch") or "main",
                "verify_filename": ch.get("verify_filename") or "verify.txt",
            }
        except Exception as ch_err:
            logger.debug(f"Could not auto-issue ownership challenge for {repo_name}: {ch_err}")
        return (
            False,
            False,
            "Авторство не подтверждено",
            "unverified",
            False,
            (
                f"Подтверди, что `{repo_name}` — твой репозиторий (чужие репо без подтверждения заблокированы).\n"
                f"Нажми кнопку ниже → на GitHub нажми зелёную кнопку **Commit changes** — я сама проверю всё за пару секунд и сразу запущу скан!"
            ),
            challenge_info,
        )

    accessible, msg, can_pr = await OwnershipVerifier.verify_github_access(effective_token, repo_name)
    if not accessible:
        return False, False, "Закрытый репозиторий", "unverified", False, msg, None
    return True, False, "Публичный доступ (Read-Only)", "public-readonly", can_pr, msg, None


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
        require_ownership = bool(data.get("require_ownership", True))

        repo_name = OwnershipVerifier.parse_github_repo(repo_url)
        if not repo_name:
            await websocket.send_json({"event_type": "SystemError", "message": "Неверный формат GitHub URL или owner/repo."})
            await websocket.close()
            return

        allowed, auth_verified, auth_status, auth_actor, can_create_pr, auth_msg, challenge_info = await _authorize_ws_scan(
            repo_name, user_token, proof_token, require_ownership
        )
        if not allowed:
            ws_err: Dict[str, Any] = {
                "event_type": "SystemError",
                "code": "OWNERSHIP_REQUIRED",
                "repo_name": repo_name,
                "message": auth_msg,
            }
            if challenge_info:
                ws_err.update(challenge_info)
            await websocket.send_json(ws_err)
            await websocket.close()
            return

        await websocket.send_json({"event_type": "SystemLog", "message": f"Проверка доступа: {auth_status}"})
        await websocket.send_json({"event_type": "SystemLog", "message": f"Клонирование репозитория {repo_name}..."})
        clone_token = user_token or (settings.github_token or "")

        async def _emit_clone_status(msg: str) -> None:
            await websocket.send_json({"event_type": "SystemLog", "message": msg})

        outcome = await clone_repo_resilient(
            repo_name, repo_dir, token=clone_token, on_status=_emit_clone_status
        )
        if not outcome.success:
            await websocket.send_json({
                "event_type": "SystemError",
                "message": outcome.error or f"Не удалось клонировать репозиторий {repo_name}.",
            })
            await websocket.close()
            return

        if outcome.mode == "sparse" and outcome.files_checked_out:
            await websocket.send_json({
                "event_type": "SystemLog",
                "message": f"Загружено {outcome.files_checked_out} ключевых файлов исходного кода — запускаю SAST & Secret Engine...",
            })
            
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
        commit_sha, branch, author, commits = await _extract_git_metadata(
            repo_dir,
            fallback_sha=scan_uuid[:12],
            fallback_branch="main",
            fallback_author=auth_actor,
            repo_name=repo_name,
            token=clone_token,
        )
        artifacts = await finalize_scan_audit(
            result,
            repo_name=repo_name,
            commit_sha=commit_sha,
            branch=branch,
            author=author,
            commit_url=f"https://github.com/{repo_name}/commit/{commit_sha}" if len(commit_sha) == 40 else None,
        )
        sev_counts = {sev.value: count for sev, count in result.findings_by_severity.items()}
        await websocket.send_json({
            "event_type": "ScanResult",
            "repo_name": repo_name,
            "commit_sha": commit_sha,
            "branch": branch,
            "author": author,
            "commits": commits,
            "severity_counts": sev_counts,
            "total_findings": result.total_findings,
            "security_score": artifacts.score,
            "grade": artifacts.grade,
            "recommendation": artifacts.recommendation,
            "summary": artifacts.summary.text if artifacts.summary else "",
            "summary_ai_generated": bool(artifacts.summary and artifacts.summary.ai_generated),
            "report_pdf_url": artifacts.report_pdf_url,
            "report_md_url": artifacts.report_md_url,
            "financial_risk": (
                {**artifacts.risk.model_dump(), "headline": artifacts.risk.headline} if artifacts.risk else None
            ),
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
    should_reset, user_text, summary_note, _ = parse_chat_payload(raw_data)
    return should_reset, user_text, summary_note


def _build_chat_client() -> tuple[AsyncOpenAI, str]:
    """Build the configured AsyncOpenAI client and model name."""
    if not settings.air_gapped and settings.llm_provider == LLMProvider.OPENROUTER and settings.openrouter_api_key:
        return (
            AsyncOpenAI(base_url="https://openrouter.ai/api/v1", api_key=settings.openrouter_api_key, timeout=20.0),
            settings.openrouter_model,
        )
    if not settings.air_gapped and settings.llm_provider == LLMProvider.GEMINI and settings.gemini_api_key:
        return (
            AsyncOpenAI(
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key=settings.gemini_api_key,
                timeout=20.0,
            ),
            settings.gemini_model,
        )
    return (
        AsyncOpenAI(base_url=settings.ollama_base_url.rstrip("/") + "/v1", api_key="ollama", timeout=20.0),
        settings.ollama_model,
    )


class ChatHttpRequest(BaseModel):
    message: str
    scan_context: Optional[Dict[str, Any]] = None


class AIConfigUpdateRequest(BaseModel):
    provider: str = "ollama"  # ollama | openrouter | anthropic | gemini | openai
    model: Optional[str] = None
    api_key: Optional[str] = None
    reset: bool = False


@app.get("/api/ai/config")
async def get_ai_config():
    """Return active AI engine status and discovered local Ollama models (never returns API keys)."""
    return await get_runtime_status()


@app.post("/api/ai/config")
async def update_ai_config(req: AIConfigUpdateRequest):
    """Switch active AI model between strict local Ollama (0 bytes cloud) and session-only BYOK."""
    try:
        if req.reset or req.provider.strip().lower() == "ollama":
            if req.reset:
                reset_runtime_override()
            else:
                set_runtime_override("ollama", model=req.model, api_key=None)
        else:
            set_runtime_override(req.provider, model=req.model, api_key=req.api_key)
    except ValueError as err:
        return JSONResponse(status_code=400, content={"error": str(err)})
    return await get_runtime_status()


async def _try_handle_bot_command(data: str) -> Optional[Dict[str, Any]]:
    """Mirror Telegram bot commands (/verify and GitHub repo URL/slug scanning) directly in web chat."""
    text = data.strip()
    if not text:
        return None

    # 1. /verify command (1:1 with Telegram bot/main.py)
    if text.startswith("/verify"):
        parts = text.split()
        if len(parts) < 2:
            return {
                "reply": (
                    "### Проверка авторства (`/verify`)\n\n"
                    "- `/verify owner/repo` — получить одноразовый код подтверждения\n"
                    "- `/verify owner/repo cybersec-verify-xxxx` — проверить код в коммите или `verify.txt`"
                ),
                "ai_generated": False,
            }
        target = parts[1]
        if len(parts) >= 3:
            ok, msg = await OwnershipVerifier.verify_commit_challenge(target, parts[2])
            badge = "✅" if ok else "⛔"
            payload: Dict[str, Any] = {"reply": f"{badge} {msg}", "ai_generated": False}
            if ok:
                parsed_repo = OwnershipVerifier.parse_github_repo(target) or target
                proof_token = OwnershipVerifier.create_proof_token(parsed_repo, "commit_challenge", "verified-author")
                payload["verified_authorship"] = {
                    "target": parsed_repo,
                    "proof_token": proof_token,
                    "method": "commit_challenge",
                    "actor": "verified-author",
                    "role": "CommitVerified",
                    "message": msg,
                }
                payload["reply"] = (
                    f"✅ {msg}\n\n"
                    f"Доступ открыт — теперь вставь `https://github.com/{parsed_repo}` для запуска аудита."
                )
            return payload
        try:
            ch = await OwnershipVerifier.issue_challenge_async(target, "github")
            code = ch["challenge_code"]
            repo = ch["target"]
            verify_url = ch.get("verify_url") or OwnershipVerifier.build_github_verify_url(repo, code)
            return {
                "reply": (
                    f"Подтверди, что `{repo}` — твой репозиторий (код `{code}`). Нажми кнопку ниже → на GitHub нажми **Commit changes** — я сама всё проверю и сразу запущу аудит!"
                ),
                "verify_challenge": {
                    "repo_name": repo,
                    "challenge_code": code,
                    "verify_url": verify_url,
                    "verify_filename": ch.get("verify_filename") or "verify.txt",
                    "default_branch": ch.get("default_branch") or "main",
                },
                "ai_generated": False,
            }
        except ValueError as err:
            return {"reply": f"⛔ {err}", "ai_generated": False}

    # 1.5. /autofix or natural Russian intent ("исправь и закоммить", "пофикси и запушь")
    low = text.lower()
    autofix_intent = (
        low.startswith(("/autofix", "/fix", "/heal", "/commit"))
        or bool(re.search(r"\bавтофикс", low))
        or (
            re.search(r"(исправ|пофикс|почин|самоисцел|запатч|фикс)", low)
            and re.search(
                r"(коммит|закоммит|commit|пуш|запуш|push|\bpr\b|\bпр\b|pull\s*request|github|гитхаб)",
                low,
            )
        )
    )
    if autofix_intent:
        direct = bool(re.search(r"(прямо в main|сразу в main|--direct|direct)", low))
        return {
            "action": "AUTOFIX",
            "direct_commit": direct,
            "reply": "Запускаю Auto-Fix & Commit (как Claude Code): исправляю баги → пересканирую → готовлю атомарный коммит в GitHub…",
            "ai_generated": False,
        }

    # 2. GitHub URL anywhere in message OR clean bare owner/repo message
    repo_candidate = next((w for w in text.split() if "github.com/" in w), None)
    if repo_candidate:
        parsed = OwnershipVerifier.parse_github_repo(repo_candidate)
        if parsed:
            return {
                "action": "SCAN",
                "github_url": f"https://github.com/{parsed}",
                "reply": f"Клонирую `{parsed}`, читаю коммиты и запускаю локальный аудит...",
                "ai_generated": False,
            }
    elif len(text.split()) == 1 and "/" in text and not text.startswith("/"):
        parsed = OwnershipVerifier.parse_github_repo(text)
        if parsed:
            return {
                "action": "SCAN",
                "github_url": f"https://github.com/{parsed}",
                "reply": f"Клонирую `{parsed}`, читаю коммиты и запускаю локальный аудит...",
                "ai_generated": False,
            }

    return None


_GROUNDED_PRODUCT_FAQ_PROMPTS = {
    "самоисцеление и git-секреты",
    "как работает проверка авторства?",
    "как работает проверка авторства",
    "оцени риск в тенге (коап рк)",
}

_APPSEC_CHAT_SYSTEM_PROMPT = (
    "Ты Aegis Orca (Commit Guardian) — живая, умная и дружелюбная косатка-компаньон и AI AppSec инженер. "
    "Ты умеешь свободно и естественно общаться на любые обычные темы (поприветствовать, поболтать, поддержать, "
    "помочь с идеей, кодом, питчем, учебой или пошутить), отвечая по-человечески, живо и без канцелярита. "
    "А когда спрашивают про безопасность или кидают репозиторий — ты профи по AppSec: 12 сканеров (Semgrep, Bandit, "
    "pip-audit, Python AST Taint, JS/TS/Next.js Taint & Server Actions, OSV/npm SCA, AI Business-Logic Auditor на "
    "IDOR/Auth/SSRF/Race Conditions, «Машина времени Git» для секретов в удалённых коммитах, Self-Healing Auto-Fix "
    "с SAST-перепроверкой и атомарным коммитом в GitHub, оценка риска по КоАП РК ст. 79 в ₸, Strict Ownership Gate "
    "с HMAC proof_token). Отвечай на русском языке кратко, понятно и по делу."
)


@app.post("/api/chat")
async def http_chat(req: ChatHttpRequest):
    """HTTP fallback for AI AppSec chat when WebSocket transport is unavailable."""
    data = req.message.strip()
    if not data:
        return {"reply": "", "ai_generated": False}

    cmd_result = await _try_handle_bot_command(data)
    if cmd_result is not None:
        return cmd_result

    ctx_dict = req.scan_context if isinstance(req.scan_context, dict) and req.scan_context.get("repo_name") else None
    _, resolved_model, _, _ = await resolve_active_llm()

    # Serve exact built-in Commit Guardian FAQ quick-prompts deterministically (exact KZ law & feature facts)
    if data.lower() in _GROUNDED_PRODUCT_FAQ_PROMPTS and not ctx_dict:
        return {
            "reply": build_offline_appsec_reply(data, ctx_dict, resolved_model),
            "ai_generated": False,
            "model": resolved_model,
        }

    scan_context_note = format_scan_context_note(ctx_dict)
    user_content = f"{scan_context_note}\n\nВопрос пользователя: {data}" if scan_context_note else data

    reply = await chat_completion(
        _APPSEC_CHAT_SYSTEM_PROMPT,
        user_content,
        temperature=0.45,
        max_tokens=700,
        timeout=20.0,
        task_label="HTTPChat",
    )
    if reply:
        return {"reply": reply, "ai_generated": True, "model": resolved_model}

    return {
        "reply": build_offline_appsec_reply(data, ctx_dict, resolved_model),
        "ai_generated": False,
        "model": resolved_model,
    }


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()

    system_prompt = _APPSEC_CHAT_SYSTEM_PROMPT
    chat_history = [{"role": "system", "content": system_prompt}]

    try:
        while True:
            raw_data = await websocket.receive_text()
            should_reset, data, scan_context_note, ctx_dict = parse_chat_payload(raw_data)
            if should_reset:
                chat_history = [{"role": "system", "content": system_prompt}]
                await websocket.send_json({"type": "done"})
                continue
            if not data:
                await websocket.send_json({"type": "done"})
                continue

            # Mirror Telegram bot commands (/verify, GitHub URL, or bare owner/repo)
            cmd_result = await _try_handle_bot_command(data)
            if cmd_result is not None:
                chat_history.append({"role": "user", "content": data})
                reply = cmd_result["reply"]
                chat_history.append({"role": "assistant", "content": reply})
                if cmd_result.get("verified_authorship"):
                    await websocket.send_json({"type": "authorship", **cmd_result["verified_authorship"]})
                if cmd_result.get("verify_challenge"):
                    await websocket.send_json({
                        "type": "verify_challenge",
                        "message": reply,
                        **cmd_result["verify_challenge"],
                    })
                    await websocket.send_json({"type": "done"})
                    continue
                if cmd_result.get("action") == "AUTOFIX":
                    await websocket.send_json({
                        "type": "action",
                        "action": "AUTOFIX",
                        "direct_commit": bool(cmd_result.get("direct_commit")),
                    })
                    await websocket.send_json({"type": "done"})
                    continue
                if cmd_result.get("action") == "SCAN":
                    # Let the frontend startScan() own the single scan progress bubble (avoid glued duplicates)
                    await websocket.send_json({"type": "action", "action": "SCAN", "github_url": cmd_result["github_url"]})
                    await websocket.send_json({"type": "done"})
                    continue
                await websocket.send_json({"type": "chunk", "content": reply})
                await websocket.send_json({"type": "done"})
                continue

            user_content = f"{scan_context_note}\n\nВопрос пользователя: {data}" if scan_context_note else data
            chat_history.append({"role": "user", "content": user_content})
            # Cap history to system prompt + recent 16 turns to keep local inference fast
            if len(chat_history) > 17:
                chat_history = [chat_history[0]] + chat_history[-16:]

            provider, model, api_key, _is_local = await resolve_active_llm()
            try:
                full_response = ""
                if provider in (LLMProvider.ANTHROPIC, LLMProvider.GEMINI) and api_key:
                    combined = "\n\n".join(
                        f"{m['role'].upper()}: {m['content']}" for m in chat_history[1:]
                    )
                    full_response = (
                        await chat_completion(
                            system_prompt,
                            combined,
                            temperature=0.45,
                            max_tokens=700,
                            timeout=25.0,
                            task_label=f"WSChat:{provider.value}",
                        )
                    ) or ""
                    if full_response:
                        await websocket.send_json({"type": "chunk", "content": full_response})
                else:
                    client = build_openai_client(provider, api_key, timeout=25.0)
                    stream = await client.chat.completions.create(
                        model=model,
                        messages=chat_history,
                        temperature=0.45,
                        max_tokens=700,
                        stream=True,
                    )
                    async for chunk in stream:
                        if chunk.choices and chunk.choices[0].delta.content:
                            content = chunk.choices[0].delta.content
                            full_response += content
                            await websocket.send_json({"type": "chunk", "content": content})
                if not full_response.strip():
                    full_response = build_offline_appsec_reply(data, ctx_dict, model)
                    await websocket.send_json({"type": "chunk", "content": full_response})
            except Exception as llm_err:
                logger.warning(f"LLM chat ({provider.value}/{model}) unavailable, serving AppSec fallback: {llm_err}")
                full_response = build_offline_appsec_reply(data, ctx_dict, model)
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
