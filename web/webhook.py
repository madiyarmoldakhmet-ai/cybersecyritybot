"""
GitHub Webhook Server & "Commit Guardian" for CyberSecurityBot.
Listens for git `push` and `pull_request` events, executes instant asynchronous
SAST & Mobile DevSecOps scans in the background, and dispatches urgent Telegram alerts.
"""

import asyncio
import hashlib
import hmac
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from aiogram import Bot
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from fastapi import APIRouter, Header, HTTPException, Request, Response, status

from core.config import settings
from core.queue_manager import task_queue
from scanners.models import SASTScanResult, Severity, VulnerabilityFinding
from scanners.sast_scanner import SASTScanner

logger = logging.getLogger("cybersecuritybot.webhook")
router = APIRouter(prefix="/api/v1", tags=["Commit Guardian Webhooks"])


def verify_github_signature(payload_body: bytes, signature_header: Optional[str]) -> bool:
    """Verify HMAC SHA-256 signature from GitHub webhook header."""
    secret = settings.github_webhook_secret
    if not secret:
        # If no secret is configured, allow requests (useful for local dev/testing)
        return True

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_signature = signature_header[7:]
    mac = hmac.new(secret.encode("utf-8"), payload_body, hashlib.sha256)
    computed_signature = mac.hexdigest()

    return hmac.compare_digest(computed_signature, expected_signature)


async def send_telegram_alert(
    chat_id: int,
    repo_name: str,
    commit_sha: str,
    author: str,
    branch: str,
    scan_result: SASTScanResult,
    commit_url: Optional[str] = None
) -> None:
    """Dispatch rich Commit Guardian security alert via Telegram Bot."""
    if not settings.telegram_bot_token:
        logger.warning("Telegram Bot Token is not configured. Cannot send Commit Guardian alert.")
        return

    bot = Bot(token=settings.telegram_bot_token)
    try:
        crit_count = scan_result.findings_by_severity.get(Severity.CRITICAL, 0)
        high_count = scan_result.findings_by_severity.get(Severity.HIGH, 0)
        med_count = scan_result.findings_by_severity.get(Severity.MEDIUM, 0)

        alert_lines = [
            "🚨 **[Commit Guardian] Обнаружена угроза безопасности!**\n",
            f"📦 **Репозиторий:** `{repo_name}`",
            f"🌿 **Ветка:** `{branch}`",
            f"👤 **Автор коммита:** `{author}`",
            f"🔖 **Коммит:** `{commit_sha[:8]}`\n",
            "📊 **Результаты сканирования (SAST & Mobile):**",
            f"• 🔴 Critical: `{crit_count}`",
            f"• 🟠 High: `{high_count}`",
            f"• 🟡 Medium: `{med_count}`\n",
            "🔍 **Критические уязвимости:**",
        ]

        # List top 3 high/critical findings
        high_findings = [f for f in scan_result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:3]
        for idx, f in enumerate(high_findings, 1):
            scanner_badge = "📱 Mobile" if f.scanner.value == "mobile" else f.scanner.value
            alert_lines.append(
                f"{idx}. [{f.severity.value}] **{f.title}** ({scanner_badge})\n"
                f"   📁 `{f.file_path}` (стр. {f.line_start or 1})\n"
                f"   💡 {f.recommendation or f.description[:100]}"
            )

        alert_text = "\n".join(alert_lines)

        buttons = []
        if commit_url:
            buttons.append([InlineKeyboardButton(text="🔗 Открыть коммит на GitHub", url=commit_url)])

        kb = InlineKeyboardMarkup(inline_keyboard=buttons) if buttons else None

        await bot.send_message(
            chat_id=chat_id,
            text=alert_text,
            reply_markup=kb,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
        logger.info(f"📬 Sent Commit Guardian Telegram alert to chat_id={chat_id} for {repo_name}")

    except Exception as e:
        logger.exception(f"Failed to send Telegram alert: {e}")
    finally:
        await bot.session.close()


async def process_guardian_audit(
    repo_name: str,
    clone_url: str,
    commit_sha: str,
    author: str,
    branch: str,
    commit_url: Optional[str] = None
) -> SASTScanResult:
    """Clone pushed commit and run multi-language SAST & Mobile security audit."""
    scan_id = str(uuid.uuid4())[:8]
    temp_dir = settings.temp_clone_dir / f"guardian_scan_{scan_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    auth_clone_url = clone_url
    if settings.github_token:
        auth_clone_url = f"https://x-access-token:{settings.github_token}@github.com/{repo_name}.git"

    try:
        # Clone single branch depth 1
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--branch", branch, auth_clone_url, str(temp_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=45.0)

        # 1. Run Strix Deep Agentic Scanner
        from scanners.strix_runner import StrixEngine
        strix_engine = StrixEngine()
        strix_res_task = asyncio.create_task(strix_engine.scan(temp_dir))

        # 2. Run AST rule scanner
        from scanners.sast_scanner import SASTScanner
        sast_scanner = SASTScanner()
        sast_res_task = asyncio.create_task(sast_scanner.scan(temp_dir))

        strix_res, sast_res = await asyncio.gather(strix_res_task, sast_res_task)

        # Merge findings (Strix first, then AST findings deduplicated)
        all_findings = list(strix_res.findings)
        seen_keys = {f"{f.file_path}:{f.line_start}:{f.title}" for f in strix_res.findings}

        for sf in sast_res.findings:
            key = f"{sf.file_path}:{sf.line_start}:{sf.title}"
            if key not in seen_keys:
                all_findings.append(sf)
                seen_keys.add(key)

        total_duration = round(strix_res.duration_seconds + sast_res.duration_seconds, 2)
        severity_counts = {}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        scan_result = SASTScanResult(
            target_path=str(temp_dir),
            total_findings=len(all_findings),
            findings_by_severity=severity_counts,
            findings=all_findings,
            duration_seconds=total_duration,
            scanners_run=[ScannerType.STRIX, ScannerType.SEMGREP, ScannerType.BANDIT],
            errors=strix_res.errors + sast_res.errors,
        )

        crit_count = scan_result.findings_by_severity.get(Severity.CRITICAL, 0)
        high_count = scan_result.findings_by_severity.get(Severity.HIGH, 0)

        # If security risks found, trigger alert
        if (crit_count + high_count) > 0:
            target_chat_id = settings.default_telegram_chat_id
            if not target_chat_id and settings.allowed_telegram_users:
                target_chat_id = settings.allowed_telegram_users[0]

            if target_chat_id:
                await send_telegram_alert(
                    chat_id=target_chat_id,
                    repo_name=repo_name,
                    commit_sha=commit_sha,
                    author=author,
                    branch=branch,
                    scan_result=scan_result,
                    commit_url=commit_url
                )

        return scan_result

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/webhook/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook_handler(
    request: Request,
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256")
) -> Dict[str, Any]:
    """
    Handle GitHub webhook push and pull_request events.
    Verifies signature and dispatches asynchronous background security audit.
    """
    body_bytes = await request.body()

    # 1. Signature Verification
    if not verify_github_signature(body_bytes, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid GitHub webhook signature."
        )

    # 2. Ping Event Handler
    if x_github_event == "ping":
        return {"status": "ok", "message": "GitHub webhook ping received successfully."}

    # 3. Parse JSON payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload.")

    repo_data = payload.get("repository", {})
    repo_name = repo_data.get("full_name", "")
    clone_url = repo_data.get("clone_url", "")

    if not repo_name:
        return {"status": "ignored", "reason": "Missing repository information."}

    # 4. Handle "push" event
    if x_github_event == "push":
        ref = payload.get("ref", "refs/heads/main")
        branch = ref.replace("refs/heads/", "")
        head_commit = payload.get("head_commit") or {}
        commit_sha = head_commit.get("id", payload.get("after", "unknown"))
        author = head_commit.get("author", {}).get("username") or payload.get("pusher", {}).get("name", "Unknown")
        commit_url = head_commit.get("url")

        task_id = await task_queue.enqueue(
            f"CommitGuardian:push:{repo_name}:{commit_sha[:7]}",
            process_guardian_audit,
            repo_name=repo_name,
            clone_url=clone_url,
            commit_sha=commit_sha,
            author=author,
            branch=branch,
            commit_url=commit_url
        )

        return {
            "status": "processing",
            "event": "push",
            "task_id": task_id,
            "repo": repo_name,
            "commit": commit_sha[:8],
            "branch": branch
        }

    # 5. Handle "pull_request" event
    elif x_github_event == "pull_request":
        action = payload.get("action", "")
        if action not in ("opened", "synchronize", "reopened"):
            return {"status": "ignored", "reason": f"Ignored PR action: {action}"}

        pr_data = payload.get("pull_request", {})
        head = pr_data.get("head", {})
        branch = head.get("ref", "main")
        commit_sha = head.get("sha", "unknown")
        author = pr_data.get("user", {}).get("login", "Unknown")
        pr_url = pr_data.get("html_url")

        task_id = await task_queue.enqueue(
            f"CommitGuardian:pr:{repo_name}:#{payload.get('number')}",
            process_guardian_audit,
            repo_name=repo_name,
            clone_url=clone_url,
            commit_sha=commit_sha,
            author=author,
            branch=branch,
            commit_url=pr_url
        )

        return {
            "status": "processing",
            "event": "pull_request",
            "task_id": task_id,
            "repo": repo_name,
            "pr_number": payload.get("number"),
            "commit": commit_sha[:8]
        }

    return {"status": "ignored", "event": x_github_event}
