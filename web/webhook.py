"""
GitHub Webhook Server & "Commit Guardian" for Aegis.
Listens for git `push` and `pull_request` events, executes instant asynchronous
SAST & Mobile DevSecOps scans in the background, and dispatches urgent Telegram alerts.
"""

import asyncio
import hashlib
import hmac
import html
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlunparse

from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from fastapi import APIRouter, Header, HTTPException, Request, Response, status
import httpx

from aegis.ai.audit_summarizer import AuditSummarizer
from aegis.core.audit_pipeline import finalize_scan_audit
from aegis.core.config import settings
from aegis.core.metrics_store import get_metrics_store
from aegis.core.queue_manager import task_queue
from aegis.reporting import AuditReportWriter
from aegis.scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from aegis.scanners.sast_scanner import SASTScanner
from aegis.scanners.security_score import calculate_score, get_grade

logger = logging.getLogger("aegis.webhook")
router = APIRouter(prefix="/api/v1", tags=["Commit Guardian Webhooks"])


def verify_github_signature(payload_body: bytes, signature_header: Optional[str]) -> bool:
    """Verify HMAC SHA-256 signature from GitHub webhook header."""
    secret = settings.github_webhook_secret
    if not secret:
        # Unsigned webhooks are tolerated only outside production (local dev / demos)
        if settings.environment.lower() == "production":
            logger.error("Rejected webhook: GITHUB_WEBHOOK_SECRET is required in production.")
            return False
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
    commit_url: Optional[str] = None,
    report_name: Optional[str] = None
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
        score = calculate_score(scan_result.findings)
        grade, _, _ = get_grade(score)

        e = html.escape
        alert_lines = [
            "🚨 <b>[Commit Guardian] Обнаружена угроза безопасности!</b>\n",
            f"📦 <b>Репозиторий:</b> <code>{e(repo_name)}</code>",
            f"🌿 <b>Ветка:</b> <code>{e(branch)}</code>",
            f"👤 <b>Автор коммита:</b> <code>{e(author)}</code>",
            f"🔖 <b>Коммит:</b> <code>{e(commit_sha[:8])}</code>",
            f"🏅 <b>Security Score:</b> <code>{score}/100 ({e(grade)})</code>\n",
            "📊 <b>Результаты сканирования (SAST &amp; Mobile):</b>",
            f"• 🔴 Critical: <code>{crit_count}</code>",
            f"• 🟠 High: <code>{high_count}</code>",
            f"• 🟡 Medium: <code>{med_count}</code>\n",
            "🔍 <b>Критические уязвимости:</b>",
        ]

        # List top 3 high/critical findings
        high_findings = [f for f in scan_result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:3]
        for idx, f in enumerate(high_findings, 1):
            scanner_badge = "📱 Mobile" if f.scanner.value == "mobile" else f.scanner.value
            rec = f.recommendation or f.description[:100]
            alert_lines.append(
                f"{idx}. [{e(f.severity.value)}] <b>{e(f.title)}</b> ({e(scanner_badge)})\n"
                f"   📁 <code>{e(f.file_path)}</code> (стр. {f.line_start or 1})\n"
                f"   💡 {e(rec)}"
            )

        if report_name:
            alert_lines.append(f"\n📄 <b>Отчёт аудита:</b> <code>{e(report_name)}</code>")

        alert_text = "\n".join(alert_lines)

        buttons = []
        if commit_url:
            buttons.append([InlineKeyboardButton(text="🔗 Открыть коммит на GitHub", url=commit_url)])

        kb = InlineKeyboardMarkup(inline_keyboard=buttons) if buttons else None

        await bot.send_message(
            chat_id=chat_id,
            text=alert_text,
            reply_markup=kb,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True
        )
        logger.info(f"📬 Sent Commit Guardian Telegram alert to chat_id={chat_id} for {repo_name}")

    except Exception as e:
        logger.exception(f"Failed to send Telegram alert: {e}")
    finally:
        await bot.session.close()


async def post_github_pr_comment(
    repo_name: str,
    pr_number: int,
    commit_sha: str,
    scan_result: SASTScanResult,
    score: int,
    grade: str,
    summary_text: str,
) -> bool:
    """Post automated Commit Guardian audit summary on a GitHub Pull Request."""
    token = (settings.github_token or "").strip()
    if not token or token.startswith("ghp_your"):
        return False

    crit = scan_result.findings_by_severity.get(Severity.CRITICAL, 0)
    high = scan_result.findings_by_severity.get(Severity.HIGH, 0)
    med = scan_result.findings_by_severity.get(Severity.MEDIUM, 0)
    top_rows = ""
    for f in scan_result.findings[:5]:
        cwe = ", ".join(f.cwe) or "—"
        top_rows += f"| **{f.severity.value}** | {f.title} | `{f.file_path}:{f.line_start or 1}` | `{cwe}` |\n"

    table_block = (
        "| Severity | Issue | Location | CWE |\n|---|---|---|---|\n" + top_rows
        if top_rows
        else "_Критических и заметных уязвимостей не обнаружено._\n"
    )
    body = (
        f"## 🔒 Commit Guardian — On-Premise Audit (`{commit_sha[:8]}`)\n\n"
        f"- **Security Score:** `{score}/100 ({grade})`\n"
        f"- **Findings:** Critical `{crit}` · High `{high}` · Medium `{med}` · Total `{scan_result.total_findings}`\n"
        f"- **Privacy:** Проанализировано локально (без передачи кода во внешние облака)\n\n"
        f"### Заключение\n{summary_text}\n\n"
        f"### Детали находок\n{table_block}"
    )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "Commit-Guardian",
                },
                json={"body": body},
            )
        if resp.status_code in (200, 201):
            logger.info(f"Posted PR audit comment on {repo_name}#{pr_number}")
            return True
        logger.warning(f"GitHub PR comment returned HTTP {resp.status_code} for {repo_name}#{pr_number}")
    except Exception as exc:
        logger.warning(f"Failed to post PR comment on {repo_name}#{pr_number}: {exc}")
    return False


async def process_guardian_audit(
    repo_name: str,
    clone_url: str,
    commit_sha: str,
    author: str,
    branch: str,
    commit_url: Optional[str] = None,
    pr_number: Optional[int] = None,
) -> SASTScanResult:
    """Clone pushed commit and run multi-language SAST & Mobile security audit."""
    scan_id = str(uuid.uuid4())[:8]
    temp_dir = settings.temp_clone_dir / f"guardian_scan_{scan_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    auth_clone_url = clone_url
    if settings.github_token:
        parsed = urlparse(clone_url or "")
        if parsed.scheme == "https" and parsed.netloc:
            host = parsed.netloc.split("@")[-1]
            auth_clone_url = urlunparse(parsed._replace(netloc=f"x-access-token:{settings.github_token}@{host}"))
        else:
            auth_clone_url = f"https://x-access-token:{settings.github_token}@github.com/{repo_name}.git"

    try:
        # Clone single branch depth 1
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--branch", branch, "--", auth_clone_url, str(temp_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=45.0)
        if proc.returncode != 0:
            # Never report an empty checkout as a clean audit
            err = stderr.decode("utf-8", errors="replace")
            if settings.github_token:
                err = err.replace(settings.github_token, "***")
            raise RuntimeError(f"git clone failed for {repo_name}@{branch}: {err.strip()[:300]}")

        # 1. Run Aegis Deep Agentic Scanner
        from aegis.scanners.aegis_runner import AegisEngine
        aegis_engine = AegisEngine()
        aegis_res_task = asyncio.create_task(aegis_engine.scan(temp_dir))

        # 2. Run AST rule scanner
        from aegis.scanners.sast_scanner import SASTScanner
        sast_scanner = SASTScanner()
        sast_res_task = asyncio.create_task(sast_scanner.scan(temp_dir))

        aegis_res, sast_res = await asyncio.gather(aegis_res_task, sast_res_task)

        # Merge findings (Aegis first, then AST findings deduplicated)
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

        scan_result = SASTScanResult(
            target_path=str(temp_dir),
            total_findings=len(all_findings),
            findings_by_severity=severity_counts,
            findings=all_findings,
            duration_seconds=total_duration,
            scanners_run=[ScannerType.STRIX, ScannerType.SEMGREP, ScannerType.BANDIT],
            errors=aegis_res.errors + sast_res.errors,
        )

        # 3. Local AI summary + compliance report + observability metrics
        artifacts = await finalize_scan_audit(
            scan_result,
            repo_name=repo_name,
            commit_sha=commit_sha,
            branch=branch,
            author=author,
            commit_url=commit_url,
            summarizer_cls=AuditSummarizer,
            writer_cls=AuditReportWriter,
        )
        report_name = artifacts.report_name

        if pr_number is not None:
            await post_github_pr_comment(
                repo_name=repo_name,
                pr_number=pr_number,
                commit_sha=commit_sha,
                scan_result=scan_result,
                score=artifacts.score,
                grade=artifacts.grade,
                summary_text=artifacts.summary.text if artifacts.summary else "",
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
                    commit_url=commit_url,
                    report_name=report_name
                )

        return scan_result

    except Exception as e:
        try:
            get_metrics_store().record_failure(repo_name, commit_sha, branch, str(e))
        except Exception:
            logger.exception("Failed to record audit failure metrics")
        raise

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
            commit_url=pr_url,
            pr_number=payload.get("number"),
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
