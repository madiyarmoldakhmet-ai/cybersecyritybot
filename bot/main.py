"""
Main entry point for Aegis Telegram Daemon.
Initializes aiogram Dispatcher, middlewares, and starts polling.
"""

import asyncio
import html
import logging
import uuid
import shutil
from pathlib import Path
from typing import Optional
from aiogram import Bot, Dispatcher, Router, types, F
from aiogram.filters import CommandStart
from aiogram.types import FSInputFile, InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from aegis.core.archive_utils import safe_extract_zip
from aegis.core.audit_pipeline import finalize_scan_audit
from aegis.core.config import settings
from aegis.core.logging_config import setup_logging
from aegis.core.verifier import OwnershipVerifier
from aegis.scanners.models import SASTScanResult, Severity
from aegis.scanners.sast_scanner import SASTScanner
from aegis.scanners.security_score import calculate_score, get_grade
from aegis.core.event_bus import ScanEventBus

setup_logging()
logger = logging.getLogger("aegis.main")

router = Router()


def _is_authorized_user(user_id: Optional[int]) -> bool:
    """Allow all users only when ALLOWED_TELEGRAM_USERS is empty in development."""
    if not settings.allowed_telegram_users:
        return settings.environment.lower() != "production"
    return user_id in settings.allowed_telegram_users


def _format_scan_summary(result: SASTScanResult) -> str:
    """Format an HTML-safe Telegram summary from SASTScanResult."""
    crit = result.findings_by_severity.get(Severity.CRITICAL, 0)
    high = result.findings_by_severity.get(Severity.HIGH, 0)
    med = result.findings_by_severity.get(Severity.MEDIUM, 0)
    low = result.findings_by_severity.get(Severity.LOW, 0)
    score = calculate_score(result.findings)
    grade, _, _ = get_grade(score)

    lines = [
        f"✅ <b>[Commit Guardian] Сканирование завершено</b> ({result.duration_seconds:.2f} с)",
        f"🏅 <b>Security Score:</b> <code>{score}/100 ({html.escape(grade)})</code>",
        f"Найдено уязвимостей: <b>{result.total_findings}</b> "
        f"(🔴 {crit} · 🟠 {high} · 🟡 {med} · 🔵 {low})",
    ]

    top = sorted(
        result.findings,
        key=lambda f: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO].index(f.severity),
    )[:5]
    if top:
        lines.append("\n<b>Топ находок:</b>")
        for idx, f in enumerate(top, 1):
            loc = html.escape(f"{f.file_path}:{f.line_start or 1}")
            lines.append(f"{idx}. [<b>{html.escape(f.severity.value)}</b>] {html.escape(f.title)} — <code>{loc}</code>")
    return "\n".join(lines)


async def _deliver_scan_result(
    message: types.Message,
    status_msg: types.Message,
    result: SASTScanResult,
    repo_name: str,
    commit_sha: str,
) -> None:
    """Persist audit report, update Telegram status message, and attach Compliance PDF."""
    author = message.from_user.username or str(message.from_user.id) if message.from_user else "telegram-user"
    artifacts = await finalize_scan_audit(
        result,
        repo_name=repo_name,
        commit_sha=commit_sha,
        branch="main",
        author=author,
    )
    summary_html = _format_scan_summary(result)
    if artifacts.risk and artifacts.risk.total_kzt:
        summary_html += f"\n\n💸 <b>{html.escape(artifacts.risk.headline)}</b> <i>(ст. 79 КоАП РК)</i>"
    if artifacts.summary and artifacts.summary.text:
        summary_html += f"\n\n🧠 <b>Заключение:</b>\n{html.escape(artifacts.summary.text[:800])}"
    await status_msg.edit_text(summary_html, parse_mode=ParseMode.HTML)

    if artifacts.report_pdf_path and Path(artifacts.report_pdf_path).is_file():
        await message.reply_document(
            FSInputFile(artifacts.report_pdf_path),
            caption=f"📄 Compliance-отчёт Commit Guardian · Score {artifacts.score}/100 ({artifacts.grade})",
        )


@router.message(CommandStart())
async def send_welcome(message: types.Message):
    """Handler for the /start command. Sends a welcome message."""
    if not _is_authorized_user(message.from_user.id if message.from_user else None):
        await message.answer("⛔ Доступ ограничен.")
        return

    welcome_text = (
        "🔒 <b>Commit Guardian</b> — локальный DevSecOps-аудит без утечки кода в облако.\n\n"
        "Отправьте <b>ZIP-архив</b> или ссылку на публичный <b>GitHub-репозиторий</b> — "
        "я проверю код на уязвимости, посчитаю Security Score и пришлю официальный <b>PDF-отчёт</b>."
    )
    kb = None
    if settings.web_app_url.startswith("https://"):
        kb = InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="🖥 Открыть консоль", web_app=WebAppInfo(url=settings.web_app_url))]]
        )
    await message.answer(welcome_text, parse_mode=ParseMode.HTML, reply_markup=kb)


@router.message(F.document)
async def handle_document(message: types.Message, bot: Bot):
    if not _is_authorized_user(message.from_user.id if message.from_user else None):
        await message.reply("⛔ Доступ ограничен.")
        return

    if not message.document.file_name or not message.document.file_name.lower().endswith(".zip"):
        await message.reply("Пожалуйста, отправьте ZIP-архив.")
        return

    if message.document.file_size and message.document.file_size > 20 * 1024 * 1024:
        await message.reply("Файл слишком большой. Лимит 20MB.")
        return

    status_msg = await message.reply("Скачиваю архив...")

    scan_uuid = str(uuid.uuid4())
    repo_dir = settings.temp_clone_dir / f"tg_{scan_uuid}"
    zip_path = repo_dir / "upload.zip"
    extract_dir = repo_dir / "code"

    repo_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        await bot.download(message.document, destination=zip_path)
        await status_msg.edit_text("Распаковка и анализ...")

        safe_extract_zip(zip_path, extract_dir)

        event_bus = ScanEventBus(scan_id=scan_uuid)
        scanner = SASTScanner(event_bus=event_bus)

        result = await scanner.scan(extract_dir)
        zip_label = Path(message.document.file_name).stem or "archive"
        await _deliver_scan_result(message, status_msg, result, f"telegram/{zip_label}", scan_uuid[:12])
    except Exception as e:
        logger.error(f"Error processing zip: {e}")
        await status_msg.edit_text(f"Ошибка при сканировании: {html.escape(str(e)[:300])}", parse_mode=ParseMode.HTML)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
        logger.info("Код удалён с сервера")


@router.message(F.text.startswith("/verify"))
async def handle_verify_command(message: types.Message):
    """Issue or check commit-based repository authorship proof from Telegram."""
    if not _is_authorized_user(message.from_user.id if message.from_user else None):
        await message.reply("⛔ Доступ ограничен.")
        return

    parts = (message.text or "").strip().split()
    if len(parts) < 2:
        await message.reply(
            "Использование:\n"
            "• <code>/verify owner/repo</code> — получить код подтверждения\n"
            "• <code>/verify owner/repo cybersec-verify-xxxx</code> — проверить авторство в коммите или <code>verify.txt</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    target = parts[1]
    if len(parts) >= 3:
        ok, msg = await OwnershipVerifier.verify_commit_challenge(target, parts[2])
        badge = "✅" if ok else "⛔"
        await message.reply(f"{badge} {html.escape(msg)}", parse_mode=ParseMode.HTML)
        return

    try:
        ch = OwnershipVerifier.issue_challenge(target, "github")
        code = html.escape(ch["challenge_code"])
        repo = html.escape(ch["target"])
        await message.reply(
            f"🔐 <b>Код подтверждения авторства для</b> <code>{repo}</code>:\n"
            f"<code>{code}</code>\n\n"
            f"Выполните в репозитории:\n"
            f"<code>git commit --allow-empty -m \"{code}\" &amp;&amp; git push</code>\n\n"
            f"Затем проверьте командой:\n"
            f"<code>/verify {repo} {code}</code>",
            parse_mode=ParseMode.HTML,
        )
    except ValueError as err:
        await message.reply(f"⛔ {html.escape(str(err))}")


@router.message(F.text)
async def handle_repo_url(message: types.Message):
    if not _is_authorized_user(message.from_user.id if message.from_user else None):
        await message.reply("⛔ Доступ ограничен.")
        return

    repo_name = OwnershipVerifier.parse_github_repo((message.text or "").strip())
    if not repo_name:
        await message.reply("Отправьте ZIP-архив, ссылку на GitHub или <code>/verify owner/repo</code> для проверки авторства.", parse_mode=ParseMode.HTML)
        return

    is_accessible, access_msg, _ = await OwnershipVerifier.verify_github_access(settings.github_token, repo_name)
    if not is_accessible:
        await message.reply(f"⛔ {html.escape(access_msg)}", parse_mode=ParseMode.HTML)
        return

    status_msg = await message.reply(f"Клонирую <code>{html.escape(repo_name)}</code> и запускаю скан...", parse_mode=ParseMode.HTML)

    scan_uuid = str(uuid.uuid4())
    repo_dir = settings.temp_clone_dir / f"tg_{scan_uuid}"
    repo_dir.mkdir(parents=True, exist_ok=True)
    clone_url = f"https://github.com/{repo_name}.git"

    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--", clone_url, str(repo_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=45.0)
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")[:200]
            await status_msg.edit_text(f"Не удалось клонировать репозиторий: <code>{html.escape(err)}</code>", parse_mode=ParseMode.HTML)
            return

        scanner = SASTScanner(event_bus=ScanEventBus(scan_id=scan_uuid))
        result = await scanner.scan(repo_dir)
        await _deliver_scan_result(message, status_msg, result, repo_name, scan_uuid[:12])
    except Exception as e:
        logger.error(f"Error scanning repository {repo_name}: {e}")
        await status_msg.edit_text(f"Ошибка при сканировании: {html.escape(str(e)[:300])}", parse_mode=ParseMode.HTML)
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
        logger.info("Код удалён с сервера")


async def run_bot() -> None:
    """Initialize and start Telegram bot long polling."""
    token = settings.telegram_bot_token
    if not token or token == "your_telegram_bot_token_here":
        logger.error(
            "TELEGRAM_BOT_TOKEN is not configured! Please set it in .env or environment variables."
        )
        return

    bot = Bot(
        token=token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    storage = MemoryStorage()
    dp = Dispatcher(storage=storage)

    # Register bot routers
    dp.include_router(router)

    logger.info(f"Starting {settings.app_name} Telegram Bot...")

    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


def main():
    try:
        asyncio.run(run_bot())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot stopped by user.")


if __name__ == "__main__":
    main()
