"""
Telegram Bot Handlers for CyberSecurityBot (aiogram 3.x).
Provides interactive security audit, ownership verification, AI remediation, and auto-PR workflow.
"""

import asyncio
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Dict, Optional

from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
import httpx

from ai.remediation_engine import RemediationEngine, RemediationResult
from core.config import LLMProvider, settings
from core.pr_creator import PullRequestCreator
from core.verifier import OwnershipVerifier
from scanners.models import SASTScanResult, Severity, VulnerabilityFinding
from scanners.sast_scanner import SASTScanner

logger = logging.getLogger("cybersecuritybot.bot")
router = Router()

# In-memory storage for active scan sessions: session_id -> dict
SCAN_SESSIONS: Dict[str, Dict] = {}


class AuditStates(StatesGroup):
    waiting_for_token = State()
    waiting_for_repo = State()


def get_main_menu_keyboard() -> InlineKeyboardMarkup:
    """Generate main menu inline keyboard."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🛡️ Начать аудит репозитория",
                    callback_data="start_audit"
                )
            ],
            [
                InlineKeyboardButton(
                    text="⚡ Статус AI Движка (Ollama)",
                    callback_data="check_ai_status"
                ),
                InlineKeyboardButton(
                    text="📖 Справка",
                    callback_data="help_info"
                )
            ],
        ]
    )


@router.message(CommandStart())
async def handle_start(message: Message, state: FSMContext) -> None:
    """Handle /start command with rich welcome and status."""
    await state.clear()
    user_name = message.from_user.first_name if message.from_user else "Разработчик"

    welcome_text = (
        f"👋 **Привет, {user_name}!**\n\n"
        f"Я — **CyberSecurityBot**, твой автономный DevSecOps & AI Pentester ассистент.\n\n"
        f"🔹 **Что я умею:**\n"
        f"1. 🔑 **Proof of Ownership** — проверка прав доступа к репозиторию перед аудитом.\n"
        f"2. 🔍 **SAST & Dependency Scan** — поиск уязвимостей через Semgrep, Bandit и Pip-Audit.\n"
        f"3. 🧠 **AI Remediation** — анализ ошибок локальной моделью `{settings.ollama_model}`.\n"
        f"4. 🚀 **Auto-PR** — автоматическое открытие Pull Request с готовым исправленным кодом.\n\n"
        f"Нажми кнопку ниже, чтобы начать аудит!"
    )

    await message.answer(welcome_text, reply_markup=get_main_menu_keyboard(), parse_mode="Markdown")


@router.callback_query(F.data == "help_info")
@router.message(Command("help"))
async def handle_help(event: Message | CallbackQuery) -> None:
    """Display help information."""
    help_text = (
        "📖 **Справка по работе с CyberSecurityBot**\n\n"
        "1. **GitHub Token:**\n"
        "   Для аудита и создания Pull Request требуется Personal Access Token (classic или fine-grained) "
        "с правами `repo` (чтение кода и создание PR).\n"
        "   Создать токен: [GitHub Tokens](https://github.com/settings/tokens)\n\n"
        "2. **Проверка прав (Proof of Ownership):**\n"
        "   Бот проверяет, что ваш токен имеет права `push` или `admin` на сканируемый репозиторий.\n\n"
        "3. **AI Движок:**\n"
        f"   По умолчанию используется локальный сервер Ollama (`{settings.ollama_base_url}`) "
        f"с моделью `{settings.ollama_model}`."
    )

    if isinstance(event, CallbackQuery):
        await event.message.answer(help_text, parse_mode="Markdown", disable_web_page_preview=True)
        await event.answer()
    else:
        await event.answer(help_text, parse_mode="Markdown", disable_web_page_preview=True)


@router.callback_query(F.data == "check_ai_status")
@router.message(Command("status"))
async def handle_status(event: Message | CallbackQuery) -> None:
    """Check availability of Ollama local model and configuration."""
    msg = event.message if isinstance(event, CallbackQuery) else event
    status_msg = await msg.answer("⏳ Проверяем доступность AI движка...")

    ollama_ok = False
    models_list = []
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags")
            if resp.status_code == 200:
                ollama_ok = True
                data = resp.json()
                models_list = [m.get("name") for m in data.get("models", [])]
    except Exception:
        ollama_ok = False

    ollama_icon = "🟢 Доступен" if ollama_ok else "🔴 Недоступен (проверьте `ollama serve`)"
    gemini_icon = "🟢 Настроен" if settings.gemini_api_key else "⚪ Не задан"

    status_text = (
        f"⚡ **Статус AI и Сервисов:**\n\n"
        f"🖥 **Ollama Engine:** {ollama_icon}\n"
        f"📍 **URL:** `{settings.ollama_base_url}`\n"
        f"🎯 **Целевая модель:** `{settings.ollama_model}`\n"
        f"📦 **Загруженные модели:** `{', '.join(models_list) if models_list else 'Нет'}`\n\n"
        f"☁️ **Gemini Fallback:** {gemini_icon} (`{settings.gemini_model}`)\n"
        f"⚙️ **Текущий активный провайдер:** `{settings.llm_provider.value}`"
    )

    await status_msg.edit_text(status_text, parse_mode="Markdown")
    if isinstance(event, CallbackQuery):
        await event.answer()


@router.callback_query(F.data == "start_audit")
async def start_audit_flow(callback: CallbackQuery, state: FSMContext) -> None:
    """Start audit wizard by requesting GitHub Token."""
    # Check if global default token is already configured
    if settings.github_token:
        await state.update_data(github_token=settings.github_token)
        await state.set_state(AuditStates.waiting_for_repo)
        await callback.message.answer(
            "🔑 Используется системный GitHub Token.\n\n"
            "🌐 **Введите ссылку на репозиторий для аудита:**\n"
            "*(Пример: `https://github.com/owner/repo` или `owner/repo`)*",
            parse_mode="Markdown"
        )
    else:
        await state.set_state(AuditStates.waiting_for_token)
        await callback.message.answer(
            "🔑 **Шаг 1: Введите ваш GitHub Personal Access Token**\n\n"
            "Токен нужен для проверки прав владения (Proof of Ownership) и создания Pull Request.\n"
            "_(Токен используется только в рамках текущей сессии и не сохраняется на диск)_",
            parse_mode="Markdown"
        )
    await callback.answer()


@router.message(AuditStates.waiting_for_token)
async def process_token_input(message: Message, state: FSMContext) -> None:
    """Save user token and ask for repository."""
    token = message.text.strip()
    if not token or len(token) < 10:
        await message.answer("⚠️ Некорректный токен. Пожалуйста, отправьте валидный GitHub Token.")
        return

    # Delete message containing token for security
    try:
        await message.delete()
    except Exception:
        pass

    await state.update_data(github_token=token)
    await state.set_state(AuditStates.waiting_for_repo)

    await message.answer(
        "✅ Токен принят!\n\n"
        "🌐 **Шаг 2: Введите ссылку на репозиторий для аудита:**\n"
        "*(Пример: `https://github.com/owner/repo` или `madiyarmoldakhmet-ai/cybersecyritybot`)*",
        parse_mode="Markdown"
    )


@router.message(AuditStates.waiting_for_repo)
async def process_repo_audit(message: Message, state: FSMContext) -> None:
    """Verify repo ownership, clone, and execute SAST security audit."""
    repo_input = message.text.strip()
    repo_name = OwnershipVerifier.parse_github_repo(repo_input)

    if not repo_name:
        await message.answer(
            "⚠️ Неверный формат репозитория. Введите `owner/repo` или полную ссылку на GitHub."
        )
        return

    user_data = await state.get_data()
    github_token = user_data.get("github_token") or settings.github_token

    if not github_token:
        await message.answer("⚠️ GitHub Token не найден. Начните заново с /start.")
        await state.clear()
        return

    status_msg = await message.answer(
        f"🔐 **Верификация прав доступа к `{repo_name}`...**",
        parse_mode="Markdown"
    )

    # 1. Verify ownership permissions
    is_owner, verify_msg = await OwnershipVerifier.verify_github_access(github_token, repo_name)
    if not is_owner:
        await status_msg.edit_text(
            f"❌ **Ошибка верификации прав владения!**\n\n{verify_msg}",
            parse_mode="Markdown"
        )
        return

    await status_msg.edit_text(
        f"✅ {verify_msg}\n\n"
        f"⏳ **Клонирование репозитория во временную защищенную песочницу...**",
        parse_mode="Markdown"
    )

    # 2. Clone repository to temp sandbox
    session_id = str(uuid.uuid4())[:8]
    temp_dir = settings.temp_clone_dir / f"scan_{session_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    clone_url = f"https://x-access-token:{github_token}@github.com/{repo_name}.git"

    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", clone_url, str(temp_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)

        if proc.returncode != 0:
            err_text = stderr.decode("utf-8", errors="replace")
            await status_msg.edit_text(
                f"❌ Ошибка клонирования репозитория:\n```\n{err_text[:300]}\n```",
                parse_mode="Markdown"
            )
            shutil.rmtree(temp_dir, ignore_errors=True)
            return

        # 3. Run SAST Scanners
        await status_msg.edit_text(
            f"🔍 **Запуск анализа безопасности:**\n"
            f"• 🛡️ Сканирование Semgrep (SAST)\n"
            f"• 🐍 Анализ кода Bandit (Python AST)\n"
            f"• 📦 Проверка зависимостей Pip-Audit (CVEs)\n\n"
            f"⏳ *Пожалуйста, подождите...*",
            parse_mode="Markdown"
        )

        scanner = SASTScanner()
        scan_result: SASTScanResult = await scanner.scan(temp_dir)

        # Save scan session
        SCAN_SESSIONS[session_id] = {
            "repo_name": repo_name,
            "github_token": github_token,
            "temp_dir": temp_dir,
            "scan_result": scan_result,
            "remediations": {}
        }

        # Build response card
        crit_count = scan_result.findings_by_severity.get(Severity.CRITICAL, 0)
        high_count = scan_result.findings_by_severity.get(Severity.HIGH, 0)
        med_count = scan_result.findings_by_severity.get(Severity.MEDIUM, 0)
        low_count = scan_result.findings_by_severity.get(Severity.LOW, 0)

        summary_card = (
            f"📊 **Результаты аудита безопасности `{repo_name}`**\n\n"
            f"⏱ Время сканирования: `{scan_result.duration_seconds} сек`\n"
            f"🚨 Всего обнаружено уязвимостей: **`{scan_result.total_findings}`**\n\n"
            f"🔴 **Critical / High:** `{crit_count + high_count}`\n"
            f"🟡 **Medium:** `{med_count}`\n"
            f"🔵 **Low / Info:** `{low_count}`\n\n"
        )

        if scan_result.total_findings == 0:
            summary_card += "🎉 **Поздравляем!** Уязвимостей в кодовой базе не обнаружено."
            buttons = []
        else:
            summary_card += "Выберите действие для анализа и автоматического исправления:"
            buttons = [
                [
                    InlineKeyboardButton(
                        text=f"📋 Список уязвимостей ({scan_result.total_findings})",
                        callback_data=f"show_findings_{session_id}"
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="🤖 Сгенерировать AI-исправление и PR",
                        callback_data=f"remediate_{session_id}"
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="📄 Скачать отчет (Markdown)",
                        callback_data=f"download_report_{session_id}"
                    )
                ]
            ]

        keyboard = InlineKeyboardMarkup(inline_keyboard=buttons)
        await status_msg.edit_text(summary_card, reply_markup=keyboard, parse_mode="Markdown")

    except Exception as e:
        logger.exception(f"Error during scan: {e}")
        await status_msg.edit_text(f"❌ Ошибка в процессе аудита: {str(e)}")
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.callback_query(F.data.startswith("show_findings_"))
async def handle_show_findings(callback: CallbackQuery) -> None:
    """Display list of found vulnerabilities with severity."""
    session_id = callback.data.replace("show_findings_", "")
    session = SCAN_SESSIONS.get(session_id)

    if not session:
        await callback.answer("⚠️ Сессия аудита устарела. Запустите новый аудит.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    findings = scan_result.findings[:10]  # Show top 10

    lines = [f"🔍 **Топ уязвимостей для `{session['repo_name']}`:**\n"]
    for idx, f in enumerate(findings, 1):
        sev_icon = "🔴" if f.severity in [Severity.CRITICAL, Severity.HIGH] else ("🟡" if f.severity == Severity.MEDIUM else "🔵")
        lines.append(
            f"{idx}. {sev_icon} **[{f.severity.value}]** `{f.title}`\n"
            f"   📁 `{f.file_path}` (стр. {f.line_start or 1})\n"
            f"   ℹ️ {f.description[:120]}..."
        )

    if len(scan_result.findings) > 10:
        lines.append(f"\n_...и еще {len(scan_result.findings) - 10} уязвимостей._")

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🤖 Сгенерировать AI-исправление и PR",
                    callback_data=f"remediate_{session_id}"
                )
            ]
        ]
    )

    await callback.message.answer("\n\n".join(lines), reply_markup=kb, parse_mode="Markdown")
    await callback.answer()


@router.callback_query(F.data.startswith("remediate_"))
async def handle_remediation_and_pr(callback: CallbackQuery) -> None:
    """Analyze the top vulnerability with LLM and open a Pull Request."""
    session_id = callback.data.replace("remediate_", "")
    session = SCAN_SESSIONS.get(session_id)

    if not session:
        await callback.answer("⚠️ Сессия аудита устарела.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    if not scan_result.findings:
        await callback.answer("Нет уязвимостей для исправления.", show_alert=True)
        return

    target_finding: VulnerabilityFinding = scan_result.findings[0]
    await callback.message.answer(
        f"🤖 **ИИ ({settings.ollama_model}) анализирует уязвимость:**\n"
        f"`{target_finding.title}` в `{target_finding.file_path}`...\n"
        f"⏳ *Генерация безопасного патча...*",
        parse_mode="Markdown"
    )

    # 1. Run AI Remediation
    engine = RemediationEngine()
    remediation: RemediationResult = await engine.analyze_and_remediate(target_finding)

    analysis_msg = (
        f"💡 **AI Анализ и Решение:**\n\n"
        f"📌 **Первопричина:**\n{remediation.explanation_ru}\n\n"
        f"⚠️ **Impact:**\n{remediation.impact_analysis}\n\n"
        f"🛠 **План исправления:**\n" + "\n".join(f"• {s}" for s in remediation.remediation_steps)
    )
    await callback.message.answer(analysis_msg, parse_mode="Markdown")

    # 2. Automatically create Pull Request on GitHub
    pr_status_msg = await callback.message.answer("🚀 **Создаем защищенную ветку и Pull Request на GitHub...**")

    # Relative file path inside repo
    clean_path = target_finding.file_path
    if "temp_scans" in clean_path:
        clean_path = clean_path.split("/")[-1]

    success, msg, pr_url = await PullRequestCreator.create_remediation_pr(
        token=session["github_token"],
        repo_identifier=session["repo_name"],
        file_path=clean_path,
        fixed_content=remediation.fixed_code,
        finding=target_finding,
        remediation=remediation,
    )

    if success and pr_url:
        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="🔗 Открыть Pull Request на GitHub", url=pr_url)]
            ]
        )
        await pr_status_msg.edit_text(
            f"🎉 **Pull Request успешно создан!**\n\n"
            f"Исправление для `{target_finding.title}` отправлено в ваш репозиторий.\n"
            f"Ссылка: {pr_url}",
            reply_markup=kb,
            parse_mode="Markdown"
        )
    else:
        await pr_status_msg.edit_text(f"❌ Не удалось создать PR:\n{msg}")

    await callback.answer()


@router.callback_query(F.data.startswith("download_report_"))
async def handle_download_report(callback: CallbackQuery) -> None:
    """Generate and send Markdown vulnerability audit report."""
    session_id = callback.data.replace("download_report_", "")
    session = SCAN_SESSIONS.get(session_id)

    if not session:
        await callback.answer("Сессия устарела.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    repo_name = session["repo_name"]

    # Generate Markdown content
    md_content = f"# Security Audit Report for {repo_name}\n\n"
    md_content += f"- **Generated by:** CyberSecurityBot DevSecOps Engine\n"
    md_content += f"- **Total Findings:** {scan_result.total_findings}\n"
    md_content += f"- **Duration:** {scan_result.duration_seconds}s\n\n"
    md_content += "## Findings Summary\n\n"

    for idx, f in enumerate(scan_result.findings, 1):
        md_content += f"### {idx}. [{f.severity.value}] {f.title}\n"
        md_content += f"- **Scanner:** {f.scanner.value}\n"
        md_content += f"- **File:** `{f.file_path}` (lines: {f.line_start}-{f.line_end})\n"
        md_content += f"- **CWE:** {', '.join(f.cwe) if f.cwe else 'N/A'}\n"
        md_content += f"- **Description:** {f.description}\n"
        if f.code_snippet:
            md_content += f"\n```\n{f.code_snippet}\n```\n"
        md_content += "\n---\n"

    file_bytes = md_content.encode("utf-8")
    doc = BufferedInputFile(file_bytes, filename=f"audit_report_{session_id}.md")

    await callback.message.answer_document(doc, caption=f"📄 Полный отчет аудита для `{repo_name}`")
    await callback.answer()
