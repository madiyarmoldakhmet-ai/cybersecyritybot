"""
Telegram Bot Handlers for CyberSecurityBot (aiogram 3.x).
Provides interactive security audit, strict ownership verification (Token & Commit Challenge),
AI remediation, and auto-PR workflow.
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
    waiting_for_auth_method = State()
    waiting_for_token = State()
    waiting_for_repo = State()
    waiting_for_commit_check = State()


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
        f"1. 🔐 **Proof of Ownership** — строгая проверка авторства репозитория перед аудитом.\n"
        f"2. 🔍 **SAST & Multi-Language Scan** — поиск уязвимостей в Flutter/Dart, JS/TS, Python, Firestore и секретах.\n"
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
        "1. **Proof of Ownership (Проверка авторства):**\n"
        "   • **GitHub Token:** мгновенная авторизация по токену, проверка прав владельца/контрибьютора и авто-создание PR.\n"
        "   • **Commit Challenge:** подтверждение владения без передачи токена через разовый коммит с кодом.\n\n"
        "2. **Поддерживаемые технологии:**\n"
        "   • Flutter & Dart, JavaScript & TypeScript, Python, HTML, .env, Firestore Rules.\n\n"
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
    """Start audit wizard with choice of ownership verification method."""
    await state.clear()

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🔑 GitHub Access Token (Полный доступ + Auto-PR)",
                    callback_data="auth_method_token"
                )
            ],
            [
                InlineKeyboardButton(
                    text="📝 Commit Challenge (Без токена через коммит)",
                    callback_data="auth_method_commit"
                )
            ]
        ]
    )

    await callback.message.answer(
        "🔐 **Подтверждение авторства (Proof of Ownership)**\n\n"
        "Для защиты чужих проектов перед запуском аудита бот должен убедиться, что вы являетесь владельцем или автором репозитория.\n\n"
        "Выберите удобный способ подтверждения:",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    await callback.answer()


@router.callback_query(F.data == "auth_method_token")
async def handle_auth_token_choice(callback: CallbackQuery, state: FSMContext) -> None:
    """Prompt user for GitHub Token."""
    await state.set_state(AuditStates.waiting_for_token)
    await state.update_data(auth_mode="token")

    await callback.message.answer(
        "🔑 **Шаг 1: Введите ваш GitHub Personal Access Token**\n\n"
        "Бот проверит ваш логин и права владельца/контрибьютора на репозиторий.\n"
        "_(Сообщение с токеном будет автоматически удалено после чтения)_\n\n"
        "Ссылка для создания: [GitHub Settings > Tokens](https://github.com/settings/tokens)",
        parse_mode="Markdown",
        disable_web_page_preview=True
    )
    await callback.answer()


@router.callback_query(F.data == "auth_method_commit")
async def handle_auth_commit_choice(callback: CallbackQuery, state: FSMContext) -> None:
    """Prompt user for repository name for commit challenge."""
    await state.set_state(AuditStates.waiting_for_repo)
    await state.update_data(auth_mode="commit", github_token="")

    await callback.message.answer(
        "📝 **Режим Commit Challenge (без токена)**\n\n"
        "Введите ссылку на ваш репозиторий:\n"
        "*(Пример: `https://github.com/owner/repo` или `madiyarmoldakhmet-ai/cybersecyritybot`)*",
        parse_mode="Markdown"
    )
    await callback.answer()


@router.message(AuditStates.waiting_for_token)
async def process_token_input(message: Message, state: FSMContext) -> None:
    """Save user token and ask for repository."""
    token = message.text.strip()
    if not token or len(token) < 10:
        await message.answer("⚠️ Некорректный токен. Отправьте валидный GitHub Token:")
        return

    # Delete message containing token for security
    try:
        await message.delete()
    except Exception:
        pass

    await state.update_data(github_token=token, auth_mode="token")
    await state.set_state(AuditStates.waiting_for_repo)

    await message.answer(
        "✅ **Токен принят!**\n\n"
        "🌐 **Шаг 2: Введите ссылку на репозиторий для аудита:**\n"
        "*(Пример: `https://github.com/owner/repo` или `madiyarmoldakhmet-ai/cybersecyritybot`)*",
        parse_mode="Markdown"
    )


@router.message(AuditStates.waiting_for_repo)
async def process_repo_input(message: Message, state: FSMContext) -> None:
    """Handle repo input and execute appropriate verification flow."""
    repo_input = message.text.strip()
    repo_name = OwnershipVerifier.parse_github_repo(repo_input)

    if not repo_name:
        await message.answer(
            "⚠️ Неверный формат репозитория. Введите `owner/repo` или полную ссылку на GitHub."
        )
        return

    user_data = await state.get_data()
    auth_mode = user_data.get("auth_mode", "token")
    github_token = user_data.get("github_token", "")

    # Flow A: Commit Challenge
    if auth_mode == "commit":
        challenge_code = OwnershipVerifier.generate_commit_challenge()
        await state.update_data(repo_name=repo_name, challenge_code=challenge_code)
        await state.set_state(AuditStates.waiting_for_commit_check)

        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="🔍 Проверить коммит на GitHub",
                        callback_data="verify_commit_now"
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="❌ Отмена",
                        callback_data="start_audit"
                    )
                ]
            ]
        )

        instruction_msg = (
            f"📝 **Подтверждение владения через коммит:**\n\n"
            f"📁 **Репозиторий:** `{repo_name}`\n"
            f"🔑 **Код подтверждения:** `{challenge_code}`\n\n"
            f"Выполните в терминале вашего проекта команду:\n"
            f"```bash\ngit commit --allow-empty -m \"{challenge_code}\" && git push origin main\n```\n\n"
            f"После отправки коммита на GitHub нажмите кнопку ниже:"
        )
        await message.answer(instruction_msg, reply_markup=kb, parse_mode="Markdown")
        return

    # Flow B: Token Verification (Strict)
    status_msg = await message.answer(
        f"🔐 **Проверка прав владения для `{repo_name}`...**",
        parse_mode="Markdown"
    )

    auth_res = await OwnershipVerifier.verify_repo_ownership_strict(github_token, repo_name)

    if not auth_res["verified"]:
        await status_msg.edit_text(
            f"{auth_res['message']}\n\n"
            f"🚫 *Аудит чужих репозиториев без подтверждения владения строго заблокирован.*",
            parse_mode="Markdown"
        )
        await state.clear()
        return

    # Authorized successfully
    await status_msg.edit_text(
        f"✅ {auth_res['message']}\n\n"
        f"⏳ **Клонирование репозитория во временную песочницу...**",
        parse_mode="Markdown"
    )

    await run_sast_audit_pipeline(
        status_msg=status_msg,
        repo_name=repo_name,
        github_token=github_token,
        can_create_pr=auth_res["can_create_pr"]
    )


@router.callback_query(F.data == "verify_commit_now")
async def handle_verify_commit_callback(callback: CallbackQuery, state: FSMContext) -> None:
    """Verify presence of commit challenge on GitHub."""
    user_data = await state.get_data()
    repo_name = user_data.get("repo_name")
    challenge_code = user_data.get("challenge_code")

    if not repo_name or not challenge_code:
        await callback.answer("Сессия проверки устарела. Начните заново.", show_alert=True)
        return

    status_msg = await callback.message.answer(
        f"🔍 **Проверяем последние коммиты в `{repo_name}`...**",
        parse_mode="Markdown"
    )

    verified, msg = await OwnershipVerifier.verify_commit_challenge(repo_name, challenge_code)

    if not verified:
        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="🔄 Повторить проверку коммита",
                        callback_data="verify_commit_now"
                    )
                ]
            ]
        )
        await status_msg.edit_text(
            f"❌ {msg}",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        await callback.answer()
        return

    await status_msg.edit_text(
        f"✅ {msg}\n\n"
        f"⏳ **Клонирование репозитория во временную песочницу...**",
        parse_mode="Markdown"
    )

    await run_sast_audit_pipeline(
        status_msg=status_msg,
        repo_name=repo_name,
        github_token="",
        can_create_pr=False
    )
    await callback.answer()


async def run_sast_audit_pipeline(
    status_msg: Message,
    repo_name: str,
    github_token: str,
    can_create_pr: bool
) -> None:
    """Clone verified repo, run multi-language SAST audit, and render rich results."""
    session_id = str(uuid.uuid4())[:8]
    temp_dir = settings.temp_clone_dir / f"scan_{session_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    clone_url = (
        f"https://x-access-token:{github_token}@github.com/{repo_name}.git"
        if github_token
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
            err_text = stderr.decode("utf-8", errors="replace")
            await status_msg.edit_text(
                f"❌ Ошибка клонирования репозитория:\n```\n{err_text[:300]}\n```",
                parse_mode="Markdown"
            )
            shutil.rmtree(temp_dir, ignore_errors=True)
            return

        # Run SAST Scanners
        await status_msg.edit_text(
            f"🔍 **Запуск мультиязычного аудита безопасности:**\n"
            f"• 📱 Flutter / Dart (SSL bypass, URLs, storage)\n"
            f"• 🌐 JavaScript / TypeScript / DOM XSS\n"
            f"• 🐍 Python AST & Bandit (SQLi, eval, subprocess)\n"
            f"• 🔑 Поиск секретов (Firebase, Telegram, Private Keys)\n"
            f"• 📦 Проверка зависимостей Pip-Audit (CVEs)\n\n"
            f"⏳ *Пожалуйста, подождите...*",
            parse_mode="Markdown"
        )

        scanner = SASTScanner()
        scan_result: SASTScanResult = await scanner.scan(temp_dir)

        SCAN_SESSIONS[session_id] = {
            "repo_name": repo_name,
            "github_token": github_token,
            "can_create_pr": can_create_pr,
            "temp_dir": temp_dir,
            "scan_result": scan_result,
            "remediations": {}
        }

        # Build Summary Card
        crit_count = scan_result.findings_by_severity.get(Severity.CRITICAL, 0)
        high_count = scan_result.findings_by_severity.get(Severity.HIGH, 0)
        med_count = scan_result.findings_by_severity.get(Severity.MEDIUM, 0)
        low_count = scan_result.findings_by_severity.get(Severity.LOW, 0)

        status_emoji = "🔴" if (crit_count + high_count > 0) else ("🟡" if med_count > 0 else "🟢")

        summary_text = (
            f"{status_emoji} **Аудит безопасности `{repo_name}` завершен!**\n\n"
            f"⏱ **Время сканирования:** `{scan_result.duration_seconds} сек`\n"
            f"🔎 **Всего найдено уязвимостей:** `{scan_result.total_findings}`\n\n"
            f"📊 **Распределение по критичности:**\n"
            f"• 🔴 Critical: `{crit_count}`\n"
            f"• 🟠 High: `{high_count}`\n"
            f"• 🟡 Medium: `{med_count}`\n"
            f"• 🔵 Low/Info: `{low_count}`\n\n"
        )

        if scan_result.total_findings > 0:
            top_f = scan_result.findings[0]
            summary_text += (
                f"🚨 **Главная угроза:** `{top_f.title}`\n"
                f"📁 Файл: `{top_f.file_path}` (стр. {top_f.line_start or 1})\n\n"
                f"Нажмите кнопку ниже для просмотра деталей и генерации AI-исправления:"
            )
        else:
            summary_text += "🎉 **Уязвимостей не обнаружено! Репозиторий чист.**"

        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="📋 Показать список уязвимостей",
                        callback_data=f"show_findings_{session_id}"
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="📄 Скачать отчет (Markdown)",
                        callback_data=f"download_report_{session_id}"
                    )
                ]
            ]
        ) if scan_result.total_findings > 0 else InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="📄 Скачать отчет (Markdown)",
                        callback_data=f"download_report_{session_id}"
                    )
                ]
            ]
        )

        await status_msg.edit_text(summary_text, reply_markup=kb, parse_mode="Markdown")

    except Exception as ex:
        logger.exception(f"Audit pipeline error: {ex}")
        await status_msg.edit_text(f"❌ Ошибка во время аудита: `{str(ex)}`")
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
    can_create_pr = session.get("can_create_pr", False)
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

    btn_text = "🤖 Сгенерировать AI-исправление и PR" if can_create_pr else "💡 AI-анализ уязвимостей и патч"
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=btn_text,
                    callback_data=f"remediate_{session_id}"
                )
            ]
        ]
    )

    await callback.message.answer("\n\n".join(lines), reply_markup=kb, parse_mode="Markdown")
    await callback.answer()


@router.callback_query(F.data.startswith("remediate_"))
async def handle_remediation_and_pr(callback: CallbackQuery) -> None:
    """Analyze the top vulnerability with LLM and open a Pull Request (if authorized)."""
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

    # 1. Run AI Remediation with robust error handling
    try:
        engine = RemediationEngine()
        remediation: RemediationResult = await engine.analyze_and_remediate(target_finding)

        analysis_msg = (
            f"💡 **AI Анализ и Решение:**\n\n"
            f"📌 **Первопричина:**\n{remediation.explanation_ru}\n\n"
            f"⚠️ **Impact:**\n{remediation.impact_analysis}\n\n"
            f"🛠 **План исправления:**\n" + "\n".join(f"• {s}" for s in remediation.remediation_steps) + "\n\n"
            f"🔒 **Исправленный код:**\n```python\n{remediation.fixed_code[:600]}\n```"
        )
        await callback.message.answer(analysis_msg, parse_mode="Markdown")

    except Exception as ex:
        logger.exception(f"AI remediation failed: {ex}")
        await callback.message.answer(
            f"⚠️ **Ошибка при генерации AI-исправления:**\n`{str(ex)}`\n\n"
            "Убедитесь, что сервер Ollama запущен (`ollama run qwen2.5-coder:14b`) или задан GEMINI_API_KEY в `.env`."
        )
        await callback.answer()
        return

    # 2. Check if Auto-PR can be opened
    can_create_pr = session.get("can_create_pr", False)
    github_token = session.get("github_token", "")

    if not can_create_pr or not github_token:
        await callback.message.answer(
            "ℹ️ **Режим Read-Only:** Автоматическое открытие Pull Request недоступно без GitHub токена с правами записи.\n"
            "Вы можете вручную скопировать предложенный исправленный код выше.",
            parse_mode="Markdown"
        )
        await callback.answer()
        return

    pr_status_msg = await callback.message.answer("🚀 **Создаем защищенную ветку и Pull Request на GitHub...**")

    # Relative file path inside repo
    clean_path = target_finding.file_path
    if "temp_scans" in clean_path:
        clean_path = clean_path.split("/")[-1]

    try:
        success, msg, pr_url = await PullRequestCreator.create_remediation_pr(
            token=github_token,
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
    except Exception as pr_ex:
        logger.exception(f"PR creation unexpected exception: {pr_ex}")
        await pr_status_msg.edit_text(f"❌ Исключение при создании PR: `{str(pr_ex)}`")

    await callback.answer()


@router.callback_query(F.data.startswith("download_report_"))
async def handle_download_report(callback: CallbackQuery) -> None:
    """Generate and send Markdown vulnerability audit report."""
    session_id = callback.data.replace("download_report_", "")
    session = SCAN_SESSIONS.get(session_id)

    if not session:
        await callback.answer("⚠️ Сессия аудита не найдена.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    repo_name = session["repo_name"]

    report_lines = [
        f"# 🛡️ Отчет по безопасности: {repo_name}",
        f"**Дата аудита:** {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Всего уязвимостей:** {scan_result.total_findings}",
        f"**Длительность сканирования:** {scan_result.duration_seconds} сек\n",
        "## 📊 Сводка по критичности:",
        f"- 🔴 Critical: {scan_result.findings_by_severity.get(Severity.CRITICAL, 0)}",
        f"- 🟠 High: {scan_result.findings_by_severity.get(Severity.HIGH, 0)}",
        f"- 🟡 Medium: {scan_result.findings_by_severity.get(Severity.MEDIUM, 0)}",
        f"- 🔵 Low: {scan_result.findings_by_severity.get(Severity.LOW, 0)}\n",
        "## 🔍 Обнаруженные уязвимости:\n",
    ]

    for idx, f in enumerate(scan_result.findings, 1):
        report_lines.extend([
            f"### {idx}. [{f.severity.value}] {f.title}",
            f"- **ID:** `{f.id}`",
            f"- **Сканер:** `{f.scanner.value}`",
            f"- **Файл:** `{f.file_path}` (стр. {f.line_start}-{f.line_end})",
            f"- **CWE:** {', '.join(f.cwe) if f.cwe else 'N/A'}",
            f"- **Описание:** {f.description}",
            f"- **Рекомендация:** {f.recommendation or 'N/A'}\n",
            "```python",
            f"{f.code_snippet or '# No snippet'}",
            "```\n",
        ])

    report_content = "\n".join(report_lines)
    file_bytes = report_content.encode("utf-8")
    doc = BufferedInputFile(file_bytes, filename=f"security_report_{repo_name.replace('/', '_')}.md")

    await callback.message.answer_document(
        document=doc,
        caption=f"📄 **Полный отчет по безопасности для `{repo_name}`**",
        parse_mode="Markdown"
    )
    await callback.answer()
