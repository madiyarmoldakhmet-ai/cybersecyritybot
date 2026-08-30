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
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
import httpx

from ai.remediation_engine import ExploitPayload, RemediationEngine, RemediationResult, StaticVerification
from core.config import LLMProvider, settings
from core.pr_creator import PullRequestCreator
from core.verifier import OwnershipVerifier
from exploit.executor import execute_payload
from scanners.models import SASTScanResult, ScannerType, Severity, VulnerabilityFinding
from scanners.sast_scanner import SASTScanner
from scanners.strix_runner import StrixEngine
from scanners.vuln_classifier import VulnCategory, classify_vulnerability

logger = logging.getLogger("cybersecuritybot.bot")
router = Router()

# In-memory storage for active scan sessions: session_id -> dict
SCAN_SESSIONS: Dict[str, Dict] = {}


class AuditStates(StatesGroup):
    waiting_for_auth_method = State()
    waiting_for_token = State()
    waiting_for_repo = State()
    waiting_for_commit_check = State()
    waiting_for_target_url = State()


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
                    text="🎬 О проекте / Промо",
                    callback_data="show_promo"
                ),
                InlineKeyboardButton(
                    text="⚡ Статус AI (Cloud)",
                    callback_data="check_ai_status"
                ),
            ],
            [
                InlineKeyboardButton(
                    text="📖 Справка",
                    callback_data="help_info"
                )
            ]
        ]
    )


@router.message(CommandStart())
async def handle_start(message: Message, state: FSMContext) -> None:
    """Handle /start command with rich welcome and optional promo animation."""
    await state.clear()
    user_name = message.from_user.first_name if message.from_user else "Разработчик"

    welcome_text = (
        f"👋 **Привет, {user_name}!**\n\n"
        f"Я — **CyberSecurityBot**, твой автономный DevSecOps & AI Pentester ассистент.\n\n"
        f"🔹 **Что я умею:**\n"
        f"1. 🔐 **Proof of Ownership** — строгая проверка авторства репозитория перед аудитом.\n"
        f"2. 🔍 **SAST & Deep Pentest (Strix)** — поиск уязвимостей в Flutter/Dart, JS/TS, Python, Firestore и секретах.\n"
        f"3. 🧠 **AI Remediation** — AI анализ ошибок и патчинг кода.\n"
        f"4. 🚀 **Auto-PR** — автоматическое открытие Pull Request с готовым исправленным кодом.\n\n"
        f"Нажми кнопку ниже, чтобы начать аудит!"
    )

    promo_path = Path("assets/promo.mp4")
    gif_path = Path("assets/demo.gif")

    if promo_path.exists():
        try:
            video_file = FSInputFile(str(promo_path))
            await message.answer_video(
                video=video_file,
                caption=welcome_text,
                reply_markup=get_main_menu_keyboard(),
                parse_mode="Markdown"
            )
            return
        except Exception as e:
            logger.debug(f"Failed to send promo video: {e}")
    elif gif_path.exists():
        try:
            anim_file = FSInputFile(str(gif_path))
            await message.answer_animation(
                animation=anim_file,
                caption=welcome_text,
                reply_markup=get_main_menu_keyboard(),
                parse_mode="Markdown"
            )
            return
        except Exception as e:
            logger.debug(f"Failed to send demo gif: {e}")

    await message.answer(welcome_text, reply_markup=get_main_menu_keyboard(), parse_mode="Markdown")


@router.callback_query(F.data == "show_promo")
@router.message(Command("about"), Command("promo"))
async def handle_about_promo(event: Message | CallbackQuery) -> None:
    """Send product promo video and overview."""
    msg = event.message if isinstance(event, CallbackQuery) else event

    about_text = (
        "🎬 **О проекте CyberSecurityBot**\n\n"
        "CyberSecurityBot — автономный DevSecOps & AI Pentester ассистент нового поколения.\n\n"
        "🌟 **Ключевые преимущества:**\n"
        "• 🔐 **Proof of Ownership:** Защита от несанкционированного аудита.\n"
        "• ⚡ **SAST & Multi-Language:** Анализ Dart, JS/TS, Python, Firestore rules.\n"
        "• 🤖 **Strix Deep Pentest:** Мульти-агентный аудит бизнес-логики и IDOR (Apache 2.0).\n"
        "• 🧠 **Hybrid AI:** Полная приватность через Ollama или скорость Cloud Gemini.\n"
        "• 🚀 **Auto-PR:** Автоматическое устранение уязвимостей в 1 клик.\n\n"
        "🔗 **GitHub:** [madiyarmoldakhmet-ai/cybersecyritybot](https://github.com/madiyarmoldakhmet-ai/cybersecyritybot)"
    )

    promo_path = Path("assets/promo.mp4")
    gif_path = Path("assets/demo.gif")

    sent = False
    if promo_path.exists():
        try:
            video_file = FSInputFile(str(promo_path))
            await msg.answer_video(video=video_file, caption=about_text, parse_mode="Markdown")
            sent = True
        except Exception as e:
            logger.debug(f"Failed to send promo video in /about: {e}")
    elif gif_path.exists() and not sent:
        try:
            anim_file = FSInputFile(str(gif_path))
            await msg.answer_animation(animation=anim_file, caption=about_text, parse_mode="Markdown")
            sent = True
        except Exception as e:
            logger.debug(f"Failed to send demo gif in /about: {e}")

    if not sent:
        await msg.answer(about_text, parse_mode="Markdown")

    if isinstance(event, CallbackQuery):
        await event.answer()


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
        f"   Текущий провайдер: `{settings.llm_provider.value}`.\n"
        f"   Для настройки измените переменные в `.env`."
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

    is_gemini_active = settings.llm_provider == "gemini" and settings.gemini_api_key
    is_openrouter_active = settings.llm_provider == "openrouter" and settings.openrouter_api_key
    
    if is_openrouter_active:
        ai_status = "🟢 Online (OpenRouter Cloud)"
        active_engine = "☁️ OpenRouter API"
        active_model = settings.openrouter_model
    elif is_gemini_active:
        ai_status = "🟢 Online (Google Cloud)"
        active_engine = "☁️ Google Gemini"
        active_model = settings.gemini_model
    elif ollama_ok:
        ai_status = "🟢 Online (Private Cluster)"
        active_engine = "🖥 Private Local AI"
        active_model = settings.ollama_model
    else:
        ai_status = "⚠️ Высокая нагрузка (Попробуйте позже)"
        active_engine = "☁️ AI Cluster"
        active_model = "N/A"

    status_text = (
        f"📊 **Статус Платформы CyberSecurityBot**\n\n"
        f"🚀 **Основной движок:** {active_engine}\n"
        f"🧠 **Нейросеть:** `{active_model}`\n"
        f"🔌 **Состояние API:** {ai_status}\n\n"
        f"🛡️ **Strix Security Engine:** 🟢 Активен (v1.0.0)\n"
        f"🌐 **GitHub Webhooks:** 🟢 Подключены"
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
                    text="🚀 Быстрый старт (Проверка через коммит, 0 настроек)",
                    callback_data="auth_method_commit"
                )
            ],
            [
                InlineKeyboardButton(
                    text="🔑 Продвинутый (GitHub Token + Auto-PR)",
                    callback_data="auth_method_token"
                )
            ]
        ]
    )

    await callback.message.answer(
        "🔐 **Авторизация проекта**\n\n"
        "Мы не сканируем чужие проекты без разрешения. Чтобы начать аудит, подтвердите, что репозиторий ваш.\n\n"
        "Для новичков рекомендуем **Быстрый старт** — вам просто нужно будет добавить один пустой коммит в ваш код.",
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
            f"📝 **Подтверждение владения через Commit / verify.txt:**\n\n"
            f"📁 **Репозиторий:** `{repo_name}`\n"
            f"🔑 **Код подтверждения:** `{challenge_code}`\n\n"
            f"**Вариант 1 (Быстрый пустой коммит):**\n"
            f"```bash\ngit commit --allow-empty -m \"{challenge_code}\" && git push origin main\n```\n\n"
            f"**Вариант 2 (Через файл verify.txt):**\n"
            f"```bash\necho \"{challenge_code}\" > verify.txt && git add verify.txt && git commit -m \"verify ownership\" && git push origin main\n```\n\n"
            f"После отправки изменений на GitHub нажмите кнопку ниже:"
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
    await state.update_data(
        repo_name=repo_name,
        github_token=github_token,
        can_create_pr=auth_res["can_create_pr"]
    )

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="⚡ Быстрый SAST-скан (0.5 сек)",
                    callback_data="scan_mode_fast"
                )
            ],
            [
                InlineKeyboardButton(
                    text="🤖 Deep AI Pentest (Агенты Strix, 1-3 мин)",
                    callback_data="scan_mode_deep"
                )
            ]
        ]
    )

    await status_msg.edit_text(
        f"✅ {auth_res['message']}\n\n"
        f"🎯 **Выберите режим аудита безопасности:**\n\n"
        f"• ⚡ **Быстрый SAST-скан:** экспресс-поиск по AST и правилам (Semgrep, Bandit, Pip-Audit, Secrets).\n"
        f"• 🤖 **Deep AI Pentest (Strix):** мульти-агентный глубокий анализ логики, IDOR и цепочек атак.\n\n"
        f"_Deep Scanning powered by Strix Engine (Apache 2.0)_",
        reply_markup=kb,
        parse_mode="Markdown"
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

    await state.update_data(
        repo_name=repo_name,
        github_token="",
        can_create_pr=False
    )

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="⚡ Быстрый SAST-скан (0.5 сек)",
                    callback_data="scan_mode_fast"
                )
            ],
            [
                InlineKeyboardButton(
                    text="🤖 Deep AI Pentest (Агенты Strix, 1-3 мин)",
                    callback_data="scan_mode_deep"
                )
            ]
        ]
    )

    await status_msg.edit_text(
        f"✅ {msg}\n\n"
        f"🎯 **Выберите режим аудита безопасности:**\n\n"
        f"• ⚡ **Быстрый SAST-скан:** экспресс-поиск по AST и правилам (Semgrep, Bandit, Pip-Audit, Secrets).\n"
        f"• 🤖 **Deep AI Pentest (Strix):** мульти-агентный глубокий анализ логики, IDOR и цепочек атак.\n\n"
        f"_Deep Scanning powered by Strix Engine (Apache 2.0)_",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    await callback.answer()


@router.callback_query(F.data == "scan_mode_fast")
async def handle_scan_mode_fast(callback: CallbackQuery, state: FSMContext) -> None:
    """Handle choice of fast SAST scan."""
    user_data = await state.get_data()
    repo_name = user_data.get("repo_name")
    github_token = user_data.get("github_token", "")
    can_create_pr = user_data.get("can_create_pr", False)

    if not repo_name:
        await callback.answer("⚠️ Сессия аудита устарела. Начните заново с /start.", show_alert=True)
        return

    status_msg = await callback.message.answer(
        f"⏳ **Клонирование репозитория `{repo_name}` во временную песочницу...**",
        parse_mode="Markdown"
    )
    await callback.answer()

    await run_sast_audit_pipeline(
        status_msg=status_msg,
        repo_name=repo_name,
        github_token=github_token,
        can_create_pr=can_create_pr
    )


@router.callback_query(F.data == "scan_mode_deep")
async def handle_scan_mode_deep(callback: CallbackQuery, state: FSMContext) -> None:
    """Handle choice of deep Strix AI Pentest scan."""
    user_data = await state.get_data()
    repo_name = user_data.get("repo_name")
    github_token = user_data.get("github_token", "")
    can_create_pr = user_data.get("can_create_pr", False)

    if not repo_name:
        await callback.answer("⚠️ Сессия аудита устарела. Начните заново с /start.", show_alert=True)
        return

    status_msg = await callback.message.answer(
        f"⏳ **Клонирование репозитория `{repo_name}` во временную песочницу...**",
        parse_mode="Markdown"
    )
    await callback.answer()

    await run_deep_strix_audit_pipeline(
        status_msg=status_msg,
        repo_name=repo_name,
        github_token=github_token,
        can_create_pr=can_create_pr
    )


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
                f"Выберите действие ниже для анализа, генерации проверочного запроса или авто-исправления:"
            )
            btn_pr_text = "🤖 Сгенерировать AI-исправление и PR" if can_create_pr else "💡 AI-анализ и патч"
            # Adaptive button: exploit for remote vulns, verify for static, POC for XSS
            top_vuln_category = classify_vulnerability(top_f)
            
            verify_btn = None
            if "xss" in top_f.title.lower() or "cross-site scripting" in top_f.title.lower() or "innerhtml" in top_f.title.lower():
                verify_btn = InlineKeyboardButton(
                    text="📸 Сгенерировать скриншот взлома (PoC)",
                    callback_data=f"exploit_poc_gen_{session_id}_0"
                )
            elif top_vuln_category == VulnCategory.EXPLOITABLE_REMOTE:
                verify_btn = InlineKeyboardButton(
                    text="🧪 Сгенерировать проверочный запрос",
                    callback_data=f"exploit_gen_{session_id}_0"
                )
            else:
                verify_btn = InlineKeyboardButton(
                    text="🔍 Верифицировать в коде",
                    callback_data=f"static_verify_{session_id}_0"
                )
            kb = InlineKeyboardMarkup(
                inline_keyboard=[
                    [verify_btn],
                    [
                        InlineKeyboardButton(
                            text=btn_pr_text,
                            callback_data=f"remediate_{session_id}"
                        )
                    ],
                    [
                        InlineKeyboardButton(
                            text=f"📋 Список уязвимостей ({scan_result.total_findings})",
                            callback_data=f"show_findings_{session_id}"
                        )
                    ],
                    [
                        InlineKeyboardButton(
                            text="📄 Скачать отчет (Markdown)",
                            callback_data=f"download_report_{session_id}"
                        )
                    ],
                    [
                        InlineKeyboardButton(
                            text="📄 Сгенерировать финальный PDF-отчет",
                            callback_data=f"download_pdf_report_{session_id}"
                        )
                    ]
                ]
            )
        else:
            summary_text += "🎉 **Уязвимостей не обнаружено! Репозиторий чист.**"
            kb = InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        InlineKeyboardButton(
                            text="📄 Скачать отчет (Markdown)",
                            callback_data=f"download_report_{session_id}"
                        )
                    ],
                    [
                        InlineKeyboardButton(
                            text="📄 Сгенерировать финальный PDF-отчет",
                            callback_data=f"download_pdf_report_{session_id}"
                        )
                    ]
                ]
            )

        await status_msg.edit_text(summary_text, reply_markup=kb, parse_mode="Markdown")

    except Exception as ex:
        logger.exception(f"Audit pipeline error: {ex}")
        await status_msg.edit_text(f"❌ Ошибка во время аудита: `{str(ex)}`")
        shutil.rmtree(temp_dir, ignore_errors=True)


async def run_deep_strix_audit_pipeline(
    status_msg: Message,
    repo_name: str,
    github_token: str,
    can_create_pr: bool
) -> None:
    """Clone verified repo, run deep Strix agentic pentest with animated progress, and render results."""
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

        # Start multi-agent animation background loop
        anim_messages = [
            "🕵️ **[Strix Recon Agent]** Картирование эндпоинтов, доверенных зон и архитектуры... 🔍\n⏳ *Анализ поверхности атаки и моделей данных*",
            "⚔️ **[Strix Attack Agent]** Поиск цепочек IDOR, инъекций и логических дыр... ⚡\n⏳ *Анализ прав доступа, BOLA и потоков данных*",
            "🧪 **[Strix PoC Builder]** Конструирование верификационных эксплойтов... 🎯\n⏳ *Генерация точных cURL-векторов и доказательств*",
            "📝 **[Strix Engine]** Синтез отчета и подготовка авто-патчей... 🛡️\n⏳ *Финальная верификация находок*",
        ]

        async def status_animator():
            idx = 0
            while True:
                await asyncio.sleep(4.5)
                text = anim_messages[idx % len(anim_messages)]
                try:
                    await status_msg.edit_text(text, parse_mode="Markdown")
                except Exception:
                    pass
                idx += 1

        anim_task = asyncio.create_task(status_animator())

        # 1. Run Strix Deep Agentic Scanner (Ollama local qwen2.5-coder)
        strix_engine = StrixEngine()
        strix_res: SASTScanResult = await strix_engine.scan(temp_dir)

        # 2. Also run AST rule scanner for multi-language rule baseline
        sast_scanner = SASTScanner()
        sast_res: SASTScanResult = await sast_scanner.scan(temp_dir)

        # Cancel animation task cleanly
        anim_task.cancel()
        try:
            await anim_task
        except asyncio.CancelledError:
            pass

        # Merge findings (Strix first, then AST findings deduplicated)
        all_findings: List[VulnerabilityFinding] = list(strix_res.findings)
        seen_keys = {f"{f.file_path}:{f.line_start}:{f.title}" for f in strix_res.findings}

        for sf in sast_res.findings:
            key = f"{sf.file_path}:{sf.line_start}:{sf.title}"
            if key not in seen_keys:
                all_findings.append(sf)
                seen_keys.add(key)

        total_duration = round(strix_res.duration_seconds + sast_res.duration_seconds, 2)
        severity_counts: Dict[Severity, int] = {}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        combined_result = SASTScanResult(
            target_path=str(temp_dir),
            total_findings=len(all_findings),
            findings_by_severity=severity_counts,
            findings=all_findings,
            duration_seconds=total_duration,
            scanners_run=[ScannerType.STRIX, ScannerType.SEMGREP, ScannerType.BANDIT],
            errors=strix_res.errors + sast_res.errors,
        )

        SCAN_SESSIONS[session_id] = {
            "repo_name": repo_name,
            "github_token": github_token,
            "can_create_pr": can_create_pr,
            "temp_dir": temp_dir,
            "scan_result": combined_result,
            "scan_mode": "deep_strix",
            "remediations": {}
        }

        # Build Summary Card
        crit_count = severity_counts.get(Severity.CRITICAL, 0)
        high_count = severity_counts.get(Severity.HIGH, 0)
        med_count = severity_counts.get(Severity.MEDIUM, 0)
        low_count = severity_counts.get(Severity.LOW, 0)

        status_emoji = "🔴" if (crit_count + high_count > 0) else ("🟡" if med_count > 0 else "🟢")

        summary_text = (
            f"{status_emoji} **Deep AI Pentest `{repo_name}` завершен!**\n"
            f"_Deep Scanning powered by Strix Engine (Apache 2.0)_\n\n"
            f"⏱ **Время работы агентов:** `{total_duration} сек`\n"
            f"🔎 **Всего выявлено проблем:** `{len(all_findings)}`\n\n"
            f"📊 **Распределение по критичности:**\n"
            f"• 🔴 Critical: `{crit_count}`\n"
            f"• 🟠 High: `{high_count}`\n"
            f"• 🟡 Medium: `{med_count}`\n"
            f"• 🔵 Low/Info: `{low_count}`\n\n"
        )

        if len(all_findings) > 0:
            top_f = all_findings[0]
            summary_text += (
                f"🚨 **Главная угроза:** `{top_f.title}`\n"
                f"📁 Файл: `{top_f.file_path}` (стр. {top_f.line_start or 1})\n\n"
                f"Выберите действие ниже для анализа, генерации проверочного запроса или авто-исправления:"
            )
            btn_pr_text = "🤖 Сгенерировать AI-исправление и PR" if can_create_pr else "💡 AI-анализ и патч"
            # Adaptive button: exploit for remote vulns, verify for static
            top_vuln_category = classify_vulnerability(top_f)
            if top_vuln_category == VulnCategory.EXPLOITABLE_REMOTE:
                verify_btn = InlineKeyboardButton(
                    text="🧪 Сгенерировать проверочный запрос",
                    callback_data=f"exploit_gen_{session_id}_0"
                )
            else:
                verify_btn = InlineKeyboardButton(
                    text="🔍 Верифицировать в коде",
                    callback_data=f"static_verify_{session_id}_0"
                )
            kb = InlineKeyboardMarkup(
                inline_keyboard=[
                    [verify_btn],
                    [
                        InlineKeyboardButton(
                            text=btn_pr_text,
                            callback_data=f"remediate_{session_id}"
                        )
                    ],
                    [
                        InlineKeyboardButton(
                            text=f"📋 Список уязвимостей ({len(all_findings)})",
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
            )
        else:
            summary_text += "🎉 **Уязвимостей не обнаружено! Репозиторий защищен.**"
            kb = InlineKeyboardMarkup(
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
        logger.exception(f"Deep Strix audit error: {ex}")
        await status_msg.edit_text(f"❌ Ошибка во время глубокого аудита: `{str(ex)}`")
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.callback_query(F.data.startswith("show_findings_"))
async def handle_show_findings(callback: CallbackQuery, state: FSMContext) -> None:
    """Display list of found vulnerabilities with interactive buttons per finding."""
    session_id = callback.data.replace("show_findings_", "")
    session = SCAN_SESSIONS.get(session_id)

    if not session:
        await callback.answer("⚠️ Сессия аудита устарела. Запустите новый аудит.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    can_create_pr = session.get("can_create_pr", False)
    findings = scan_result.findings[:10]  # Show top 10

    lines = [f"🔍 **Топ уязвимостей для `{session['repo_name']}`:**\n"]
    buttons = []

    for idx, f in enumerate(findings):
        sev_icon = "🔴" if f.severity in [Severity.CRITICAL, Severity.HIGH] else ("🟡" if f.severity == Severity.MEDIUM else "🔵")
        lines.append(
            f"{idx + 1}. {sev_icon} **[{f.severity.value}]** `{f.title}`\n"
            f"   📁 `{f.file_path}` (стр. {f.line_start or 1})\n"
            f"   ℹ️ {f.description[:120]}..."
        )
        buttons.append([
            InlineKeyboardButton(
                text=f"{idx + 1}. 🔍 {f.title[:32]}",
                callback_data=f"view_finding_{session_id}_{idx}"
            )
        ])

    if len(scan_result.findings) > 10:
        lines.append(f"\n_...и еще {len(scan_result.findings) - 10} уязвимостей._")

    # Global action buttons
    btn_pr_text = "🤖 Сгенерировать AI-исправление и PR" if can_create_pr else "💡 AI-анализ уязвимостей и патч"
    buttons.append([
        InlineKeyboardButton(
            text=btn_pr_text,
            callback_data=f"remediate_{session_id}"
        )
    ])
    buttons.append([
        InlineKeyboardButton(
            text="📄 Скачать отчет (Markdown)",
            callback_data=f"download_report_{session_id}"
        )
    ])

    kb = InlineKeyboardMarkup(inline_keyboard=buttons)
    await callback.message.answer("\n\n".join(lines), reply_markup=kb, parse_mode="Markdown")
    await callback.answer()


@router.callback_query(F.data.startswith("view_finding_"))
async def handle_view_finding_detail(callback: CallbackQuery, state: FSMContext) -> None:
    """Display individual finding card with exploit payload generation and remediation options."""
    parts = callback.data.split("_")
    session_id = parts[2]
    idx = int(parts[3])

    session = SCAN_SESSIONS.get(session_id)
    if not session:
        await callback.answer("⚠️ Сессия аудита устарела.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    if idx >= len(scan_result.findings):
        await callback.answer("⚠️ Уязвимость не найдена.", show_alert=True)
        return

    f: VulnerabilityFinding = scan_result.findings[idx]

    # Store current active finding in FSM
    await state.update_data(
        current_session_id=session_id,
        current_finding_idx=idx,
        current_finding=f.model_dump(),
        code_context=f.code_snippet or ""
    )

    sev_icon = "🔴" if f.severity in [Severity.CRITICAL, Severity.HIGH] else ("🟡" if f.severity == Severity.MEDIUM else "🔵")
    scanner_names = {
        ScannerType.MOBILE: "📱 Mobile DevSecOps (Flutter/Firebase)",
        ScannerType.STRIX: "🤖 Strix Deep Pentest Engine (Apache-2.0)",
        ScannerType.SEMGREP: "🛡️ Semgrep SAST",
        ScannerType.BANDIT: "🐍 Bandit AST Linter",
        ScannerType.PIP_AUDIT: "📦 Pip-Audit (CVEs)",
        ScannerType.CUSTOM: "🔍 Static Security Inspector",
        ScannerType.DAST: "🌐 DAST Web Auditor",
    }
    scanner_title = scanner_names.get(f.scanner, f.scanner.value)

    detail_text = (
        f"{sev_icon} **Уязвимость #{idx + 1}: [{f.severity.value}]**\n\n"
        f"📌 **Название:** `{f.title}`\n"
        f"📁 **Файл:** `{f.file_path}` (стр. {f.line_start or 1}-{f.line_end or 1})\n"
        f"🔎 **Сканер:** `{scanner_title}`\n"
        f"📝 **Описание:** {f.description}\n"
    )
    if f.cwe:
        detail_text += f"🏷 **CWE:** `{', '.join(f.cwe)}`\n"
    if f.recommendation:
        detail_text += f"💡 **Рекомендация:** {f.recommendation}\n"
    if f.code_snippet:
        detail_text += f"\n**Контекст кода:**\n```python\n{f.code_snippet[:400]}\n```"

    # Adaptive button: exploit for remote vulns, verify for static
    finding_category = classify_vulnerability(f)
    if finding_category == VulnCategory.EXPLOITABLE_REMOTE:
        verify_btn = InlineKeyboardButton(
            text="🧪 Сгенерировать проверочный запрос",
            callback_data=f"exploit_gen_{session_id}_{idx}"
        )
    else:
        verify_btn = InlineKeyboardButton(
            text="🔍 Верифицировать в коде",
            callback_data=f"static_verify_{session_id}_{idx}"
        )
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [verify_btn],
            [
                InlineKeyboardButton(
                    text="🤖 Сгенерировать AI-исправление и PR",
                    callback_data=f"remediate_finding_{session_id}_{idx}"
                )
            ],
            [
                InlineKeyboardButton(
                    text="🛠 Сгенерировать Auto-Fix",
                    callback_data=f"autofix_{session_id}_{idx}"
                )
            ],
            [
                InlineKeyboardButton(
                    text="📋 Назад к списку",
                    callback_data=f"show_findings_{session_id}"
                )
            ]
        ]
    )

    await callback.message.answer(detail_text, reply_markup=kb, parse_mode="Markdown")
    await callback.answer()


@router.callback_query(F.data.startswith("exploit_gen_") | (F.data == "exploit_generate"))
async def handle_generate_exploit(callback: CallbackQuery, state: FSMContext) -> None:
    """Generate verification exploit payload using RemediationEngine with smart classification."""
    data = await state.get_data()
    target_finding: Optional[VulnerabilityFinding] = None
    code_context: str = ""

    if callback.data.startswith("exploit_gen_"):
        parts = callback.data.split("_")
        session_id = parts[2]
        idx = int(parts[3])
        session = SCAN_SESSIONS.get(session_id)
        if session and idx < len(session["scan_result"].findings):
            target_finding = session["scan_result"].findings[idx]
            code_context = target_finding.code_snippet or ""
            await state.update_data(
                current_session_id=session_id,
                current_finding_idx=idx,
                current_finding=target_finding.model_dump(),
                code_context=code_context
            )

    if not target_finding:
        raw_finding = data.get("current_finding")
        if isinstance(raw_finding, dict):
            target_finding = VulnerabilityFinding(**raw_finding)
            code_context = data.get("code_context", target_finding.code_snippet or "")
        elif isinstance(raw_finding, VulnerabilityFinding):
            target_finding = raw_finding
            code_context = data.get("code_context", target_finding.code_snippet or "")

    if not target_finding:
        await callback.answer("⚠️ Нет активной уязвимости для генерации запроса.", show_alert=True)
        return

    active_model = settings.gemini_model if settings.llm_provider == "gemini" and settings.gemini_api_key else settings.ollama_model
    status_msg = await callback.message.answer(
        f"🧪 **Генерация проверочного запроса для:** `{target_finding.title}`...\n"
        f"⏳ *ИИ ({active_model}) анализирует вектор атаки и формирует запрос...*",
        parse_mode="Markdown"
    )

    try:
        engine = RemediationEngine()
        result = await engine.generate_verification(
            finding=target_finding,
            code_context=code_context,
            endpoint=data.get("endpoint")
        )

        # Smart dispatch: ExploitPayload vs StaticVerification
        if isinstance(result, StaticVerification):
            await _display_static_verification(status_msg, target_finding, result)
        else:
            # ExploitPayload path
            payload = result
            await state.update_data(exploit_payload=payload.model_dump())

            # Don't offer "Run" button if confidence is 0 (broken exploit)
            if payload.confidence > 0.0:
                msg_text = (
                    f"🧪 **Проверочный запрос для подтверждения уязвимости:**\n\n"
                    f"📌 **Уязвимость:** `{target_finding.title}`\n"
                    f"🎯 **Индикатор успеха:** `{payload.success_indicator}`\n"
                    f"📊 **Уверенность (Confidence):** `{payload.confidence:.2f}`\n\n"
                    f"📋 **cURL команда:**\n"
                    f"```bash\n{payload.curl_command}\n```"
                )
                kb = InlineKeyboardMarkup(
                    inline_keyboard=[
                        [
                            InlineKeyboardButton(
                                text="🚀 Запустить проверку",
                                callback_data="exploit_run"
                            )
                        ]
                    ]
                )
                await status_msg.edit_text(msg_text, reply_markup=kb, parse_mode="Markdown")
            else:
                # Exploit generation returned 0 confidence — inform user clearly
                msg_text = (
                    f"⚠️ **Автоматическая генерация HTTP-эксплойта не удалась**\n\n"
                    f"📌 **Уязвимость:** `{target_finding.title}`\n"
                    f"📁 **Файл:** `{target_finding.file_path}`\n\n"
                    f"💡 Эта уязвимость может требовать ручного анализа или специфического окружения "
                    f"для эксплуатации. Рекомендуем использовать AI-исправление для устранения проблемы."
                )
                await status_msg.edit_text(msg_text, parse_mode="Markdown")

    except Exception as ex:
        logger.exception(f"Exploit generation failed: {ex}")
        await status_msg.edit_text(
            f"⚠️ Ошибка при генерации проверочного запроса: `{str(ex)[:200]}`\n\n"
            f"💡 Попробуйте использовать AI-исправление вместо проверочного запроса.",
            parse_mode="Markdown"
        )

    await callback.answer()


@router.callback_query(F.data.startswith("exploit_poc_gen_"))
async def handle_generate_poc_screenshot(callback: CallbackQuery, state: FSMContext) -> None:
    """Generate DAST PoC screenshot for XSS vulnerabilities."""
    parts = callback.data.split("_")
    session_id = parts[3]
    idx = int(parts[4])

    session = SCAN_SESSIONS.get(session_id)
    if not session:
        await callback.answer("⚠️ Сессия аудита устарела.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    if idx >= len(scan_result.findings):
        await callback.answer("⚠️ Уязвимость не найдена.", show_alert=True)
        return

    target_finding = scan_result.findings[idx]
    code_context = target_finding.code_snippet or ""

    status_msg = await callback.message.answer(
        f"📸 **Генерация Proof-of-Concept скриншота для:** `{target_finding.title}`...\n"
        f"⏳ *Бот разворачивает headless-браузер и инжектит пэйлоад...*",
        parse_mode="Markdown"
    )

    try:
        from scanners.dast_scanner import DASTScanner
        scanner = DASTScanner()
        
        # We generate a simple payload for POC
        payload = "<img src=x onerror=window.STRIX_XSS=true>"
        
        success, screenshot_path = await scanner.verify_xss_poc(code_context, payload)
        
        if success and screenshot_path and os.path.exists(screenshot_path):
            photo = FSInputFile(screenshot_path)
            await callback.message.answer_photo(
                photo=photo,
                caption=f"🔥 **STRIX DAST:** Уязвимость `{target_finding.title}` успешно подтверждена!\n\n"
                        f"Бот внедрил пэйлоад `{payload}` и он выполнился в браузере.\n"
                        f"Спорь с этим, вибкодер 😈",
                parse_mode="Markdown"
            )
            await status_msg.delete()
        else:
            await status_msg.edit_text(
                f"🛡️ **DAST сканирование завершено**\n\n"
                f"Не удалось подтвердить уязвимость автоматически. Возможно, в коде есть экранирование (CSP или санитизация), "
                f"либо сниппет слишком сложен для автоматической мок-среды."
            )
    except Exception as ex:
        logger.exception(f"DAST PoC generation failed: {ex}")
        await status_msg.edit_text(
            f"⚠️ Ошибка при генерации DAST PoC: `{str(ex)[:200]}`"
        )

    await callback.answer()


@router.callback_query(F.data.startswith("static_verify_"))
async def handle_static_verification(callback: CallbackQuery, state: FSMContext) -> None:
    """Generate local static verification for code quality vulnerabilities."""
    parts = callback.data.split("_")
    session_id = parts[2]
    idx = int(parts[3])

    session = SCAN_SESSIONS.get(session_id)
    if not session:
        await callback.answer("⚠️ Сессия аудита устарела.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    if idx >= len(scan_result.findings):
        await callback.answer("⚠️ Уязвимость не найдена.", show_alert=True)
        return

    target_finding = scan_result.findings[idx]
    code_context = target_finding.code_snippet or ""

    active_model = settings.gemini_model if settings.llm_provider == "gemini" and settings.gemini_api_key else settings.ollama_model
    status_msg = await callback.message.answer(
        f"🔍 **Верификация уязвимости в коде:** `{target_finding.title}`...\n"
        f"⏳ *ИИ ({active_model}) анализирует исходный код...*",
        parse_mode="Markdown"
    )

    try:
        engine = RemediationEngine()
        verification = await engine.generate_static_verification(
            finding=target_finding,
            code_context=code_context
        )
        await _display_static_verification(status_msg, target_finding, verification)
    except Exception as ex:
        logger.exception(f"Static verification failed: {ex}")
        await status_msg.edit_text(
            f"⚠️ Ошибка при верификации: `{str(ex)[:200]}`",
            parse_mode="Markdown"
        )

    await callback.answer()


async def _display_static_verification(
    status_msg: Message,
    finding: VulnerabilityFinding,
    verification: StaticVerification
) -> None:
    """Render StaticVerification result in Telegram."""
    cmds_text = ""
    if verification.verification_commands:
        cmds_list = "\n".join(verification.verification_commands[:5])
        cmds_text = f"\n🔧 **Команды для локальной верификации:**\n```bash\n{cmds_list}\n```"

    fix_text = ""
    if verification.fix_snippet:
        fix_text = f"\n✅ **Исправленный код:**\n```\n{verification.fix_snippet[:600]}\n```"

    msg_text = (
        f"🔍 **Верификация уязвимости в коде**\n\n"
        f"📌 **Уязвимость:** `{finding.title}`\n"
        f"📁 **Файл:** `{finding.file_path}` (стр. {finding.line_start or 1})\n"
        f"🏷 **Тип:** Статическая / конфигурационная\n"
        f"📊 **Уверенность:** `{verification.confidence:.2f}`\n\n"
        f"📝 **Описание проблемы:**\n{verification.explanation}\n\n"
        f"⚠️ **Риски:**\n{verification.risk_description}"
        f"{cmds_text}"
        f"{fix_text}"
    )

    # Truncate if too long for Telegram (4096 char limit)
    if len(msg_text) > 4000:
        msg_text = msg_text[:3990] + "\n..."  

    await status_msg.edit_text(msg_text, parse_mode="Markdown")


@router.callback_query(F.data == "exploit_run")
async def handle_run_exploit(callback: CallbackQuery, state: FSMContext) -> None:
    """Execute stored payload against target URL or ask user for base URL."""
    data = await state.get_data()
    payload_data = data.get("exploit_payload")
    target_url = data.get("target_url")

    if not payload_data:
        await callback.answer("⚠️ Сначала сгенерируйте проверочный запрос.", show_alert=True)
        return

    if not target_url:
        await state.set_state(AuditStates.waiting_for_target_url)
        await callback.message.answer(
            "🌐 **Введите базовый URL целевого сервиса для проверки:**\n\n"
            "*(Пример: `http://localhost:8000` или `https://api.test-app.com`)*",
            parse_mode="Markdown"
        )
        await callback.answer()
        return

    await execute_and_display_payload(callback.message, payload_data, target_url)
    await callback.answer()


@router.message(AuditStates.waiting_for_target_url)
async def process_target_url_input(message: Message, state: FSMContext) -> None:
    """Receive target URL and run validation payload."""
    target_url = message.text.strip()
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        await message.answer("⚠️ Пожалуйста, укажите валидный URL, начинающийся с `http://` или `https://`:")
        return

    await state.update_data(target_url=target_url)
    data = await state.get_data()
    payload_data = data.get("exploit_payload")

    if not payload_data:
        await message.answer("⚠️ Проверочный запрос не найден в сессии. Сгенерируйте его заново.")
        return

    await execute_and_display_payload(message, payload_data, target_url)


async def execute_and_display_payload(
    message: Message,
    payload_dict: dict,
    target_url: str
) -> None:
    """Execute payload via executor and render results in Telegram."""
    payload = ExploitPayload(**payload_dict) if isinstance(payload_dict, dict) else payload_dict

    # Don't send broken requests (confidence 0 = no valid exploit)
    if payload.confidence == 0.0 or (not payload.payload and not payload.body):
        await message.answer(
            f"⚠️ **Невозможно выполнить проверку**\n\n"
            f"Проверочный запрос не был успешно сгенерирован (confidence: 0.00).\n"
            f"Эта уязвимость может не поддаваться автоматической HTTP-верификации.\n\n"
            f"💡 Рекомендуем использовать AI-исправление для устранения проблемы.",
            parse_mode="Markdown"
        )
        return

    status_msg = await message.answer(
        f"🚀 **Отправка проверочного запроса на `{target_url}`...**\n"
        f"⏳ *Ожидание ответа сервера...*",
        parse_mode="Markdown"
    )

    try:
        success, output = await execute_payload(
            base_url=target_url,
            payload=payload.payload,
            method=payload.method,
            headers=payload.headers,
            body=payload.body,
            success_indicator=payload.success_indicator,
        )

        if success:
            status_icon = "✅"
            status_title = "Уязвимость подтверждена!"
            status_detail = "Индикатор эксплуатации обнаружен в ответе сервера."
        else:
            status_icon = "🛡"
            status_title = "Уязвимость не подтверждена"
            status_detail = "Индикатор эксплуатации не найден. Сервер может быть защищён, либо требуется другой вектор атаки."

        result_text = (
            f"{status_icon} **Результат проверки: {status_title}**\n\n"
            f"ℹ️ {status_detail}\n\n"
            f"🌐 **Целевой URL:** `{target_url}`\n\n"
            f"{output[:1500] if output else '(Пустой ответ)'}"
        )

        # Truncate for Telegram limit
        if len(result_text) > 4000:
            result_text = result_text[:3990] + "\n..."

        await status_msg.edit_text(result_text, parse_mode="Markdown")

    except Exception as ex:
        logger.exception(f"Execute payload error: {ex}")
        await status_msg.edit_text(
            f"❌ Ошибка при выполнении запроса: `{str(ex)[:200]}`\n\n"
            f"💡 Проверьте доступность целевого URL и попробуйте снова.",
            parse_mode="Markdown"
        )


@router.callback_query(F.data.startswith("remediate_"))
async def handle_remediation_and_pr(callback: CallbackQuery, state: FSMContext) -> None:
    """Analyze finding with LLM and open a Pull Request (if authorized)."""
    target_finding: Optional[VulnerabilityFinding] = None
    session_id: Optional[str] = None

    if callback.data.startswith("remediate_finding_"):
        parts = callback.data.split("_")
        session_id = parts[2]
        idx = int(parts[3])
        session = SCAN_SESSIONS.get(session_id)
        if session and idx < len(session["scan_result"].findings):
            target_finding = session["scan_result"].findings[idx]
    else:
        session_id = callback.data.replace("remediate_", "")
        session = SCAN_SESSIONS.get(session_id)
        if session and session["scan_result"].findings:
            target_finding = session["scan_result"].findings[0]

    if not session or not target_finding:
        await callback.answer("⚠️ Сессия аудита устарела.", show_alert=True)
        return

    active_model = settings.gemini_model if settings.llm_provider == "gemini" and settings.gemini_api_key else settings.ollama_model
    await callback.message.answer(
        f"🤖 **ИИ ({active_model}) анализирует уязвимость:**\n"
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
        "> **Deep Scanning powered by Strix Engine (Apache 2.0)**\n",
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


@router.callback_query(F.data.startswith("download_pdf_report_"))
async def handle_download_pdf_report(callback: CallbackQuery) -> None:
    """Generate and send PDF vulnerability audit report including SCA."""
    session_id = callback.data.replace("download_pdf_report_", "")
    session = SCAN_SESSIONS.get(session_id)

    if not session:
        await callback.answer("⚠️ Сессия аудита не найдена.", show_alert=True)
        return

    scan_result: SASTScanResult = session["scan_result"]
    repo_name = session["repo_name"]
    temp_dir = session["temp_dir"]

    status_msg = await callback.message.answer(
        f"⏳ **Генерация Enterprise PDF-отчета для `{repo_name}`...**\n"
        f"🔍 *Запуск SCA-сканирования (проверка зависимостей)...*",
        parse_mode="Markdown"
    )

    try:
        # Run SCA Scanner
        from scanners.sca_scanner import SCAScanner
        sca_scanner = SCAScanner()
        sca_findings = await sca_scanner.scan(temp_dir)
        
        if sca_findings:
            # Merge SCA findings into scan_result
            scan_result.findings.extend(sca_findings)
            scan_result.total_findings += len(sca_findings)
            
            for finding in sca_findings:
                if finding.severity not in scan_result.findings_by_severity:
                    scan_result.findings_by_severity[finding.severity] = 0
                scan_result.findings_by_severity[finding.severity] += 1

        await status_msg.edit_text(
            f"⏳ **Генерация Enterprise PDF-отчета для `{repo_name}`...**\n"
            f"📑 *Верстка документа...*",
            parse_mode="Markdown"
        )

        # Generate PDF
        from scanners.pdf_generator import PDFReportGenerator
        
        pdf_path = f"/tmp/strix_report_{session_id}.pdf"
        generator = PDFReportGenerator(pdf_path)
        
        # We don't have DAST screenshots saved in the session natively, 
        # but if we wanted, we could pass them here. For now, empty list.
        success = generator.generate(scan_result, repo_name, dast_screenshots=[])
        
        if success and os.path.exists(pdf_path):
            doc = FSInputFile(pdf_path, filename=f"Strix_Report_{repo_name.replace('/', '_')}.pdf")
            await callback.message.answer_document(
                document=doc,
                caption=f"📄 **Финальный PDF-отчет по безопасности для `{repo_name}`**\n"
                        f"(Включает результаты SAST и SCA)",
                parse_mode="Markdown"
            )
            await status_msg.delete()
        else:
            await status_msg.edit_text("❌ Ошибка при формировании PDF файла.")

    except Exception as ex:
        logger.exception(f"PDF generation failed: {ex}")
        await status_msg.edit_text(f"❌ Ошибка генерации отчета: `{str(ex)[:200]}`", parse_mode="Markdown")

    await callback.answer()