"""
Main entry point for Aegis Telegram Daemon.
Initializes aiogram Dispatcher, middlewares, and starts polling.
"""

import asyncio
import logging
import sys
import uuid
import shutil
from pathlib import Path
from aiogram import Bot, Dispatcher, Router, types, F
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from aegis.core.config import settings
from aegis.scanners.sast_scanner import SASTScanner
from aegis.core.event_bus import ScanEventBus

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("aegis.main")

router = Router()

@router.message(CommandStart())
async def send_welcome(message: types.Message):
    """Handler for the /start command. Sends a welcome message."""
    welcome_text = (
        "Aegis — сканер уязвимостей. Отправьте ZIP-архив с кодом или ссылку на репозиторий."
    )
    
    await message.answer(welcome_text, parse_mode=ParseMode.MARKDOWN)

@router.message(F.document)
async def handle_document(message: types.Message, bot: Bot):
    if not message.document.file_name.endswith('.zip'):
        await message.reply("Пожалуйста, отправьте ZIP-архив.")
        return

    if message.document.file_size > 20 * 1024 * 1024:
        await message.reply("Файл слишком большой. Лимит 20MB.")
        return

    status_msg = await message.reply("Скачиваю архив...")
    
    scan_uuid = str(uuid.uuid4())
    repo_dir = Path(f"/tmp/aegis_scans/{scan_uuid}")
    zip_path = repo_dir / "upload.zip"
    extract_dir = repo_dir / "code"
    
    repo_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        await bot.download(message.document, destination=zip_path)
        await status_msg.edit_text("Распаковка и анализ...")
        
        shutil.unpack_archive(zip_path, extract_dir)
        
        event_bus = ScanEventBus(scan_id=scan_uuid)
        scanner = SASTScanner(event_bus=event_bus)
        
        result = await scanner.scan(extract_dir)
        
        count = len(result) if result else 0
        await status_msg.edit_text(f"Сканирование завершено. Найдено уязвимостей: {count}.")
    except Exception as e:
        logger.error(f"Error processing zip: {e}")
        await status_msg.edit_text(f"Ошибка при сканировании: {str(e)}")
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
        default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN)
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
