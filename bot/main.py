"""
Main entry point for Aegis Telegram Daemon.
Initializes aiogram Dispatcher, middlewares, and starts polling.
"""

import asyncio
import logging
import sys
from aiogram import Bot, Dispatcher, Router, types
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from aegis.core.config import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("aegis.main")

router = Router()

@router.message(CommandStart())
async def send_welcome(message: types.Message):
    """Handler for the /start command. Sends a welcome message with a Web App button."""
    web_app_url = settings.web_app_url
    
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="Launch Aegis Dashboard",
            web_app=WebAppInfo(url=web_app_url)
        )]
    ])
    
    welcome_text = (
        "🛡 *Welcome to Aegis AI Security Engine!*\n\n"
        "I am an advanced Autonomous AI-DevSecOps Scanner designed to find 0-day vulnerabilities in Flutter apps.\n\n"
        "Click the button below to launch the interactive Visual Dashboard and start scanning your repositories in real-time."
    )
    
    await message.answer(welcome_text, reply_markup=markup, parse_mode=ParseMode.MARKDOWN)


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
