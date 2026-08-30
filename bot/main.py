"""
Main entry point for CyberSecurityBot Telegram Daemon.
Initializes aiogram Dispatcher, middlewares, and starts polling.
"""

import asyncio
import logging
import sys
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from bot.handlers import router
from core.config import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("cybersecuritybot.main")


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
    if settings.llm_provider == "openrouter" and settings.openrouter_api_key:
        active_model = settings.openrouter_model
    elif settings.llm_provider == "gemini" and settings.gemini_api_key:
        active_model = settings.gemini_model
    else:
        active_model = settings.ollama_model
    logger.info(f"Active LLM Provider: {settings.llm_provider.value} | Model: {active_model}")

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
