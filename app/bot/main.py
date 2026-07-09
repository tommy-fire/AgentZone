"""AgentZone bot entrypoint.

Deliberately minimal: long polling only. No webhook, no HTTP server, no
web panel — nothing that would ever need an open inbound port or a domain
name. The server's IP is only ever revealed to the admin inside a private
Telegram message.
"""
from __future__ import annotations

import asyncio
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

try:
    log_dir = Path("/opt/agentzone/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(log_dir / "bot.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger().addHandler(file_handler)
except Exception:
    logging.exception("Failed to initialize file logging (continuing with stdout only)")

logger = logging.getLogger(__name__)

from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage

from bot import handlers
from bot.config import settings
from bot.services.expiry_monitor import expiry_monitor_loop


def create_dispatcher() -> Dispatcher:
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(handlers.router)
    return dp


async def main() -> None:
    bot = Bot(token=settings.BOT_TOKEN)
    dp = create_dispatcher()
    asyncio.create_task(expiry_monitor_loop(bot, settings.ADMIN_ID))
    logger.info("AgentZone bot started (polling only, admin_id=%s)", settings.ADMIN_ID)
    try:
        await dp.start_polling(bot)
    finally:
        logger.warning("Bot polling stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        logger.exception("Bot crashed during startup/runtime")
        raise
