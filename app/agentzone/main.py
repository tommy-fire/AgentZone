"""AgentZone bot entrypoint."""
from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage

from agentzone.config import settings
from agentzone.handlers import router
from agentzone.logging_setup import configure_logging
from agentzone.monitor import expiry_monitor_loop

configure_logging(settings)
logger = logging.getLogger(__name__)



def create_dispatcher() -> Dispatcher:
    dispatcher = Dispatcher(storage=MemoryStorage())
    dispatcher.include_router(router)
    return dispatcher


async def main() -> None:
    bot = Bot(token=settings.BOT_TOKEN)
    dispatcher = create_dispatcher()
    asyncio.create_task(expiry_monitor_loop(bot, settings.ADMIN_ID))
    logger.info("AgentZone bot started (polling only, admin_id=%s)", settings.ADMIN_ID)
    try:
        await dispatcher.start_polling(bot)
    finally:
        logger.warning("Bot polling stopped")



def run() -> None:
    try:
        asyncio.run(main())
    except Exception:  # noqa: BLE001 - top-level crash logging
        logger.exception("Bot crashed during startup/runtime")
        raise


if __name__ == "__main__":
    run()
