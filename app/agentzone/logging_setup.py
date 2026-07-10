"""Logging bootstrap for the bot process."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from agentzone.config import Settings

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"



def configure_logging(runtime_settings: Settings) -> None:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    try:
        runtime_settings.log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            runtime_settings.log_dir / "bot.log",
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logging.getLogger().addHandler(handler)
    except Exception:  # noqa: BLE001 - stdout logging remains available
        logging.exception("Failed to initialize file logging (continuing with stdout only)")
