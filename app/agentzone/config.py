"""Runtime settings for AgentZone."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven runtime configuration.

    AgentZone deliberately keeps its settings surface small: one Telegram
    bot, one admin, one server IP, one privileged helper.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    BOT_TOKEN: str
    ADMIN_ID: int

    SERVER_IP: str = ""

    AGENTZONE_PORT_RANGE_START: int = 20000
    AGENTZONE_PORT_RANGE_END: int = 20100
    AGENTZONE_MAX_TTL_MINUTES: int = 10080  # 7 days

    AGENTZONE_HELPER_PATH: str = "/usr/local/sbin/agentzone-helper"
    AGENTZONE_STATE_DIR: str = "/var/lib/agentzone"
    AGENTZONE_LOG_DIR: str = "/opt/agentzone/logs"
    AGENTZONE_MONITOR_POLL_SECONDS: int = 30

    TIMEZONE: str = "UTC"

    @property
    def log_dir(self) -> Path:
        return Path(self.AGENTZONE_LOG_DIR)


settings = Settings()  # type: ignore[call-arg]
