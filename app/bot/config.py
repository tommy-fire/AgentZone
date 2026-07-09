"""Runtime settings, loaded from environment variables / .env.

Kept intentionally tiny: AgentZone has exactly one job (issue and revoke
temporary SSH access for an AI agent), so it does not need a database,
a web panel, or webhooks. Everything lives in one small state file managed
by the root-owned helper script (see app/scripts/agentzone_helper.sh).
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Telegram ---
    BOT_TOKEN: str
    # Single admin only, by design: this bot's only purpose is letting the
    # server owner grant/revoke SSH access, so there is no multi-admin
    # access model to build or audit.
    ADMIN_ID: int

    # --- Network ---
    # Always the bare public IPv4 — no domain. AgentZone never runs a web
    # server, so there is nothing to put a domain in front of; the fewer
    # public-facing artifacts, the smaller the attack surface. The IP is
    # only ever sent to the admin in a private Telegram message, never
    # logged publicly or embedded in any file this repo could leak.
    SERVER_IP: str = ""

    # --- Grant defaults ---
    # Range of TCP ports the helper allocates one-per-grant from. Kept out
    # of the well-known range (<1024) and away from common service ports.
    AGENTZONE_PORT_RANGE_START: int = 20000
    AGENTZONE_PORT_RANGE_END: int = 20100
    # Upper bound an admin can request for a single grant's TTL. "0" in a
    # /grant flow means "no expiry, until manually revoked" and is allowed
    # regardless of this cap.
    AGENTZONE_MAX_TTL_MINUTES: int = 10080  # 7 days

    # --- Paths (overridable for tests) ---
    AGENTZONE_HELPER_PATH: str = "/usr/local/sbin/agentzone-helper"
    AGENTZONE_STATE_DIR: str = "/var/lib/agentzone"
    TIMEZONE: str = "UTC"


settings = Settings()  # type: ignore[call-arg]
