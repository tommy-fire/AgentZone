"""Background expiry monitor for grants."""
from __future__ import annotations

import asyncio
import logging

from aiogram import Bot

from agentzone import grants
from agentzone.config import settings

logger = logging.getLogger(__name__)


async def expiry_monitor_loop(bot: Bot, admin_id: int) -> None:
    """Revoke grants that should no longer be active.

    The primary revocation path is the systemd timer invoking the helper.
    This loop is an extra safety net inside the bot process itself.
    """

    while True:
        try:
            items = await grants.list_grants()
            for item in items:
                if item.active:
                    continue
                try:
                    await grants.revoke_access(grant_id=item.grant_id, reason="expired")
                    logger.info("Revoked expired grant %s (user=%s)", item.grant_id, item.username)
                    try:
                        await bot.send_message(
                            admin_id,
                            (
                                "⏱ Grant expired and was revoked automatically.\n"
                                f"User: <code>{item.username}</code>\n"
                                f"Grant: <code>{item.grant_id}</code>"
                            ),
                            parse_mode="HTML",
                        )
                    except Exception:  # noqa: BLE001 - notifications are best effort
                        logger.debug("Could not notify the admin about an auto-revoke", exc_info=True)
                except grants.GrantError:
                    logger.exception("Failed to auto-revoke expired grant %s", item.grant_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - keep the safety loop alive
            logger.exception("Expiry monitor iteration failed")

        await asyncio.sleep(settings.AGENTZONE_MONITOR_POLL_SECONDS)
