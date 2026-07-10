"""Background safety net for grant expiry.

The primary expiry mechanism is a systemd timer that calls
``agentzone-helper expire-check`` once a minute, plus this in-process bot
loop. The helper also sets a coarse day-granularity ``chage -E`` account
expiry as a fallback if both timer-based checks fail. This loop is thus a
THIRD, independent safety net, so a single misconfigured timer can never
leave an expired grant active unnoticed.
"""
from __future__ import annotations

import asyncio
import logging

from aiogram import Bot

from bot.services import grants

logger = logging.getLogger(__name__)

_POLL_SECONDS = 30


async def expiry_monitor_loop(bot: Bot, admin_id: int) -> None:
    while True:
        try:
            active_grants = await grants.list_grants()
            for grant in active_grants:
                if not grant.active:
                    try:
                        await grants.revoke_access(grant_id=grant.grant_id, reason="expired")
                        logger.info("Revoked expired grant %s (user=%s)", grant.grant_id, grant.username)
                        try:
                            await bot.send_message(
                                admin_id,
                                f"⏱ Access expired and was revoked automatically.\n"
                                f"User: <code>{grant.username}</code>\n"
                                f"Grant: <code>{grant.grant_id}</code>",
                                parse_mode="HTML",
                            )
                        except Exception:
                            logger.debug("Could not notify admin about auto-revoke", exc_info=True)
                    except grants.GrantError:
                        logger.exception("Failed to auto-revoke expired grant %s", grant.grant_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Expiry monitor iteration failed")
        await asyncio.sleep(_POLL_SECONDS)
