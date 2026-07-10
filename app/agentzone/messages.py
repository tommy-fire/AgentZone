"""User-facing Telegram copy assembled in one place."""
from __future__ import annotations

from collections.abc import Sequence

from agentzone import grants
from agentzone.models import GrantInfo


WELCOME_TEXT = (
    "🤖 <b>AgentZone</b>\n\n"
    "Give an AI agent temporary SSH access without sharing your own account.\n\n"
    "From here you can:\n"
    "• issue a new SSH grant\n"
    "• review active and expired grants\n"
    "• revoke one grant or everything at once"
)


PROCESSING_TEXT = "⏳ Working on it…"
CANCELLED_TEXT = "Cancelled. Nothing was changed."
NO_GRANTS_TEXT = "No grants are recorded yet."
ALL_REVOKED_TEXT = "✅ All grants were revoked and cleaned up."
ONE_REVOKED_TEXT = "✅ Grant revoked and all managed traces were cleaned up."



def grant_username_prompt() -> str:
    return (
        "Step 1 / 4\n\n"
        "Send the Linux username for the new account.\n"
        "Allowed: letters, digits, '-' and '_'."
    )



def grant_pubkey_prompt() -> str:
    return (
        "Step 2 / 4\n\n"
        "Send the agent's <b>SSH public key</b>.\n"
        "Example: <code>ssh-ed25519 AAAA... comment</code>"
    )



def grant_password_prompt() -> str:
    return (
        "Step 3 / 4\n\n"
        "Send a password for this account (minimum 8 characters).\n\n"
        "⚠️ This password is <b>not</b> used for SSH login. SSH stays key-only. "
        "The password is only for local <code>sudo</code> on the server."
    )



def grant_ttl_prompt() -> str:
    return "Step 4 / 4\n\nHow long should this access stay alive?"



def grant_custom_ttl_prompt(max_minutes: int) -> str:
    return f"Send the TTL in minutes (1-{max_minutes})."



def grant_failed_text(error: str) -> str:
    return f"❌ Could not create the grant.\n<code>{error}</code>"



def grant_success_text(*, host: str, result: dict[str, str], fallback_username: str) -> str:
    username = result.get("username", fallback_username)
    port = result.get("port", "?")
    expires = grants.format_iso(result.get("expires_at", "never"))
    fingerprint = result.get("fingerprint", "unknown")
    ssh_command = f"ssh -p {port} {username}@{host}"
    return (
        "✅ <b>Access granted</b>\n\n"
        f"User: <code>{username}</code>\n"
        f"Port: <code>{port}</code>\n"
        f"Expires: <code>{expires}</code>\n"
        f"Key fingerprint: <code>{fingerprint}</code>\n\n"
        "Connect with:\n"
        f"<code>{ssh_command}</code>\n\n"
        "SSH authentication is public-key only. The password you entered is "
        "kept for local <code>sudo</code> on the server and is never accepted "
        "as a network login.\n\n"
        "⚠️ This message contains the server IP and is shown only in your "
        "private admin chat."
    )



def server_info_text(*, host: str, active_count: int, port_range_start: int, port_range_end: int) -> str:
    return (
        "🌐 <b>Server info</b>\n\n"
        f"IP: <code>{host or 'unknown'}</code>\n"
        f"Active grants: <code>{active_count}</code>\n"
        f"Managed port range: <code>{port_range_start}-{port_range_end}</code>\n\n"
        "The IP is shown only to you in this private chat."
    )



def grants_overview_text(items: Sequence[GrantInfo]) -> str:
    if not items:
        return NO_GRANTS_TEXT

    active = sum(1 for item in items if item.active)
    expired = len(items) - active
    lines = [
        "📋 <b>Grants</b>",
        "",
        f"Active: <code>{active}</code> · expired: <code>{expired}</code>",
    ]
    for item in items:
        status = "🟢 active" if item.active else "🔴 expired"
        remaining = grants.format_remaining(item.ttl_remaining_sec) if item.active else "—"
        lines.extend(
            [
                "",
                f"<b>{item.username}</b> · <code>port {item.port}</code> · {status}",
                f"Expires: {grants.format_iso(item.expires_at)}",
                f"Remaining: {remaining}",
                f"Key: <code>{item.fingerprint}</code>",
            ]
        )
    return "\n".join(lines)



def revoke_all_warning_text() -> str:
    return (
        "⚠️ This will revoke every active grant and delete every managed "
        "agent account. Continue?"
    )



def invalid_custom_ttl_text(max_minutes: int) -> str:
    return f"❌ Enter a whole number of minutes between 1 and {max_minutes}."
