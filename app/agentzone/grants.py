"""Business logic around validating and managing SSH grants."""
from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone

from agentzone.helper import helper_gateway
from agentzone.models import GrantError, GrantInfo, NormalizedPublicKey

_KEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{2,32}$")


async def _run_helper(*args: str, stdin: str | None = None) -> tuple[int, dict[str, str], str]:
    result = await helper_gateway.run(*args, stdin=stdin)
    return result.exit_code, result.data, result.raw



def normalize_public_key(raw: str) -> NormalizedPublicKey:
    text = " ".join((raw or "").strip().split())
    if "\n" in raw or "\r" in raw:
        raise GrantError("The SSH public key must be a single line.")

    match = _KEY_RE.match(text)
    if not match:
        raise GrantError("Expected a key like: ssh-ed25519 AAAA... comment")

    key_type, key_b64, comment = match.groups()
    try:
        decoded = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - user input validation
        raise GrantError("The SSH key contains invalid base64 data.") from exc
    if len(decoded) < 32:
        raise GrantError("The SSH key looks too short to be valid.")

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write(f"{key_type} {key_b64}" + (f" {comment}" if comment else "") + "\n")
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", tmp_path],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if result.returncode != 0:
        raise GrantError("ssh-keygen could not parse this SSH key.")

    parts = result.stdout.strip().split()
    fingerprint = parts[1] if len(parts) >= 2 else "unknown"
    return NormalizedPublicKey(
        text=f"{key_type} {key_b64}" + (f" {comment}" if comment else ""),
        fingerprint=fingerprint,
        comment=comment or "",
    )



def validate_password(password: str) -> str:
    password = (password or "").strip()
    if len(password) < 8:
        raise GrantError("Password must be at least 8 characters.")
    if "\n" in password or "\r" in password:
        raise GrantError("Password must be a single line.")
    return password



def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not _USERNAME_RE.match(username):
        raise GrantError("Username must be 2-32 characters: letters, digits, '-', '_'.")
    return username


async def grant_access(
    *,
    username: str,
    pubkey: str,
    password: str,
    ttl_minutes: int | None,
    admin_id: int,
) -> dict[str, str]:
    user = validate_username(username)
    key = normalize_public_key(pubkey)
    pwd = validate_password(password)

    args = ["grant", "--username", user, "--admin-id", str(admin_id)]
    if ttl_minutes is not None:
        args += ["--ttl", str(int(ttl_minutes))]

    code, data, raw = await _run_helper(*args, stdin=f"{key.text}\n{pwd}\n")
    if code != 0 or data.get("ok") != "true":
        raise GrantError(raw or f"Helper exited with code {code}")
    return data


async def revoke_access(
    *,
    grant_id: str | None = None,
    all_grants: bool = False,
    reason: str = "manual",
) -> dict[str, str]:
    args = ["revoke", "--reason", reason]
    if all_grants:
        args.append("--all")
    elif grant_id:
        args += ["--grant-id", grant_id]
    else:
        raise GrantError("Either grant_id or all_grants=True is required.")

    code, data, raw = await _run_helper(*args)
    if code != 0 or data.get("ok") != "true":
        raise GrantError(raw or f"Helper exited with code {code}")
    return data


async def list_grants() -> list[GrantInfo]:
    code, _data, raw = await _run_helper("status")
    if code != 0:
        raise GrantError(raw or f"Helper exited with code {code}")
    return sort_grants(_parse_status(raw))



def _parse_status(raw: str) -> list[GrantInfo]:
    grants: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for line in (raw or "").splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "grant_id":
            if current is not None:
                grants.append(current)
            current = {"id": value}
            continue
        if key.startswith("grant_") and current is not None:
            current[key[len("grant_"):]] = value

    if current is not None:
        grants.append(current)

    return [
        GrantInfo(
            grant_id=item.get("id", ""),
            username=item.get("username", ""),
            port=int(item.get("port", "0") or 0),
            fingerprint=item.get("fingerprint", ""),
            active=(item.get("active", "false") or "").lower() == "true",
            expires_at=item.get("expires_at", "") or "never",
            granted_at=item.get("granted_at", ""),
            ttl_remaining_sec=int(item.get("ttl_remaining_sec", "0") or 0),
        )
        for item in grants
    ]



def sort_grants(grants: list[GrantInfo]) -> list[GrantInfo]:
    def key(item: GrantInfo) -> tuple[int, int, int, str]:
        if item.ttl_remaining_sec < 0:
            ttl_rank = 10**12
        else:
            ttl_rank = item.ttl_remaining_sec
        return (0 if item.active else 1, 0 if item.ttl_remaining_sec >= 0 else 1, ttl_rank, item.username)

    return sorted(grants, key=key)



def format_remaining(seconds: int) -> str:
    if seconds < 0:
        return "no expiry"
    minutes, sec = divmod(max(0, seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"



def format_iso(value: str) -> str:
    if not value or value == "never":
        return "never"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:  # noqa: BLE001 - best-effort formatting for bot output
        return value


__all__ = [
    "GrantError",
    "GrantInfo",
    "NormalizedPublicKey",
    "format_iso",
    "format_remaining",
    "grant_access",
    "list_grants",
    "normalize_public_key",
    "revoke_access",
    "sort_grants",
    "validate_password",
    "validate_username",
]
