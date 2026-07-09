"""Thin async wrapper around the root-owned agentzone_helper.sh script.

The bot process runs as an unprivileged user and never touches sshd, UFW,
or /etc/passwd directly. It shells out to the helper through a narrow
sudoers rule installed by install.sh. Keeping this boundary explicit means
a bug in the bot's Python code cannot, by itself, grant root — only the
helper (a single small, reviewable script) can.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bot.config import settings


class GrantError(ValueError):
    """Raised for invalid input or a failed helper call."""


_KEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$")


@dataclass(frozen=True)
class NormalizedPublicKey:
    text: str
    fingerprint: str
    comment: str


def normalize_public_key(raw: str) -> NormalizedPublicKey:
    """Validate and canonicalize a single-line OpenSSH public key.

    Runs the same structural checks the helper re-runs as root: this lets
    the bot show a friendly error immediately, without spending a
    subprocess round-trip on obviously malformed input.
    """
    text = " ".join((raw or "").strip().split())
    if "\n" in raw or "\r" in raw:
        raise GrantError("The key must be a single line.")
    match = _KEY_RE.match(text)
    if not match:
        raise GrantError("Expected a key like: ssh-ed25519 AAAA... comment")

    key_type, key_b64, comment = match.groups()
    try:
        decoded = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - user-friendly error
        raise GrantError("Invalid base64 in the key.") from exc
    if len(decoded) < 32:
        raise GrantError("Key looks too short to be valid.")

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write(f"{key_type} {key_b64} {comment or ''}\n")
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
        raise GrantError("ssh-keygen could not parse this key.")
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


_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{2,32}$")


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not _USERNAME_RE.match(username):
        raise GrantError(
            "Username must be 2-32 characters: letters, digits, '-', '_'."
        )
    return username


def _parse_kv_output(raw: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


async def _run_helper(*args: str, stdin: str | None = None) -> tuple[int, dict[str, str], str]:
    helper = Path(settings.AGENTZONE_HELPER_PATH)
    if not helper.exists():
        raw = f"Helper not installed at {helper}"
        return 127, {"ok": "false", "error": raw}, raw

    run_as_root_directly = os.geteuid() == 0
    if run_as_root_directly:
        # No privilege escalation needed: the bot itself IS root (e.g. a
        # dev/test environment), so it must be able to exec the file
        # directly.
        if not os.access(helper, os.X_OK):
            raw = f"Helper is not executable: {helper}"
            return 126, {"ok": "false", "error": raw}, raw
        cmd = [str(helper), *args]
    else:
        # Normal deployment: the bot runs as the unprivileged "agentzone"
        # system user, which install.sh deliberately does NOT add to any
        # group that can read/execute the 0750 root:root helper directly
        # (see install.sh's "Installing the privileged helper" step) — the
        # helper is only ever meant to run as root, via the narrow sudoers
        # rule install.sh also installs. os.access() here would check the
        # CALLING user's permission bits, which are and should stay empty;
        # checking them would always report "not executable" even though
        # `sudo -n` (below) can run it just fine. So we only verify sudo
        # itself is available and let the actual sudo invocation surface
        # any real permission problem.
        import shutil
        if shutil.which("sudo") is None:
            raw = "sudo is not installed — cannot invoke the privileged helper"
            return 127, {"ok": "false", "error": raw}, raw
        cmd = ["sudo", "-n", str(helper), *args]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out_b, err_b = await proc.communicate(stdin.encode("utf-8") if stdin is not None else None)
    out = out_b.decode("utf-8", "replace")
    err = err_b.decode("utf-8", "replace")
    raw = (out + (("\n" + err) if err else "")).strip()
    return proc.returncode or 0, _parse_kv_output(out), raw



@dataclass(frozen=True)
class GrantInfo:
    grant_id: str
    username: str
    port: int
    fingerprint: str
    active: bool
    expires_at: str
    granted_at: str
    ttl_remaining_sec: int


async def grant_access(
    *,
    username: str,
    pubkey: str,
    password: str,
    ttl_minutes: int | None,
    admin_id: int,
) -> dict[str, str]:
    """Create (or reuse) a Linux user, its own sshd port, and a sudo rule.

    ttl_minutes=None means "no expiry, until manually revoked".
    """
    user = validate_username(username)
    key = normalize_public_key(pubkey)
    pwd = validate_password(password)

    args = ["grant", "--username", user, "--admin-id", str(admin_id)]
    if ttl_minutes is not None:
        args += ["--ttl", str(int(ttl_minutes))]
    stdin_payload = f"{key.text}\n{pwd}\n"
    code, data, raw = await _run_helper(*args, stdin=stdin_payload)
    if code != 0 or data.get("ok") != "true":
        raise GrantError(raw or f"Helper exited with code {code}")
    return data


async def revoke_access(*, grant_id: str | None = None, all_grants: bool = False, reason: str = "manual") -> dict[str, str]:
    args = ["revoke", "--reason", reason]
    if all_grants:
        args += ["--all"]
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
    return _parse_status(raw)


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
        elif key.startswith("grant_") and current is not None:
            current[key[len("grant_"):]] = value
    if current is not None:
        grants.append(current)
    return [
        GrantInfo(
            grant_id=g.get("id", ""),
            username=g.get("username", ""),
            port=int(g.get("port", "0") or 0),
            fingerprint=g.get("fingerprint", ""),
            active=(g.get("active", "false") or "").lower() == "true",
            expires_at=g.get("expires_at", "") or "never",
            granted_at=g.get("granted_at", ""),
            ttl_remaining_sec=int(g.get("ttl_remaining_sec", "0") or 0),
        )
        for g in grants
    ]


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
    except Exception:  # noqa: BLE001 - best-effort formatting
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
    "validate_password",
    "validate_username",
]
