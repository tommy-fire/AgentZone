from __future__ import annotations

import pytest

from agentzone import grants

VALID_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIyZkw9h6qIVs2qj9vafvaOWCzsYMd05DV1jT4ca6Sw unit-test-key"


def test_normalize_public_key_accepts_valid_ed25519():
    key = grants.normalize_public_key(VALID_PUBKEY)
    assert key.text == VALID_PUBKEY
    assert key.fingerprint.startswith("SHA256:")
    assert key.comment == "unit-test-key"


def test_normalize_public_key_rejects_garbage():
    with pytest.raises(grants.GrantError):
        grants.normalize_public_key("not-a-key")


def test_normalize_public_key_rejects_multiline():
    with pytest.raises(grants.GrantError):
        grants.normalize_public_key(VALID_PUBKEY + "\nssh-ed25519 AAAA x")


def test_validate_password_rejects_short():
    with pytest.raises(grants.GrantError):
        grants.validate_password("short")
    with pytest.raises(grants.GrantError):
        grants.validate_password("12345678901")


def test_validate_password_accepts_valid():
    assert grants.validate_password("  longenoughpassword  ") == "longenoughpassword"


def test_validate_password_rejects_multiline():
    with pytest.raises(grants.GrantError):
        grants.validate_password("longenough\npassword")


@pytest.mark.parametrize("name", ["agent1", "a_b-c", "_svc", "x" * 32])
def test_validate_username_accepts_valid(name):
    assert grants.validate_username(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "a", "x" * 33, "bad user", "bad;user", "user`whoami`", "AB", "1agent"],
)
def test_validate_username_rejects_invalid(name):
    with pytest.raises(grants.GrantError):
        grants.validate_username(name)


def test_format_remaining_buckets():
    assert grants.format_remaining(-1) == "no expiry"
    assert grants.format_remaining(5) == "5s"
    assert grants.format_remaining(65) == "1m 5s"
    assert grants.format_remaining(3665) == "1h 1m"
    assert grants.format_remaining(90000) == "1d 1h"


def test_format_iso_handles_never_and_missing():
    assert grants.format_iso("") == "never"
    assert grants.format_iso("never") == "never"


def test_format_iso_formats_utc_timestamp():
    assert grants.format_iso("2026-01-02T03:04:05Z") == "2026-01-02 03:04 UTC"


def test_parse_status_multiple_grants():
    raw = (
        "grant_count=2\n"
        "grant_id=aaa111\n"
        "grant_username=agent-one\n"
        "grant_port=20000\n"
        "grant_fingerprint=SHA256:abc\n"
        "grant_active=true\n"
        "grant_expires_at=2026-01-01T00:00:00Z\n"
        "grant_granted_at=2025-01-01T00:00:00Z\n"
        "grant_ttl_remaining_sec=120\n"
        "grant_id=bbb222\n"
        "grant_username=agent-two\n"
        "grant_port=20001\n"
        "grant_fingerprint=SHA256:def\n"
        "grant_active=false\n"
        "grant_expires_at=2020-01-01T00:00:00Z\n"
        "grant_granted_at=2019-01-01T00:00:00Z\n"
        "grant_ttl_remaining_sec=0\n"
        "active_count=1\n"
    )
    parsed = grants._parse_status(raw)
    assert len(parsed) == 2
    assert parsed[0].grant_id == "aaa111"
    assert parsed[0].username == "agent-one"
    assert parsed[0].port == 20000
    assert parsed[0].active is True
    assert parsed[1].grant_id == "bbb222"
    assert parsed[1].active is False


@pytest.mark.asyncio
async def test_helper_missing_raises_grant_error(monkeypatch):
    from agentzone.config import settings
    monkeypatch.setattr(settings, "AGENTZONE_HELPER_PATH", "/no/such/helper")
    with pytest.raises(grants.GrantError):
        await grants.list_grants()


@pytest.mark.asyncio
async def test_run_helper_does_not_check_local_exec_bit_when_using_sudo(monkeypatch, tmp_path):
    """Regression: the deployed helper is 0750 root:root and the bot runs
    as an unprivileged system user with no group access to it (see
    install.sh). os.access(helper, os.X_OK) against the CALLING user's
    permissions therefore always reports "not executable", even though
    `sudo -n` can run it fine. _run_helper must only require the helper
    to exist and sudo to be available -- not that the current process can
    exec it directly -- whenever it is not already root."""
    from agentzone.config import settings

    fake_helper = tmp_path / "helper"
    fake_helper.write_text("#!/bin/sh\necho ok=true\n")
    fake_helper.chmod(0o750)  # not executable by "others" (simulates real deploy)
    from agentzone import helper

    monkeypatch.setattr(settings, "AGENTZONE_HELPER_PATH", str(fake_helper))
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)  # simulate unprivileged bot user

    code, data, raw = await grants._run_helper("status")
    # It must have attempted to invoke via sudo rather than failing on the
    # local exec-bit check (code 126 would indicate the old, broken
    # behavior). Since there is no real sudoers rule in this sandbox, the
    # sudo invocation itself may fail (e.g. "sudo: a password is
    # required") -- what matters is that it got there instead of bailing
    # out at 126 with "not executable".
    assert code != 126
    assert "not executable" not in raw


@pytest.mark.asyncio
async def test_grant_access_rejects_bad_username_before_shelling_out(monkeypatch):
    async def _boom(*a, **kw):
        raise AssertionError("helper should not be invoked for invalid input")

    monkeypatch.setattr(grants, "_run_helper", _boom)
    with pytest.raises(grants.GrantError):
        await grants.grant_access(
            username="bad user",
            pubkey=VALID_PUBKEY,
            password="longenoughpassword",
            ttl_minutes=60,
            admin_id=1,
        )
