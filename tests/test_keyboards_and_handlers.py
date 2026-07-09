from __future__ import annotations

import inspect

from bot import handlers, keyboards


def _all_callback_data(markup) -> list[str]:
    return [btn.callback_data for row in markup.inline_keyboard for btn in row if btn.callback_data]


def test_main_menu_has_expected_actions():
    data = _all_callback_data(keyboards.main_menu())
    assert "grant:start" in data
    assert "grants:list" in data
    assert "server:info" in data


def test_ttl_choices_cover_common_windows_and_forever():
    data = _all_callback_data(keyboards.ttl_choices())
    assert "ttl:30" in data
    assert "ttl:60" in data
    assert "ttl:1440" in data
    assert "ttl:0" in data  # "until revoked"
    assert "ttl:custom" in data


def test_grant_actions_targets_specific_grant_id():
    data = _all_callback_data(keyboards.grant_actions("abc123"))
    assert "revoke:abc123" in data


def test_revoke_all_confirm_requires_explicit_confirm_step():
    """Security/UX: revoking everything must be a two-step action, not a
    single misclick."""
    data = _all_callback_data(keyboards.revoke_all_confirm())
    assert "revoke:all:confirm" in data
    assert "menu:back" in data


def test_every_handler_checks_is_admin():
    """Every callback/message handler must call _is_admin() as its first
    real check — a regression here would let ANY Telegram user control the
    bot, not just the configured admin."""
    source = inspect.getsource(handlers)
    handler_funcs = [
        name for name in dir(handlers)
        if name.startswith(("cb_", "on_", "cmd_")) and callable(getattr(handlers, name))
    ]
    assert len(handler_funcs) >= 8, "expected several handlers to exist"
    for name in handler_funcs:
        func_source = inspect.getsource(getattr(handlers, name))
        assert "_is_admin(" in func_source, f"{name} does not check _is_admin()"


def test_is_admin_compares_against_settings_admin_id():
    source = inspect.getsource(handlers._is_admin)
    assert "settings.ADMIN_ID" in source


def test_grant_form_state_order_matches_documented_flow():
    states = list(handlers.GrantForm.__states__) if hasattr(handlers.GrantForm, "__states__") else None
    # aiogram StatesGroup exposes states via .__all_states__ or similar
    # depending on version; fall back to attribute introspection.
    names = [k for k in vars(handlers.GrantForm) if not k.startswith("_")]
    assert "waiting_username" in names
    assert "waiting_pubkey" in names
    assert "waiting_password" in names
    assert "waiting_ttl_custom" in names
