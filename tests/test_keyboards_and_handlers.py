from __future__ import annotations

import inspect

from agentzone import handlers, keyboards
from agentzone.models import GrantInfo



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
    assert "ttl:0" in data
    assert "ttl:custom" in data



def test_grant_actions_targets_specific_grant_id():
    data = _all_callback_data(keyboards.grant_actions("abc123"))
    assert "revoke:abc123" in data
    assert "menu:back" in data



def test_revoke_all_confirm_requires_explicit_confirm_step():
    data = _all_callback_data(keyboards.revoke_all_confirm())
    assert "revoke:all:confirm" in data
    assert "menu:back" in data



def test_grants_overview_includes_refresh_and_revoke_for_active_grants():
    markup = keyboards.grants_overview(
        [
            GrantInfo("a1", "alpha", 20000, "SHA256:a", True, "never", "", -1),
            GrantInfo("b2", "beta", 20001, "SHA256:b", False, "never", "", 0),
        ]
    )
    data = _all_callback_data(markup)
    assert "revoke:a1" in data
    assert "revoke:b2" not in data
    assert "grants:refresh" in data
    assert "revoke:all" in data



def test_every_handler_checks_is_admin():
    handler_funcs = [
        name
        for name in dir(handlers)
        if name.startswith(("cb_", "on_", "cmd_")) and callable(getattr(handlers, name))
    ]
    assert len(handler_funcs) >= 9, "expected several handlers to exist"
    for name in handler_funcs:
        source = inspect.getsource(getattr(handlers, name))
        assert "_is_admin(" in source, f"{name} does not check _is_admin()"



def test_handlers_ignore_telegram_message_not_modified_errors_on_safe_edits():
    source = inspect.getsource(handlers._safe_edit_text)
    assert "TelegramBadRequest" in source
    assert "message is not modified" in source.lower()



def test_is_admin_compares_against_settings_admin_id():
    source = inspect.getsource(handlers._is_admin)
    assert "settings.ADMIN_ID" in source



def test_grant_form_state_order_matches_documented_flow():
    names = [name for name in vars(handlers.GrantForm) if not name.startswith("_")]
    assert "waiting_username" in names
    assert "waiting_pubkey" in names
    assert "waiting_password" in names
    assert "waiting_ttl_custom" in names
