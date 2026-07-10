"""Telegram handlers for the single-admin AgentZone bot."""
from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router, types
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from agentzone import grants, keyboards, messages
from agentzone.config import settings

router = Router()
logger = logging.getLogger(__name__)


class GrantForm(StatesGroup):
    waiting_username = State()
    waiting_pubkey = State()
    waiting_password = State()
    waiting_ttl_custom = State()



def _is_admin(user_id: int) -> bool:
    return int(user_id) == int(settings.ADMIN_ID)



def _draft_from_state(data: dict[str, Any]) -> dict[str, str]:
    return {
        "username": data.get("username") or "",
        "pubkey": data.get("pubkey") or "",
        "password": data.get("password") or "",
    }



def _chat_id(event: types.Message | types.CallbackQuery) -> int:
    if isinstance(event, types.CallbackQuery):
        return event.message.chat.id
    return event.chat.id


async def _safe_edit_text(message: types.Message, text: str, **kwargs: Any) -> bool:
    try:
        await message.edit_text(text, **kwargs)
        return True
    except TelegramBadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return False
        raise


async def _show_home(event: types.Message | types.CallbackQuery, state: FSMContext | None = None) -> None:
    if state is not None:
        await state.clear()
    if isinstance(event, types.CallbackQuery):
        changed = await _safe_edit_text(
            event.message,
            messages.WELCOME_TEXT,
            parse_mode="HTML",
            reply_markup=keyboards.main_menu(),
        )
        if changed:
            await event.answer()
        else:
            await event.answer("Already on the main menu")
        return
    await event.answer(messages.WELCOME_TEXT, parse_mode="HTML", reply_markup=keyboards.main_menu())


async def _render_grants_list(callback: types.CallbackQuery) -> None:
    try:
        items = await grants.list_grants()
    except grants.GrantError as exc:
        await _safe_edit_text(
            callback.message,
            f"❌ Could not read grants.\n<code>{exc}</code>",
            parse_mode="HTML",
            reply_markup=keyboards.back_to_menu(),
        )
        await callback.answer()
        return

    changed = await _safe_edit_text(
        callback.message,
        messages.grants_overview_text(items),
        parse_mode="HTML",
        reply_markup=keyboards.grants_overview(items),
    )
    if changed:
        await callback.answer()
    else:
        await callback.answer("Grants list is already up to date")


async def _finalize_grant(
    event: types.Message | types.CallbackQuery,
    state: FSMContext,
    ttl_minutes: int | None,
) -> None:
    data = await state.get_data()
    draft = _draft_from_state(data)
    await state.clear()

    try:
        result = await grants.grant_access(
            username=draft["username"],
            pubkey=draft["pubkey"],
            password=draft["password"],
            ttl_minutes=ttl_minutes,
            admin_id=event.from_user.id,
        )
    except grants.GrantError as exc:
        await event.bot.send_message(
            _chat_id(event),
            messages.grant_failed_text(str(exc)),
            parse_mode="HTML",
            reply_markup=keyboards.back_to_menu(),
        )
        if isinstance(event, types.CallbackQuery):
            await event.answer("Grant failed", show_alert=True)
        return

    await event.bot.send_message(
        _chat_id(event),
        messages.grant_success_text(
            host=settings.SERVER_IP or "<server-ip-unknown>",
            result=result,
            fallback_username=draft["username"],
        ),
        parse_mode="HTML",
        reply_markup=keyboards.grant_actions(result.get("grant_id", "")),
    )
    if isinstance(event, types.CallbackQuery):
        await event.answer("Grant created")


@router.message(Command("start", "help"))
async def cmd_start(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    await _show_home(message, state)


@router.callback_query(F.data == "menu:back")
async def cb_menu_back(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await _show_home(callback, state)


@router.callback_query(F.data == "server:info")
async def cb_server_info(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    try:
        items = await grants.list_grants()
        active_count = sum(1 for item in items if item.active)
    except grants.GrantError:
        active_count = 0
    changed = await _safe_edit_text(
        callback.message,
        messages.server_info_text(
            host=settings.SERVER_IP,
            active_count=active_count,
            port_range_start=settings.AGENTZONE_PORT_RANGE_START,
            port_range_end=settings.AGENTZONE_PORT_RANGE_END,
        ),
        parse_mode="HTML",
        reply_markup=keyboards.back_to_menu(),
    )
    if changed:
        await callback.answer()
    else:
        await callback.answer("Server info is already current")


@router.callback_query(F.data == "grant:start")
async def cb_grant_start(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await state.set_state(GrantForm.waiting_username)
    changed = await _safe_edit_text(
        callback.message,
        messages.grant_username_prompt(),
        reply_markup=keyboards.cancel_only(),
    )
    if changed:
        await callback.answer()
    else:
        await callback.answer("Grant flow is already open")


@router.callback_query(F.data == "grant:cancel")
async def cb_grant_cancel(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await state.clear()
    changed = await _safe_edit_text(
        callback.message,
        messages.CANCELLED_TEXT,
        reply_markup=keyboards.main_menu(),
    )
    if changed:
        await callback.answer()
    else:
        await callback.answer("Already cancelled")


@router.message(GrantForm.waiting_username)
async def on_username(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    try:
        username = grants.validate_username(message.text or "")
    except grants.GrantError as exc:
        await message.answer(f"❌ {exc}", reply_markup=keyboards.cancel_only())
        return
    await state.update_data(username=username)
    await state.set_state(GrantForm.waiting_pubkey)
    await message.answer(messages.grant_pubkey_prompt(), parse_mode="HTML", reply_markup=keyboards.cancel_only())


@router.message(GrantForm.waiting_pubkey)
async def on_pubkey(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    try:
        key = grants.normalize_public_key(message.text or "")
    except grants.GrantError as exc:
        await message.answer(f"❌ {exc}", reply_markup=keyboards.cancel_only())
        return
    await state.update_data(pubkey=key.text)
    await state.set_state(GrantForm.waiting_password)
    await message.answer(messages.grant_password_prompt(), parse_mode="HTML", reply_markup=keyboards.cancel_only())


@router.message(GrantForm.waiting_password)
async def on_password(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    try:
        password = grants.validate_password(message.text or "")
    except grants.GrantError as exc:
        await message.answer(f"❌ {exc}", reply_markup=keyboards.cancel_only())
        return
    await state.update_data(password=password)
    try:
        await message.delete()
    except Exception:  # noqa: BLE001 - message deletion is best effort
        logger.debug("Could not delete the password message", exc_info=True)
    await message.answer(messages.grant_ttl_prompt(), reply_markup=keyboards.ttl_choices())


@router.callback_query(F.data.startswith("ttl:"), GrantForm.waiting_password)
async def cb_ttl_choice(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    choice = callback.data.split(":", 1)[1]
    if choice == "custom":
        await state.set_state(GrantForm.waiting_ttl_custom)
        changed = await _safe_edit_text(
            callback.message,
            messages.grant_custom_ttl_prompt(settings.AGENTZONE_MAX_TTL_MINUTES),
        )
        if changed:
            await callback.answer()
        else:
            await callback.answer("Send the custom TTL in minutes")
        return

    minutes = int(choice)
    await _safe_edit_text(callback.message, messages.PROCESSING_TEXT)
    await _finalize_grant(callback, state, ttl_minutes=(minutes or None))


@router.message(GrantForm.waiting_ttl_custom)
async def on_ttl_custom(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    raw = (message.text or "").strip()
    if not raw.isdigit() or not (1 <= int(raw) <= settings.AGENTZONE_MAX_TTL_MINUTES):
        await message.answer(messages.invalid_custom_ttl_text(settings.AGENTZONE_MAX_TTL_MINUTES))
        return
    await message.answer(messages.PROCESSING_TEXT)
    await _finalize_grant(message, state, ttl_minutes=int(raw))


@router.callback_query(F.data == "grants:list")
async def cb_grants_list(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await _render_grants_list(callback)


@router.callback_query(F.data == "grants:refresh")
async def cb_grants_refresh(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await _render_grants_list(callback)


@router.callback_query(F.data.startswith("revoke:") & ~F.data.in_({"revoke:all", "revoke:all:confirm"}))
async def cb_revoke_one(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    grant_id = callback.data.split(":", 1)[1]
    try:
        await grants.revoke_access(grant_id=grant_id, reason="manual")
    except grants.GrantError as exc:
        await callback.answer(f"Failed: {exc}", show_alert=True)
        return
    await _safe_edit_text(
        callback.message,
        messages.ONE_REVOKED_TEXT,
        reply_markup=keyboards.back_to_menu(),
    )
    await callback.answer("Grant revoked")


@router.callback_query(F.data == "revoke:all")
async def cb_revoke_all_prompt(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    changed = await _safe_edit_text(
        callback.message,
        messages.revoke_all_warning_text(),
        reply_markup=keyboards.revoke_all_confirm(),
    )
    if changed:
        await callback.answer()
    else:
        await callback.answer("Confirmation is already shown")


@router.callback_query(F.data == "revoke:all:confirm")
async def cb_revoke_all_confirm(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    try:
        await grants.revoke_access(all_grants=True, reason="manual")
    except grants.GrantError as exc:
        await callback.answer(f"Failed: {exc}", show_alert=True)
        return
    await _safe_edit_text(
        callback.message,
        messages.ALL_REVOKED_TEXT,
        reply_markup=keyboards.main_menu(),
    )
    await callback.answer("All grants revoked")
