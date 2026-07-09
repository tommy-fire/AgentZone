"""Admin-only Telegram flow: grant / list / revoke SSH access.

The bot has exactly one admin (settings.ADMIN_ID) and exactly one job. Every
handler re-checks the sender's ID even though aiogram filters already do —
defense in depth against a filter being accidentally removed later.
"""
from __future__ import annotations

import logging

from aiogram import F, Router, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from bot import keyboards as kb
from bot.config import settings
from bot.services import grants

router = Router()
logger = logging.getLogger(__name__)


def _is_admin(user_id: int) -> bool:
    return int(user_id) == int(settings.ADMIN_ID)


class GrantForm(StatesGroup):
    waiting_username = State()
    waiting_pubkey = State()
    waiting_password = State()
    waiting_ttl_custom = State()


def _pending_grant(state_data: dict) -> dict:
    return {
        "username": state_data.get("username"),
        "pubkey": state_data.get("pubkey"),
        "password": state_data.get("password"),
    }


async def _finalize_grant(message_or_callback, state: FSMContext, ttl_minutes: int | None) -> None:
    data = await state.get_data()
    pending = _pending_grant(data)
    await state.clear()

    admin_id = message_or_callback.from_user.id
    bot = message_or_callback.bot
    chat_id = message_or_callback.message.chat.id if isinstance(message_or_callback, types.CallbackQuery) else message_or_callback.chat.id

    try:
        result = await grants.grant_access(
            username=pending["username"],
            pubkey=pending["pubkey"],
            password=pending["password"],
            ttl_minutes=ttl_minutes,
            admin_id=admin_id,
        )
    except grants.GrantError as exc:
        await bot.send_message(chat_id, f"❌ Failed to grant access:\n<code>{exc}</code>", parse_mode="HTML")
        return

    host = settings.SERVER_IP or "<server-ip-unknown>"
    port = result.get("port", "?")
    username = result.get("username", pending["username"])
    expires = grants.format_iso(result.get("expires_at", "never"))

    text = (
        "✅ <b>Access granted</b>\n\n"
        f"User: <code>{username}</code>\n"
        f"Port: <code>{port}</code> (unique to this grant)\n"
        f"Expires: <code>{expires}</code>\n\n"
        "Connect with:\n"
        f"<code>ssh -p {port} {username}@{host}</code>\n\n"
        "Authentication is by SSH key only. The password you set is used "
        "only locally for <code>sudo</code> on the server, never over the network.\n\n"
        "⚠️ This message contains the server's IP address — it is sent "
        "only to you and never logged or displayed anywhere else."
    )
    await bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb.grant_actions(result.get("grant_id", "")))


@router.message(Command("start"))
async def cmd_start(message: types.Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    await message.answer(
        "🤖 <b>AgentZone</b>\n\n"
        "Grant or revoke temporary SSH access for an AI agent on this server.",
        parse_mode="HTML",
        reply_markup=kb.main_menu(),
    )


@router.callback_query(F.data == "menu:back")
async def cb_menu_back(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await state.clear()
    await callback.message.edit_text(
        "🤖 <b>AgentZone</b>\n\nGrant or revoke temporary SSH access for an AI agent on this server.",
        parse_mode="HTML",
        reply_markup=kb.main_menu(),
    )
    await callback.answer()


@router.callback_query(F.data == "server:info")
async def cb_server_info(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    host = settings.SERVER_IP or "unknown"
    try:
        active = [g for g in await grants.list_grants() if g.active]
    except grants.GrantError:
        active = []
    text = (
        "🌐 <b>Server info</b>\n\n"
        f"IP: <code>{host}</code>\n"
        f"Active grants: <code>{len(active)}</code>\n\n"
        "This IP is shown only to you, in this private chat."
    )
    await callback.message.edit_text(text, parse_mode="HTML", reply_markup=kb.back_to_menu())
    await callback.answer()


# ---------------------------------------------------------------------------
# Grant flow
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "grant:start")
async def cb_grant_start(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await state.set_state(GrantForm.waiting_username)
    await callback.message.edit_text(
        "Step 1/4 — Send a username for the new account (letters, digits, '-', '_').",
        reply_markup=kb.cancel_only(),
    )
    await callback.answer()


@router.callback_query(F.data == "grant:cancel")
async def cb_grant_cancel(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await state.clear()
    await callback.message.edit_text("Cancelled.", reply_markup=kb.main_menu())
    await callback.answer()


@router.message(GrantForm.waiting_username)
async def on_username(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    try:
        username = grants.validate_username(message.text or "")
    except grants.GrantError as exc:
        await message.answer(f"❌ {exc}\nTry again.", reply_markup=kb.cancel_only())
        return
    await state.update_data(username=username)
    await state.set_state(GrantForm.waiting_pubkey)
    await message.answer(
        "Step 2/4 — Send the agent's SSH <b>public</b> key "
        "(e.g. <code>ssh-ed25519 AAAA... comment</code>).",
        parse_mode="HTML",
        reply_markup=kb.cancel_only(),
    )


@router.message(GrantForm.waiting_pubkey)
async def on_pubkey(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    try:
        key = grants.normalize_public_key(message.text or "")
    except grants.GrantError as exc:
        await message.answer(f"❌ {exc}\nTry again.", reply_markup=kb.cancel_only())
        return
    await state.update_data(pubkey=key.text)
    await state.set_state(GrantForm.waiting_password)
    await message.answer(
        "Step 3/4 — Send a password for this account (min 8 characters).\n\n"
        "⚠️ This password is <b>not</b> used to log in over SSH (key-only). "
        "It is used only locally on the server, for <code>sudo</code>.\n\n"
        "Delete your message right after sending it, if you like — the bot "
        "already has what it needs.",
        parse_mode="HTML",
        reply_markup=kb.cancel_only(),
    )


@router.message(GrantForm.waiting_password)
async def on_password(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    try:
        password = grants.validate_password(message.text or "")
    except grants.GrantError as exc:
        await message.answer(f"❌ {exc}\nTry again.", reply_markup=kb.cancel_only())
        return
    await state.update_data(password=password)
    # Best-effort: encourage removing the plaintext password from chat
    # history. Telegram may reject deletion (e.g. if too old); ignore.
    try:
        await message.delete()
    except Exception:
        pass
    await message.answer(
        "Step 4/4 — How long should this access last?",
        reply_markup=kb.ttl_choices(),
    )


@router.callback_query(F.data.startswith("ttl:"), GrantForm.waiting_password)
async def cb_ttl_choice(callback: types.CallbackQuery, state: FSMContext) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    choice = callback.data.split(":", 1)[1]
    if choice == "custom":
        await state.set_state(GrantForm.waiting_ttl_custom)
        await callback.message.edit_text(
            f"Send the TTL in minutes (1-{settings.AGENTZONE_MAX_TTL_MINUTES}).",
        )
        await callback.answer()
        return
    minutes = int(choice)
    await callback.message.edit_text("⏳ Granting access…")
    await _finalize_grant(callback, state, ttl_minutes=(minutes or None))
    await callback.answer()


@router.message(GrantForm.waiting_ttl_custom)
async def on_ttl_custom(message: types.Message, state: FSMContext) -> None:
    if not _is_admin(message.from_user.id):
        return
    raw = (message.text or "").strip()
    if not raw.isdigit() or not (1 <= int(raw) <= settings.AGENTZONE_MAX_TTL_MINUTES):
        await message.answer(
            f"❌ Enter a whole number of minutes between 1 and {settings.AGENTZONE_MAX_TTL_MINUTES}."
        )
        return
    await message.answer("⏳ Granting access…")
    await _finalize_grant(message, state, ttl_minutes=int(raw))


# ---------------------------------------------------------------------------
# List / revoke
# ---------------------------------------------------------------------------

@router.callback_query(F.data == "grants:list")
async def cb_grants_list(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    try:
        all_grants = await grants.list_grants()
    except grants.GrantError as exc:
        await callback.message.edit_text(f"❌ Could not read grants:\n<code>{exc}</code>", parse_mode="HTML", reply_markup=kb.back_to_menu())
        await callback.answer()
        return

    if not all_grants:
        await callback.message.edit_text("No grants (active or expired) on record.", reply_markup=kb.back_to_menu())
        await callback.answer()
        return

    lines = ["📋 <b>Grants</b>\n"]
    keyboard_rows = []
    for g in all_grants:
        status = "🟢 active" if g.active else "🔴 expired"
        remaining = grants.format_remaining(g.ttl_remaining_sec) if g.active else "—"
        lines.append(
            f"\n<b>{g.username}</b> (port {g.port}) — {status}\n"
            f"Expires: {grants.format_iso(g.expires_at)} (remaining: {remaining})\n"
            f"Key: <code>{g.fingerprint}</code>"
        )
        if g.active:
            keyboard_rows.append(
                [types.InlineKeyboardButton(text=f"🛑 Revoke {g.username}", callback_data=f"revoke:{g.grant_id}")]
            )
    keyboard_rows.append([types.InlineKeyboardButton(text="⚠️ Revoke ALL", callback_data="revoke:all")])
    keyboard_rows.append([types.InlineKeyboardButton(text="⬅ Back", callback_data="menu:back")])
    await callback.message.edit_text(
        "\n".join(lines),
        parse_mode="HTML",
        reply_markup=types.InlineKeyboardMarkup(inline_keyboard=keyboard_rows),
    )
    await callback.answer()


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
    await callback.message.edit_text("✅ Grant revoked. All traces of that session were cleaned up.", reply_markup=kb.back_to_menu())
    await callback.answer()


@router.callback_query(F.data == "revoke:all")
async def cb_revoke_all_prompt(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    await callback.message.edit_text(
        "⚠️ This will revoke every active grant and delete every agent "
        "account this bot created. Continue?",
        reply_markup=kb.revoke_all_confirm(),
    )
    await callback.answer()


@router.callback_query(F.data == "revoke:all:confirm")
async def cb_revoke_all_confirm(callback: types.CallbackQuery) -> None:
    if not _is_admin(callback.from_user.id):
        return await callback.answer()
    try:
        await grants.revoke_access(all_grants=True, reason="manual")
    except grants.GrantError as exc:
        await callback.answer(f"Failed: {exc}", show_alert=True)
        return
    await callback.message.edit_text("✅ All grants revoked and cleaned up.", reply_markup=kb.main_menu())
    await callback.answer()
