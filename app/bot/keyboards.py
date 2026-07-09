"""Inline keyboards for the admin flow."""
from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def main_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="➕ Grant access", callback_data="grant:start")],
            [InlineKeyboardButton(text="📋 Active grants", callback_data="grants:list")],
            [InlineKeyboardButton(text="🌐 Server info", callback_data="server:info")],
        ]
    )


def cancel_only() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="✖ Cancel", callback_data="grant:cancel")]]
    )


def ttl_choices() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="30 min", callback_data="ttl:30"),
                InlineKeyboardButton(text="1 hour", callback_data="ttl:60"),
                InlineKeyboardButton(text="4 hours", callback_data="ttl:240"),
            ],
            [
                InlineKeyboardButton(text="1 day", callback_data="ttl:1440"),
                InlineKeyboardButton(text="7 days", callback_data="ttl:10080"),
            ],
            [InlineKeyboardButton(text="♾ Until I revoke it", callback_data="ttl:0")],
            [InlineKeyboardButton(text="✏️ Custom (minutes)", callback_data="ttl:custom")],
            [InlineKeyboardButton(text="✖ Cancel", callback_data="grant:cancel")],
        ]
    )


def grant_actions(grant_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🛑 Revoke this grant", callback_data=f"revoke:{grant_id}")],
        ]
    )


def back_to_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="⬅ Back", callback_data="menu:back")]]
    )


def revoke_all_confirm() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="⚠️ Yes, revoke ALL grants", callback_data="revoke:all:confirm")],
            [InlineKeyboardButton(text="✖ Cancel", callback_data="menu:back")],
        ]
    )
