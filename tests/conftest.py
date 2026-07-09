"""Pytest configuration: make app/ importable and stub environment vars
needed by pydantic-settings, without requiring a real .env file."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent.parent / "app"
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

os.environ.setdefault("BOT_TOKEN", "0:test_token_stub")
os.environ.setdefault("ADMIN_ID", "123456789")
