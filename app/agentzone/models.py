"""Small domain objects shared across the bot modules."""
from __future__ import annotations

from dataclasses import dataclass


class GrantError(ValueError):
    """Raised for invalid input or a failed helper call."""


@dataclass(frozen=True)
class NormalizedPublicKey:
    text: str
    fingerprint: str
    comment: str


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
