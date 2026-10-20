# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""API tokens: issuing them and checking the ones callers present.

A token is `vy_` followed by 32 random bytes (urlsafe base64). That is far too
much entropy to guess, so a plain SHA-256 is enough to store it - unlike a
password, it needs no slow, salted hash. The token itself is never stored,
logged or returned after creation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import API_TOKEN_PREFIX, API_TOKEN_SCOPE_WRITE
from app.models import ApiToken

#: Characters of the token kept for display, `vy_` included.
DISPLAY_PREFIX_LENGTH = 8

#: `last_used_at` is refreshed at most this often, so a busy integration does
#: not turn every read into a write.
LAST_USED_RESOLUTION = timedelta(minutes=1)


@dataclass(frozen=True)
class TokenPrincipal:
    """The caller behind a valid token, as the rest of the request sees it."""

    id: int
    name: str
    scope: str

    @property
    def can_write(self) -> bool:
        return self.scope == API_TOKEN_SCOPE_WRITE


def generate() -> str:
    return f"{API_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def looks_like_ours(value: str) -> bool:
    """Only tokens with our prefix are ours; anything else is someone else's."""
    return value.startswith(API_TOKEN_PREFIX)


def is_active(token: ApiToken, *, today: date | None = None) -> bool:
    """A token without an end date holds forever; otherwise up to and including it."""
    if token.expires_on is None:
        return True
    return token.expires_on >= (today or date.today())


async def create(
    session: AsyncSession,
    *,
    name: str,
    scope: str,
    expires_on: date | None,
    created_by: str | None,
) -> tuple[ApiToken, str]:
    """Store a new token; returns the row and the token, shown only this once."""
    token = generate()
    row = ApiToken(
        name=name,
        token_hash=hash_token(token),
        token_prefix=token[:DISPLAY_PREFIX_LENGTH],
        scope=scope,
        expires_on=expires_on,
        created_by=created_by,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row, token


async def authenticate(session: AsyncSession, token: str) -> TokenPrincipal | None:
    """The caller of a valid, unexpired token, or None."""
    digest = hash_token(token)
    row = (
        await session.execute(select(ApiToken).where(ApiToken.token_hash == digest))
    ).scalar_one_or_none()
    # The lookup is by hash, so it leaks nothing about the token; the compare
    # just keeps the check constant-time should the lookup ever change.
    if row is None or not hmac.compare_digest(row.token_hash, digest):
        return None
    if not is_active(row):
        return None

    now = datetime.now(UTC)
    if row.last_used_at is None or now - row.last_used_at >= LAST_USED_RESOLUTION:
        row.last_used_at = now
        await session.commit()

    return TokenPrincipal(id=row.id, name=row.name, scope=row.scope)
