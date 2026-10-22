# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Identity of the caller (SPEC section 13).

The only place in the application that decides who the user is. Nothing else
may read an identity from a request, and the identity never comes from the body
or from the frontend. It comes from one of two places:

- an API token (`Authorization: Bearer vy_...`) issued in the app, for other
  systems calling the API; it works in every AUTH_MODE,
- the headers an authenticating reverse proxy sets, when AUTH_MODE says so.
"""

from __future__ import annotations

import logging

from fastapi import Request

from app.config import Settings
from app.db import session_factory
from app.errors import AppError
from app.services import api_tokens
from app.services.api_tokens import TokenPrincipal

logger = logging.getLogger(__name__)

AUTH_MODE_NONE = "none"
AUTH_MODE_PROXY_HEADER = "proxy-header"

#: Tokens are managed by people, never by another token: a leaked token must
#: not be able to mint itself a successor or delete the others.
TOKEN_MANAGEMENT_PATH = "/api/tokens"

#: Methods a read-only token may use.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: The MCP endpoint (app.mcp_server). MCP sends every call as a POST, yet it
#: only reads, so a read-only token may use it.
MCP_PATH = "/mcp"

#: Prefix of the identity recorded for audit when a token made the change.
TOKEN_IDENTITY_PREFIX = "token:"


class UnauthenticatedError(AppError):
    status_code = 401


class TokenRejectedError(UnauthenticatedError):
    """A token was presented and it is not valid (unknown, deleted, expired)."""


class ForbiddenError(AppError):
    status_code = 403


def bearer_token(request: Request) -> str | None:
    """Our API token from the Authorization header, if the caller sent one.

    A bearer token without our prefix is ignored rather than rejected: an
    identity proxy may pass its own token upstream, and that must keep working
    exactly as before tokens existed.
    """
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.strip().partition(" ")
    value = value.strip()
    if scheme.lower() != "bearer" or not api_tokens.looks_like_ours(value):
        return None
    return value


def token_principal(request: Request) -> TokenPrincipal | None:
    """The token the request was authenticated with, if any."""
    return getattr(getattr(request, "state", None), "api_token", None)


async def authenticate_request(request: Request, settings: Settings) -> None:
    """Gate in front of /api/* and /mcp: raises when the request may not go on.

    With a token, the token decides - also in proxy-header mode, where a
    machine caller has no proxy identity. Without one, nothing changes against
    the behaviour before tokens: proxy-header mode requires the header and
    `none` lets the request through.
    """
    mcp = is_mcp_path(request.url.path)
    token = bearer_token(request)
    if token is not None:
        async with session_factory()() as session:
            principal = await api_tokens.authenticate(session, token)
        if principal is None:
            logger.warning("Rejected an unknown or expired API token on %s %s", request.method, request.url.path)
            raise TokenRejectedError("auth.token_invalid")
        if request.url.path == TOKEN_MANAGEMENT_PATH or request.url.path.startswith(f"{TOKEN_MANAGEMENT_PATH}/"):
            raise ForbiddenError("auth.token_management_forbidden")
        if request.method not in SAFE_METHODS and not principal.can_write and not mcp:
            raise ForbiddenError("auth.token_read_only", name=principal.name)
        request.state.api_token = principal
        return

    if mcp:
        # Agents call it, not people behind the proxy; the token is also the
        # only audit trail of what an agent asked.
        raise UnauthenticatedError("auth.token_required")

    if settings.auth_mode == AUTH_MODE_PROXY_HEADER:
        identity_from_request(request, settings)


def is_mcp_path(path: str) -> bool:
    return path == MCP_PATH or path.startswith(f"{MCP_PATH}/")


def identity_from_request(request: Request, settings: Settings) -> str | None:
    """Who is calling, or None when the app runs without identity.

    A request authenticated with a token is that token (`token:<name>`). In
    `proxy-header` mode a missing header is an error: the app must not be
    reachable without the proxy, so the absence means it was bypassed.
    """
    principal = token_principal(request)
    if principal is not None:
        return f"{TOKEN_IDENTITY_PREFIX}{principal.name}"

    if settings.auth_mode != AUTH_MODE_PROXY_HEADER:
        return None

    for header in settings.auth_header_names:
        value = request.headers.get(header)
        if value and value.strip():
            return value.strip()

    raise UnauthenticatedError(
        "auth.header_missing", headers=", ".join(settings.auth_header_names)
    )


def optional_identity(request: Request, settings: Settings) -> str | None:
    """Identity for audit fields; never fails the request."""
    try:
        return identity_from_request(request, settings)
    except UnauthenticatedError:
        return None
