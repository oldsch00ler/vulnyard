# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""API tokens for other systems calling the API (SPEC section 13).

These endpoints are for people only: a request authenticated with a token is
refused before it gets here (see `app.auth`).
"""

from __future__ import annotations

import logging
from datetime import date

from fastapi import APIRouter, Response, status
from sqlalchemy import select

from app.constants import API_TOKEN_SCOPES
from app.dependencies import AuditIdentityDep, SessionDep
from app.errors import AppError
from app.models import ApiToken
from app.schemas import ApiTokenCreate, ApiTokenCreated, ApiTokenList, ApiTokenRead
from app.services import api_tokens as service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tokens", tags=["tokens"])

MAX_NAME = 128


@router.get("", response_model=ApiTokenList)
async def list_tokens(session: SessionDep) -> ApiTokenList:
    rows = list(
        (await session.execute(select(ApiToken).order_by(ApiToken.name, ApiToken.id))).scalars()
    )
    return ApiTokenList(items=[_read(row) for row in rows], total=len(rows))


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: ApiTokenCreate, session: SessionDep, identity: AuditIdentityDep
) -> ApiTokenCreated:
    name = _name(payload.name)
    scope = _scope(payload.scope)
    expires_on = _expires_on(payload.expires_on)

    row, token = await service.create(
        session, name=name, scope=scope, expires_on=expires_on, created_by=identity
    )
    logger.info("API token %r (%s) created by %s", row.name, row.scope, identity or "-")
    return ApiTokenCreated(**_read(row).model_dump(), token=token)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(
    token_id: int, session: SessionDep, identity: AuditIdentityDep
) -> Response:
    row = await session.get(ApiToken, token_id)
    if row is None:
        raise AppError("api_token.not_found", status_code=404, id=token_id)
    await session.delete(row)
    await session.commit()
    logger.info("API token %r deleted by %s", row.name, identity or "-")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _read(row: ApiToken) -> ApiTokenRead:
    return ApiTokenRead(
        id=row.id,
        name=row.name,
        token_prefix=row.token_prefix,
        scope=row.scope,
        expires_on=row.expires_on,
        active=service.is_active(row),
        last_used_at=row.last_used_at,
        created_at=row.created_at,
        created_by=row.created_by,
    )


def _name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise AppError("validation.token_name_required", status_code=422)
    if len(cleaned) > MAX_NAME:
        raise AppError("validation.token_name_too_long", status_code=422, limit=MAX_NAME)
    return cleaned


def _scope(value: str) -> str:
    cleaned = (value or "").strip().lower()
    if cleaned not in API_TOKEN_SCOPES:
        raise AppError(
            "validation.token_scope_invalid",
            status_code=422,
            allowed=", ".join(API_TOKEN_SCOPES),
        )
    return cleaned


def _expires_on(value: date | None) -> date | None:
    """A date already gone would mint a token that never works - a typo, not a wish."""
    if value is not None and value < date.today():
        raise AppError("validation.token_expires_on_in_past", status_code=422)
    return value
