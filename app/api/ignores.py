# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Ignore rules: vulnerabilities we decided not to act on.

Creating, changing or deleting a rule pushes the change straight to
Dependency-Track, so that its metrics - which the dashboard, the trend and the
chat notifications all read - agree with what the UI shows.
"""

from __future__ import annotations

import logging
from datetime import date

from fastapi import APIRouter, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import ANALYSIS_STATES, ANY_COMPONENT
from app.dependencies import AuditIdentityDep, RequiredDTrackDep, SessionDep
from app.errors import AppError
from app.models import IgnoreApplication, IgnoreRule, ScanTarget
from app.schemas import (
    IgnoreApplyResult,
    IgnoreRuleCreate,
    IgnoreRuleList,
    IgnoreRuleRead,
    IgnoreRuleUpdate,
)
from app.services import ignores as service
from app.services import vulnerabilities as vulnerability_service
from app.services.dashboard import invalidate_cache
from app.services.dtrack import DependencyTrackClient
from app.services.snapshots import take_snapshot

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ignores", tags=["ignores"])

#: A vulnerability id is short; the pattern can be a whole purl with qualifiers.
MAX_VULN_ID = 128
MAX_PATTERN = 512


@router.get("", response_model=IgnoreRuleList)
async def list_rules(
    session: SessionDep,
    target_id: int | None = Query(default=None),
    only_global: bool = Query(default=False),
) -> IgnoreRuleList:
    query = select(IgnoreRule).order_by(IgnoreRule.vuln_id, IgnoreRule.id)
    if only_global:
        query = query.where(IgnoreRule.target_id.is_(None))
    elif target_id is not None:
        query = query.where(IgnoreRule.target_id == target_id)
    rules = list((await session.execute(query)).scalars())
    return IgnoreRuleList(
        items=[await _read(session, rule) for rule in rules], total=len(rules)
    )


@router.post("", response_model=IgnoreRuleRead, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: IgnoreRuleCreate,
    session: SessionDep,
    dtrack: RequiredDTrackDep,
    identity: AuditIdentityDep,
) -> IgnoreRuleRead:
    vuln_id = _vuln_id(payload.vuln_id)
    pattern = _pattern(payload.purl_pattern)
    state = _state(payload.analysis_state)
    await _target_exists(session, payload.target_id)
    await _not_duplicate(session, vuln_id, pattern, payload.target_id)

    rule = IgnoreRule(
        vuln_id=vuln_id,
        purl_pattern=pattern,
        target_id=payload.target_id,
        analysis_state=state,
        reason=payload.reason.strip(),
        expires_on=_expires_on(payload.expires_on),
        created_by=identity,
    )
    session.add(rule)
    await session.commit()
    await session.refresh(rule)

    # Apply at once: a rule that only takes effect after the next scan would look
    # broken to whoever just created it.
    await service.apply_rules(session, dtrack)
    await _settled(session, dtrack)
    return await _read(session, rule)


@router.patch("/{rule_id}", response_model=IgnoreRuleRead)
async def update_rule(
    rule_id: int,
    payload: IgnoreRuleUpdate,
    session: SessionDep,
    dtrack: RequiredDTrackDep,
) -> IgnoreRuleRead:
    rule = await _rule(session, rule_id)

    if payload.purl_pattern is not None:
        rule.purl_pattern = _pattern(payload.purl_pattern)
    if payload.analysis_state is not None:
        rule.analysis_state = _state(payload.analysis_state)
    if payload.reason is not None:
        rule.reason = payload.reason.strip()
    if payload.clear_expiry:
        rule.expires_on = None
    elif payload.expires_on is not None:
        rule.expires_on = _expires_on(payload.expires_on)

    await session.commit()
    # A narrowed pattern or a past date has to take suppressions back, which
    # apply_rules does in the same pass.
    await service.apply_rules(session, dtrack)
    await service.revert_expired(session, dtrack)
    await _settled(session, dtrack)
    return await _read(session, rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int, session: SessionDep, dtrack: RequiredDTrackDep
) -> Response:
    rule = await _rule(session, rule_id)
    # Take the suppressions back first: once the rule is gone we no longer know
    # where they were applied.
    await service.revert_rule(session, dtrack, rule)
    await session.delete(rule)
    await session.commit()
    await _settled(session, dtrack)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/apply", response_model=IgnoreApplyResult)
async def apply_now(session: SessionDep, dtrack: RequiredDTrackDep) -> IgnoreApplyResult:
    """Re-apply every rule; also used after a Dependency-Track outage."""
    outcome = await service.apply_rules(session, dtrack)
    expired = await service.revert_expired(session, dtrack)
    await _settled(session, dtrack)
    return IgnoreApplyResult(
        suppressed=outcome.suppressed,
        reverted=outcome.reverted + expired.reverted,
        failed=outcome.failed + expired.failed,
        projects=outcome.projects,
        errors=sorted({*outcome.errors, *expired.errors}),
    )


# --- helpers ------------------------------------------------------------------


async def _settled(session: AsyncSession, dtrack: DependencyTrackClient) -> None:
    """Everything a changed rule makes stale: caches and today's trend point.

    The trend reads `metric_snapshots`, written once every morning, so without
    re-taking today's row the graph would keep showing a finding that has just
    been ignored. Earlier days are history and are left alone.
    """
    invalidate_cache()
    vulnerability_service.invalidate_cache()
    try:
        await take_snapshot(session, dtrack)
    except AppError as error:
        logger.warning("Could not refresh today's metric snapshot: %s", error.code)


async def _rule(session: AsyncSession, rule_id: int) -> IgnoreRule:
    rule = await session.get(IgnoreRule, rule_id)
    if rule is None:
        raise AppError("ignore.not_found", status_code=404, id=rule_id)
    return rule


async def _read(session: AsyncSession, rule: IgnoreRule) -> IgnoreRuleRead:
    target_name: str | None = None
    if rule.target_id is not None:
        target = await session.get(ScanTarget, rule.target_id)
        target_name = target.name if target else None
    applied = await session.scalar(
        select(func.count())
        .select_from(IgnoreApplication)
        .where(IgnoreApplication.rule_id == rule.id)
    )
    return IgnoreRuleRead(
        id=rule.id,
        vuln_id=rule.vuln_id,
        purl_pattern=rule.purl_pattern,
        target_id=rule.target_id,
        target_name=target_name,
        analysis_state=rule.analysis_state,
        reason=rule.reason,
        expires_on=rule.expires_on,
        active=service.is_active(rule),
        applied_count=int(applied or 0),
        created_at=rule.created_at,
        created_by=rule.created_by,
    )


def _vuln_id(value: str) -> str:
    cleaned = value.strip().upper()
    if not cleaned:
        raise AppError("validation.vuln_id_required", status_code=422)
    if len(cleaned) > MAX_VULN_ID:
        raise AppError("validation.vuln_id_too_long", status_code=422, limit=MAX_VULN_ID)
    return cleaned


def _pattern(value: str) -> str:
    cleaned = (value or "").strip() or ANY_COMPONENT
    if len(cleaned) > MAX_PATTERN:
        raise AppError("validation.purl_pattern_too_long", status_code=422, limit=MAX_PATTERN)
    return cleaned


def _expires_on(value: date | None) -> date | None:
    """A date already gone would store a rule that never holds - a typo, not a wish."""
    if value is not None and value < date.today():
        raise AppError("validation.expires_on_in_past", status_code=422)
    return value


def _state(value: str) -> str:
    upper = (value or "").strip().upper()
    if upper not in ANALYSIS_STATES:
        raise AppError(
            "validation.analysis_state_invalid",
            status_code=422,
            allowed=", ".join(ANALYSIS_STATES),
        )
    return upper


async def _target_exists(session: AsyncSession, target_id: int | None) -> None:
    if target_id is None:
        return
    if await session.get(ScanTarget, target_id) is None:
        raise AppError("target.not_found", status_code=404, id=target_id)


async def _not_duplicate(
    session: AsyncSession, vuln_id: str, pattern: str, target_id: int | None
) -> None:
    query = select(IgnoreRule).where(
        IgnoreRule.vuln_id == vuln_id, IgnoreRule.purl_pattern == pattern
    )
    query = (
        query.where(IgnoreRule.target_id.is_(None))
        if target_id is None
        else query.where(IgnoreRule.target_id == target_id)
    )
    if (await session.execute(query.limit(1))).scalar_one_or_none() is not None:
        raise AppError("ignore.duplicate", status_code=409)
