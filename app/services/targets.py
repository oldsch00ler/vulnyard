# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scan target validation and persistence."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import (
    BRANCH_MODE_CUSTOM,
    BRANCH_MODES,
    TARGET_KIND_GROUP,
    TARGET_KIND_PROJECT,
    TARGET_KINDS,
)
from app.errors import ConflictError, NotFoundError, ValidationError
from app.models import ScanTarget
from app.schemas import TargetCreate, TargetSelection, TargetUpdate
from app.services.discovery import TargetSpec
from app.services.sources import SourceCredentials
from app.services.sources.base import RepositorySource
from app.validation import (
    is_valid_branch_pattern,
    is_valid_cron,
    is_valid_path_pattern,
    is_valid_source_url,
    is_valid_webhook_url,
)

MAX_BRANCHES_LIMIT = 100
MAX_PATTERNS = 50


def validate_selection(selection: TargetSelection) -> None:
    """Validate what the user chose; errors are codes with parameters."""
    if selection.kind not in TARGET_KINDS:
        raise ValidationError("validation.kind_invalid", kind=selection.kind)
    if not selection.source_ref.strip():
        raise ValidationError("validation.source_ref_required")
    if selection.branch_mode not in BRANCH_MODES:
        raise ValidationError("validation.branch_mode_invalid", mode=selection.branch_mode)

    if not 1 <= selection.max_branches_per_project <= MAX_BRANCHES_LIMIT:
        raise ValidationError(
            "validation.max_branches_out_of_range", min=1, max=MAX_BRANCHES_LIMIT
        )

    for collection, name in ((selection.branch_patterns, "branch"), (selection.exclude_patterns, "exclude")):
        if len(collection) > MAX_PATTERNS:
            raise ValidationError("validation.too_many_patterns", max=MAX_PATTERNS)

    for pattern in selection.branch_patterns:
        if not is_valid_branch_pattern(pattern):
            raise ValidationError("validation.branch_pattern_invalid", pattern=pattern)

    for pattern in selection.exclude_patterns:
        if not is_valid_path_pattern(pattern):
            raise ValidationError("validation.path_pattern_invalid", pattern=pattern)

    if selection.branch_mode == BRANCH_MODE_CUSTOM:
        if not selection.branch_patterns and not selection.include_default_branch:
            raise ValidationError("validation.branch_selection_empty")


def validate_source_url(url: str | None) -> str | None:
    """Normalise the instance URL; empty means "use the one from the environment"."""
    if url is None:
        return None
    stripped = url.strip().rstrip("/")
    if not stripped:
        return None
    if not is_valid_source_url(stripped):
        raise ValidationError("validation.source_url_invalid")
    return stripped


def validate_source_token(token: str | None) -> str | None:
    if token is None:
        return None
    stripped = token.strip()
    return stripped or None


def credentials_from_payload(payload: TargetSelection) -> SourceCredentials | None:
    """Credentials a request carries, if it carries any.

    A token alone means "same instance, own token"; a URL alone is refused,
    because a foreign instance will not accept the environment's token.
    """
    url = validate_source_url(getattr(payload, "source_url", None))
    token = validate_source_token(getattr(payload, "source_token", None))
    if url and not token:
        raise ValidationError("validation.source_token_required")
    if not token:
        return None
    return SourceCredentials(url=url or "", token=token)


def validate_webhook(url: str | None) -> str | None:
    """Normalise a webhook URL; empty means "fall back to the global one"."""
    if url is None:
        return None
    stripped = url.strip()
    if not stripped:
        return None
    if not is_valid_webhook_url(stripped):
        raise ValidationError("validation.webhook_invalid")
    return stripped


def validate_cron(expression: str | None) -> None:
    if expression is None or not expression.strip():
        return
    if not is_valid_cron(expression):
        raise ValidationError("validation.cron_invalid", expression=expression)


def spec_from_selection(selection: TargetSelection) -> TargetSpec:
    return TargetSpec(
        kind=selection.kind,
        source_ref=selection.source_ref,
        include_subgroups=selection.include_subgroups,
        branch_mode=selection.branch_mode,
        branch_patterns=tuple(selection.branch_patterns),
        include_default_branch=selection.include_default_branch,
        max_branches_per_project=selection.max_branches_per_project,
        exclude_patterns=tuple(selection.exclude_patterns),
    )


def spec_from_target(target: ScanTarget) -> TargetSpec:
    return TargetSpec(
        kind=target.kind,
        source_ref=target.source_ref,
        include_subgroups=target.include_subgroups,
        branch_mode=target.branch_mode,
        branch_patterns=tuple(target.branch_patterns or ()),
        include_default_branch=target.include_default_branch,
        max_branches_per_project=target.max_branches_per_project,
        exclude_patterns=tuple(target.exclude_patterns or ()),
    )


async def resolve_source_metadata(
    source: RepositorySource, kind: str, source_ref: str
) -> tuple[str, str]:
    """Return (name, path) of the group/project from the source."""
    if kind == TARGET_KIND_GROUP:
        group = await source.get_group(source_ref)
        return group.name or group.path, group.path
    if kind == TARGET_KIND_PROJECT:
        project = await source.get_project(source_ref)
        return project.name or project.path_with_namespace, project.path_with_namespace
    raise ValidationError("validation.kind_invalid", kind=kind)


async def list_targets(session: AsyncSession, *, enabled: bool | None = None) -> tuple[list[ScanTarget], int]:
    query = select(ScanTarget).order_by(ScanTarget.name)
    count_query = select(func.count()).select_from(ScanTarget)
    if enabled is not None:
        query = query.where(ScanTarget.enabled.is_(enabled))
        count_query = count_query.where(ScanTarget.enabled.is_(enabled))
    items = list((await session.execute(query)).scalars())
    total = (await session.execute(count_query)).scalar_one()
    return items, total


async def get_target(session: AsyncSession, target_id: int) -> ScanTarget:
    target = await session.get(ScanTarget, target_id)
    if target is None:
        raise NotFoundError("target.not_found", id=target_id)
    return target


async def create_target(
    session: AsyncSession,
    payload: TargetCreate,
    *,
    name: str,
    source_path: str,
    updated_by: str | None = None,
) -> ScanTarget:
    target = ScanTarget(
        name=name,
        source=payload.source,
        kind=payload.kind,
        source_ref=str(payload.source_ref),
        source_path=source_path,
        include_subgroups=payload.include_subgroups if payload.kind == TARGET_KIND_GROUP else False,
        branch_mode=payload.branch_mode,
        branch_patterns=list(payload.branch_patterns),
        include_default_branch=payload.include_default_branch,
        max_branches_per_project=payload.max_branches_per_project,
        schedule_cron=_normalise_cron(payload.schedule_cron),
        exclude_patterns=list(payload.exclude_patterns),
        skip_unchanged=payload.skip_unchanged,
        enabled=payload.enabled,
        notify_webhook_url=validate_webhook(payload.notify_webhook_url),
        source_url=validate_source_url(payload.source_url),
        source_token=validate_source_token(payload.source_token),
        updated_by=updated_by,
    )
    session.add(target)
    try:
        await session.commit()
    except IntegrityError as error:
        await session.rollback()
        raise ConflictError("target.duplicate", path=source_path) from error
    await session.refresh(target)
    return target


async def update_target(
    session: AsyncSession,
    target: ScanTarget,
    payload: TargetUpdate,
    *,
    updated_by: str | None = None,
) -> ScanTarget:
    data = payload.model_dump(exclude_unset=True)

    if "name" in data:
        name = (data["name"] or "").strip()
        if not name:
            raise ValidationError("validation.name_empty")
        data["name"] = name

    if "schedule_cron" in data:
        data["schedule_cron"] = _normalise_cron(data["schedule_cron"])
    if "notify_webhook_url" in data:
        data["notify_webhook_url"] = validate_webhook(data["notify_webhook_url"])
    if "source_url" in data:
        data["source_url"] = validate_source_url(data["source_url"])
    if "source_token" in data:
        data["source_token"] = validate_source_token(data["source_token"])

    # A target on another instance needs a token of its own.
    resulting_url = data.get("source_url", target.source_url)
    resulting_token = data.get("source_token", target.source_token)
    if resulting_url and not resulting_token:
        raise ValidationError("validation.source_token_required")
    if target.kind != TARGET_KIND_GROUP:
        data.pop("include_subgroups", None)

    for field, value in data.items():
        setattr(target, field, value)
    target.updated_by = updated_by

    await session.commit()
    await session.refresh(target)
    return target


async def delete_target(session: AsyncSession, target: ScanTarget) -> None:
    await session.delete(target)
    await session.commit()


def _normalise_cron(expression: str | None) -> str | None:
    """An empty expression means manual runs only."""
    if expression is None:
        return None
    stripped = expression.strip()
    return stripped or None
