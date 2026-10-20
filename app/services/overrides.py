# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Per-project branch overrides (SPEC 6, `project_branch_overrides`)."""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import BRANCH_MODE_CUSTOM, BRANCH_MODES, SOURCE_GITLAB
from app.errors import NotFoundError, ValidationError
from app.models import Project, ProjectBranchOverride
from app.services.discovery import BranchSelection
from app.validation import is_valid_branch_pattern

MAX_PATTERNS = 50


async def load_overrides(
    session: AsyncSession, source: str = SOURCE_GITLAB
) -> dict[str, BranchSelection]:
    """All overrides of a source, keyed by the project reference."""
    rows = await session.execute(
        select(ProjectBranchOverride).where(ProjectBranchOverride.source == source)
    )
    return {
        row.source_project_id: BranchSelection(
            branch_mode=row.branch_mode,
            branch_patterns=tuple(row.branch_patterns or ()),
            include_default_branch=row.include_default_branch,
        )
        for row in rows.scalars()
    }


async def get_override(
    session: AsyncSession, source: str, source_project_id: str
) -> ProjectBranchOverride | None:
    return await session.get(ProjectBranchOverride, (source, source_project_id))


async def set_override(
    session: AsyncSession,
    *,
    source: str,
    source_project_id: str,
    branch_mode: str,
    branch_patterns: list[str],
    include_default_branch: bool,
    updated_by: str | None = None,
) -> ProjectBranchOverride:
    """Create or replace the override of one project."""
    _validate(branch_mode, branch_patterns, include_default_branch)

    override = await get_override(session, source, source_project_id)
    if override is None:
        override = ProjectBranchOverride(source=source, source_project_id=source_project_id)
        session.add(override)

    override.branch_mode = branch_mode
    override.branch_patterns = list(branch_patterns)
    override.include_default_branch = include_default_branch
    override.updated_by = updated_by

    await session.commit()
    await session.refresh(override)
    return override


async def delete_override(session: AsyncSession, source: str, source_project_id: str) -> None:
    await session.execute(
        delete(ProjectBranchOverride).where(
            ProjectBranchOverride.source == source,
            ProjectBranchOverride.source_project_id == source_project_id,
        )
    )
    await session.commit()


async def get_project(session: AsyncSession, project_id: int) -> Project:
    project = await session.get(Project, project_id)
    if project is None:
        raise NotFoundError("project.not_found", id=project_id)
    return project


def _validate(branch_mode: str, branch_patterns: list[str], include_default_branch: bool) -> None:
    if branch_mode not in BRANCH_MODES:
        raise ValidationError("validation.branch_mode_invalid", mode=branch_mode)
    if len(branch_patterns) > MAX_PATTERNS:
        raise ValidationError("validation.too_many_patterns", max=MAX_PATTERNS)
    for pattern in branch_patterns:
        if not is_valid_branch_pattern(pattern):
            raise ValidationError("validation.branch_pattern_invalid", pattern=pattern)
    if branch_mode == BRANCH_MODE_CUSTOM and not branch_patterns and not include_default_branch:
        raise ValidationError("validation.branch_selection_empty")
