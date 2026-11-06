# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Persistence of discovered projects (SPEC 7.1 step 5)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import JOB_ACTIVE_STATUSES, JOB_QUEUED
from app.errors import ConflictError
from app.models import Project, ProjectBranchOverride, ScanJob, ScanTarget, TargetProject
from app.services.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


async def sync_target_projects(
    session: AsyncSession,
    target: ScanTarget,
    result: DiscoveryResult,
) -> list[Project]:
    """Upsert the discovered project+branch rows and link them to the target.

    Rows that disappeared from the target lose the link but are kept, so their
    history stays visible (SPEC 6, `projects`).
    """
    now = datetime.now(UTC)
    projects: list[Project] = []

    for discovered in result.projects:
        source_project = discovered.project
        for branch in discovered.branches:
            project = await _upsert_project(
                session,
                source=target.source,
                source_project_id=source_project.ref,
                branch=branch.branch,
                path_with_namespace=source_project.path_with_namespace,
                name=source_project.name,
                web_url=source_project.web_url,
                default_branch=source_project.default_branch,
                is_default_branch=branch.is_default_branch,
                commit_sha=branch.commit_sha,
                archived=source_project.archived,
                empty_repo=source_project.empty_repo,
                seen_at=now,
            )
            projects.append(project)

    await session.flush()
    await _link_to_target(session, target, projects)
    await session.commit()

    for project in projects:
        await session.refresh(project)
    return projects


async def _upsert_project(
    session: AsyncSession,
    *,
    source: str,
    source_project_id: str,
    branch: str,
    path_with_namespace: str,
    name: str,
    web_url: str,
    default_branch: str | None,
    is_default_branch: bool,
    commit_sha: str | None,
    archived: bool,
    empty_repo: bool,
    seen_at: datetime,
) -> Project:
    existing = (
        await session.execute(
            select(Project).where(
                Project.source == source,
                Project.source_project_id == source_project_id,
                Project.branch == branch,
            )
        )
    ).scalar_one_or_none()

    if existing is None:
        project = Project(
            source=source,
            source_project_id=source_project_id,
            branch=branch,
            path_with_namespace=path_with_namespace,
            name=name,
            web_url=web_url,
            default_branch=default_branch,
            is_default_branch=is_default_branch,
            last_commit_sha=commit_sha,
            archived=archived,
            empty_repo=empty_repo,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
        )
        session.add(project)
        return project

    existing.path_with_namespace = path_with_namespace
    existing.name = name
    existing.web_url = web_url
    existing.default_branch = default_branch
    existing.is_default_branch = is_default_branch
    existing.archived = archived
    existing.empty_repo = empty_repo
    existing.last_seen_at = seen_at
    if commit_sha:
        existing.last_commit_sha = commit_sha
    return existing


async def _link_to_target(session: AsyncSession, target: ScanTarget, projects: list[Project]) -> None:
    """Rebuild the M:N links of the target to exactly the discovered rows."""
    wanted = {project.id for project in projects if project.id is not None}

    existing = set(
        (
            await session.execute(
                select(TargetProject.project_id).where(TargetProject.target_id == target.id)
            )
        ).scalars()
    )

    for project_id in wanted - existing:
        session.add(TargetProject(target_id=target.id, project_id=project_id))

    stale = existing - wanted
    if stale:
        await session.execute(
            delete(TargetProject).where(
                TargetProject.target_id == target.id, TargetProject.project_id.in_(stale)
            )
        )


async def delete_project(session: AsyncSession, project: Project) -> None:
    """Forget a project+branch row together with its jobs and snapshots.

    Dependency-Track is left alone: its project and SBOM stay, only Vulnyard
    stops showing the row. A project that is still part of a scan target comes
    back at the next discovery, so this is meant for rows that are gone from
    the source or whose target was deleted; a live project is excluded instead.
    """
    busy = await session.scalar(
        select(ScanJob.id)
        .where(
            ScanJob.project_id == project.id,
            ScanJob.status.in_((JOB_QUEUED, *JOB_ACTIVE_STATUSES)),
        )
        .limit(1)
    )
    if busy is not None:
        raise ConflictError("project.scan_in_progress", id=project.id)

    siblings = await session.scalar(
        select(Project.id)
        .where(
            Project.source == project.source,
            Project.source_project_id == project.source_project_id,
            Project.id != project.id,
        )
        .limit(1)
    )
    if siblings is None:
        # The override belongs to the source project, not to one branch row;
        # it goes with the last row so nothing lingers.
        await session.execute(
            delete(ProjectBranchOverride).where(
                ProjectBranchOverride.source == project.source,
                ProjectBranchOverride.source_project_id == project.source_project_id,
            )
        )

    await session.delete(project)
    await session.commit()
    logger.info("project %s (%s) deleted", project.id, project.path_with_namespace)
