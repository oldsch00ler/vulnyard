# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scan runs and their jobs: creation, listing and bookkeeping (SPEC section 8)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import (
    JOB_ACTIVE_STATUSES,
    JOB_DONE,
    JOB_FAILED,
    JOB_QUEUED,
    JOB_SKIPPED,
    RUN_DONE,
    RUN_FAILED,
    RUN_QUEUED,
    RUN_RUNNING,
    TRIGGER_MANUAL,
)
from app.errors import NotFoundError
from app.models import Project, ScanJob, ScanRun, ScanTarget
from app.services.discovery import discover
from app.services.overrides import load_overrides
from app.services.projects import sync_target_projects
from app.services.sources import SourceProvider
from app.services.targets import spec_from_target

logger = logging.getLogger(__name__)


async def create_run_for_targets(
    session: AsyncSession,
    sources: SourceProvider,
    targets: list[ScanTarget],
    *,
    trigger: str = TRIGGER_MANUAL,
    triggered_by: str | None = None,
    global_exclude_patterns: tuple[str, ...] = (),
    force: bool = False,
) -> ScanRun:
    """Discover the targets and queue a job per project+branch.

    Every target is discovered with its own credentials, so a run can span
    several GitLab instances. `force` ignores the "skip unchanged" setting of the
    targets (SPEC 7.2). Discovery failures make the whole run `failed`; a single
    project failing later does not (SPEC 7.4).
    """
    run = ScanRun(
        trigger=trigger,
        target_id=targets[0].id if len(targets) == 1 else None,
        triggered_by=triggered_by,
        status=RUN_QUEUED,
    )
    session.add(run)
    await session.commit()
    await session.refresh(run)

    try:
        overrides = await load_overrides(session)
        # (project, whether an unchanged commit may be skipped)
        entries: list[tuple[Project, bool]] = []
        for target in targets:
            result = await discover(
                sources.for_target(target),
                spec_from_target(target),
                global_exclude_patterns=global_exclude_patterns,
                overrides=overrides,
            )
            skip_unchanged = target.skip_unchanged and not force
            entries.extend(
                (project, skip_unchanged)
                for project in await sync_target_projects(session, target, result)
            )
    except Exception as error:  # noqa: BLE001 - recorded on the run and re-raised
        run.status = RUN_FAILED
        run.finished_at = datetime.now(UTC)
        await session.commit()
        logger.warning("Discovery failed for run %s: %s", run.id, type(error).__name__)
        raise

    queued, skipped = await queue_jobs(session, run, entries)
    run.total = queued + skipped
    run.skipped = skipped
    if queued == 0:
        run.status = RUN_DONE
        run.finished_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(run)
    return run


async def create_run_for_project(
    session: AsyncSession,
    project: Project,
    *,
    trigger: str = TRIGGER_MANUAL,
    triggered_by: str | None = None,
    force: bool = True,
) -> ScanRun:
    """Queue a run for one project+branch that is already known (SPEC 11)."""
    run = ScanRun(trigger=trigger, triggered_by=triggered_by, status=RUN_QUEUED)
    session.add(run)
    await session.commit()
    await session.refresh(run)

    queued, skipped = await queue_jobs(session, run, [(project, not force)])
    run.total = queued + skipped
    run.skipped = skipped
    if queued == 0:
        run.status = RUN_DONE
        run.finished_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(run)
    return run


async def queue_jobs(
    session: AsyncSession, run: ScanRun, entries: list[tuple[Project, bool]]
) -> tuple[int, int]:
    """Create the jobs of a run; returns (queued, skipped).

    Deduplication per SPEC section 8: a project+branch with a queued or running
    job does not get a second one. A project whose commit did not change since
    the last successful scan is recorded as skipped (SPEC 7.2) – Dependency-Track
    keeps evaluating new CVEs against the stored SBOM on its own.
    """
    if not entries:
        return 0, 0

    busy = set(
        (
            await session.execute(
                select(ScanJob.project_id).where(
                    ScanJob.project_id.in_([project.id for project, _ in entries]),
                    ScanJob.status.in_((JOB_QUEUED, *JOB_ACTIVE_STATUSES)),
                )
            )
        ).scalars()
    )

    queued = 0
    skipped = 0
    seen: set[int] = set()
    for project, skip_unchanged in entries:
        if project.id in busy or project.id in seen or project.excluded:
            continue
        seen.add(project.id)

        if skip_unchanged and _is_unchanged(project):
            now = datetime.now(UTC)
            session.add(
                ScanJob(
                    run_id=run.id,
                    project_id=project.id,
                    status=JOB_SKIPPED,
                    commit_sha=project.last_commit_sha,
                    skip_reason="job.unchanged",
                    started_at=now,
                    finished_at=now,
                    duration_ms=0,
                )
            )
            skipped += 1
            continue

        session.add(ScanJob(run_id=run.id, project_id=project.id, status=JOB_QUEUED))
        queued += 1

    await session.commit()
    return queued, skipped


def _is_unchanged(project: Project) -> bool:
    """Whether the branch was already scanned at this very commit."""
    return bool(
        project.last_commit_sha
        and project.last_commit_sha == project.last_scanned_sha
        and project.dt_project_uuid
    )


async def list_runs(session: AsyncSession, *, limit: int = 20, offset: int = 0) -> tuple[list[ScanRun], int]:
    items = list(
        (
            await session.execute(
                select(ScanRun).order_by(ScanRun.id.desc()).limit(limit).offset(offset)
            )
        ).scalars()
    )
    total = (await session.execute(select(func.count()).select_from(ScanRun))).scalar_one()
    return items, total


async def get_run(session: AsyncSession, run_id: int) -> ScanRun:
    run = await session.get(ScanRun, run_id)
    if run is None:
        raise NotFoundError("run.not_found", id=run_id)
    return run


async def get_run_jobs(session: AsyncSession, run_id: int) -> list[tuple[ScanJob, Project]]:
    rows = await session.execute(
        select(ScanJob, Project)
        .join(Project, Project.id == ScanJob.project_id)
        .where(ScanJob.run_id == run_id)
        .order_by(ScanJob.id)
    )
    return [(job, project) for job, project in rows.all()]


async def refresh_run_counters(session: AsyncSession, run_id: int) -> ScanRun | None:
    """Recompute the run counters and status from its jobs."""
    run = await session.get(ScanRun, run_id)
    if run is None:
        return None

    rows = await session.execute(
        select(ScanJob.status, func.count()).where(ScanJob.run_id == run_id).group_by(ScanJob.status)
    )
    counts = {status: count for status, count in rows.all()}

    run.total = sum(counts.values())
    run.succeeded = counts.get(JOB_DONE, 0)
    run.failed = counts.get(JOB_FAILED, 0)
    run.skipped = counts.get(JOB_SKIPPED, 0)

    pending = counts.get(JOB_QUEUED, 0) + sum(counts.get(status, 0) for status in JOB_ACTIVE_STATUSES)
    if pending:
        if run.status != RUN_RUNNING:
            run.status = RUN_RUNNING
            run.started_at = run.started_at or datetime.now(UTC)
    elif run.status in (RUN_QUEUED, RUN_RUNNING):
        # Every job finished – the run is done even if some jobs failed.
        run.status = RUN_DONE
        run.finished_at = datetime.now(UTC)

    await session.commit()
    return run


#: Error codes that mean scanning itself is broken, not one project.
SYSTEMIC_ERROR_CODES = (
    "source.unauthorized",
    "source.forbidden",
    "source.unreachable",
    "dtrack.unauthorized",
    "dtrack.forbidden",
    "dtrack.unreachable",
    "dtrack.bom_spec_version_unsupported",
    "scan.trivy_missing",
    "clone.unauthorized",
)


async def systemic_failure(session: AsyncSession, run_id: int) -> tuple[str, dict, int, int] | None:
    """Whether a finished run failed for a reason that affects everything.

    Returns (code, params, failed, total) when most of the run failed on the
    same systemic error, otherwise None: a single broken repository is not worth
    waking anybody up.
    """
    rows = await session.execute(
        select(ScanJob.error_code, ScanJob.error_params, func.count())
        .where(ScanJob.run_id == run_id, ScanJob.status == JOB_FAILED)
        .group_by(ScanJob.error_code, ScanJob.error_params)
        .order_by(func.count().desc())
    )
    failures = rows.all()
    if not failures:
        return None

    total = (
        await session.execute(
            select(func.count()).select_from(ScanJob).where(ScanJob.run_id == run_id)
        )
    ).scalar_one()
    failed = sum(count for _, _, count in failures)

    code, params, count = failures[0]
    if code not in SYSTEMIC_ERROR_CODES:
        return None
    # One project failing on its own does not mean scanning is broken.
    if total > 1 and count * 2 < total:
        return None
    return code, dict(params or {}), int(failed), int(total)


async def count_jobs_by_status(session: AsyncSession) -> dict[str, int]:
    rows = await session.execute(select(ScanJob.status, func.count()).group_by(ScanJob.status))
    return {status: count for status, count in rows.all()}
