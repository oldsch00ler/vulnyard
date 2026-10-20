# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scan runs: history, detail and manual triggering (SPEC section 11)."""

from __future__ import annotations

from fastapi import APIRouter, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuditIdentityDep, LocaleDep, SessionDep, SourcesDep, WorkerDep
from app.errors import ValidationError
from app.i18n import t
from app.models import Project, ScanJob, ScanRun, ScanTarget
from app.schemas import JobRead, RunDetail, RunList, RunRead
from app.services import runs as run_service
from app.services import targets as target_service
from app.services.app_settings import get_global_exclude_patterns

#: Statuses in which a run can still be cancelled.
ACTIVE_RUN_STATUSES = ("queued", "running")

router = APIRouter(prefix="/runs", tags=["runs"])


@router.get("", response_model=RunList)
async def list_runs(
    session: SessionDep,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> RunList:
    items, total = await run_service.list_runs(session, limit=limit, offset=offset)
    names = await _target_names(session, [run.target_id for run in items])
    return RunList(items=[_run(run, names) for run in items], total=total)


@router.get("/{run_id}", response_model=RunDetail)
async def read_run(run_id: int, session: SessionDep, locale: LocaleDep) -> RunDetail:
    run = await run_service.get_run(session, run_id)
    jobs = await run_service.get_run_jobs(session, run_id)
    names = await _target_names(session, [run.target_id])
    return RunDetail(
        **_run(run, names).model_dump(),
        jobs=[_job(job, project, locale) for job, project in jobs],
    )


@router.post("", response_model=RunDetail, status_code=status.HTTP_201_CREATED)
async def create_run(
    session: SessionDep,
    sources: SourcesDep,
    worker: WorkerDep,
    locale: LocaleDep,
    identity: AuditIdentityDep,
    force: bool = Query(default=False),
) -> RunDetail:
    """Scan everything: all enabled targets. `force` rescans unchanged commits."""
    targets, _ = await target_service.list_targets(session, enabled=True)
    if not targets:
        raise ValidationError("scan.no_enabled_targets")

    run = await run_service.create_run_for_targets(
        session,
        sources,
        targets,
        triggered_by=identity,
        global_exclude_patterns=await get_global_exclude_patterns(session),
        force=force,
    )
    worker.notify()
    return await _detail(session, run, locale)


@router.post("/{run_id}/cancel", response_model=RunDetail)
async def cancel_run(
    run_id: int, session: SessionDep, worker: WorkerDep, locale: LocaleDep
) -> RunDetail:
    """Cancel queued jobs and stop the running ones (SPEC section 8)."""
    run = await run_service.get_run(session, run_id)
    if run.status not in ACTIVE_RUN_STATUSES:
        raise ValidationError("run.not_cancellable", status=run.status)

    await worker.cancel_run(run_id)
    await session.refresh(run)
    return await _detail(session, run, locale)


async def _detail(session: AsyncSession, run: ScanRun, locale: str) -> RunDetail:
    jobs = await run_service.get_run_jobs(session, run.id)
    names = await _target_names(session, [run.target_id])
    return RunDetail(
        **_run(run, names).model_dump(),
        jobs=[_job(job, project, locale) for job, project in jobs],
    )


async def _target_names(session: AsyncSession, target_ids: list[int | None]) -> dict[int, str]:
    wanted = [target_id for target_id in target_ids if target_id is not None]
    if not wanted:
        return {}
    rows = await session.execute(
        select(ScanTarget.id, ScanTarget.name).where(ScanTarget.id.in_(wanted))
    )
    return {target_id: name for target_id, name in rows.all()}


def _run(run: ScanRun, names: dict[int, str]) -> RunRead:
    return RunRead(
        id=run.id,
        trigger=run.trigger,
        target_id=run.target_id,
        target_name=names.get(run.target_id) if run.target_id else None,
        triggered_by=run.triggered_by,
        status=run.status,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        total=run.total,
        succeeded=run.succeeded,
        failed=run.failed,
        skipped=run.skipped,
    )


def _job(job: ScanJob, project: Project, locale: str) -> JobRead:
    params = job.error_params or {}
    return JobRead(
        id=job.id,
        project_id=project.id,
        path_with_namespace=project.path_with_namespace,
        name=project.name,
        branch=project.branch,
        is_default_branch=project.is_default_branch,
        web_url=project.web_url,
        status=job.status,
        commit_sha=job.commit_sha,
        components_count=job.components_count,
        sbom_bytes=job.sbom_bytes,
        dt_project_uuid=project.dt_project_uuid,
        skip_reason=job.skip_reason,
        skip_message=t(job.skip_reason, locale) if job.skip_reason else None,
        error_code=job.error_code,
        error_params=params,
        error_message=t(job.error_code, locale, **params) if job.error_code else None,
        error_detail=job.error_detail,
        log_tail=job.log_tail,
        queued_at=job.queued_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        duration_ms=job.duration_ms,
    )
