# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""GET /api/status – configuration state and runtime configuration for the frontend."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request

from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import JOB_ACTIVE_STATUSES, JOB_QUEUED
from app.dependencies import SessionDep

from app import APP_NAME, __version__
from app.config import Settings, get_settings
from app.i18n import available_locales
from app.errors import AppError
from app.dependencies import AuditIdentityDep
from app.schemas import (
    AppInfo,
    IdentityResponse,
    ConfigStatus,
    DependencyTrackStatus,
    RuntimeConfig,
    SchedulerStatus,
    SourceStatus,
    StatusResponse,
    ToolStatus,
    ToolsStatus,
    WorkerStatus,
)
from app.services.cache import TTLCache
from app.services.dtrack import MIN_SUPPORTED_VERSION, DependencyTrackClient
from app.services.queue import ScanWorker
from app.services.scheduler import ScanScheduler
from app.services.runs import count_jobs_by_status
from app.services.sources.base import RepositorySource
from app.services.tools import ToolInfo

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system"])

# Reachability of the source and of Dependency-Track is checked at most once a
# minute, so opening the UI does not hammer either of them.
_reachability_cache = TTLCache(ttl_seconds=60)


@router.get("/status", response_model=StatusResponse)
async def read_status(request: Request, session: SessionDep) -> StatusResponse:
    """State of the application. Never contains tokens, only whether they are set."""
    settings: Settings = get_settings()
    trivy: ToolInfo = request.app.state.trivy
    git: ToolInfo = request.app.state.git
    source: RepositorySource | None = getattr(request.app.state, "source", None)
    dtrack: DependencyTrackClient | None = getattr(request.app.state, "dtrack", None)
    worker: ScanWorker | None = getattr(request.app.state, "worker", None)
    scheduler: ScanScheduler | None = getattr(request.app.state, "scheduler", None)

    missing = settings.missing_scan_config
    dtrack_supported = dtrack.features.supported if dtrack is not None else None
    scanning_enabled = bool(worker is not None and worker.enabled)

    reachable, source_version = await _source_reachability(source)
    dtrack_reachable, dtrack_version = await _dtrack_reachability(dtrack)
    job_counts = await _job_counts(session)

    return StatusResponse(
        app=AppInfo(name=APP_NAME, version=__version__),
        config=ConfigStatus(
            complete=not missing,
            missing=missing,
            scanning_enabled=scanning_enabled,
        ),
        tools=ToolsStatus(
            trivy=_tool_status(trivy),
            git=_tool_status(git),
        ),
        source=SourceStatus(
            kind="gitlab",
            url=settings.gitlab_url,
            configured=settings.source_configured,
            reachable=reachable,
            version=source_version,
        ),
        dtrack=DependencyTrackStatus(
            configured=settings.dtrack_configured,
            ui_url=settings.effective_dt_ui_url or None,
            reachable=dtrack_reachable,
            version=dtrack_version,
            supported=dtrack_supported,
            minimum_version=".".join(str(part) for part in MIN_SUPPORTED_VERSION),
        ),
        scheduler=SchedulerStatus(
            running=bool(scheduler and scheduler.running),
            scheduled_targets=scheduler.scheduled_targets if scheduler else 0,
            next_run_at=scheduler.next_run_time() if scheduler and scheduler.running else None,
        ),
        worker=WorkerStatus(
            running=bool(worker and worker.running),
            active_jobs=(
                sum(job_counts.get(status, 0) for status in JOB_ACTIVE_STATUSES)
                if job_counts is not None
                else None
            ),
            queued_jobs=job_counts.get(JOB_QUEUED, 0) if job_counts is not None else None,
        ),
        runtime=RuntimeConfig(
            dt_ui_url=settings.effective_dt_ui_url or None,
            source_url=settings.gitlab_url or None,
            auth_mode=settings.auth_mode,
            default_locale=settings.default_locale,
            available_locales=list(available_locales()),
        ),
    )


@router.get("/me", response_model=IdentityResponse)
async def read_identity(identity: AuditIdentityDep) -> IdentityResponse:
    """Who is calling, according to AUTH_MODE (SPEC section 13)."""
    settings = get_settings()
    return IdentityResponse(email=identity, auth_mode=settings.auth_mode)


async def _source_reachability(source: RepositorySource | None) -> tuple[bool | None, str | None]:
    """(reachable, version) of the source; None when it is not configured."""
    if source is None:
        return None, None

    async def check() -> tuple[bool | None, str | None]:
        try:
            return True, await source.version()
        except AppError as error:
            logger.warning("Repository source is not reachable: %s", error.code)
            return False, None

    return await _reachability_cache.get_or_set("source", check)


async def _job_counts(session: AsyncSession) -> dict[str, int] | None:
    """Job counts per status; None when the database cannot be queried."""
    try:
        return await count_jobs_by_status(session)
    except Exception:  # noqa: BLE001 - the status endpoint must keep answering
        logger.warning("Could not read job counts from the database")
        return None


async def _dtrack_reachability(
    dtrack: DependencyTrackClient | None,
) -> tuple[bool | None, str | None]:
    """(reachable, version) of Dependency-Track; None when not configured."""
    if dtrack is None:
        return None, None

    async def check() -> tuple[bool | None, str | None]:
        try:
            features = await dtrack.detect_features()
        except AppError as error:
            logger.warning("Dependency-Track is not reachable: %s", error.code)
            return False, None
        return True, features.version

    return await _reachability_cache.get_or_set("dtrack", check)


def _tool_status(info: ToolInfo) -> ToolStatus:
    return ToolStatus(available=info.available, path=info.path, version=info.version)
