# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Dashboard data: our projects joined with Dependency-Track metrics (SPEC 9.4).

Dependency-Track stays the source of truth about vulnerabilities. The whole
project listing with metrics comes in one paged request and is cached for a
minute, so opening the UI does not hammer the instance.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import JOB_FAILED
from app.models import MetricSnapshot, Project, ScanJob, ScanRun, ScanTarget, TargetProject
from app.services.cache import TTLCache
from app.services.dtrack import DependencyTrackClient, DTMetrics, DTProject

logger = logging.getLogger(__name__)

#: Dependency-Track answers are cached for a minute (SPEC 9.4).
CACHE_TTL_SECONDS = 60
_cache = TTLCache(ttl_seconds=CACHE_TTL_SECONDS)

SEVERITIES = ("critical", "high", "medium", "low", "unassigned")
#: Order used by the minimum severity filter.
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

EMPTY_METRICS = DTMetrics()


def invalidate_cache() -> None:
    """Drop the cached Dependency-Track data (after a scan finished)."""
    _cache.invalidate()


@dataclass(slots=True)
class ProjectRow:
    """One project of ours with the metrics Dependency-Track reports for it."""

    project: Project
    metrics: DTMetrics
    target_names: tuple[str, ...] = ()
    target_ids: tuple[int, ...] = ()
    dt_last_import: datetime | None = None


async def dtrack_projects(dtrack: DependencyTrackClient) -> dict[str, DTProject]:
    """All Dependency-Track projects by UUID, cached."""

    async def load() -> dict[str, DTProject]:
        projects = await dtrack.list_projects()
        return {project.uuid: project for project in projects}

    return await _cache.get_or_set("dtrack-projects", load)


async def project_rows(
    session: AsyncSession,
    dtrack: DependencyTrackClient | None,
    *,
    only_default_branch: bool = True,
) -> list[ProjectRow]:
    """Our project rows joined with the current Dependency-Track metrics."""
    query = select(Project).where(Project.excluded.is_(False))
    if only_default_branch:
        # Summaries, trend and top projects count the default branch only, so
        # several branches of one repository are not added up (SPEC 9.2).
        query = query.where(Project.is_default_branch.is_(True))
    projects = list((await session.execute(query)).scalars())

    dt_projects: dict[str, DTProject] = {}
    if dtrack is not None:
        dt_projects = await dtrack_projects(dtrack)

    targets, target_ids = await _targets_of_projects(session)

    rows: list[ProjectRow] = []
    for project in projects:
        dt_project = dt_projects.get(project.dt_project_uuid or "")
        rows.append(
            ProjectRow(
                project=project,
                metrics=(dt_project.metrics if dt_project and dt_project.metrics else EMPTY_METRICS),
                target_names=targets.get(project.id, ()),
                target_ids=target_ids.get(project.id, ()),
                dt_last_import=dt_project.last_bom_import if dt_project else None,
            )
        )
    return rows


async def summary(session: AsyncSession, dtrack: DependencyTrackClient | None) -> dict[str, object]:
    """Severity totals plus the state of scanning (SPEC 12.1)."""
    rows = await project_rows(session, dtrack)

    totals = {severity: 0 for severity in SEVERITIES}
    components = 0
    vulnerable_components = 0
    vulnerable_projects = 0
    for row in rows:
        for severity in SEVERITIES:
            totals[severity] += getattr(row.metrics, severity)
        components += row.metrics.components
        vulnerable_components += row.metrics.vulnerable_components
        if row.metrics.total > 0:
            vulnerable_projects += 1

    scanned = sum(1 for row in rows if row.project.dt_project_uuid)

    return {
        "severities": totals,
        "findings_total": sum(totals.values()),
        "projects_total": len(rows),
        "projects_scanned": scanned,
        "projects_vulnerable": vulnerable_projects,
        "components": components,
        "vulnerable_components": vulnerable_components,
        "scan_state": await scan_state(session),
    }


async def scan_state(session: AsyncSession) -> dict[str, object]:
    """Last run, failures in the last 24 hours and the pending work."""
    last_run = (
        await session.execute(select(ScanRun).order_by(ScanRun.id.desc()).limit(1))
    ).scalar_one_or_none()

    since = datetime.now(UTC) - timedelta(hours=24)
    failed_recently = (
        await session.execute(
            select(func.count())
            .select_from(ScanJob)
            .where(ScanJob.status == JOB_FAILED, ScanJob.finished_at >= since)
        )
    ).scalar_one()

    return {
        "last_run_id": last_run.id if last_run else None,
        "last_run_status": last_run.status if last_run else None,
        "last_run_finished_at": last_run.finished_at if last_run else None,
        "failed_jobs_24h": int(failed_recently),
    }


async def top_projects(
    session: AsyncSession, dtrack: DependencyTrackClient | None, *, limit: int = 10
) -> list[ProjectRow]:
    """Riskiest projects: by inherited risk score, then by critical findings."""
    rows = await project_rows(session, dtrack)

    def sort_key(row: ProjectRow) -> tuple[float, int, int]:
        return (
            -(row.metrics.inherited_risk_score or 0.0),
            -row.metrics.critical,
            -row.metrics.high,
        )

    return [row for row in sorted(rows, key=sort_key) if row.metrics.total > 0][:limit]


async def trend(
    session: AsyncSession, days: int, *, target_id: int | None = None
) -> list[dict[str, object]]:
    """Daily severity totals from our snapshots (SPEC 9.4).

    With `target_id` the trend covers only the projects of that target, so it is
    possible to see whose numbers are moving.
    """
    since = (datetime.now(UTC) - timedelta(days=days)).date()

    query = (
        select(
            MetricSnapshot.date,
            func.sum(MetricSnapshot.critical),
            func.sum(MetricSnapshot.high),
            func.sum(MetricSnapshot.medium),
            func.sum(MetricSnapshot.low),
            func.sum(MetricSnapshot.unassigned),
            func.count(MetricSnapshot.id),
        )
        .join(Project, Project.id == MetricSnapshot.project_id)
        .where(
            MetricSnapshot.date >= since,
            Project.is_default_branch.is_(True),
            Project.excluded.is_(False),
        )
        .group_by(MetricSnapshot.date)
        .order_by(MetricSnapshot.date)
    )
    if target_id is not None:
        query = query.where(
            Project.id.in_(
                select(TargetProject.project_id).where(TargetProject.target_id == target_id)
            )
        )

    rows = await session.execute(query)

    return [
        {
            "date": date,
            "critical": int(critical or 0),
            "high": int(high or 0),
            "medium": int(medium or 0),
            "low": int(low or 0),
            "unassigned": int(unassigned or 0),
            "projects": int(projects or 0),
        }
        for date, critical, high, medium, low, unassigned, projects in rows.all()
    ]


@dataclass(slots=True)
class TargetSummary:
    """Per-target totals plus how they moved over the trend window."""

    target_id: int
    name: str
    kind: str
    source_path: str
    enabled: bool
    projects_total: int = 0
    projects_vulnerable: int = 0
    severities: dict[str, int] = field(default_factory=lambda: {s: 0 for s in SEVERITIES})
    components: int = 0
    vulnerable_components: int = 0
    risk_score: float = 0.0
    #: Change of the findings total over the window; None without snapshots.
    change: int | None = None

    @property
    def findings_total(self) -> int:
        return sum(self.severities.values())


async def by_target(
    session: AsyncSession, dtrack: DependencyTrackClient | None, *, days: int = 30
) -> list[TargetSummary]:
    """Summary per scan target, ordered by how risky it is."""
    targets = list((await session.execute(select(ScanTarget).order_by(ScanTarget.name))).scalars())
    rows = await project_rows(session, dtrack)

    by_project: dict[int, list[int]] = {}
    for row in rows:
        by_project[row.project.id] = list(row.target_ids)

    summaries: dict[int, TargetSummary] = {
        target.id: TargetSummary(
            target_id=target.id,
            name=target.name,
            kind=target.kind,
            source_path=target.source_path,
            enabled=target.enabled,
        )
        for target in targets
    }

    for row in rows:
        for target_id in by_project.get(row.project.id, ()):
            summary = summaries.get(target_id)
            if summary is None:
                continue
            summary.projects_total += 1
            if row.metrics.total:
                summary.projects_vulnerable += 1
            for severity in SEVERITIES:
                summary.severities[severity] += getattr(row.metrics, severity)
            summary.components += row.metrics.components
            summary.vulnerable_components += row.metrics.vulnerable_components
            summary.risk_score += row.metrics.inherited_risk_score or 0.0

    changes = await _changes_per_target(session, days)
    for target_id, change in changes.items():
        if target_id in summaries:
            summaries[target_id].change = change

    return sorted(
        summaries.values(),
        key=lambda item: (-item.severities["critical"], -item.findings_total, item.name),
    )


async def _changes_per_target(session: AsyncSession, days: int) -> dict[int, int]:
    """Findings total now minus at the start of the window, per target."""
    since = (datetime.now(UTC) - timedelta(days=days)).date()

    rows = await session.execute(
        select(
            TargetProject.target_id,
            MetricSnapshot.date,
            func.sum(
                MetricSnapshot.critical
                + MetricSnapshot.high
                + MetricSnapshot.medium
                + MetricSnapshot.low
                + MetricSnapshot.unassigned
            ),
        )
        .join(Project, Project.id == MetricSnapshot.project_id)
        .join(TargetProject, TargetProject.project_id == Project.id)
        .where(
            MetricSnapshot.date >= since,
            Project.is_default_branch.is_(True),
            Project.excluded.is_(False),
        )
        .group_by(TargetProject.target_id, MetricSnapshot.date)
        .order_by(TargetProject.target_id, MetricSnapshot.date)
    )

    series: dict[int, list[int]] = {}
    for target_id, _date, total in rows.all():
        series.setdefault(int(target_id), []).append(int(total or 0))

    # A single point cannot show a change.
    return {
        target_id: points[-1] - points[0]
        for target_id, points in series.items()
        if len(points) >= 2
    }


async def _targets_of_projects(
    session: AsyncSession,
) -> tuple[dict[int, tuple[str, ...]], dict[int, tuple[int, ...]]]:
    """Target names and ids per project id, for the project table and filters."""
    rows = await session.execute(
        select(TargetProject.project_id, ScanTarget.id, ScanTarget.name).join(
            ScanTarget, ScanTarget.id == TargetProject.target_id
        )
    )
    names: dict[int, list[str]] = {}
    ids: dict[int, list[int]] = {}
    for project_id, target_id, name in rows.all():
        names.setdefault(project_id, []).append(name)
        ids.setdefault(project_id, []).append(target_id)
    return (
        {project_id: tuple(sorted(value)) for project_id, value in names.items()},
        {project_id: tuple(sorted(value)) for project_id, value in ids.items()},
    )
