# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Projects: listing, detail, findings, history and per-project settings."""

from __future__ import annotations

from fastapi import APIRouter, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dashboard import project_item
from app.dependencies import (
    AuditIdentityDep,
    DTrackDep,
    LocaleDep,
    RequiredDTrackDep,
    SessionDep,
    SourceDep,
    WorkerDep,
)
from app.errors import NotFoundError
from app.i18n import t
from app.models import MetricSnapshot, Project, ScanJob
from app.schemas import (
    AffectedProject,
    BranchOverrideRead,
    BranchOverrideWrite,
    FindingList,
    FindingRead,
    ProjectBranchSummary,
    ProjectDetail,
    ProjectHistory,
    ProjectHistoryItem,
    ProjectList,
    ProjectPatch,
    RunRead,
    TrendPoint,
)
from app.services import dashboard as dashboard_service
from app.services import overrides as override_service
from app.services import epss
from app.services import runs as run_service
from app.services.dashboard import SEVERITIES, SEVERITY_ORDER, ProjectRow
from app.services.dtrack import DTFinding

router = APIRouter(prefix="/projects", tags=["projects"])

DEFAULT_PAGE_SIZE = 25
SORT_FIELDS = ("path", "risk", "critical", "last_scan")


@router.get("", response_model=ProjectList)
async def list_projects(
    session: SessionDep,
    dtrack: DTrackDep,
    target_id: int | None = Query(default=None),
    search: str = Query(default=""),
    min_severity: str | None = Query(default=None),
    scan_status: str | None = Query(default=None, alias="status"),
    branch: str = Query(default="default", pattern="^(default|all)$"),
    sort: str = Query(default="risk"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=200),
) -> ProjectList:
    """Projects with their Dependency-Track metrics, filtered and sorted."""
    rows = await dashboard_service.project_rows(
        session, dtrack, only_default_branch=branch == "default"
    )

    rows = [row for row in rows if _matches(row, search, min_severity, scan_status, target_id)]
    rows = _sorted(rows, sort)

    total = len(rows)
    start = (page - 1) * page_size
    return ProjectList(
        items=[project_item(row) for row in rows[start : start + page_size]],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{project_id}", response_model=ProjectDetail)
async def read_project(project_id: int, session: SessionDep, dtrack: DTrackDep) -> ProjectDetail:
    project = await override_service.get_project(session, project_id)
    rows = await dashboard_service.project_rows(session, dtrack, only_default_branch=False)
    row = next((item for item in rows if item.project.id == project_id), None)
    if row is None:
        # Excluded projects are filtered out of the listing but still have a detail.
        row = ProjectRow(project=project, metrics=dashboard_service.EMPTY_METRICS)

    siblings = list(
        (
            await session.execute(
                select(Project)
                .where(
                    Project.source == project.source,
                    Project.source_project_id == project.source_project_id,
                )
                .order_by(Project.is_default_branch.desc(), Project.branch)
            )
        ).scalars()
    )

    override = await override_service.get_override(
        session, project.source, project.source_project_id
    )

    base = project_item(row).model_dump()
    return ProjectDetail(
        **base,
        default_branch=project.default_branch,
        last_commit_sha=project.last_commit_sha,
        last_scanned_sha=project.last_scanned_sha,
        dt_last_import=row.dt_last_import,
        branches=[
            ProjectBranchSummary(
                id=sibling.id,
                branch=sibling.branch,
                is_default_branch=sibling.is_default_branch,
                last_scan_at=sibling.last_scan_at,
            )
            for sibling in siblings
        ],
        branch_override=(
            BranchOverrideWrite(
                branch_mode=override.branch_mode,
                branch_patterns=list(override.branch_patterns or []),
                include_default_branch=override.include_default_branch,
            )
            if override is not None
            else None
        ),
    )


@router.get("/{project_id}/findings", response_model=FindingList)
async def read_findings(
    project_id: int,
    session: SessionDep,
    dtrack: RequiredDTrackDep,
    suppressed: bool = Query(default=False),
) -> FindingList:
    """Findings of the project as Dependency-Track reports them (SPEC 9.4)."""
    project = await override_service.get_project(session, project_id)
    if not project.dt_project_uuid:
        raise NotFoundError("project.not_scanned_yet", id=project_id)

    findings = await dtrack.project_findings(project.dt_project_uuid, suppressed=suppressed)
    findings = await epss.with_epss(dtrack, findings)
    findings.sort(key=lambda finding: (_severity_rank(finding), finding.component_name))
    return FindingList(items=[_finding(finding) for finding in findings], total=len(findings))


@router.get("/{project_id}/history", response_model=ProjectHistory)
async def read_history(project_id: int, session: SessionDep, locale: LocaleDep) -> ProjectHistory:
    """Scan history of the project plus its own metric snapshots."""
    project = await override_service.get_project(session, project_id)

    jobs = list(
        (
            await session.execute(
                select(ScanJob)
                .where(ScanJob.project_id == project.id)
                .order_by(ScanJob.id.desc())
                .limit(50)
            )
        ).scalars()
    )

    snapshots = list(
        (
            await session.execute(
                select(MetricSnapshot)
                .where(MetricSnapshot.project_id == project.id)
                .order_by(MetricSnapshot.date)
            )
        ).scalars()
    )

    return ProjectHistory(
        items=[
            ProjectHistoryItem(
                job_id=job.id,
                run_id=job.run_id,
                status=job.status,
                commit_sha=job.commit_sha,
                components_count=job.components_count,
                skip_reason=job.skip_reason,
                skip_message=t(job.skip_reason, locale) if job.skip_reason else None,
                error_code=job.error_code,
                error_message=(
                    t(job.error_code, locale, **(job.error_params or {})) if job.error_code else None
                ),
                started_at=job.started_at,
                finished_at=job.finished_at,
                duration_ms=job.duration_ms,
            )
            for job in jobs
        ],
        snapshots=[
            TrendPoint(
                date=snapshot.date,
                critical=snapshot.critical,
                high=snapshot.high,
                medium=snapshot.medium,
                low=snapshot.low,
                unassigned=snapshot.unassigned,
                projects=1,
            )
            for snapshot in snapshots
        ],
    )


@router.patch("/{project_id}", response_model=ProjectDetail)
async def patch_project(
    project_id: int, payload: ProjectPatch, session: SessionDep, dtrack: DTrackDep
) -> ProjectDetail:
    """Exclude a project from scanning, or put it back."""
    project = await override_service.get_project(session, project_id)
    if payload.excluded is not None:
        project.excluded = payload.excluded
    await session.commit()
    return await read_project(project_id, session, dtrack)


@router.post("/{project_id}/scan", response_model=RunRead, status_code=status.HTTP_201_CREATED)
async def scan_project(
    project_id: int,
    session: SessionDep,
    source: SourceDep,
    worker: WorkerDep,
    identity: AuditIdentityDep,
    force: bool = Query(default=True),
) -> RunRead:
    """Scan this one project+branch now (SPEC 11)."""
    project = await override_service.get_project(session, project_id)
    run = await run_service.create_run_for_project(
        session, project, triggered_by=identity, force=force
    )
    worker.notify()
    return RunRead(
        id=run.id,
        trigger=run.trigger,
        target_id=run.target_id,
        target_name=None,
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


# --- branch override ----------------------------------------------------------


@router.get("/{project_id}/branch-override", response_model=BranchOverrideRead)
async def read_branch_override(project_id: int, session: SessionDep) -> BranchOverrideRead:
    """Branch selection that overrides the target's one for this project."""
    project = await override_service.get_project(session, project_id)
    override = await override_service.get_override(
        session, project.source, project.source_project_id
    )
    if override is None:
        raise NotFoundError("project.branch_override_not_found", id=project_id)
    return _override(override, project)


@router.put("/{project_id}/branch-override", response_model=BranchOverrideRead)
async def write_branch_override(
    project_id: int,
    payload: BranchOverrideWrite,
    session: SessionDep,
    identity: AuditIdentityDep,
) -> BranchOverrideRead:
    project = await override_service.get_project(session, project_id)
    override = await override_service.set_override(
        session,
        source=project.source,
        source_project_id=project.source_project_id,
        branch_mode=payload.branch_mode,
        branch_patterns=payload.branch_patterns,
        include_default_branch=payload.include_default_branch,
        updated_by=identity,
    )
    return _override(override, project)


@router.delete("/{project_id}/branch-override", status_code=status.HTTP_204_NO_CONTENT)
async def remove_branch_override(project_id: int, session: SessionDep) -> Response:
    """Drop the override; the project follows its target again."""
    project = await override_service.get_project(session, project_id)
    await override_service.delete_override(session, project.source, project.source_project_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- helpers ------------------------------------------------------------------


def _override(override, project: Project) -> BranchOverrideRead:  # noqa: ANN001 - ORM row
    return BranchOverrideRead(
        source=override.source,
        source_project_id=override.source_project_id,
        path_with_namespace=project.path_with_namespace,
        branch_mode=override.branch_mode,
        branch_patterns=list(override.branch_patterns or []),
        include_default_branch=override.include_default_branch,
        updated_at=override.updated_at,
        updated_by=override.updated_by,
    )


def _finding(finding: DTFinding) -> FindingRead:
    return FindingRead(
        vuln_id=finding.vuln_id,
        source=finding.source,
        severity=finding.severity,
        cvss_v3_score=finding.cvss_v3_score,
        epss_score=finding.epss_score,
        epss_percentile=finding.epss_percentile,
        cwe=finding.cwe,
        published=finding.published,
        component_name=finding.component_name,
        component_version=finding.component_version,
        purl=finding.purl,
        latest_version=finding.latest_version,
        suppressed=finding.suppressed,
        attributed_on=finding.attributed_on,
    )


def _severity_rank(finding: DTFinding) -> int:
    severity = finding.severity.lower()
    return SEVERITY_ORDER.get(severity, len(SEVERITIES))


def _matches(
    row: ProjectRow,
    search: str,
    min_severity: str | None,
    scan_status: str | None,
    target_id: int | None,
) -> bool:
    if search and search.lower() not in row.project.path_with_namespace.lower():
        return False
    if scan_status and (row.project.last_scan_status or "") != scan_status:
        return False
    if target_id is not None and target_id not in row.target_ids:
        return False
    if min_severity:
        wanted = SEVERITY_ORDER.get(min_severity.lower())
        if wanted is not None:
            counted = sum(
                getattr(row.metrics, severity)
                for severity in SEVERITIES
                if SEVERITY_ORDER[severity] <= wanted
            )
            if counted == 0:
                return False
    return True


def _sorted(rows: list[ProjectRow], sort: str) -> list[ProjectRow]:
    key = sort if sort in SORT_FIELDS else "risk"
    if key == "path":
        return sorted(rows, key=lambda row: row.project.path_with_namespace)
    if key == "critical":
        return sorted(rows, key=lambda row: (-row.metrics.critical, -row.metrics.high))
    if key == "last_scan":
        return sorted(
            rows,
            key=lambda row: (row.project.last_scan_at is None, row.project.last_scan_at),
            reverse=False,
        )
    return sorted(
        rows,
        key=lambda row: (
            -(row.metrics.inherited_risk_score or 0.0),
            -row.metrics.critical,
            row.project.path_with_namespace,
        ),
    )
