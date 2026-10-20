# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Dashboard: summary, trend and the riskiest projects (SPEC 12.1)."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.dependencies import DTrackDep, SchedulerDep, SessionDep
from app.schemas import (
    DashboardSummary,
    ProjectListItem,
    ScanStateRead,
    SeverityCounts,
    TargetSummaryList,
    TargetSummaryRead,
    TrendPoint,
    TrendResponse,
)
from app.services import dashboard as dashboard_service
from app.services.dashboard import ProjectRow

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

ALLOWED_TREND_DAYS = (30, 90, 180)


@router.get("/summary", response_model=DashboardSummary)
async def read_summary(
    session: SessionDep, dtrack: DTrackDep, scheduler: SchedulerDep
) -> DashboardSummary:
    """Totals over the default branches plus the state of scanning."""
    data = await dashboard_service.summary(session, dtrack)
    state = dict(data["scan_state"])  # type: ignore[arg-type]
    if scheduler is not None and scheduler.running:
        state["next_run_at"] = scheduler.next_run_time()

    return DashboardSummary(
        severities=SeverityCounts(**data["severities"]),  # type: ignore[arg-type]
        findings_total=int(data["findings_total"]),  # type: ignore[arg-type]
        projects_total=int(data["projects_total"]),  # type: ignore[arg-type]
        projects_scanned=int(data["projects_scanned"]),  # type: ignore[arg-type]
        projects_vulnerable=int(data["projects_vulnerable"]),  # type: ignore[arg-type]
        components=int(data["components"]),  # type: ignore[arg-type]
        vulnerable_components=int(data["vulnerable_components"]),  # type: ignore[arg-type]
        scan_state=ScanStateRead(**state),
    )


@router.get("/trend", response_model=TrendResponse)
async def read_trend(
    session: SessionDep,
    days: int = Query(default=30),
    target_id: int | None = Query(default=None),
) -> TrendResponse:
    """Daily severity totals from our own snapshots, optionally for one target."""
    window = days if days in ALLOWED_TREND_DAYS else ALLOWED_TREND_DAYS[0]
    points = await dashboard_service.trend(session, window, target_id=target_id)
    return TrendResponse(
        days=window,
        target_id=target_id,
        points=[TrendPoint(**point) for point in points],  # type: ignore[arg-type]
    )


@router.get("/by-target", response_model=TargetSummaryList)
async def read_by_target(
    session: SessionDep, dtrack: DTrackDep, days: int = Query(default=30)
) -> TargetSummaryList:
    """Per-target totals, so it is visible whose numbers are growing."""
    window = days if days in ALLOWED_TREND_DAYS else ALLOWED_TREND_DAYS[0]
    summaries = await dashboard_service.by_target(session, dtrack, days=window)
    return TargetSummaryList(
        days=window,
        items=[
            TargetSummaryRead(
                target_id=item.target_id,
                name=item.name,
                kind=item.kind,
                source_path=item.source_path,
                enabled=item.enabled,
                projects_total=item.projects_total,
                projects_vulnerable=item.projects_vulnerable,
                severities=SeverityCounts(**item.severities),
                findings_total=item.findings_total,
                components=item.components,
                vulnerable_components=item.vulnerable_components,
                risk_score=round(item.risk_score, 1),
                change=item.change,
            )
            for item in summaries
        ],
    )


@router.get("/top-projects", response_model=list[ProjectListItem])
async def read_top_projects(
    session: SessionDep, dtrack: DTrackDep, limit: int = Query(default=10, ge=1, le=50)
) -> list[ProjectListItem]:
    rows = await dashboard_service.top_projects(session, dtrack, limit=limit)
    return [project_item(row) for row in rows]


def project_item(row: ProjectRow) -> ProjectListItem:
    """Shared mapping of a project row to the API model."""
    project = row.project
    metrics = row.metrics
    return ProjectListItem(
        id=project.id,
        source=project.source,
        source_project_id=project.source_project_id,
        path_with_namespace=project.path_with_namespace,
        name=project.name,
        branch=project.branch,
        is_default_branch=project.is_default_branch,
        web_url=project.web_url,
        targets=list(row.target_names),
        severities=SeverityCounts(
            critical=metrics.critical,
            high=metrics.high,
            medium=metrics.medium,
            low=metrics.low,
            unassigned=metrics.unassigned,
        ),
        findings_total=metrics.total,
        components=metrics.components,
        vulnerable_components=metrics.vulnerable_components,
        risk_score=metrics.inherited_risk_score,
        last_scan_at=project.last_scan_at,
        last_scan_status=project.last_scan_status,
        dt_project_uuid=project.dt_project_uuid,
        excluded=project.excluded,
    )
