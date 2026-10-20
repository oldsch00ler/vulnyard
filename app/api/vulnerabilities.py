# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Vulnerabilities across our projects, grouped per CVE (SPEC 12.4).

Scoped to the projects we scan on purpose: Dependency-Track is usually shared,
and its grouped endpoint has no project filter, so it would answer with other
teams' projects too.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.dependencies import RequiredDTrackDep, SessionDep
from app.schemas import (
    AffectedComponent,
    AffectedProject,
    AffectedProjectList,
    VulnerabilityItem,
    VulnerabilityList,
)
from app.services import vulnerabilities as service

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

SEVERITY_VALUES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED")
DEFAULT_PAGE_SIZE = 25


@router.get("", response_model=VulnerabilityList)
async def list_vulnerabilities(
    session: SessionDep,
    dtrack: RequiredDTrackDep,
    min_severity: str | None = Query(default=None),
    search: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=100),
    include_ignored: bool = Query(default=False),
) -> VulnerabilityList:
    """Vulnerabilities of our projects grouped per vulnerability id."""
    groups = await service.grouped(session, dtrack, include_suppressed=include_ignored)
    matching = service.filtered(groups, severity=_severity(min_severity), search=search)
    return VulnerabilityList(
        items=[
            VulnerabilityItem(
                vuln_id=item.vuln_id,
                source=item.source,
                severity=item.severity,
                cvss_v3_score=item.cvss_v3_score,
                epss_score=item.epss_score,
                affected_project_count=item.affected_project_count,
                published=item.published,
                ignored=bool(item.affected) and all(one.suppressed for one in item.affected),
            )
            for item in service.page_of(matching, page=page, page_size=page_size)
        ],
        total=len(matching),
        page=page,
        page_size=page_size,
    )


@router.get("/{source}/{vuln_id}/projects", response_model=AffectedProjectList)
async def list_affected_projects(
    source: str,
    vuln_id: str,
    session: SessionDep,
    dtrack: RequiredDTrackDep,
    include_ignored: bool = Query(default=True),
) -> AffectedProjectList:
    """Our projects affected by one vulnerability, with the component."""
    groups = await service.grouped(session, dtrack, include_suppressed=include_ignored)
    group = next(
        (
            item
            for item in groups
            if item.vuln_id.upper() == vuln_id.upper() and item.source.upper() == source.upper()
        ),
        None,
    )
    if group is None:
        return AffectedProjectList(items=[], components=[], total=0, ours=0)

    items = [
        AffectedProject(
            dt_project_uuid=str(one.project.dt_project_uuid),
            dt_name=one.project.path_with_namespace,
            dt_version=one.project.branch,
            project_id=one.project.id,
            path_with_namespace=one.project.path_with_namespace,
            branch=one.project.branch,
            web_url=one.project.web_url,
            is_default_branch=one.project.is_default_branch,
        )
        for one in _per_project(group)
    ]
    components = [
        AffectedComponent(
            project_id=one.project.id,
            path_with_namespace=one.project.path_with_namespace,
            branch=one.project.branch,
            web_url=one.project.web_url,
            is_default_branch=one.project.is_default_branch,
            component_name=one.component_name,
            component_version=one.component_version,
            purl=one.purl,
            latest_version=one.latest_version,
            suppressed=one.suppressed,
        )
        for one in group.affected
    ]
    components.sort(key=lambda one: (one.path_with_namespace, one.branch, one.component_name))
    items.sort(key=lambda item: (item.path_with_namespace or "", item.branch or ""))
    return AffectedProjectList(
        items=items, components=components, total=len(items), ours=len(items)
    )


def _per_project(group: service.GroupedVulnerability) -> list[service.AffectedProjectFinding]:
    """One entry per project, even when several of its components are affected."""
    seen: dict[int, service.AffectedProjectFinding] = {}
    for one in group.affected:
        seen.setdefault(one.project.id, one)
    return list(seen.values())


def _severity(value: str | None) -> str | None:
    """Dependency-Track names severities in upper case; so do we."""
    if not value:
        return None
    upper = value.upper()
    return upper if upper in SEVERITY_VALUES else None
