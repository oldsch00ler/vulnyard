# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Vulnerabilities of our projects, grouped per vulnerability (SPEC 12.4).

Dependency-Track's grouped endpoint (`/finding/grouped`) covers the whole
instance and takes no project filter, so on a shared Dependency-Track it answers
with other teams' projects as well. The summary therefore reads the findings of
the projects we scan and does the grouping, filtering and paging here.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.errors import AppError
from app.models import Project
from app.services.cache import TTLCache
from app.services.dtrack import DependencyTrackClient, DTFinding

logger = logging.getLogger(__name__)

#: Same minute as the dashboard: opening the page must not hammer the instance.
CACHE_TTL_SECONDS = 60
_cache = TTLCache(ttl_seconds=CACHE_TTL_SECONDS)

#: How many projects we ask Dependency-Track about at once.
CONCURRENCY = 5

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNASSIGNED": 4}


def invalidate_cache() -> None:
    _cache.invalidate()


@dataclass(slots=True)
class AffectedProjectFinding:
    """One of our projects affected by a vulnerability, with the component."""

    project: Project
    component_name: str
    component_version: str | None
    purl: str | None
    latest_version: str | None
    suppressed: bool
    attributed_on: datetime | None = None

    @property
    def newer_version_available(self) -> bool:
        return bool(self.latest_version) and self.latest_version != self.component_version


@dataclass(slots=True)
class GroupedVulnerability:
    """A vulnerability with the projects of ours it affects."""

    vuln_id: str
    source: str
    severity: str
    cvss_v3_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    published: datetime | None = None
    aliases: set[str] = field(default_factory=set)
    affected: list[AffectedProjectFinding] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime | None:
        """When Dependency-Track first attributed it to one of our projects."""
        dates = [one.attributed_on for one in self.affected if one.attributed_on is not None]
        return min(dates) if dates else None

    @property
    def affected_project_count(self) -> int:
        return len({finding.project.id for finding in self.affected})

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.upper(), len(SEVERITY_ORDER))


async def grouped(
    session: AsyncSession,
    dtrack: DependencyTrackClient,
    *,
    include_suppressed: bool = False,
) -> list[GroupedVulnerability]:
    """Findings of our projects grouped per vulnerability, worst first.

    Cached for a minute per suppressed/not variant; a finished scan invalidates it.
    """

    async def load() -> list[GroupedVulnerability]:
        projects = list(
            (
                await session.execute(select(Project).where(Project.dt_project_uuid.is_not(None)))
            ).scalars()
        )
        findings = await _findings_of(dtrack, projects, include_suppressed=include_suppressed)
        return _group(findings, include_suppressed=include_suppressed)

    key = f"grouped:{include_suppressed}"
    return await _cache.get_or_set(key, load)


def filtered(
    items: list[GroupedVulnerability], *, severity: str | None = None, search: str = ""
) -> list[GroupedVulnerability]:
    """Filter by exactly one severity and a substring of the vulnerability id."""
    wanted = (severity or "").upper() or None
    needle = search.strip().lower()
    return [
        item
        for item in items
        if (wanted is None or item.severity.upper() == wanted)
        and (not needle or needle in item.vuln_id.lower())
    ]


def page_of(
    items: list[GroupedVulnerability], *, page: int, page_size: int
) -> list[GroupedVulnerability]:
    start = (page - 1) * page_size
    return items[start : start + page_size]


# --- internals ----------------------------------------------------------------


async def _findings_of(
    dtrack: DependencyTrackClient, projects: list[Project], *, include_suppressed: bool
) -> list[tuple[Project, DTFinding]]:
    """Findings of every project, a handful of projects at a time."""
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def one(project: Project) -> list[tuple[Project, DTFinding]]:
        async with semaphore:
            try:
                found = await dtrack.project_findings(
                    str(project.dt_project_uuid), suppressed=include_suppressed
                )
            except AppError as error:
                # One unreachable project must not empty the whole page.
                logger.warning(
                    "Findings of %s@%s unavailable: %s",
                    project.path_with_namespace,
                    project.branch,
                    error.code,
                )
                return []
        return [(project, finding) for finding in found]

    results = await asyncio.gather(*(one(project) for project in projects))
    return [pair for group in results for pair in group]


def _group(
    findings: list[tuple[Project, DTFinding]], *, include_suppressed: bool
) -> list[GroupedVulnerability]:
    groups: dict[tuple[str, str], GroupedVulnerability] = {}
    for project, finding in findings:
        if finding.suppressed and not include_suppressed:
            continue
        key = (finding.source, finding.vuln_id)
        group = groups.get(key)
        if group is None:
            group = GroupedVulnerability(
                vuln_id=finding.vuln_id,
                source=finding.source,
                severity=finding.severity,
                cvss_v3_score=finding.cvss_v3_score,
                epss_score=finding.epss_score,
                epss_percentile=finding.epss_percentile,
                published=finding.published,
            )
            groups[key] = group
        group.aliases.update(finding.aliases)
        group.affected.append(
            AffectedProjectFinding(
                project=project,
                component_name=finding.component_name,
                component_version=finding.component_version,
                purl=finding.purl,
                latest_version=finding.latest_version,
                suppressed=finding.suppressed,
                attributed_on=finding.attributed_on,
            )
        )

    ordered = sorted(
        groups.values(),
        key=lambda item: (item.severity_rank, -item.affected_project_count, item.vuln_id),
    )
    return ordered
