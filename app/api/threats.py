# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Current threats among the vulnerabilities of our projects (SPEC 9.7, 12.8)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Query

from app.dependencies import KevDep, RequiredDTrackDep, SessionDep
from app.schemas import KevFeedStatus, KevInfo, ThreatCounts, ThreatItem, ThreatList
from app.services import threats as service
from app.services import vulnerabilities as vulnerability_service

router = APIRouter(prefix="/threats", tags=["threats"])

DEFAULT_PAGE_SIZE = 25


@router.get("", response_model=ThreatList)
async def list_threats(
    session: SessionDep,
    dtrack: RequiredDTrackDep,
    kev: KevDep,
    epss: float = Query(default=service.DEFAULT_EPSS_THRESHOLD, ge=0.0, le=1.0),
    days: int = Query(default=service.DEFAULT_NEW_DAYS, ge=1, le=365),
    reason: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=100),
) -> ThreatList:
    """Exploited, likely exploited and new serious vulnerabilities, most urgent first.

    Ignored findings are left out: somebody already decided about them.
    """
    vulnerabilities = await vulnerability_service.grouped(session, dtrack, include_suppressed=False)
    catalog = await kev.entries()
    threats = service.select(
        vulnerabilities, catalog, now=datetime.now(UTC), epss_threshold=epss, new_days=days
    )

    counts = ThreatCounts(
        **{name: sum(1 for threat in threats if name in threat.reasons) for name in service.REASONS}
    )
    if reason in service.REASONS:
        threats = [threat for threat in threats if reason in threat.reasons]

    start = (page - 1) * page_size
    status = kev.status()
    return ThreatList(
        items=[_item(threat) for threat in threats[start : start + page_size]],
        total=len(threats),
        page=page,
        page_size=page_size,
        counts=counts,
        kev=KevFeedStatus(
            enabled=status.enabled,
            available=status.available,
            count=status.count,
            fetched_at=status.fetched_at,
            released_at=status.released_at,
            error_code=status.error_code,
        ),
        epss_available=any(item.epss_score is not None for item in vulnerabilities),
        epss_threshold=epss,
        new_days=days,
    )


def _item(threat: service.Threat) -> ThreatItem:
    vulnerability = threat.vulnerability
    entry = threat.kev
    return ThreatItem(
        vuln_id=vulnerability.vuln_id,
        source=vulnerability.source,
        severity=vulnerability.severity,
        cvss_v3_score=vulnerability.cvss_v3_score,
        epss_score=vulnerability.epss_score,
        epss_percentile=vulnerability.epss_percentile,
        reasons=list(threat.reasons),
        cve_ids=list(threat.cve_ids),
        kev=KevInfo(
            cve_id=entry.cve_id,
            name=entry.name,
            date_added=entry.date_added,
            due_date=entry.due_date,
            ransomware=entry.ransomware,
            required_action=entry.required_action,
        )
        if entry is not None
        else None,
        first_seen=vulnerability.first_seen,
        affected_project_count=vulnerability.affected_project_count,
        newer_version_available=any(one.newer_version_available for one in vulnerability.affected),
    )
