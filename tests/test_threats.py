# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Current threats: the KEV catalog, the selection and the API (SPEC 9.7)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.services.dtrack import _finding
from app.services.kev import KevCatalog, KevEntry, KevStatus, parse_catalog
from app.services.threats import EXPLOITED, LIKELY, NEW, select
from app.services.vulnerabilities import AffectedProjectFinding, GroupedVulnerability
from tests.fakes import FakeDependencyTrack
from tests.test_dashboard_api import _finding as dt_finding
from tests.test_dashboard_api import scanned  # noqa: F401 - fixture

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)

CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "dateReleased": "2026-10-21T14:04:39.8983Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget Command Injection",
            "dateAdded": "2026-10-20",
            "dueDate": "2026-11-10",
            "knownRansomwareCampaignUse": "Known",
            "requiredAction": "Apply mitigations per vendor instructions.",
        },
        {
            "cveID": "cve-2026-0002",
            "dateAdded": "2026-09-01",
            "dueDate": "not a date",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


# --- the catalog ----------------------------------------------------------------


def test_catalog_is_parsed_by_upper_case_cve_id() -> None:
    entries, released = parse_catalog(CATALOG)

    assert set(entries) == {"CVE-2026-0001", "CVE-2026-0002"}
    first = entries["CVE-2026-0001"]
    assert first.ransomware is True
    assert first.date_added == date(2026, 10, 20)
    assert first.due_date == date(2026, 11, 10)
    assert entries["CVE-2026-0002"].ransomware is False
    assert entries["CVE-2026-0002"].due_date is None
    assert released == datetime(2026, 10, 21, 14, 4, 39, 898300, tzinfo=UTC)


def test_a_broken_catalog_is_refused() -> None:
    with pytest.raises(ValueError):
        parse_catalog({"vulnerabilities": "nope"})
    with pytest.raises(ValueError):
        parse_catalog([])


def _catalog(handler, url: str = "https://kev.example.com/feed.json") -> KevCatalog:  # noqa: ANN001
    catalog = KevCatalog(Settings(kev_feed_url=url))
    catalog._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # noqa: SLF001
    return catalog


async def test_catalog_is_fetched_once_and_kept_when_a_refresh_fails() -> None:
    calls: list[str] = []
    fail = False

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(503) if fail else httpx.Response(200, json=CATALOG)

    catalog = _catalog(handler)
    try:
        assert "CVE-2026-0001" in await catalog.entries()
        # Fresh for a day: no second download.
        await catalog.entries()
        assert len(calls) == 1
        assert catalog.status().available is True
        assert catalog.status().count == 2

        # A failed refresh keeps the previous copy and says so.
        fail = True
        catalog._attempted_at = datetime.now(UTC) - timedelta(days=2)  # noqa: SLF001 - make it due
        assert "CVE-2026-0001" in await catalog.entries()
        status = catalog.status()
        assert status.available is True
        assert status.error_code == "kev.unavailable"
    finally:
        await catalog.close()


async def test_disabled_catalog_never_downloads() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be called")

    catalog = _catalog(handler, url="")
    try:
        assert await catalog.entries() == {}
        assert catalog.status() == KevStatus(enabled=False, available=False)
    finally:
        await catalog.close()


def test_dependency_track_aliases_are_read() -> None:
    finding = _finding(
        {
            "vulnerability": {
                "vulnId": "GHSA-aaaa-bbbb-cccc",
                "source": "GITHUB",
                "aliases": [{"cveId": "CVE-2026-0001", "ghsaId": "GHSA-aaaa-bbbb-cccc"}],
            },
            "component": {"name": "express"},
        }
    )

    assert finding.aliases == ("CVE-2026-0001",)


# --- the selection ----------------------------------------------------------------


def _vulnerability(
    vuln_id: str,
    severity: str = "MEDIUM",
    *,
    epss: float | None = None,
    aliases: set[str] | None = None,
    first_seen: datetime | None = None,
) -> GroupedVulnerability:
    group = GroupedVulnerability(
        vuln_id=vuln_id,
        source="GITHUB" if vuln_id.startswith("GHSA") else "NVD",
        severity=severity,
        epss_score=epss,
        aliases=aliases or set(),
    )
    group.affected.append(
        AffectedProjectFinding(
            project=None,  # type: ignore[arg-type] - not used by the selection
            component_name="express",
            component_version="4.0.0",
            purl="pkg:npm/express@4.0.0",
            latest_version="5.0.0",
            suppressed=False,
            attributed_on=first_seen,
        )
    )
    return group


def test_threats_are_selected_by_evidence_not_by_severity() -> None:
    kev = {"CVE-2026-0001": KevEntry(cve_id="CVE-2026-0001")}
    vulnerabilities = [
        # Exploited, found under its GHSA id with the CVE as an alias.
        _vulnerability("GHSA-aaaa", "MEDIUM", aliases={"CVE-2026-0001"}),
        _vulnerability("CVE-2026-0010", "LOW", epss=0.42),
        _vulnerability("CVE-2026-0011", "CRITICAL", first_seen=NOW - timedelta(days=2)),
        # Critical, but old, unlikely and not exploited: not a threat.
        _vulnerability("CVE-2026-0012", "CRITICAL", epss=0.01, first_seen=NOW - timedelta(days=90)),
        # New, but only medium.
        _vulnerability("CVE-2026-0013", "MEDIUM", first_seen=NOW - timedelta(days=1)),
    ]

    threats = select(vulnerabilities, kev, now=NOW)

    assert [(t.vulnerability.vuln_id, t.reasons) for t in threats] == [
        ("GHSA-aaaa", (EXPLOITED,)),
        ("CVE-2026-0010", (LIKELY,)),
        ("CVE-2026-0011", (NEW,)),
    ]
    assert threats[0].cve_ids == ("CVE-2026-0001",)
    assert threats[0].kev is kev["CVE-2026-0001"]


def test_exploited_come_first_ransomware_before_others_then_epss() -> None:
    kev = {
        "CVE-2026-0001": KevEntry(cve_id="CVE-2026-0001"),
        "CVE-2026-0002": KevEntry(cve_id="CVE-2026-0002", ransomware=True),
    }
    vulnerabilities = [
        _vulnerability("CVE-2026-0003", "CRITICAL", epss=0.9),
        _vulnerability("CVE-2026-0001", "LOW", epss=0.2),
        _vulnerability("CVE-2026-0002", "LOW"),
    ]

    ordered = [t.vulnerability.vuln_id for t in select(vulnerabilities, kev, now=NOW)]

    assert ordered == ["CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0003"]


def test_thresholds_can_be_changed() -> None:
    vulnerabilities = [
        _vulnerability("CVE-2026-0010", epss=0.05),
        _vulnerability("CVE-2026-0011", "HIGH", first_seen=NOW - timedelta(days=20)),
    ]

    assert select(vulnerabilities, {}, now=NOW) == []
    loose = select(vulnerabilities, {}, now=NOW, epss_threshold=0.01, new_days=30)
    assert [t.vulnerability.vuln_id for t in loose] == ["CVE-2026-0010", "CVE-2026-0011"]


# --- the API ---------------------------------------------------------------------


class FakeKev:
    def __init__(self, entries: dict[str, KevEntry], status: KevStatus | None = None) -> None:
        self._entries = entries
        self._status = status or KevStatus(enabled=True, available=bool(entries), count=len(entries))

    async def entries(self) -> dict[str, KevEntry]:
        return self._entries

    def status(self) -> KevStatus:
        return self._status

    async def close(self) -> None:
        return None


def test_threats_api_lists_and_counts_threats_of_our_projects(
    scanned: TestClient,  # noqa: F811 - fixture
) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    recent = datetime.now(UTC) - timedelta(days=1)
    dtrack.findings = {
        "dt-10-main": [
            replace(dt_finding("GHSA-aaaa", "MEDIUM", source="GITHUB"), aliases=("CVE-2026-0001",)),
            replace(dt_finding("CVE-2026-0002", "LOW"), epss_score=0.5, epss_percentile=0.97),
            replace(dt_finding("CVE-2026-0003", "HIGH"), attributed_on=recent),
            dt_finding("CVE-2026-0004", "CRITICAL"),
            # Ignored: somebody already decided, so it is no threat any more.
            replace(dt_finding("CVE-2026-0005", "LOW", suppressed=True), aliases=("CVE-2026-0001",)),
        ],
    }
    scanned.app.state.kev = FakeKev(
        {"CVE-2026-0001": KevEntry(cve_id="CVE-2026-0001", ransomware=True, due_date=date(2026, 11, 1))}
    )

    body = scanned.get("/api/threats").json()

    assert [item["vuln_id"] for item in body["items"]] == ["GHSA-aaaa", "CVE-2026-0002", "CVE-2026-0003"]
    assert body["counts"] == {"exploited": 1, "likely": 1, "new": 1}
    first = body["items"][0]
    assert first["reasons"] == ["exploited"]
    assert first["cve_ids"] == ["CVE-2026-0001"]
    assert first["kev"]["ransomware"] is True
    assert first["kev"]["due_date"] == "2026-11-01"
    assert body["items"][1]["epss_percentile"] == 0.97
    assert body["epss_available"] is True
    assert body["kev"]["available"] is True

    only_new = scanned.get("/api/threats?reason=new").json()
    assert [item["vuln_id"] for item in only_new["items"]] == ["CVE-2026-0003"]
    # The counts describe everything, not just the filtered list.
    assert only_new["counts"] == body["counts"]

    stricter = scanned.get("/api/threats?epss=0.6").json()
    assert "CVE-2026-0002" not in [item["vuln_id"] for item in stricter["items"]]


def test_threats_api_reports_a_missing_catalog_and_missing_epss(
    scanned: TestClient,  # noqa: F811 - fixture
) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    dtrack.findings = {"dt-10-main": [dt_finding("CVE-2026-0004", "CRITICAL")]}
    scanned.app.state.kev = FakeKev(
        {}, KevStatus(enabled=True, available=False, error_code="kev.unavailable")
    )

    body = scanned.get("/api/threats").json()

    assert body["items"] == []
    assert body["kev"] == {
        "enabled": True,
        "available": False,
        "count": 0,
        "fetched_at": None,
        "released_at": None,
        "error_code": "kev.unavailable",
    }
    assert body["epss_available"] is False


def test_threats_api_validates_the_thresholds(scanned: TestClient) -> None:  # noqa: F811
    assert scanned.get("/api/threats?epss=2").status_code == 422
    assert scanned.get("/api/threats?days=0").status_code == 422
