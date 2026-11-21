# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Withdrawn advisories: the upstream lookups and the automatic ignore rules."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.services.advisories import AdvisoryLookup, parse_cve_record, parse_osv
from app.services.dtrack import DTFinding
from tests.fakes import FakeAdvisories, FakeDependencyTrack, FakeSource, branch, project

WITHDRAWN = datetime(2026, 11, 18, 15, 38, 56, tzinfo=UTC)
GHSA = "GHSA-fc5q-39xc-vjpf"
CVE = "CVE-2026-112366"


# --- parsing ------------------------------------------------------------------


def test_an_osv_record_says_when_it_was_withdrawn() -> None:
    assert parse_osv({"id": GHSA, "withdrawn": "2026-11-18T15:38:56Z"}) == WITHDRAWN
    assert parse_osv({"id": GHSA, "modified": "2026-11-19T16:15:03.414400251Z"}) is None


def test_a_rejected_cve_record_is_withdrawn() -> None:
    rejected = {
        "cveMetadata": {
            "state": "REJECTED",
            "dateUpdated": "2025-01-01T00:00:22.634Z",
            "dateRejected": "2025-01-01T00:00:22.634Z",
        }
    }
    published = {"cveMetadata": {"state": "PUBLISHED", "dateUpdated": "2026-10-19T16:40:19.321Z"}}

    assert parse_cve_record(rejected) == datetime(2025, 1, 1, 0, 0, 22, 634000, tzinfo=UTC)
    assert parse_cve_record(published) is None


def test_a_broken_answer_is_refused() -> None:
    with pytest.raises(ValueError):
        parse_osv([])
    with pytest.raises(ValueError):
        parse_cve_record({"error": "nope"})


# --- the lookup ---------------------------------------------------------------


def _lookup(handler, **settings: str) -> AdvisoryLookup:  # noqa: ANN001
    lookup = AdvisoryLookup(
        Settings(
            osv_api_url=settings.get("osv", "https://osv.example.com"),
            cve_api_url=settings.get("cve", "https://cve.example.com/api"),
        )
    )
    lookup._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # noqa: SLF001
    return lookup


async def test_ghsa_goes_to_osv_and_cve_to_the_cve_program() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.host == "osv.example.com":
            return httpx.Response(200, json={"id": GHSA, "withdrawn": "2026-11-18T15:38:56Z"})
        return httpx.Response(200, json={"cveMetadata": {"state": "PUBLISHED"}})

    lookup = _lookup(handler)
    try:
        # OSV ids are case-sensitive; Vulnyard keeps them in upper case.
        assert await lookup.withdrawn_at("GHSA-FC5Q-39XC-VJPF") == WITHDRAWN
        assert await lookup.withdrawn_at(CVE) is None
    finally:
        await lookup.close()

    assert requested == [
        f"https://osv.example.com/v1/vulns/{GHSA}",
        f"https://cve.example.com/api/cve/{CVE}",
    ]


async def test_an_unknown_id_stands_and_an_outage_is_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("GHSA-0000-0000-0000"):
            return httpx.Response(404, json={"code": 5})
        return httpx.Response(503)

    lookup = _lookup(handler)
    try:
        assert await lookup.withdrawn_at("GHSA-0000-0000-0000") is None
        with pytest.raises(httpx.HTTPStatusError):
            await lookup.withdrawn_at(GHSA)
    finally:
        await lookup.close()


def test_an_empty_url_turns_its_half_off() -> None:
    no_cve = AdvisoryLookup(Settings(osv_api_url="https://osv.example.com", cve_api_url=""))
    neither = AdvisoryLookup(Settings(osv_api_url="", cve_api_url=""))

    assert no_cve.handles(GHSA, "GITHUB") is True
    assert no_cve.handles(CVE, "NVD") is False
    assert neither.enabled is False
    # Sources whose ids no upstream here knows are never asked about.
    assert no_cve.handles("SNYK-JS-FOO-123", "SNYK") is False


# --- through the database -----------------------------------------------------


def finding(vuln_id: str, source: str, project_uuid: str) -> DTFinding:
    return DTFinding(
        vuln_id=vuln_id,
        source=source,
        severity="HIGH",
        component_name="picomatch",
        component_version="4.0.7",
        purl="pkg:npm/picomatch@4.0.7",
        dt_project_uuid=project_uuid,
        dt_component_uuid=f"component-picomatch-{project_uuid}",
        dt_vulnerability_uuid=f"vuln-{vuln_id}",
    )


@pytest.fixture
def scanned(scan_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Two scanned projects carrying a withdrawn GHSA and its standing CVE alias."""
    from app.services import ignores

    monkeypatch.setattr(ignores, "METRICS_SETTLE_INTERVAL_SECONDS", 0)
    source: FakeSource = scan_client.app.state.source
    source._projects = [  # noqa: SLF001 - test fake
        project("10", "team/app", default_branch="main"),
        project("11", "team/api", default_branch="main"),
    ]
    source._branches = {  # noqa: SLF001 - test fake
        "10": [branch("main", is_default=True)],
        "11": [branch("main", is_default=True)],
    }
    target_id = scan_client.post(
        "/api/targets", json={"kind": "group", "source_ref": "1"}
    ).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    _run_sql(
        scan_client,
        "UPDATE projects SET dt_project_uuid = 'dt-' || source_project_id || '-' || branch",
    )
    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.findings = {
        uuid: [finding(GHSA, "GITHUB", uuid), finding(CVE, "NVD", uuid)]
        for uuid in ("dt-10-main", "dt-11-main")
    }
    scan_client.app.state.advisories = FakeAdvisories({GHSA.upper(): WITHDRAWN})
    return scan_client


def _run_sql(client: TestClient, statement: str) -> None:
    from sqlalchemy import text

    from app.db import session_factory

    async def execute() -> None:
        async with session_factory()() as session:
            await session.execute(text(statement))
            await session.commit()

    client.portal.call(execute)  # type: ignore[attr-defined]


def test_a_withdrawn_advisory_is_suppressed_everywhere(scanned: TestClient) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack

    result = scanned.post("/api/ignores/apply").json()

    assert result["suppressed"] == 2
    suppressed = [call for call in dtrack.analyses if call.suppressed]
    assert {call.vulnerability_uuid for call in suppressed} == {f"vuln-{GHSA}"}
    assert {call.analysis_state for call in suppressed} == {"FALSE_POSITIVE"}
    assert all("withdrawn" in (call.comment or "") for call in suppressed)

    rules = scanned.get("/api/ignores").json()["items"]
    assert len(rules) == 1
    assert rules[0]["vuln_id"] == GHSA.upper()
    assert rules[0]["origin"] == "withdrawn"
    assert rules[0]["target_id"] is None
    assert rules[0]["withdrawn_at"].startswith("2026-11-18")


def test_the_cve_alias_stays_while_the_cve_itself_stands(scanned: TestClient) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack

    scanned.post("/api/ignores/apply")

    assert all(call.vulnerability_uuid != f"vuln-{CVE}" for call in dtrack.analyses)


def test_a_known_advisory_is_not_asked_about_again_until_the_daily_pass(
    scanned: TestClient,
) -> None:
    advisories: FakeAdvisories = scanned.app.state.advisories
    scanned.post("/api/ignores/apply")
    assert sorted(advisories.calls) == sorted([GHSA, CVE])

    advisories.calls.clear()
    scanned.post("/api/ignores/apply")

    assert advisories.calls == []


def test_a_restored_advisory_loses_its_rule(scanned: TestClient) -> None:
    from app.db import session_factory
    from app.services.advisories import sync_withdrawn

    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    advisories: FakeAdvisories = scanned.app.state.advisories
    scanned.post("/api/ignores/apply")
    dtrack.analyses.clear()

    advisories.withdrawn.clear()

    async def daily() -> None:
        async with session_factory()() as session:
            # The daily pass, a day later.
            await sync_withdrawn(
                session, dtrack, advisories, now=datetime(2099, 1, 1, tzinfo=UTC)  # type: ignore[arg-type]
            )

    scanned.portal.call(daily)  # type: ignore[attr-defined]

    assert scanned.get("/api/ignores").json()["total"] == 0
    reverted = [call for call in dtrack.analyses if not call.suppressed]
    assert sorted(call.project_uuid for call in reverted) == ["dt-10-main", "dt-11-main"]


def test_a_deleted_automatic_rule_does_not_come_back(scanned: TestClient) -> None:
    scanned.post("/api/ignores/apply")
    rule_id = scanned.get("/api/ignores").json()["items"][0]["id"]

    assert scanned.delete(f"/api/ignores/{rule_id}").status_code == 204
    scanned.post("/api/ignores/apply")

    assert scanned.get("/api/ignores").json()["total"] == 0


def test_an_unreachable_upstream_changes_nothing(scanned: TestClient) -> None:
    advisories: FakeAdvisories = scanned.app.state.advisories
    advisories.fails = True

    response = scanned.post("/api/ignores/apply")

    assert response.status_code == 200
    assert scanned.get("/api/ignores").json()["total"] == 0
    # Not remembered as "stands": the next pass asks again.
    advisories.fails = False
    scanned.post("/api/ignores/apply")
    assert scanned.get("/api/ignores").json()["total"] == 1


def test_a_manual_rule_for_the_same_advisory_is_kept(scanned: TestClient) -> None:
    scanned.post("/api/ignores", json={"vuln_id": GHSA, "reason": "known"})

    scanned.post("/api/ignores/apply")

    rules = scanned.get("/api/ignores").json()["items"]
    assert [rule["origin"] for rule in rules] == ["manual"]
