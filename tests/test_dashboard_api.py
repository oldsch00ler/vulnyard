# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Dashboard, project listing, findings and vulnerabilities (SPEC 9.4, 12)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.services.dtrack import (
    DTAffectedProject,
    DTFinding,
    DTGroupedVulnerability,
    DTMetrics,
    DTProject,
)
from tests.fakes import FakeDependencyTrack, FakeSource, branch, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


@pytest.fixture
def scanned(scan_client: TestClient) -> TestClient:
    """Two scanned projects (plus a second branch) with metrics in Dependency-Track."""
    source: FakeSource = scan_client.app.state.source
    source._projects = [  # noqa: SLF001 - test fake
        project("10", "team/app", default_branch="main"),
        project("11", "team/api", default_branch="main"),
    ]
    source._branches = {  # noqa: SLF001 - test fake
        "10": [branch("main", is_default=True), branch("develop")],
        "11": [branch("main", is_default=True)],
    }

    # Custom branch selection, so team/app also has a develop row to test the
    # "default branch only" rules of the summary and the trend.
    target_id = scan_client.post(
        "/api/targets",
        json={**GROUP_TARGET, "branch_mode": "custom", "branch_patterns": ["develop"]},
    ).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")

    # Pretend the jobs finished and Dependency-Track knows the projects.
    _run_sql(
        scan_client,
        """
        UPDATE projects
           SET dt_project_uuid = 'dt-' || source_project_id || '-' || branch,
               last_scanned_sha = last_commit_sha,
               last_scan_status = 'done',
               last_scan_at = now()
        """,
    )
    _run_sql(scan_client, "UPDATE scan_jobs SET status = 'done', finished_at = now()")

    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.projects = [
        DTProject(
            uuid="dt-10-main",
            name="team/app",
            version="main",
            metrics=DTMetrics(
                critical=2, high=3, medium=1, low=0, unassigned=1,
                components=40, vulnerable_components=5, inherited_risk_score=57.0,
            ),
        ),
        DTProject(
            uuid="dt-11-main",
            name="team/api",
            version="main",
            metrics=DTMetrics(
                critical=0, high=1, medium=2, low=4, unassigned=0,
                components=12, vulnerable_components=2, inherited_risk_score=11.5,
            ),
        ),
        DTProject(
            uuid="dt-10-develop",
            name="team/app",
            version="develop",
            metrics=DTMetrics(critical=9, high=9, components=41, vulnerable_components=9),
        ),
    ]
    _invalidate(scan_client)
    return scan_client


def test_summary_counts_only_default_branches(scanned: TestClient) -> None:
    body = scanned.get("/api/dashboard/summary").json()

    # The develop branch of team/app must not be added to the totals (SPEC 9.2).
    assert body["severities"] == {"critical": 2, "high": 4, "medium": 3, "low": 4, "unassigned": 1}
    assert body["findings_total"] == 14
    assert body["projects_total"] == 2
    assert body["projects_scanned"] == 2
    assert body["projects_vulnerable"] == 2
    assert body["components"] == 52
    assert body["vulnerable_components"] == 7


def test_summary_reports_the_state_of_scanning(scanned: TestClient) -> None:
    body = scanned.get("/api/dashboard/summary").json()

    assert body["scan_state"]["last_run_id"] == 1
    assert body["scan_state"]["failed_jobs_24h"] == 0


def test_summary_works_without_dependency_track(scan_client: TestClient) -> None:
    scan_client.app.state.dtrack = None
    _invalidate(scan_client)

    body = scan_client.get("/api/dashboard/summary").json()

    assert body["findings_total"] == 0
    assert body["projects_total"] == 0


def test_top_projects_are_ordered_by_risk(scanned: TestClient) -> None:
    body = scanned.get("/api/dashboard/top-projects?limit=5").json()

    assert [item["path_with_namespace"] for item in body] == ["team/app", "team/api"]
    assert body[0]["risk_score"] == 57.0
    assert body[0]["severities"]["critical"] == 2
    assert body[0]["targets"] == ["Team"]


def test_project_listing_filters_and_sorts(scanned: TestClient) -> None:
    default_only = scanned.get("/api/projects").json()
    assert default_only["total"] == 2
    assert {item["branch"] for item in default_only["items"]} == {"main"}

    all_branches = scanned.get("/api/projects?branch=all").json()
    assert all_branches["total"] == 3

    by_path = scanned.get("/api/projects?sort=path").json()
    assert [item["path_with_namespace"] for item in by_path["items"]] == ["team/api", "team/app"]

    searched = scanned.get("/api/projects?search=api").json()
    assert [item["path_with_namespace"] for item in searched["items"]] == ["team/api"]

    critical_only = scanned.get("/api/projects?min_severity=critical").json()
    assert [item["path_with_namespace"] for item in critical_only["items"]] == ["team/app"]


def test_project_listing_filters_by_target(scanned: TestClient) -> None:
    assert scanned.get("/api/projects?target_id=1").json()["total"] == 2
    assert scanned.get("/api/projects?target_id=999").json()["total"] == 0


def test_project_listing_pages(scanned: TestClient) -> None:
    first = scanned.get("/api/projects?page_size=1&page=1").json()
    second = scanned.get("/api/projects?page_size=1&page=2").json()

    assert first["total"] == 2
    assert first["items"][0]["id"] != second["items"][0]["id"]


def test_project_detail_lists_branches_and_metrics(scanned: TestClient) -> None:
    listing = scanned.get("/api/projects?search=app").json()
    project_id = listing["items"][0]["id"]

    body = scanned.get(f"/api/projects/{project_id}").json()

    assert body["path_with_namespace"] == "team/app"
    assert body["severities"]["critical"] == 2
    assert [b["branch"] for b in body["branches"]] == ["main", "develop"]
    assert body["branch_override"] is None
    assert body["last_scanned_sha"] == body["last_commit_sha"]


def test_project_findings_come_from_dependency_track(scanned: TestClient) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    dtrack.findings["dt-10-main"] = [
        DTFinding(
            vuln_id="CVE-2026-0001",
            source="NVD",
            severity="MEDIUM",
            component_name="left-pad",
            component_version="1.3.0",
        ),
        DTFinding(
            vuln_id="CVE-2026-9999",
            source="NVD",
            severity="CRITICAL",
            cvss_v3_score=9.8,
            epss_score=0.42,
            component_name="requests",
            component_version="2.31.0",
            purl="pkg:pypi/requests@2.31.0",
        ),
        DTFinding(
            vuln_id="CVE-2026-0002",
            source="NVD",
            severity="HIGH",
            component_name="hidden",
            suppressed=True,
        ),
    ]
    project_id = scanned.get("/api/projects?search=app").json()["items"][0]["id"]

    body = scanned.get(f"/api/projects/{project_id}/findings").json()

    # Suppressed findings are left out and the rest is ordered by severity.
    assert [item["vuln_id"] for item in body["items"]] == ["CVE-2026-9999", "CVE-2026-0001"]
    assert body["total"] == 2
    assert body["items"][0]["cvss_v3_score"] == 9.8
    assert body["items"][0]["epss_score"] == 0.42

    with_suppressed = scanned.get(f"/api/projects/{project_id}/findings?suppressed=true").json()
    assert len(with_suppressed["items"]) == 3


def test_findings_of_an_unscanned_project_are_refused(scan_client: TestClient) -> None:
    source: FakeSource = scan_client.app.state.source
    source._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    source._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    project_id = scan_client.get("/api/projects?branch=all").json()["items"][0]["id"]

    response = scan_client.get(f"/api/projects/{project_id}/findings")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "project.not_scanned_yet"


def test_project_history_shows_jobs_and_snapshots(scanned: TestClient) -> None:
    project_id = scanned.get("/api/projects?search=app").json()["items"][0]["id"]
    _run_sql(
        scanned,
        """
        INSERT INTO metric_snapshots (date, project_id, critical, high, medium, low, unassigned,
                                      components, vulnerable_components, suppressed)
        VALUES (:day, :project_id, 1, 2, 3, 4, 0, 40, 5, 0)
        """,
        {"day": (datetime.now(UTC) - timedelta(days=1)).date(), "project_id": project_id},
    )

    body = scanned.get(f"/api/projects/{project_id}/history").json()

    assert len(body["items"]) == 1
    assert body["items"][0]["status"] == "done"
    assert len(body["snapshots"]) == 1
    assert body["snapshots"][0]["high"] == 2


def test_excluding_a_project_hides_it_from_the_listing(scanned: TestClient) -> None:
    project_id = scanned.get("/api/projects?search=api").json()["items"][0]["id"]

    body = scanned.patch(f"/api/projects/{project_id}", json={"excluded": True}).json()
    assert body["excluded"] is True

    assert scanned.get("/api/projects").json()["total"] == 1
    # The detail still works, so it can be put back.
    assert scanned.get(f"/api/projects/{project_id}").json()["excluded"] is True
    scanned.patch(f"/api/projects/{project_id}", json={"excluded": False})
    assert scanned.get("/api/projects").json()["total"] == 2


def test_scanning_one_project_queues_a_single_job(scanned: TestClient) -> None:
    project_id = scanned.get("/api/projects?search=api").json()["items"][0]["id"]

    response = scanned.post(f"/api/projects/{project_id}/scan")

    assert response.status_code == 201
    run = response.json()
    assert run["total"] == 1
    detail = scanned.get(f"/api/runs/{run['id']}").json()
    assert [job["path_with_namespace"] for job in detail["jobs"]] == ["team/api"]


def test_trend_comes_from_our_snapshots(scanned: TestClient) -> None:
    project_ids = [item["id"] for item in scanned.get("/api/projects").json()["items"]]
    today = datetime.now(UTC).date()
    for offset, critical in ((2, 1), (1, 3)):
        for project_id in project_ids:
            _run_sql(
                scanned,
                """
                INSERT INTO metric_snapshots (date, project_id, critical, high, medium, low,
                                              unassigned, components, vulnerable_components, suppressed)
                VALUES (:day, :project_id, :critical, 0, 0, 0, 0, 10, 1, 0)
                """,
                {"day": today - timedelta(days=offset), "project_id": project_id, "critical": critical},
            )

    body = scanned.get("/api/dashboard/trend?days=30").json()

    assert body["days"] == 30
    assert [point["critical"] for point in body["points"]] == [2, 6]
    assert body["points"][0]["projects"] == 2


def test_trend_window_falls_back_to_thirty_days(scanned: TestClient) -> None:
    assert scanned.get("/api/dashboard/trend?days=7").json()["days"] == 30
    assert scanned.get("/api/dashboard/trend?days=180").json()["days"] == 180


def _finding(
    vuln_id: str,
    severity: str,
    *,
    source: str = "NVD",
    purl: str = "pkg:npm/express@5.1.0",
    component: str = "express",
    project_uuid: str = "dt-10-main",
    suppressed: bool = False,
) -> DTFinding:
    """A finding shaped the way Dependency-Track really reports one."""
    return DTFinding(
        vuln_id=vuln_id,
        source=source,
        severity=severity,
        component_name=component,
        component_version=purl.rsplit("@", 1)[-1],
        purl=purl,
        suppressed=suppressed,
        dt_project_uuid=project_uuid,
        dt_component_uuid=f"component-{component}-{project_uuid}",
        dt_vulnerability_uuid=f"vuln-{vuln_id}",
    )


def test_vulnerability_list_is_grouped_and_filterable(scanned: TestClient) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    dtrack.findings = {
        "dt-10-main": [
            _finding("CVE-2026-9999", "CRITICAL"),
            _finding("GHSA-abcd", "HIGH", source="GITHUB", purl="pkg:npm/lodash@4.17.20",
                     component="lodash"),
        ],
        "dt-11-main": [_finding("CVE-2026-9999", "CRITICAL", project_uuid="dt-11-main")],
    }

    body = scanned.get("/api/vulnerabilities").json()
    # Worst first, then by how many of our projects it hits.
    assert [item["vuln_id"] for item in body["items"]] == ["CVE-2026-9999", "GHSA-abcd"]
    assert body["total"] == 2
    assert body["items"][0]["affected_project_count"] == 2
    assert body["items"][1]["affected_project_count"] == 1

    critical = scanned.get("/api/vulnerabilities?min_severity=critical").json()
    assert [item["vuln_id"] for item in critical["items"]] == ["CVE-2026-9999"]

    searched = scanned.get("/api/vulnerabilities?search=ghsa").json()
    assert [item["vuln_id"] for item in searched["items"]] == ["GHSA-abcd"]


def test_the_summary_leaves_out_projects_that_are_not_ours(scanned: TestClient) -> None:
    """A shared Dependency-Track holds other teams' projects (SPEC 12.4).

    Its grouped endpoint has no project filter, so the summary has to be built
    from the findings of the projects we scan.
    """
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    dtrack.findings = {
        "dt-10-main": [_finding("CVE-2026-0001", "HIGH")],
        # Not one of ours: never discovered, never scanned by us.
        "somebody-elses-project": [_finding("CVE-2026-7777", "CRITICAL",
                                            project_uuid="somebody-elses-project")],
    }
    # The portfolio-wide answer would have carried it in.
    dtrack.grouped = [
        DTGroupedVulnerability(vuln_id="CVE-2026-7777", source="NVD", severity="CRITICAL",
                               affected_project_count=1),
    ]

    body = scanned.get("/api/vulnerabilities").json()

    assert [item["vuln_id"] for item in body["items"]] == ["CVE-2026-0001"]
    assert body["total"] == 1


def test_ignored_findings_are_hidden_unless_asked_for(scanned: TestClient) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    dtrack.findings = {
        "dt-10-main": [
            _finding("CVE-2026-0001", "HIGH"),
            _finding("CVE-2026-0002", "HIGH", purl="pkg:npm/ignored@1.0.0",
                     component="ignored", suppressed=True),
        ],
    }

    default = scanned.get("/api/vulnerabilities").json()
    assert [item["vuln_id"] for item in default["items"]] == ["CVE-2026-0001"]

    with_ignored = scanned.get("/api/vulnerabilities?include_ignored=true").json()
    assert [item["vuln_id"] for item in with_ignored["items"]] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert [item["ignored"] for item in with_ignored["items"]] == [False, True]


def test_affected_projects_name_our_projects_and_components(scanned: TestClient) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    dtrack.findings = {
        "dt-10-main": [_finding("CVE-2026-9999", "CRITICAL")],
        "dt-11-main": [
            _finding("CVE-2026-9999", "CRITICAL", purl="pkg:npm/lodash@4.17.20",
                     component="lodash", project_uuid="dt-11-main"),
        ],
        "somebody-elses-project": [
            _finding("CVE-2026-9999", "CRITICAL", project_uuid="somebody-elses-project"),
        ],
    }

    body = scanned.get("/api/vulnerabilities/NVD/CVE-2026-9999/projects").json()

    assert [item["path_with_namespace"] for item in body["items"]] == ["team/api", "team/app"]
    assert body["total"] == 2
    assert body["ours"] == 2
    # The component is what somebody actually has to upgrade.
    assert [one["purl"] for one in body["components"]] == [
        "pkg:npm/lodash@4.17.20",
        "pkg:npm/express@5.1.0",
    ]


def test_an_unknown_vulnerability_is_empty_not_an_error(scanned: TestClient) -> None:
    body = scanned.get("/api/vulnerabilities/NVD/CVE-1999-0001/projects").json()

    assert body["items"] == []
    assert body["total"] == 0


def test_vulnerabilities_need_dependency_track(scan_client: TestClient) -> None:
    scan_client.app.state.dtrack = None

    response = scan_client.get("/api/vulnerabilities")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "dtrack.not_configured"


def test_an_unsupported_dependency_track_disables_findings(scan_client: TestClient) -> None:
    scan_client.app.state.dtrack = FakeDependencyTrack(version="4.11.0")

    response = scan_client.get("/api/vulnerabilities")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "dtrack.version_unsupported"


def test_dependency_track_data_is_cached(scanned: TestClient) -> None:
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    before = dtrack.list_projects_calls

    scanned.get("/api/dashboard/summary")
    scanned.get("/api/dashboard/summary")
    scanned.get("/api/projects")

    # Three requests, one call to Dependency-Track (SPEC 9.4: 60 second cache).
    assert dtrack.list_projects_calls == before + 1


def test_a_finished_scan_invalidates_the_cache(scanned: TestClient) -> None:
    from app.services.dashboard import invalidate_cache

    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    scanned.get("/api/dashboard/summary")
    calls_after_first = dtrack.list_projects_calls

    invalidate_cache()
    scanned.get("/api/dashboard/summary")

    assert dtrack.list_projects_calls == calls_after_first + 1


# --- helpers ------------------------------------------------------------------


def _invalidate(client: TestClient) -> None:
    from app.services.dashboard import invalidate_cache

    invalidate_cache()


def _run_sql(client: TestClient, statement: str, params: dict[str, object] | None = None) -> None:
    from sqlalchemy import text

    from app.db import session_factory

    async def execute() -> None:
        async with session_factory()() as session:
            await session.execute(text(statement), params or {})
            await session.commit()

    client.portal.call(execute)  # type: ignore[attr-defined]
