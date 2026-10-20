# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Ignore rules: matching, scope, expiry and what reaches Dependency-Track."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app.models import IgnoreRule
from app.services.dtrack import DTFinding
from app.services.ignores import is_active, matches, rule_comment
from tests.fakes import FakeDependencyTrack, FakeSource, branch, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}
EXPRESS = "pkg:npm/express@5.1.0"


def finding(
    vuln_id: str = "CVE-2026-0001",
    *,
    purl: str = EXPRESS,
    component: str = "express",
    project_uuid: str = "dt-10-main",
    severity: str = "HIGH",
    suppressed: bool = False,
) -> DTFinding:
    return DTFinding(
        vuln_id=vuln_id,
        source="NVD",
        severity=severity,
        component_name=component,
        component_version=purl.rsplit("@", 1)[-1],
        purl=purl,
        suppressed=suppressed,
        dt_project_uuid=project_uuid,
        dt_component_uuid=f"component-{component}-{project_uuid}",
        dt_vulnerability_uuid=f"vuln-{vuln_id}",
    )


def rule(**overrides: object) -> IgnoreRule:
    defaults: dict[str, object] = {
        "id": 1,
        "vuln_id": "CVE-2026-0001",
        "purl_pattern": "*",
        "target_id": None,
        "analysis_state": "NOT_AFFECTED",
        "reason": "",
        "expires_on": None,
    }
    return IgnoreRule(**{**defaults, **overrides})  # type: ignore[arg-type]


# --- matching -----------------------------------------------------------------


def test_a_rule_without_a_pattern_covers_any_component() -> None:
    assert matches(rule(), finding()) is True
    assert matches(rule(), finding(purl="pkg:pypi/django@5.0", component="django")) is True


def test_a_rule_only_covers_its_own_vulnerability() -> None:
    assert matches(rule(vuln_id="CVE-2026-0001"), finding("CVE-2026-0002")) is False


def test_the_vulnerability_id_is_compared_without_case_or_spaces() -> None:
    assert matches(rule(vuln_id=" cve-2026-0001 "), finding("CVE-2026-0001")) is True


@pytest.mark.parametrize(
    ("pattern", "purl", "expected"),
    [
        ("pkg:npm/express@5.*", "pkg:npm/express@5.1.0", True),
        ("pkg:npm/express@5.*", "pkg:npm/express@5.0.0-beta.1", True),
        # A different major version is exactly what the pattern excludes.
        ("pkg:npm/express@5.*", "pkg:npm/express@4.18.2", False),
        ("pkg:npm/express@5.*", "pkg:npm/expressive@5.1.0", False),
        ("pkg:npm/*", "pkg:npm/lodash@4.17.20", True),
        ("pkg:npm/*", "pkg:pypi/django@5.0", False),
        # Qualifiers after the version still match a trailing wildcard.
        ("pkg:npm/express@5.*", "pkg:npm/express@5.1.0?arch=x64", True),
    ],
)
def test_the_pattern_narrows_the_rule_to_components(
    pattern: str, purl: str, expected: bool
) -> None:
    assert matches(rule(purl_pattern=pattern), finding(purl=purl)) is expected


def test_a_component_without_a_purl_never_matches_a_pattern() -> None:
    nameless = DTFinding(vuln_id="CVE-2026-0001", source="NVD", severity="HIGH", purl=None)

    assert matches(rule(purl_pattern="pkg:npm/*"), nameless) is False
    # But "anything here" still covers it.
    assert matches(rule(), nameless) is True


# --- expiry -------------------------------------------------------------------


def test_a_rule_without_an_end_date_always_holds() -> None:
    assert is_active(rule()) is True


def test_a_rule_holds_up_to_and_including_its_last_day() -> None:
    today = date(2026, 9, 29)

    assert is_active(rule(expires_on=today), today=today) is True
    assert is_active(rule(expires_on=today - timedelta(days=1)), today=today) is False


def test_the_comment_tells_a_dependency_track_reader_where_it_came_from() -> None:
    text = rule_comment(
        rule(id=7, purl_pattern="pkg:npm/express@5.*", reason="čekáme na upstream fix",
             expires_on=date(2026, 12, 31))
    )

    assert "Vulnyard" in text
    assert "#7" in text
    assert "global" in text
    assert "pkg:npm/express@5.*" in text
    assert "2026-12-31" in text
    assert "čekáme na upstream fix" in text


# --- through the API ----------------------------------------------------------


@pytest.fixture
def scanned(scan_client: TestClient) -> tuple[TestClient, int]:
    """One target with two scanned projects, both known to Dependency-Track."""
    source: FakeSource = scan_client.app.state.source
    source._projects = [  # noqa: SLF001 - test fake
        project("10", "team/app", default_branch="main"),
        project("11", "team/api", default_branch="main"),
    ]
    source._branches = {  # noqa: SLF001 - test fake
        "10": [branch("main", is_default=True)],
        "11": [branch("main", is_default=True)],
    }
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    _run_sql(
        scan_client,
        "UPDATE projects SET dt_project_uuid = 'dt-' || source_project_id || '-' || branch",
    )

    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.findings = {
        "dt-10-main": [finding(), finding("CVE-2026-0002", purl="pkg:npm/lodash@4.17.20",
                                         component="lodash")],
        "dt-11-main": [finding(project_uuid="dt-11-main")],
    }
    return scan_client, target_id


@pytest.fixture
def no_metrics_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the wait for Dependency-Track in tests that are not about it."""
    from app.services import ignores

    monkeypatch.setattr(ignores, "METRICS_SETTLE_INTERVAL_SECONDS", 0)


def _run_sql(client: TestClient, statement: str, params: dict[str, object] | None = None) -> None:
    from sqlalchemy import text

    from app.db import session_factory

    async def execute() -> None:
        async with session_factory()() as session:
            await session.execute(text(statement), params or {})
            await session.commit()

    client.portal.call(execute)  # type: ignore[attr-defined]


def test_a_global_rule_is_suppressed_in_every_project(
    scanned: tuple[TestClient, int],
) -> None:
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack

    response = client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001", "reason": "nepoužíváme"})

    assert response.status_code == 201
    body = response.json()
    assert body["target_id"] is None
    assert body["applied_count"] == 2
    # Both of our projects carry it, so both get the suppression.
    suppressed = [call for call in dtrack.analyses if call.suppressed]
    assert sorted(call.project_uuid for call in suppressed) == ["dt-10-main", "dt-11-main"]
    assert {call.analysis_state for call in suppressed} == {"NOT_AFFECTED"}
    assert all("nepoužíváme" in (call.comment or "") for call in suppressed)


def test_a_target_rule_stays_inside_that_target(scanned: tuple[TestClient, int]) -> None:
    client, target_id = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack

    # A second target with a project of its own, which the rule must not touch.
    source: FakeSource = client.app.state.source
    source._projects = [project("12", "other/app", default_branch="main")]  # noqa: SLF001
    source._branches = {"12": [branch("main", is_default=True)]}  # noqa: SLF001
    other_id = client.post(
        "/api/targets", json={"kind": "project", "source_ref": "12"}
    ).json()["id"]
    client.post(f"/api/targets/{other_id}/scan")
    _run_sql(
        client,
        "UPDATE projects SET dt_project_uuid = 'dt-12-main' WHERE source_project_id = '12'",
    )
    dtrack.findings["dt-12-main"] = [finding(project_uuid="dt-12-main")]

    client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001", "target_id": target_id})

    touched = {call.project_uuid for call in dtrack.analyses if call.suppressed}
    assert touched == {"dt-10-main", "dt-11-main"}
    assert "dt-12-main" not in touched


def test_a_pattern_picks_one_component_only(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    dtrack.findings["dt-10-main"] = [
        finding(purl="pkg:npm/express@5.1.0"),
        finding(purl="pkg:npm/express@4.18.2", component="express-old"),
    ]

    client.post(
        "/api/ignores",
        json={"vuln_id": "CVE-2026-0001", "purl_pattern": "pkg:npm/express@5.*"},
    )

    suppressed = [call for call in dtrack.analyses if call.suppressed]
    assert [call.component_uuid for call in suppressed] == [
        "component-express-dt-10-main",
        # team/api has the 5.x version too.
        "component-express-dt-11-main",
    ]


def test_deleting_a_rule_takes_the_suppression_back(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    rule_id = client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"}).json()["id"]
    dtrack.analyses.clear()

    assert client.delete(f"/api/ignores/{rule_id}").status_code == 204

    reverted = [call for call in dtrack.analyses if not call.suppressed]
    assert sorted(call.project_uuid for call in reverted) == ["dt-10-main", "dt-11-main"]
    assert {call.analysis_state for call in reverted} == {"NOT_SET"}
    assert client.get("/api/ignores").json()["total"] == 0


def test_narrowing_a_rule_releases_what_it_no_longer_covers(
    scanned: tuple[TestClient, int],
) -> None:
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    dtrack.findings["dt-10-main"] = [
        finding(purl="pkg:npm/express@5.1.0"),
        finding(purl="pkg:npm/express@4.18.2", component="express-old"),
    ]
    rule_id = client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"}).json()["id"]
    dtrack.analyses.clear()

    client.patch(f"/api/ignores/{rule_id}", json={"purl_pattern": "pkg:npm/express@5.*"})

    released = [call for call in dtrack.analyses if not call.suppressed]
    assert [call.component_uuid for call in released] == ["component-express-old-dt-10-main"]


def test_an_expired_rule_stops_holding(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    rule_id = client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"}).json()["id"]
    dtrack.analyses.clear()

    # Backdated in the database: the API refuses a date in the past on purpose.
    _run_sql(
        client,
        "UPDATE ignore_rules SET expires_on = CURRENT_DATE - 1 WHERE id = :id",
        {"id": rule_id},
    )
    result = client.post("/api/ignores/apply").json()

    assert result["reverted"] == 2
    assert [call.suppressed for call in dtrack.analyses] == [False, False]
    # The rule stays as history, marked inactive.
    listed = client.get("/api/ignores").json()["items"]
    assert listed[0]["active"] is False
    assert listed[0]["applied_count"] == 0


def test_the_same_rule_cannot_be_added_twice(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned
    client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"})

    again = client.post("/api/ignores", json={"vuln_id": "cve-2026-0001"})

    assert again.status_code == 409
    assert again.json()["error"]["code"] == "ignore.duplicate"


def test_the_same_vulnerability_can_be_ignored_per_target_and_globally(
    scanned: tuple[TestClient, int],
) -> None:
    client, target_id = scanned
    assert client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"}).status_code == 201
    scoped = client.post(
        "/api/ignores", json={"vuln_id": "CVE-2026-0001", "target_id": target_id}
    )

    assert scoped.status_code == 201


def test_applying_is_idempotent(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"})
    dtrack.analyses.clear()

    result = client.post("/api/ignores/apply").json()

    assert result["suppressed"] == 0
    assert result["reverted"] == 0
    assert dtrack.analyses == []


def test_a_failing_dependency_track_is_reported_not_swallowed(
    scanned: tuple[TestClient, int],
) -> None:
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    dtrack.analysis_fails = True

    created = client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"})

    # The rule is stored - it is a decision, not a Dependency-Track state - but
    # nothing was suppressed, and re-applying later is what fixes it.
    assert created.status_code == 201
    assert created.json()["applied_count"] == 0
    dtrack.analysis_fails = False
    assert client.post("/api/ignores/apply").json()["suppressed"] == 2


# --- validation ---------------------------------------------------------------


def test_an_empty_vulnerability_id_is_refused(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned

    response = client.post("/api/ignores", json={"vuln_id": "  "})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.vuln_id_required"


def test_an_unknown_analysis_state_is_refused(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned

    response = client.post(
        "/api/ignores", json={"vuln_id": "CVE-2026-0001", "analysis_state": "WHATEVER"}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.analysis_state_invalid"


def test_a_rule_for_an_unknown_target_is_refused(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned

    response = client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001", "target_id": 999})

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "target.not_found"


def test_an_end_date_in_the_past_is_refused(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned
    yesterday = (date.today() - timedelta(days=1)).isoformat()

    response = client.post(
        "/api/ignores", json={"vuln_id": "CVE-2026-0001", "expires_on": yesterday}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.expires_on_in_past"


def test_an_end_date_from_today_on_is_accepted(scanned: tuple[TestClient, int]) -> None:
    client, _ = scanned
    soon = (date.today() + timedelta(days=30)).isoformat()

    response = client.post(
        "/api/ignores", json={"vuln_id": "CVE-2026-0001", "expires_on": soon}
    )

    assert response.status_code == 201
    assert response.json()["expires_on"] == soon
    assert response.json()["active"] is True


# --- the worker applies them too ----------------------------------------------


def test_a_scan_applies_the_rules_to_the_project_it_scanned(
    scanned: tuple[TestClient, int],
) -> None:
    """A new scan brings new component versions, so rules are re-applied."""
    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"})

    # A scan finds the vulnerability in a version that did not exist before.
    dtrack.findings["dt-10-main"] = [
        finding(purl="pkg:npm/express@5.2.0", component="express-new"),
    ]
    dtrack.analyses.clear()

    _apply_for_first_project(client)

    suppressed = [call for call in dtrack.analyses if call.suppressed]
    assert [call.component_uuid for call in suppressed] == ["component-express-new-dt-10-main"]
    # Metrics are recomputed, otherwise the chat notification would announce a
    # vulnerability that is being ignored.
    assert "dt-10-main" in dtrack.refreshed


def _apply_for_first_project(client: TestClient) -> None:
    """Run the worker's ignore step for the project of the first job."""
    import sqlalchemy

    from app.db import session_factory
    from app.models import Project, ScanJob

    worker = client.app.state.worker

    async def run() -> None:
        async with session_factory()() as session:
            job = (await session.execute(sqlalchemy.select(ScanJob))).scalars().first()
            project = await session.get(Project, job.project_id)
            await worker._apply_ignore_rules(session, project)  # noqa: SLF001

    client.portal.call(run)  # type: ignore[attr-defined]


def test_the_worker_waits_for_the_metrics_to_catch_up(
    scanned: tuple[TestClient, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dependency-Track only *requests* a metrics refresh; it is asynchronous."""
    from app.services import ignores
    from app.services.dtrack import DTMetrics

    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    monkeypatch.setattr(ignores, "METRICS_SETTLE_INTERVAL_SECONDS", 0)

    # Two reads report the old number, then the suppression shows up.
    answers = [
        DTMetrics(high=2, suppressed=0),
        DTMetrics(high=2, suppressed=0),
        DTMetrics(high=1, suppressed=1),
    ]
    reads: list[str] = []

    async def metrics(uuid: str) -> DTMetrics:
        reads.append(uuid)
        return answers[min(len(reads) - 1, len(answers) - 1)]

    monkeypatch.setattr(dtrack, "current_project_metrics", metrics)
    client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001", "target_id": None})

    reads.clear()
    dtrack.findings["dt-10-main"] = [finding(purl="pkg:npm/express@5.9.9", component="fresh")]
    _apply_for_first_project(client)

    # One read for the baseline, then two polls: it stops as soon as the number
    # agrees instead of waiting out the bound.
    assert len(reads) == 3


# --- the trend has to agree with the cards above it ---------------------------


def test_ignoring_updates_todays_point_of_the_trend(
    scanned: tuple[TestClient, int], no_metrics_wait: None
) -> None:
    """The trend reads daily snapshots; today's is written in the morning.

    Without re-taking it, the graph would keep showing a finding that was just
    ignored, right under cards that already say zero.
    """
    from app.services.dtrack import DTMetrics, DTProject

    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    # This morning: one medium finding in each project.
    dtrack.projects = [
        DTProject(uuid="dt-10-main", name="team/app", version="main",
                  metrics=DTMetrics(medium=1, components=10)),
        DTProject(uuid="dt-11-main", name="team/api", version="main",
                  metrics=DTMetrics(medium=1, components=10)),
    ]
    _run_sql(
        client,
        "INSERT INTO metric_snapshots (date, project_id, critical, high, medium, low,"
        " unassigned, components, vulnerable_components, suppressed)"
        " SELECT CURRENT_DATE, id, 0, 0, 1, 0, 0, 10, 1, 0 FROM projects",
    )
    assert _todays_medium(client) == 2

    # Dependency-Track now reports them as suppressed.
    dtrack.projects = [
        DTProject(uuid="dt-10-main", name="team/app", version="main",
                  metrics=DTMetrics(medium=0, suppressed=1, components=10)),
        DTProject(uuid="dt-11-main", name="team/api", version="main",
                  metrics=DTMetrics(medium=0, suppressed=1, components=10)),
    ]
    client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"})

    assert _todays_medium(client) == 0


def test_yesterdays_point_is_history_and_stays(
    scanned: tuple[TestClient, int], no_metrics_wait: None
) -> None:
    from app.services.dtrack import DTMetrics, DTProject

    client, _ = scanned
    dtrack: FakeDependencyTrack = client.app.state.dtrack
    dtrack.projects = [
        DTProject(uuid="dt-10-main", name="team/app", version="main",
                  metrics=DTMetrics(medium=0, suppressed=1, components=10)),
    ]
    _run_sql(
        client,
        "INSERT INTO metric_snapshots (date, project_id, critical, high, medium, low,"
        " unassigned, components, vulnerable_components, suppressed)"
        " SELECT CURRENT_DATE - 1, id, 0, 0, 5, 0, 0, 10, 1, 0 FROM projects",
    )

    client.post("/api/ignores", json={"vuln_id": "CVE-2026-0001"})

    points = client.get("/api/dashboard/trend?days=30").json()["points"]
    yesterday = [point for point in points if point["date"] < _today()]
    assert [point["medium"] for point in yesterday] == [10]


def _today() -> str:
    return date.today().isoformat()


def _todays_medium(client: TestClient) -> int:
    points = client.get("/api/dashboard/trend?days=30").json()["points"]
    today = next((point for point in points if point["date"] == _today()), None)
    assert today is not None, points
    return today["medium"]
