# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Failure alerts, the change since the last scan, snapshot retention and the
per-target dashboard."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.services.dtrack import DTMetrics, DTProject
from app.services.notifications import (
    FailureAlert,
    build_alert_message,
    build_message,
    severity_counts,
    severity_delta,
)
from tests.fakes import FakeDependencyTrack, FakeSource, branch, member, project
from tests.test_notifications import WEBHOOK, RecordingNotifier, notification

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


# --- what changed since the last scan -----------------------------------------


def test_delta_is_written_into_the_message() -> None:
    text = build_message(
        notification(
            metrics=DTMetrics(critical=4, high=2),
            previous={"critical": 1, "high": 3, "medium": 0, "low": 0, "unassigned": 0},
        )
    )["text"]

    assert "Od posledního skenu: kritické +3, vysoké −1." in text


def test_first_scan_says_so_instead_of_a_delta() -> None:
    text = build_message(notification(previous=None))["text"]

    assert "První sken tohoto repa." in text


def test_unchanged_counts_are_stated_explicitly() -> None:
    metrics = DTMetrics(critical=2, high=3, medium=1, low=0, unassigned=1)

    text = build_message(notification(metrics=metrics, previous=severity_counts(metrics)))["text"]

    assert "Od posledního skenu bez změny." in text


def test_delta_only_lists_severities_that_moved() -> None:
    delta = severity_delta(
        DTMetrics(critical=1, high=5, medium=2),
        {"critical": 1, "high": 2, "medium": 2, "low": 0, "unassigned": 0},
    )

    assert delta == {"high": 3}


def test_worker_stores_the_counts_as_the_next_baseline(scan_client: TestClient) -> None:
    notifier = RecordingNotifier()
    scan_client.app.state.worker._notifier = notifier  # noqa: SLF001 - wiring for the test
    _scanned_project(scan_client)
    scan_client.put(
        "/api/settings",
        json={"notifications_enabled": True, "notification_webhook_url": WEBHOOK, "notification_min_severity": "high"},
    )

    # First scan: no baseline yet, so the message says it is the first one.
    _notify_and_remember(scan_client)
    assert "První sken" in notifier.sent[0][1]["text"]
    assert _stored_metrics(scan_client) == {"critical": 2, "high": 1, "medium": 0, "low": 0, "unassigned": 0}

    # Second scan with more findings: the message reports the difference.
    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.metrics_by_uuid = {"dt-10-main": DTMetrics(critical=5, high=1)}  # type: ignore[attr-defined]
    _notify_and_remember(scan_client)

    assert "Od posledního skenu: kritické +3." in notifier.sent[1][1]["text"]
    assert _stored_metrics(scan_client)["critical"] == 5


# --- alerts when scanning itself is broken ------------------------------------


def test_alert_message_names_the_problem_and_the_run() -> None:
    payload = build_alert_message(
        FailureAlert(code="source.unauthorized", params={}, run_id=7, failed=5, total=5)
    )

    assert "skenování se nedaří" in payload["text"]
    assert "GITLAB_TOKEN" in payload["text"]
    assert "Běh #7: selhalo 5 z 5 jobů" in payload["text"]
    # Alerts have their own thread, separate from the repositories.
    assert payload["thread"] == {"threadKey": "vulnyard/alerts"}


def test_a_systemic_failure_is_detected(scan_client: TestClient) -> None:
    run_id = _failed_run(scan_client, "dtrack.unauthorized", count="all")

    failure = _systemic(scan_client, run_id)

    assert failure is not None
    code, _params, failed, total = failure
    assert code == "dtrack.unauthorized"
    assert failed == total == 2


def test_one_odd_repository_is_not_a_systemic_failure(scan_client: TestClient) -> None:
    run_id = _failed_run(scan_client, "clone.branch_not_found", count="one")

    assert _systemic(scan_client, run_id) is None


def test_a_project_specific_error_never_alerts(scan_client: TestClient) -> None:
    run_id = _failed_run(scan_client, "trivy.failed", count="all")

    assert _systemic(scan_client, run_id) is None


def test_the_same_alert_is_not_repeated_within_the_cooldown(scan_client: TestClient) -> None:
    from app.db import session_factory
    from app.services.app_settings import should_send_alert

    async def check(code: str) -> bool:
        async with session_factory()() as session:
            return await should_send_alert(session, code)

    assert scan_client.portal.call(check, "source.unauthorized") is True  # type: ignore[attr-defined]
    # Same problem again: stays quiet.
    assert scan_client.portal.call(check, "source.unauthorized") is False  # type: ignore[attr-defined]
    # A different problem is always worth saying.
    assert scan_client.portal.call(check, "dtrack.unreachable") is True  # type: ignore[attr-defined]


# --- snapshot retention -------------------------------------------------------


def test_snapshots_are_kept_longer_than_the_history(scan_client: TestClient) -> None:
    from app.db import session_factory
    from app.services.retention import purge_old_snapshots, snapshot_retention_days

    _scanned_project(scan_client)
    project_id = scan_client.get("/api/projects?branch=all").json()["items"][0]["id"]
    for age in (5, 100, 170, 250):
        _insert_snapshot(scan_client, project_id, age)

    # The history retention is 30 days, but the 180 day trend must still work.
    scan_client.put("/api/settings", json={"history_retention_days": 30})

    async def run() -> tuple[int, int]:
        async with session_factory()() as session:
            days = await snapshot_retention_days(session)
            return days, await purge_old_snapshots(session)

    days, removed = scan_client.portal.call(run)  # type: ignore[attr-defined]

    assert days == 210
    assert removed == 1  # only the 250 day old one
    assert _snapshot_count(scan_client) == 3


def test_snapshot_retention_follows_a_longer_history_setting(scan_client: TestClient) -> None:
    from app.db import session_factory
    from app.services.retention import snapshot_retention_days

    scan_client.put("/api/settings", json={"history_retention_days": 400})

    async def run() -> int:
        async with session_factory()() as session:
            return await snapshot_retention_days(session)

    assert scan_client.portal.call(run) == 400  # type: ignore[attr-defined]


# --- per-target dashboard -----------------------------------------------------


def test_summaries_per_target(scanned_two_targets: TestClient) -> None:
    body = scanned_two_targets.get("/api/dashboard/by-target").json()

    assert body["days"] == 30
    items = {item["name"]: item for item in body["items"]}
    assert set(items) == {"Team", "Other"}

    team = items["Team"]
    assert team["projects_total"] == 1
    assert team["projects_vulnerable"] == 1
    assert team["severities"]["critical"] == 3
    assert team["findings_total"] == 5
    assert team["components"] == 40

    other = items["Other"]
    assert other["severities"]["critical"] == 0
    assert other["findings_total"] == 2
    # Ordered by criticals, so the risky target comes first.
    assert [item["name"] for item in body["items"]] == ["Team", "Other"]


def test_target_summary_reports_the_change_over_the_window(scanned_two_targets: TestClient) -> None:
    project_id = scanned_two_targets.get("/api/projects?search=app").json()["items"][0]["id"]
    _insert_snapshot(scanned_two_targets, project_id, 20, critical=1)
    _insert_snapshot(scanned_two_targets, project_id, 2, critical=4)

    items = {
        item["name"]: item
        for item in scanned_two_targets.get("/api/dashboard/by-target?days=30").json()["items"]
    }

    assert items["Team"]["change"] == 3
    # Without snapshots there is nothing to compare.
    assert items["Other"]["change"] is None


def test_trend_can_be_filtered_to_one_target(scanned_two_targets: TestClient) -> None:
    app_project = scanned_two_targets.get("/api/projects?search=app").json()["items"][0]["id"]
    api_project = scanned_two_targets.get("/api/projects?search=api").json()["items"][0]["id"]
    _insert_snapshot(scanned_two_targets, app_project, 3, critical=2)
    _insert_snapshot(scanned_two_targets, api_project, 3, critical=7)

    everything = scanned_two_targets.get("/api/dashboard/trend?days=30").json()
    assert [point["critical"] for point in everything["points"]] == [9]
    assert everything["target_id"] is None

    team_only = scanned_two_targets.get("/api/dashboard/trend?days=30&target_id=1").json()
    assert [point["critical"] for point in team_only["points"]] == [2]
    assert team_only["target_id"] == 1


# --- fixtures and helpers -----------------------------------------------------


import pytest  # noqa: E402 - fixtures below need it


@pytest.fixture
def scanned_two_targets(scan_client: TestClient) -> TestClient:
    """Two targets, one project each, with metrics in Dependency-Track."""
    source: FakeSource = scan_client.app.state.source
    source._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    source._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001
    scan_client.post("/api/targets", json=GROUP_TARGET)
    scan_client.post("/api/targets/1/scan")

    source._projects = [project("11", "other/api", default_branch="main")]  # noqa: SLF001
    source._branches = {"11": [branch("main", is_default=True)]}  # noqa: SLF001
    source._groups = [  # noqa: SLF001
        *source._groups,  # noqa: SLF001
        __import__("app.services.sources.base", fromlist=["SourceGroup"]).SourceGroup(
            ref="2", path="other", name="Other"
        ),
    ]
    scan_client.post("/api/targets", json={"kind": "group", "source_ref": "2"})
    scan_client.post("/api/targets/2/scan")

    _run_sql(
        scan_client,
        "UPDATE projects SET dt_project_uuid = 'dt-' || source_project_id, last_scan_status = 'done'",
    )

    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.projects = [
        DTProject(
            uuid="dt-10",
            name="team/app",
            version="main",
            metrics=DTMetrics(critical=3, high=2, components=40, vulnerable_components=4,
                              inherited_risk_score=40.0),
        ),
        DTProject(
            uuid="dt-11",
            name="other/api",
            version="main",
            metrics=DTMetrics(medium=2, components=10, vulnerable_components=1,
                              inherited_risk_score=4.0),
        ),
    ]
    from app.services.dashboard import invalidate_cache

    invalidate_cache()
    return scan_client


def _scanned_project(client: TestClient) -> None:
    source: FakeSource = client.app.state.source
    source._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    source._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001
    source.maintainers = {"10": [member("Jan Novák", "jnovak", access_level=40)]}
    client.post("/api/targets", json=GROUP_TARGET)
    client.post("/api/targets/1/scan")
    _run_sql(client, "UPDATE projects SET dt_project_uuid = 'dt-10-main'")

    dtrack: FakeDependencyTrack = client.app.state.dtrack
    dtrack.metrics_by_uuid = {"dt-10-main": DTMetrics(critical=2, high=1)}  # type: ignore[attr-defined]


def _notify_and_remember(client: TestClient) -> None:
    """Run the worker's notification and baseline steps for the first job."""
    from sqlalchemy import select

    from app.db import session_factory
    from app.models import Project, ScanJob

    worker = client.app.state.worker

    async def run() -> None:
        async with session_factory()() as session:
            job = (await session.execute(select(ScanJob))).scalars().first()
            project_row = await session.get(Project, job.project_id)
            await worker._notify(session, job, project_row)  # noqa: SLF001
            await worker._remember_metrics(session, project_row)  # noqa: SLF001

    client.portal.call(run)  # type: ignore[attr-defined]


def _stored_metrics(client: TestClient) -> dict[str, int]:
    return _query(client, "SELECT last_metrics FROM projects LIMIT 1")[0][0]


def _failed_run(client: TestClient, code: str, *, count: str) -> int:
    """A run with two jobs, all or one of them failed with `code`."""
    source: FakeSource = client.app.state.source
    source._projects = [  # noqa: SLF001
        project("10", "team/app", default_branch="main"),
        project("11", "team/api", default_branch="main"),
    ]
    source._branches = {  # noqa: SLF001
        "10": [branch("main", is_default=True)],
        "11": [branch("main", is_default=True)],
    }
    client.post("/api/targets", json=GROUP_TARGET)
    run_id = client.post("/api/targets/1/scan").json()["id"]

    if count == "all":
        _run_sql(
            client,
            "UPDATE scan_jobs SET status = 'failed', error_code = :code, error_params = '{}'::jsonb",
            {"code": code},
        )
    else:
        _run_sql(
            client,
            """
            UPDATE scan_jobs SET status = 'failed', error_code = :code, error_params = '{}'::jsonb
             WHERE id = (SELECT MIN(id) FROM scan_jobs)
            """,
            {"code": code},
        )
        _run_sql(client, "UPDATE scan_jobs SET status = 'done' WHERE error_code IS NULL")
    return run_id


def _systemic(client: TestClient, run_id: int):  # noqa: ANN201 - tuple or None
    from app.db import session_factory
    from app.services.runs import systemic_failure

    async def run():  # noqa: ANN202
        async with session_factory()() as session:
            return await systemic_failure(session, run_id)

    return client.portal.call(run)  # type: ignore[attr-defined]


def _insert_snapshot(client: TestClient, project_id: int, days_ago: int, critical: int = 1) -> None:
    _run_sql(
        client,
        """
        INSERT INTO metric_snapshots (date, project_id, critical, high, medium, low, unassigned,
                                      components, vulnerable_components, suppressed)
        VALUES (:day, :project_id, :critical, 0, 0, 0, 0, 10, 1, 0)
        ON CONFLICT (date, project_id) DO UPDATE SET critical = :critical
        """,
        {
            "day": (datetime.now(UTC) - timedelta(days=days_ago)).date(),
            "project_id": project_id,
            "critical": critical,
        },
    )


def _snapshot_count(client: TestClient) -> int:
    return int(_query(client, "SELECT count(*) FROM metric_snapshots")[0][0])


def _query(client: TestClient, statement: str) -> list[tuple]:
    from sqlalchemy import text

    from app.db import session_factory

    async def run() -> list[tuple]:
        async with session_factory()() as session:
            result = await session.execute(text(statement))
            return [tuple(row) for row in result.all()]

    return client.portal.call(run)  # type: ignore[attr-defined]


def _run_sql(client: TestClient, statement: str, params: dict[str, object] | None = None) -> None:
    from sqlalchemy import text

    from app.db import session_factory

    async def execute() -> None:
        async with session_factory()() as session:
            await session.execute(text(statement), params or {})
            await session.commit()

    client.portal.call(execute)  # type: ignore[attr-defined]
