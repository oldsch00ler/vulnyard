# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Daily metric snapshots and the backfill from Dependency-Track (SPEC 9.4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.services.dtrack import DTMetrics, DTProject
from tests.fakes import FakeDependencyTrack, FakeSource, branch, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


def _scanned_project(client: TestClient, *, uuid: str = "dt-10-main") -> int:
    source: FakeSource = client.app.state.source
    source._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    source._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001
    target_id = client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    client.post(f"/api/targets/{target_id}/scan")
    _run_sql(client, "UPDATE projects SET dt_project_uuid = :uuid", {"uuid": uuid})

    dtrack: FakeDependencyTrack = client.app.state.dtrack
    dtrack.projects = [
        DTProject(
            uuid=uuid,
            name="team/app",
            version="main",
            metrics=DTMetrics(critical=1, high=2, medium=3, low=4, components=30,
                              vulnerable_components=4, inherited_risk_score=23.0, suppressed=1),
        )
    ]
    _invalidate()
    return client.get("/api/projects?branch=all").json()["items"][0]["id"]


def test_snapshot_stores_todays_metrics(scan_client: TestClient) -> None:
    _scanned_project(scan_client)

    written = _snapshot(scan_client)

    assert written == 1
    rows = _query(scan_client, "SELECT date, critical, high, components, suppressed FROM metric_snapshots")
    assert len(rows) == 1
    assert rows[0][1:] == (1, 2, 30, 1)


def test_snapshot_is_idempotent_within_a_day(scan_client: TestClient) -> None:
    _scanned_project(scan_client)

    _snapshot(scan_client)
    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.projects[0].metrics = DTMetrics(critical=5, components=31)
    _invalidate()
    _snapshot(scan_client)

    rows = _query(scan_client, "SELECT critical FROM metric_snapshots")
    # One row per project and day, updated in place (unique date+project).
    assert rows == [(5,)]


def test_projects_without_a_dtrack_uuid_are_skipped(scan_client: TestClient) -> None:
    _scanned_project(scan_client)
    _run_sql(scan_client, "UPDATE projects SET dt_project_uuid = NULL")

    assert _snapshot(scan_client) == 0


def test_backfill_uses_the_history_of_new_projects(scan_client: TestClient) -> None:
    _scanned_project(scan_client)
    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    yesterday = datetime.now(UTC) - timedelta(days=1)
    dtrack.history["dt-10-main"] = [
        DTMetrics(critical=1, last_occurrence=yesterday - timedelta(days=1)),
        DTMetrics(critical=2, last_occurrence=yesterday),
    ]

    written = _backfill(scan_client)

    assert written == 2
    rows = _query(scan_client, "SELECT critical FROM metric_snapshots ORDER BY date")
    assert rows == [(1,), (2,)]

    # A project that already has snapshots is not asked again.
    assert _backfill(scan_client) == 0


# --- helpers ------------------------------------------------------------------


def _invalidate() -> None:
    from app.services.dashboard import invalidate_cache

    invalidate_cache()


def _snapshot(client: TestClient) -> int:
    from app.db import session_factory
    from app.services.snapshots import take_snapshot

    async def run() -> int:
        async with session_factory()() as session:
            return await take_snapshot(session, client.app.state.dtrack)

    return client.portal.call(run)  # type: ignore[attr-defined]


def _backfill(client: TestClient) -> int:
    from app.db import session_factory
    from app.services.snapshots import backfill

    async def run() -> int:
        async with session_factory()() as session:
            return await backfill(session, client.app.state.dtrack)

    return client.portal.call(run)  # type: ignore[attr-defined]


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
