# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scheduler, change detection, branch overrides, retention and cancelling."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.constants import BRANCH_MODE_CUSTOM
from app.services.discovery import BranchSelection, TargetSpec, discover
from tests.fakes import FakeSource, branch, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


# --- change detection (SPEC 7.2) ---------------------------------------------


def _with_project(client: TestClient) -> FakeSource:
    source: FakeSource = client.app.state.source
    source._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    source._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001
    return source


def _mark_scanned(client: TestClient) -> None:
    """Pretend the queued job already scanned this very commit successfully."""
    _run_sql(
        client,
        """
        UPDATE projects
           SET last_scanned_sha = last_commit_sha,
               dt_project_uuid = 'dt-uuid-1',
               last_scan_status = 'done'
        """,
    )
    _run_sql(client, "UPDATE scan_jobs SET status = 'done', finished_at = now()")


def test_unchanged_commit_is_skipped_with_a_reason(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    _mark_scanned(scan_client)

    second = scan_client.post(f"/api/targets/{target_id}/scan").json()

    assert second["total"] == 1
    assert second["skipped"] == 1
    detail = scan_client.get(f"/api/runs/{second['id']}").json()
    job = detail["jobs"][0]
    assert job["status"] == "skipped"
    assert job["skip_reason"] == "job.unchanged"
    assert "nezměnil" in job["skip_message"]


def test_force_rescans_even_an_unchanged_commit(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    _mark_scanned(scan_client)

    forced = scan_client.post(f"/api/targets/{target_id}/scan", params={"force": "true"}).json()

    assert forced["total"] == 1
    assert forced["skipped"] == 0
    detail = scan_client.get(f"/api/runs/{forced['id']}").json()
    assert detail["jobs"][0]["status"] == "queued"


def test_a_new_commit_is_scanned_again(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    _mark_scanned(scan_client)
    # The branch moved on to a new commit in the source.
    source: FakeSource = scan_client.app.state.source
    source._branches = {  # noqa: SLF001 - test fake
        "10": [branch("main", is_default=True, sha="f" * 40)]
    }

    third = scan_client.post(f"/api/targets/{target_id}/scan").json()

    assert third["skipped"] == 0
    assert third["total"] == 1


def test_target_with_skip_unchanged_off_always_scans(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post(
        "/api/targets", json={**GROUP_TARGET, "skip_unchanged": False}
    ).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    _mark_scanned(scan_client)

    second = scan_client.post(f"/api/targets/{target_id}/scan").json()

    assert second["skipped"] == 0
    assert second["total"] == 1


# --- branch overrides ---------------------------------------------------------


async def test_override_wins_over_the_target_selection() -> None:
    source = FakeSource(
        projects=[
            project("10", "team/app", default_branch="main"),
            project("11", "team/api", default_branch="main"),
        ],
        branches={
            "10": [branch("main", is_default=True), branch("develop"), branch("release/1.0")],
            "11": [branch("main", is_default=True), branch("develop")],
        },
    )
    spec = TargetSpec(kind="group", source_ref="1")

    result = await discover(
        source,
        spec,
        overrides={
            "10": BranchSelection(
                branch_mode=BRANCH_MODE_CUSTOM,
                branch_patterns=("develop", "release/*"),
                include_default_branch=False,
            )
        },
    )

    branches = {
        item.project.path_with_namespace: sorted(b.branch for b in item.branches)
        for item in result.projects
    }
    assert branches == {"team/app": ["develop", "release/1.0"], "team/api": ["main"]}


def test_branch_override_api_roundtrip(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    project_id = _first_project_id(scan_client)

    assert scan_client.get(f"/api/projects/{project_id}/branch-override").status_code == 404

    response = scan_client.put(
        f"/api/projects/{project_id}/branch-override",
        json={"branch_mode": "custom", "branch_patterns": ["release/*"], "include_default_branch": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["branch_mode"] == "custom"
    assert body["branch_patterns"] == ["release/*"]
    assert body["path_with_namespace"] == "team/app"

    assert scan_client.get(f"/api/projects/{project_id}/branch-override").status_code == 200
    assert scan_client.delete(f"/api/projects/{project_id}/branch-override").status_code == 204
    assert scan_client.get(f"/api/projects/{project_id}/branch-override").status_code == 404


def test_branch_override_rejects_an_unsafe_pattern(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    project_id = _first_project_id(scan_client)

    response = scan_client.put(
        f"/api/projects/{project_id}/branch-override",
        json={"branch_mode": "custom", "branch_patterns": ["--evil"], "include_default_branch": True},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.branch_pattern_invalid"


def test_branch_override_of_an_unknown_project(scan_client: TestClient) -> None:
    response = scan_client.put(
        "/api/projects/999/branch-override",
        json={"branch_mode": "default", "branch_patterns": [], "include_default_branch": True},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "project.not_found"


# --- cancelling ---------------------------------------------------------------


def test_cancelling_a_run_cancels_its_queued_jobs(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    run_id = scan_client.post(f"/api/targets/{target_id}/scan").json()["id"]

    response = scan_client.post(f"/api/runs/{run_id}/cancel")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "cancelled"
    assert [job["status"] for job in body["jobs"]] == ["cancelled"]


def test_a_finished_run_cannot_be_cancelled(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    run_id = scan_client.post(f"/api/targets/{target_id}/scan").json()["id"]
    scan_client.post(f"/api/runs/{run_id}/cancel")

    response = scan_client.post(f"/api/runs/{run_id}/cancel")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "run.not_cancellable"


# --- retention ----------------------------------------------------------------


def test_retention_deletes_old_runs_but_keeps_pending_ones(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    old_run = scan_client.post(f"/api/targets/{target_id}/scan").json()["id"]
    _run_sql(scan_client, "UPDATE scan_jobs SET status = 'done', finished_at = now()")
    _run_sql(
        scan_client,
        "UPDATE scan_runs SET created_at = :old, status = 'done'",
        {"old": datetime.now(UTC) - timedelta(days=200)},
    )
    # A second, still queued run from the same age must survive.
    pending_run = scan_client.post(f"/api/targets/{target_id}/scan", params={"force": "true"}).json()["id"]
    _run_sql(
        scan_client,
        "UPDATE scan_runs SET created_at = :old WHERE id = :id",
        {"old": datetime.now(UTC) - timedelta(days=200), "id": pending_run},
    )

    removed = _purge(scan_client)

    assert removed == 1
    remaining = [item["id"] for item in scan_client.get("/api/runs").json()["items"]]
    assert remaining == [pending_run]
    assert old_run not in remaining


def test_retention_uses_the_configured_number_of_days(scan_client: TestClient) -> None:
    _with_project(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.post(f"/api/targets/{target_id}/scan")
    _run_sql(scan_client, "UPDATE scan_jobs SET status = 'done', finished_at = now()")
    _run_sql(
        scan_client,
        "UPDATE scan_runs SET created_at = :old, status = 'done'",
        {"old": datetime.now(UTC) - timedelta(days=10)},
    )

    # Default retention is 90 days, so a ten day old run stays.
    assert _purge(scan_client) == 0

    _run_sql(
        scan_client,
        "INSERT INTO settings (key, value) VALUES ('history_retention_days', '7'::jsonb)",
    )
    assert _purge(scan_client) == 1


# --- scheduler ----------------------------------------------------------------


def test_scheduler_registers_a_job_per_enabled_target(scan_client: TestClient) -> None:
    _with_project(scan_client)
    scheduler = _scheduler(scan_client)
    scan_client.post("/api/targets", json=GROUP_TARGET)
    scan_client.post("/api/targets", json={"kind": "project", "source_ref": "10", "schedule_cron": None})

    count = scan_client.portal.call(scheduler.sync_targets)  # type: ignore[attr-defined]

    # Only the target with a cron expression is scheduled.
    assert count == 1
    assert scheduler.scheduled_targets == 1


def test_disabling_a_target_removes_its_scheduled_job(scan_client: TestClient) -> None:
    _with_project(scan_client)
    scheduler = _scheduler(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    scan_client.portal.call(scheduler.sync_targets)  # type: ignore[attr-defined]
    assert scheduler.scheduled_targets == 1

    scan_client.put(f"/api/targets/{target_id}", json={"enabled": False})
    scan_client.portal.call(scheduler.sync_targets)  # type: ignore[attr-defined]

    assert scheduler.scheduled_targets == 0


def test_a_broken_stored_cron_does_not_break_the_scheduler(scan_client: TestClient) -> None:
    _with_project(scan_client)
    scheduler = _scheduler(scan_client)
    scan_client.post("/api/targets", json=GROUP_TARGET)
    # Validation happens in the API, so a broken value can only get in directly.
    _run_sql(scan_client, "UPDATE scan_targets SET schedule_cron = 'not a cron'")

    count = scan_client.portal.call(scheduler.sync_targets)  # type: ignore[attr-defined]

    assert count == 1
    assert scheduler.scheduled_targets == 0


def test_scheduled_run_is_created_with_the_schedule_trigger(scan_client: TestClient) -> None:
    _with_project(scan_client)
    scheduler = _scheduler(scan_client)
    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]

    scan_client.portal.call(scheduler._run_target, target_id)  # type: ignore[attr-defined] # noqa: SLF001

    runs = scan_client.get("/api/runs").json()["items"]
    assert len(runs) == 1
    assert runs[0]["trigger"] == "schedule"
    assert runs[0]["total"] == 1


# --- helpers ------------------------------------------------------------------


def _scheduler(client: TestClient):  # noqa: ANN202 - test helper
    from app.db import session_factory
    from app.services.scheduler import ScanScheduler

    scheduler = ScanScheduler(
        client.app.state.settings,
        session_factory(),
        worker=client.app.state.worker,
        source_provider=client.app.state.source_provider,
    )
    client.app.state.scheduler = scheduler
    return scheduler


def _purge(client: TestClient) -> int:
    from app.db import session_factory
    from app.services.retention import purge_old_runs

    async def run() -> int:
        async with session_factory()() as session:
            return await purge_old_runs(session)

    return client.portal.call(run)  # type: ignore[attr-defined]


def _first_project_id(client: TestClient) -> int:
    from sqlalchemy import text

    from app.db import session_factory

    async def query() -> int:
        async with session_factory()() as session:
            result = await session.execute(text("SELECT MIN(id) FROM projects"))
            return int(result.scalar_one())

    return client.portal.call(query)  # type: ignore[attr-defined]


def _run_sql(client: TestClient, statement: str, params: dict[str, object] | None = None) -> None:
    from sqlalchemy import text

    from app.db import session_factory

    async def execute() -> None:
        async with session_factory()() as session:
            await session.execute(text(statement), params or {})
            await session.commit()

    client.portal.call(execute)  # type: ignore[attr-defined]
