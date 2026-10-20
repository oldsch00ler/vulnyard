# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Runs, job queueing and recovery (SPEC section 8)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from tests.fakes import FakeSource, branch, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


def _with_projects(client: TestClient) -> FakeSource:
    source: FakeSource = client.app.state.source
    source._projects = [  # noqa: SLF001 - test fake
        project("10", "team/app", default_branch="main"),
        project("11", "team/api", default_branch="main"),
    ]
    source._branches = {  # noqa: SLF001 - test fake
        "10": [branch("main", is_default=True)],
        "11": [branch("main", is_default=True)],
    }
    return source


def _create_target(client: TestClient) -> int:
    return client.post("/api/targets", json=GROUP_TARGET).json()["id"]


def test_scanning_a_target_queues_one_job_per_project_and_branch(scan_client: TestClient) -> None:
    _with_projects(scan_client)
    target_id = _create_target(scan_client)

    response = scan_client.post(f"/api/targets/{target_id}/scan")

    assert response.status_code == 201
    run = response.json()
    assert run["trigger"] == "manual"
    assert run["total"] == 2
    assert run["status"] == "queued"

    detail = scan_client.get(f"/api/runs/{run['id']}").json()
    assert [job["status"] for job in detail["jobs"]] == ["queued", "queued"]
    assert {job["path_with_namespace"] for job in detail["jobs"]} == {"team/app", "team/api"}
    assert detail["target_name"] == "Team"


def test_a_second_run_does_not_duplicate_queued_jobs(scan_client: TestClient) -> None:
    _with_projects(scan_client)
    target_id = _create_target(scan_client)

    scan_client.post(f"/api/targets/{target_id}/scan")
    second = scan_client.post(f"/api/targets/{target_id}/scan").json()

    # Deduplication per SPEC section 8: the projects are already queued.
    assert second["total"] == 0
    assert second["status"] == "done"


def test_scan_everything_uses_all_enabled_targets(scan_client: TestClient) -> None:
    _with_projects(scan_client)
    _create_target(scan_client)

    response = scan_client.post("/api/runs")

    assert response.status_code == 201
    assert response.json()["total"] == 2


def test_scan_everything_without_targets_is_refused(scan_client: TestClient) -> None:
    response = scan_client.post("/api/runs")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "scan.no_enabled_targets"


def test_excluded_project_is_not_queued(scan_client: TestClient) -> None:
    _with_projects(scan_client)
    target_id = _create_target(scan_client)
    scan_client.post(f"/api/targets/{target_id}/scan")

    _exclude_all_projects(scan_client)
    _finish_all_jobs(scan_client)

    second = scan_client.post(f"/api/targets/{target_id}/scan").json()
    assert second["total"] == 0


def test_runs_are_listed_newest_first(scan_client: TestClient) -> None:
    _with_projects(scan_client)
    target_id = _create_target(scan_client)
    first = scan_client.post(f"/api/targets/{target_id}/scan").json()
    _finish_all_jobs(scan_client)
    second = scan_client.post(f"/api/targets/{target_id}/scan").json()

    listing = scan_client.get("/api/runs").json()

    assert listing["total"] == 2
    assert [item["id"] for item in listing["items"]] == [second["id"], first["id"]]


def test_unknown_run_returns_a_translated_error(scan_client: TestClient) -> None:
    response = scan_client.get("/api/runs/4242")

    assert response.status_code == 404
    body = response.json()["error"]
    assert body["code"] == "run.not_found"
    assert "4242" in body["message"]


def test_recovery_fails_interrupted_jobs(scan_client: TestClient) -> None:
    _with_projects(scan_client)
    target_id = _create_target(scan_client)
    run_id = scan_client.post(f"/api/targets/{target_id}/scan").json()["id"]
    _set_all_jobs_to(scan_client, "cloning")

    scan_client.portal.call(scan_client.app.state.worker.recover)  # type: ignore[attr-defined]

    detail = scan_client.get(f"/api/runs/{run_id}").json()
    assert {job["status"] for job in detail["jobs"]} == {"failed"}
    assert {job["error_code"] for job in detail["jobs"]} == {"job.interrupted"}
    # The error is stored as a code and rendered for the response.
    assert detail["jobs"][0]["error_message"] == "Přerušeno restartem aplikace."
    assert detail["status"] == "done"
    assert detail["failed"] == 2


def test_job_error_message_is_rendered_from_the_catalogue(scan_client: TestClient) -> None:
    _with_projects(scan_client)
    target_id = _create_target(scan_client)
    run_id = scan_client.post(f"/api/targets/{target_id}/scan").json()["id"]
    _fail_first_job(scan_client, "clone.branch_not_found", {"branch": "release/9"})

    detail = scan_client.get(f"/api/runs/{run_id}").json()
    failed = next(job for job in detail["jobs"] if job["status"] == "failed")

    assert failed["error_code"] == "clone.branch_not_found"
    assert failed["error_params"] == {"branch": "release/9"}
    assert "release/9" in failed["error_message"]


# --- helpers that reach into the database directly ----------------------------


def _run_sql(client: TestClient, statement: str, params: dict[str, object] | None = None) -> None:
    from sqlalchemy import text

    from app.db import session_factory

    async def execute() -> None:
        async with session_factory()() as session:
            await session.execute(text(statement), params or {})
            await session.commit()

    client.portal.call(execute)  # type: ignore[attr-defined]


def _set_all_jobs_to(client: TestClient, status: str) -> None:
    _run_sql(client, "UPDATE scan_jobs SET status = :status", {"status": status})


def _finish_all_jobs(client: TestClient) -> None:
    _run_sql(
        client,
        "UPDATE scan_jobs SET status = 'done', finished_at = :now",
        {"now": datetime.now(UTC)},
    )


def _fail_first_job(client: TestClient, code: str, params: dict[str, object]) -> None:
    import json

    _run_sql(
        client,
        """
        UPDATE scan_jobs
           SET status = 'failed', error_code = :code, error_params = CAST(:params AS jsonb)
         WHERE id = (SELECT MIN(id) FROM scan_jobs)
        """,
        {"code": code, "params": json.dumps(params)},
    )


def _exclude_all_projects(client: TestClient) -> None:
    _run_sql(client, "UPDATE projects SET excluded = true")
