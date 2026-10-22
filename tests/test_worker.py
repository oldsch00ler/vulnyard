# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""The worker really processing a queued job (SPEC section 8 end to end)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from tests.fakes import FakeDependencyTrack, branch, project
from tests.helpers import LocalSource, make_trivy

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


def test_worker_scans_a_queued_job_and_stores_the_result(
    scan_client: TestClient, git_repository: Path, tmp_path: Path
) -> None:
    app = scan_client.app
    source = LocalSource(git_repository)
    source._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001 - test fake
    source._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    app.state.source = source

    from app.config import Settings
    from app.db import session_factory
    from app.services.queue import ScanWorker

    settings = Settings(
        **{
            **app.state.settings.model_dump(),
            "trivy_bin": str(make_trivy(tmp_path)),
            "gitlab_token": "glpat-TESTTOKEN1234567890",
            "dt_api_url": "https://dtrack.example.com",
            "dt_api_key": "odt_testkey_1234567890",
            "scan_timeout_seconds": 120,
        }
    )
    dtrack = FakeDependencyTrack()
    from tests.fakes import FakeSourceProvider

    provider = FakeSourceProvider(source)
    app.state.source_provider = provider
    worker = ScanWorker(
        settings,
        session_factory(),
        source=source,
        source_provider=provider,
        dtrack=dtrack,
        trivy_available=True,
    )
    app.state.worker = worker

    target_id = scan_client.post("/api/targets", json=GROUP_TARGET).json()["id"]
    run_id = scan_client.post(f"/api/targets/{target_id}/scan").json()["id"]

    async def drive() -> None:
        await worker.start()
        try:
            for _ in range(100):
                await asyncio.sleep(0.1)
                if worker.active_jobs == 0 and not await _pending_jobs(run_id):
                    return
        finally:
            await worker.stop()

    scan_client.portal.call(drive)  # type: ignore[attr-defined]

    detail = scan_client.get(f"/api/runs/{run_id}").json()
    assert detail["status"] == "done"
    assert detail["succeeded"] == 1
    assert detail["failed"] == 0

    job = detail["jobs"][0]
    assert job["status"] == "done"
    assert job["components_count"] == 2
    assert job["commit_sha"] and len(job["commit_sha"]) == 40
    assert job["duration_ms"] is not None
    assert job["dt_project_uuid"] == "dt-uuid-1"

    # The parent collection project of the group was created once (SPEC 9.2).
    assert dtrack.collection_projects == ["team"]
    assert dtrack.uploads[0].project_name == "team/app"
    assert dtrack.uploads[0].parent_uuid == "parent-1"


async def _pending_jobs(run_id: int) -> bool:
    """Whether the run still has jobs that are queued or being worked on."""
    from sqlalchemy import text

    from app.db import session_factory

    async with session_factory()() as session:
        result = await session.execute(
            text(
                "SELECT count(*) FROM scan_jobs "
                "WHERE run_id = :run_id AND status IN "
                "('queued', 'cloning', 'scanning', 'uploading', 'processing')"
            ),
            {"run_id": run_id},
        )
        return bool(result.scalar_one())


def test_worker_follows_the_stored_concurrency(scan_client: TestClient) -> None:
    """The limit set in the UI applies without a restart, both up and down."""
    worker = scan_client.app.state.worker
    claimed = iter(range(1, 100))

    from app.db import session_factory
    from app.services import app_settings

    async def set_limit(limit: int) -> None:
        async with session_factory()() as session:
            await app_settings.set_value(session, app_settings.KEY_SCAN_CONCURRENCY, limit)
            await session.commit()

    async def drive() -> list[int]:
        release = asyncio.Event()

        async def claim() -> int:
            return next(claimed)

        async def process(_job_id: int) -> None:
            await release.wait()

        worker._claim_job = claim  # noqa: SLF001 - no real jobs needed
        worker._process = process  # noqa: SLF001
        worker._running = True  # noqa: SLF001 - drive the dispatch by hand
        started = []
        try:
            started.append(await worker._dispatch_available())  # noqa: SLF001
            await set_limit(5)
            started.append(await worker._dispatch_available())  # noqa: SLF001
            await set_limit(1)
            started.append(await worker._dispatch_available())  # noqa: SLF001
        finally:
            worker._running = False  # noqa: SLF001
            release.set()
            await asyncio.gather(*worker._tasks.values())  # noqa: SLF001
        return started

    scan_client.put("/api/settings", json={"scan_concurrency": 3})
    started = scan_client.portal.call(drive)  # type: ignore[attr-defined]

    # 3 at first, 2 more once raised to 5, none after lowering while 5 run.
    assert started == [3, 2, 0]
    assert worker.concurrency == 1
