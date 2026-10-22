# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Shared test fixtures.

Most tests run without a database: the startup migration is patched out. Tests
that really need PostgreSQL use the `db_client` fixture and are skipped unless
VULNYARD_TEST_DATABASE_URL points at a database they may write to.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from tests.fakes import FakeDependencyTrack, FakeSource, FakeSourceProvider

# Variables that must not leak from the developer's environment into the tests.
MANAGED_ENV = (
    "DATABASE_URL",
    "GITLAB_URL",
    "GITLAB_TOKEN",
    "DT_API_URL",
    "DT_API_KEY",
    "DT_UI_URL",
    "AUTH_MODE",
    "TRIVY_BIN",
    "DEFAULT_LOCALE",
    "LOG_LEVEL",
    "TZ",
)

DUMMY_DATABASE_URL = "postgresql://vulnyard:secret@localhost:5432/vulnyard"

# Tables emptied before every database test, children first.
TABLES_TO_CLEAN = (
    "api_tokens",
    "ignore_applications",
    "ignore_rules",
    "scan_jobs",
    "scan_runs",
    "metric_snapshots",
    "target_projects",
    "project_branch_overrides",
    "projects",
    "scan_targets",
    "settings",
)


@pytest.fixture(autouse=True)
def fresh_caches() -> Iterator[None]:
    """Answers from Dependency-Track are cached for a minute in module state.

    Without this, a test would be served the previous test's numbers.
    """
    from app.services.dashboard import invalidate_cache as invalidate_dashboard
    from app.services.epss import invalidate_cache as invalidate_epss
    from app.services.vulnerabilities import invalidate_cache as invalidate_vulnerabilities

    invalidate_dashboard()
    invalidate_vulnerabilities()
    invalidate_epss()
    yield
    invalidate_dashboard()
    invalidate_vulnerabilities()
    invalidate_epss()


@pytest.fixture
def git_repository(tmp_path: Path) -> Path:
    """Local repository with one commit on branch `main`, used for real clones."""
    repo = tmp_path / "origin"
    repo.mkdir()

    def run(*args: str) -> None:
        subprocess.run(args, cwd=repo, check=True, capture_output=True)

    run("git", "init", "--initial-branch=main")
    run("git", "config", "user.email", "test@example.com")
    run("git", "config", "user.name", "Test")
    (repo / "package.json").write_text('{"name": "demo"}', encoding="utf-8")
    run("git", "add", ".")
    run("git", "commit", "-m", "initial")
    return repo


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    """Clean environment with a cached-settings reset around the test."""
    for name in MANAGED_ENV:
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield monkeypatch
    get_settings.cache_clear()


@pytest.fixture
def no_migrations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Boot the app without a database: no migration and no job recovery."""

    async def _skip_migrations(_engine: object) -> None:
        return None

    async def _skip_recovery(_self: object) -> None:
        return None

    monkeypatch.setattr("app.main.run_migrations", _skip_migrations)
    monkeypatch.setattr("app.services.queue.ScanWorker.recover", _skip_recovery)


@pytest.fixture
def fake_source() -> FakeSource:
    return FakeSource()


@pytest.fixture
def client(env: pytest.MonkeyPatch, no_migrations: None) -> Iterator[TestClient]:
    """Client of an application with the minimal viable configuration."""
    env.setenv("DATABASE_URL", DUMMY_DATABASE_URL)
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def test_database_url() -> str:
    url = os.environ.get("VULNYARD_TEST_DATABASE_URL")
    if not url:
        pytest.skip("VULNYARD_TEST_DATABASE_URL is not set")
    return url


@pytest.fixture
def db_client(
    env: pytest.MonkeyPatch, test_database_url: str, fake_source: FakeSource
) -> Iterator[TestClient]:
    """Client backed by a real database, with the source replaced by a fake."""
    env.setenv("DATABASE_URL", test_database_url)
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        _clean_database(test_client)
        # No test talks to a real GitLab.
        test_client.app.state.source = fake_source
        test_client.app.state.source_provider = FakeSourceProvider(fake_source)
        yield test_client


@pytest.fixture
def scan_client(db_client: TestClient) -> TestClient:
    """Database-backed client with a worker wired to fakes, not started.

    Jobs therefore stay queued, so the tests can assert what was queued
    without racing a running pipeline.
    """
    from app.db import session_factory
    from app.services.queue import ScanWorker

    app = db_client.app
    dtrack = FakeDependencyTrack()
    app.state.dtrack = dtrack
    app.state.worker = ScanWorker(
        app.state.settings,
        session_factory(),
        source=app.state.source,
        source_provider=app.state.source_provider,
        dtrack=dtrack,  # type: ignore[arg-type]
        trivy_available=True,
    )
    return db_client


def _clean_database(test_client: TestClient) -> None:
    """Empty the tables so tests do not see each other's rows."""
    from sqlalchemy import text

    from app.db import session_factory

    async def clean() -> None:
        async with session_factory()() as session:
            await session.execute(text(f"TRUNCATE {', '.join(TABLES_TO_CLEAN)} RESTART IDENTITY CASCADE"))
            await session.commit()

    test_client.portal.call(clean)  # type: ignore[attr-defined]
