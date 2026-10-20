# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""GET /api/status."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings


def test_status_reports_missing_scan_configuration(client: TestClient) -> None:
    payload = client.get("/api/status").json()

    assert payload["config"]["complete"] is False
    assert payload["config"]["missing"] == ["GITLAB_TOKEN", "DT_API_URL", "DT_API_KEY"]
    assert payload["config"]["scanning_enabled"] is False
    assert payload["runtime"]["auth_mode"] == "none"
    assert payload["runtime"]["default_locale"] == "cs"
    assert payload["runtime"]["available_locales"] == ["cs", "en"]


def test_status_never_exposes_tokens(env: pytest.MonkeyPatch, no_migrations: None) -> None:
    env.setenv("DATABASE_URL", "postgresql://vulnyard:dbsecret@localhost:5432/vulnyard")
    env.setenv("GITLAB_TOKEN", "glpat-supersecret")
    env.setenv("DT_API_KEY", "odt_supersecret")
    env.setenv("DT_API_URL", "https://dtrack.example.com")
    from app.main import create_app

    with TestClient(create_app()) as client:
        raw = client.get("/api/status").text

    assert "glpat-supersecret" not in raw
    assert "odt_supersecret" not in raw
    assert "dbsecret" not in raw


def test_database_url_is_normalised_for_asyncpg() -> None:
    plain = Settings(database_url="postgres://user:pass@localhost:5432/db")
    explicit = Settings(database_url="postgresql://user:pass@localhost:5432/db")
    already = Settings(database_url="postgresql+asyncpg://user:pass@localhost:5432/db")

    assert plain.database_url.startswith("postgresql+asyncpg://")
    assert explicit.database_url.startswith("postgresql+asyncpg://")
    assert already.database_url.startswith("postgresql+asyncpg://")


def test_unknown_auth_mode_falls_back_to_none() -> None:
    assert Settings(auth_mode="magic").auth_mode == "none"


def test_dt_ui_url_defaults_to_api_url() -> None:
    settings = Settings(dt_api_url="https://dtrack.example.com/")

    assert settings.effective_dt_ui_url == "https://dtrack.example.com"


def test_unknown_timezone_falls_back_to_utc() -> None:
    settings = Settings(tz="Europe/Pragu")

    assert settings.timezone_is_valid is False
    assert settings.timezone_name == "UTC"


def test_known_timezone_is_kept() -> None:
    settings = Settings(tz="Europe/Prague")

    assert settings.timezone_is_valid is True
    assert settings.timezone_name == "Europe/Prague"
