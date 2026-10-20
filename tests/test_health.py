# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Health check and error shape."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient


def test_health_returns_ok_and_is_not_cached(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "no-store"


def test_unknown_api_path_returns_json_error(client: TestClient) -> None:
    response = client.get("/api/does-not-exist")

    assert response.status_code == 404
    assert "error" in response.json()


def test_missing_database_url_stops_startup(env: pytest.MonkeyPatch) -> None:
    """Without DATABASE_URL the application refuses to start (SPEC 3.1/9)."""
    from app.main import create_app, lifespan

    app = create_app()

    async def run_lifespan() -> None:
        async with lifespan(app):
            pass

    with pytest.raises(SystemExit):
        asyncio.run(run_lifespan())
