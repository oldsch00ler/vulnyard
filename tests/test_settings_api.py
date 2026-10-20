# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Settings, connection tests and identity handling (SPEC 12.7, 13)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.auth import identity_from_request, optional_identity
from app.config import Settings
from tests.fakes import FakeDependencyTrack


# --- settings -----------------------------------------------------------------


def test_settings_start_from_the_environment_defaults(db_client: TestClient) -> None:
    body = db_client.get("/api/settings").json()

    assert body["scan_concurrency"] == 2
    assert body["history_retention_days"] == 90
    assert body["default_schedule_cron"] is None
    assert body["global_exclude_patterns"] == []


def test_settings_can_be_changed_and_are_stored(db_client: TestClient) -> None:
    response = db_client.put(
        "/api/settings",
        json={
            "scan_concurrency": 4,
            "default_schedule_cron": "0 3 * * *",
            "history_retention_days": 30,
            "global_exclude_patterns": ["sandbox/*", "*/archive-*"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scan_concurrency"] == 4
    assert body["default_schedule_cron"] == "0 3 * * *"
    assert body["history_retention_days"] == 30
    assert body["global_exclude_patterns"] == ["sandbox/*", "*/archive-*"]

    # Reading them back gives the stored values, not the environment defaults.
    assert db_client.get("/api/settings").json()["scan_concurrency"] == 4


def test_settings_reject_invalid_values(db_client: TestClient) -> None:
    too_much = db_client.put("/api/settings", json={"scan_concurrency": 99})
    assert too_much.status_code == 422
    assert too_much.json()["error"]["code"] == "validation.concurrency_out_of_range"

    bad_cron = db_client.put("/api/settings", json={"default_schedule_cron": "every night"})
    assert bad_cron.status_code == 422
    assert bad_cron.json()["error"]["code"] == "validation.cron_invalid"

    bad_pattern = db_client.put("/api/settings", json={"global_exclude_patterns": ["with space"]})
    assert bad_pattern.status_code == 422
    assert bad_pattern.json()["error"]["code"] == "validation.path_pattern_invalid"

    bad_retention = db_client.put("/api/settings", json={"history_retention_days": 0})
    assert bad_retention.status_code == 422
    assert bad_retention.json()["error"]["code"] == "validation.retention_out_of_range"


def test_global_excludes_apply_to_discovery(db_client: TestClient) -> None:
    from tests.fakes import FakeSource, FakeSourceProvider, branch, project

    source: FakeSource = db_client.app.state.source
    source._projects = [  # noqa: SLF001 - test fake
        project("10", "team/app", default_branch="main"),
        project("11", "sandbox/toy", default_branch="main"),
    ]
    source._branches = {  # noqa: SLF001 - test fake
        "10": [branch("main", is_default=True)],
        "11": [branch("main", is_default=True)],
    }
    db_client.put("/api/settings", json={"global_exclude_patterns": ["sandbox/*"]})

    preview = db_client.post("/api/targets/preview", json={"kind": "group", "source_ref": "1"}).json()

    assert [item["path_with_namespace"] for item in preview["projects"]] == ["team/app"]
    assert preview["skipped"][0]["reason"]["code"] == "discovery.skipped.excluded_by_pattern"


def test_environment_overview_never_exposes_values(db_client: TestClient) -> None:
    raw = db_client.get("/api/settings").text
    body = db_client.get("/api/settings").json()
    names = {item["name"]: item for item in body["environment"]["variables"]}

    assert names["DATABASE_URL"]["set"] is True
    assert names["GITLAB_TOKEN"]["set"] is False
    assert names["GITLAB_TOKEN"]["secret"] is True
    # Only names and flags: the configured values never appear in the response.
    assert "postgresql" not in raw
    assert db_client.app.state.settings.database_url not in raw


# --- connection tests ---------------------------------------------------------


def test_source_test_reports_a_missing_configuration(db_client: TestClient) -> None:
    db_client.app.state.source = None

    body = db_client.post("/api/settings/test-source").json()

    assert body["ok"] is False
    assert body["code"] == "source.not_configured"
    assert "GITLAB_TOKEN" in body["detail"]


def test_source_test_reports_the_version(db_client: TestClient) -> None:
    body = db_client.post("/api/settings/test-source").json()

    assert body["ok"] is True
    assert body["version"] == "17.11.1"


def test_source_test_translates_a_failure(db_client: TestClient) -> None:
    from app.errors import SourceError

    async def failing_version() -> str:
        raise SourceError("source.unauthorized")

    db_client.app.state.source.version = failing_version  # type: ignore[method-assign]

    body = db_client.post("/api/settings/test-source").json()

    assert body["ok"] is False
    assert body["code"] == "source.unauthorized"
    assert "401" in body["detail"]


def test_dtrack_test_reports_the_version(db_client: TestClient) -> None:
    db_client.app.state.dtrack = FakeDependencyTrack()

    body = db_client.post("/api/settings/test-dtrack").json()

    assert body["ok"] is True
    assert body["version"] == "4.13.6"


def test_dtrack_test_warns_about_an_unsupported_version(db_client: TestClient) -> None:
    db_client.app.state.dtrack = FakeDependencyTrack(version="4.11.0")

    body = db_client.post("/api/settings/test-dtrack").json()

    assert body["ok"] is False
    assert body["code"] == "dtrack.version_unsupported"
    assert "4.11.0" in body["detail"]


# --- identity (SPEC 13) -------------------------------------------------------


class FakeRequest:
    """Minimal stand-in carrying only headers."""

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


def test_no_identity_in_mode_none() -> None:
    settings = Settings(auth_mode="none")

    assert identity_from_request(FakeRequest({"X-Forwarded-Email": "a@b.cz"}), settings) is None  # type: ignore[arg-type]


def test_identity_comes_from_the_configured_headers_in_order() -> None:
    settings = Settings(auth_mode="proxy-header")

    first = FakeRequest({"X-Forwarded-Email": "email@example.com", "X-Forwarded-User": "user"})
    assert identity_from_request(first, settings) == "email@example.com"  # type: ignore[arg-type]

    fallback = FakeRequest({"X-Forwarded-User": "user@example.com"})
    assert identity_from_request(fallback, settings) == "user@example.com"  # type: ignore[arg-type]


def test_missing_header_in_proxy_mode_is_unauthenticated() -> None:
    from app.auth import UnauthenticatedError

    settings = Settings(auth_mode="proxy-header")

    with pytest.raises(UnauthenticatedError) as raised:
        identity_from_request(FakeRequest({}), settings)  # type: ignore[arg-type]
    assert raised.value.status_code == 401
    assert raised.value.code == "auth.header_missing"

    # The audit variant never blocks a request.
    assert optional_identity(FakeRequest({}), settings) is None  # type: ignore[arg-type]


def test_custom_auth_headers_are_honoured() -> None:
    settings = Settings(auth_mode="proxy-header", auth_headers="X-Auth-Request-Email, X-Forwarded-Email")

    request = FakeRequest({"X-Auth-Request-Email": "sso@example.com"})

    assert identity_from_request(request, settings) == "sso@example.com"  # type: ignore[arg-type]


def test_identity_is_recorded_on_a_target(db_client: TestClient) -> None:
    created = db_client.post(
        "/api/targets",
        json={"kind": "group", "source_ref": "1"},
        headers={"X-Forwarded-Email": "engineer@example.com"},
    ).json()

    # AUTH_MODE is none in the tests, so nothing is recorded – the field exists
    # and stays empty instead of trusting a header nobody asked for.
    assert created["updated_by"] is None



@pytest.fixture
def proxy_client(env: pytest.MonkeyPatch, test_database_url: str) -> TestClient:
    """Client of an app running in proxy-header mode."""
    from fastapi.testclient import TestClient as Client

    from tests.conftest import TABLES_TO_CLEAN
    from tests.fakes import FakeSource, FakeSourceProvider

    env.setenv("DATABASE_URL", test_database_url)
    env.setenv("AUTH_MODE", "proxy-header")
    from app.main import create_app

    with Client(create_app()) as client:
        from sqlalchemy import text

        from app.db import session_factory

        async def clean() -> None:
            async with session_factory()() as session:
                await session.execute(
                    text(f"TRUNCATE {', '.join(TABLES_TO_CLEAN)} RESTART IDENTITY CASCADE")
                )
                await session.commit()

        client.portal.call(clean)  # type: ignore[attr-defined]
        source = FakeSource()
        client.app.state.source = source
        client.app.state.source_provider = FakeSourceProvider(source)
        yield client


def test_proxy_header_mode_records_the_identity(proxy_client: TestClient) -> None:
    created = proxy_client.post(
        "/api/targets",
        json={"kind": "group", "source_ref": "1"},
        headers={"X-Forwarded-Email": "engineer@example.com"},
    )

    assert created.status_code == 201
    assert created.json()["updated_by"] == "engineer@example.com"


def test_proxy_header_mode_serves_the_api_with_the_header(proxy_client: TestClient) -> None:
    """With the header the API works normally; without it, it does not (SPEC 13)."""
    assert proxy_client.get("/health").status_code == 200

    with_header = proxy_client.get("/api/status", headers={"X-Forwarded-Email": "a@example.com"})
    assert with_header.status_code == 200
    assert with_header.json()["runtime"]["auth_mode"] == "proxy-header"


def test_identity_endpoint_without_auth(db_client: TestClient) -> None:
    body = db_client.get("/api/me").json()

    assert body == {"email": None, "auth_mode": "none"}


def test_identity_endpoint_in_proxy_mode(proxy_client: TestClient) -> None:
    body = proxy_client.get("/api/me", headers={"X-Forwarded-Email": "a@example.com"}).json()

    assert body == {"email": "a@example.com", "auth_mode": "proxy-header"}


def test_proxy_mode_refuses_api_requests_without_the_header(proxy_client: TestClient) -> None:
    """A bypassed proxy must not be able to change anything (SPEC 13)."""
    response = proxy_client.post("/api/targets", json={"kind": "group", "source_ref": "1"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "auth.header_missing"

    listing = proxy_client.get("/api/targets")
    assert listing.status_code == 401


def test_proxy_mode_keeps_the_health_check_open(proxy_client: TestClient) -> None:
    """The platform health check does not go through the proxy."""
    response = proxy_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
