# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Per-target GitLab credentials: a target may live on another instance or use
a token scoped to itself."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.services.sources import SourceCredentials, SourceProvider, create_source
from app.services.sources.base import SourceGroup
from tests.fakes import FakeSource, FakeSourceProvider, branch, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}
OWN_TOKEN = "glpat-own-target-token-123456"
OTHER_INSTANCE = "https://gitlab.example.org"


# --- the provider ------------------------------------------------------------


def settings_with_environment() -> Settings:
    return Settings(
        database_url="postgresql://vulnyard:secret@localhost:5432/vulnyard",
        gitlab_url="https://gitlab.example.com",
        gitlab_token="glpat-environment-token",
    )


class TargetRow:
    """Just the attributes the provider reads off a target."""

    def __init__(self, url: str | None = None, token: str | None = None) -> None:
        self.source_url = url
        self.source_token = token


def test_target_without_credentials_uses_the_environment() -> None:
    provider = SourceProvider(settings_with_environment())

    credentials = provider.credentials_for(TargetRow())

    assert credentials == SourceCredentials(
        url="https://gitlab.example.com", token="glpat-environment-token"
    )


def test_own_token_keeps_the_environment_instance() -> None:
    """The common case: same GitLab, a token scoped to this group."""
    provider = SourceProvider(settings_with_environment())

    credentials = provider.credentials_for(TargetRow(token=OWN_TOKEN))

    assert credentials == SourceCredentials(url="https://gitlab.example.com", token=OWN_TOKEN)


def test_own_instance_and_token_are_both_used() -> None:
    provider = SourceProvider(settings_with_environment())

    credentials = provider.credentials_for(TargetRow(url=OTHER_INSTANCE, token=OWN_TOKEN))

    assert credentials == SourceCredentials(url=OTHER_INSTANCE, token=OWN_TOKEN)


def test_clients_are_reused_per_credentials() -> None:
    provider = SourceProvider(settings_with_environment())
    first = provider.for_target(TargetRow(token=OWN_TOKEN))
    same = provider.for_target(TargetRow(token=OWN_TOKEN))
    other = provider.for_target(TargetRow(token="glpat-different-token-98765"))

    assert first is same, "one client per credentials, not one per job"
    assert first is not other


def test_a_client_talks_to_the_instance_it_was_built_for() -> None:
    source = create_source(
        settings_with_environment(), SourceCredentials(url=OTHER_INSTANCE, token=OWN_TOKEN)
    )

    clone = source.clone_url(project("10", "team/app"))

    assert clone.startswith(f"https://oauth2:{OWN_TOKEN}@gitlab.example.org/")
    assert "glpat-environment-token" not in clone


def test_without_any_credentials_there_is_no_client() -> None:
    from app.errors import SourceNotConfiguredError

    provider = SourceProvider(Settings(database_url="postgresql://x/y"))

    assert provider.credentials_for(TargetRow()) is None
    assert provider.global_source() is None
    with pytest.raises(SourceNotConfiguredError):
        provider.for_target(TargetRow())


def test_a_target_with_its_own_token_works_without_an_environment_token() -> None:
    """A deployment can have no central token at all."""
    provider = SourceProvider(Settings(database_url="postgresql://x/y"))

    credentials = provider.credentials_for(TargetRow(url=OTHER_INSTANCE, token=OWN_TOKEN))

    assert credentials == SourceCredentials(url=OTHER_INSTANCE, token=OWN_TOKEN)
    assert provider.get(credentials) is not None


# --- the API ------------------------------------------------------------------


def test_target_stores_its_credentials_and_never_returns_the_token(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/targets",
        json={**GROUP_TARGET, "source_url": OTHER_INSTANCE, "source_token": OWN_TOKEN},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["source_url"] == OTHER_INSTANCE
    assert body["source_url_effective"] == OTHER_INSTANCE
    assert body["source_token_configured"] is True
    assert OWN_TOKEN not in response.text
    assert OWN_TOKEN not in db_client.get("/api/targets").text


def test_a_target_without_credentials_reports_the_environment_instance(db_client: TestClient) -> None:
    body = db_client.post("/api/targets", json=GROUP_TARGET).json()

    assert body["source_url"] is None
    assert body["source_token_configured"] is False
    # Which instance it actually talks to is still visible.
    assert body["source_url_effective"] == "https://gitlab.com"


def test_another_instance_without_a_token_is_refused(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/targets", json={**GROUP_TARGET, "source_url": OTHER_INSTANCE}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.source_token_required"


def test_an_invalid_instance_url_is_refused(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/targets",
        json={**GROUP_TARGET, "source_url": "not a url", "source_token": OWN_TOKEN},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.source_url_invalid"


def test_credentials_can_be_changed_and_cleared(db_client: TestClient) -> None:
    created = db_client.post(
        "/api/targets", json={**GROUP_TARGET, "source_token": OWN_TOKEN}
    ).json()
    assert created["source_token_configured"] is True

    cleared = db_client.put(
        f"/api/targets/{created['id']}", json={"source_token": "", "source_url": ""}
    ).json()

    assert cleared["source_token_configured"] is False
    assert cleared["source_url"] is None


def test_clearing_only_the_token_of_a_foreign_instance_is_refused(db_client: TestClient) -> None:
    created = db_client.post(
        "/api/targets",
        json={**GROUP_TARGET, "source_url": OTHER_INSTANCE, "source_token": OWN_TOKEN},
    ).json()

    response = db_client.put(f"/api/targets/{created['id']}", json={"source_token": ""})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.source_token_required"


def test_the_connection_test_uses_the_targets_own_instance(db_client: TestClient) -> None:
    created = db_client.post(
        "/api/targets",
        json={**GROUP_TARGET, "source_url": OTHER_INSTANCE, "source_token": OWN_TOKEN},
    ).json()

    body = db_client.post(f"/api/targets/{created['id']}/test-source").json()

    assert body["ok"] is True
    assert OTHER_INSTANCE in body["detail"]
    assert body["version"] == "17.11.1"


# --- running a scan -----------------------------------------------------------


def test_a_run_discovers_each_target_with_its_own_credentials(scan_client: TestClient) -> None:
    provider: FakeSourceProvider = scan_client.app.state.source_provider
    default: FakeSource = provider.default
    default._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    default._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001

    # The second target lives on another instance with its own projects.
    other = FakeSource(
        projects=[project("20", "other/service", default_branch="main")],
        branches={"20": [branch("main", is_default=True)]},
        groups=[SourceGroup(ref="2", path="other", name="Other")],
    )
    provider.by_token[OWN_TOKEN] = other

    scan_client.post("/api/targets", json=GROUP_TARGET)
    scan_client.post(
        "/api/targets",
        json={"kind": "group", "source_ref": "2", "source_url": OTHER_INSTANCE, "source_token": OWN_TOKEN},
    )

    scan_client.post("/api/targets/1/scan")
    scan_client.post("/api/targets/2/scan")

    paths = {item["path_with_namespace"] for item in scan_client.get("/api/projects?branch=all").json()["items"]}
    assert paths == {"team/app", "other/service"}

    # Each discovery went to the instance and token of its own target.
    assert (OTHER_INSTANCE, OWN_TOKEN) in provider.requested
    assert ("https://git.example.com", "glpat-environment-token") in provider.requested


def test_the_job_is_cloned_with_the_targets_token(scan_client: TestClient) -> None:
    provider: FakeSourceProvider = scan_client.app.state.source_provider
    other = FakeSource(
        projects=[project("20", "other/service", default_branch="main")],
        branches={"20": [branch("main", is_default=True)]},
        groups=[SourceGroup(ref="2", path="other", name="Other")],
    )
    provider.by_token[OWN_TOKEN] = other

    scan_client.post(
        "/api/targets",
        json={"kind": "group", "source_ref": "2", "source_url": OTHER_INSTANCE, "source_token": OWN_TOKEN},
    )
    scan_client.post("/api/targets/1/scan")

    request = _build_request(scan_client)

    assert request is not None
    assert request.clone_url.startswith("https://oauth2:token@git.example.com/other/service")
    # The target's token is handed to the scanner so it can be masked.
    assert request.secrets == (OWN_TOKEN,)


def _build_request(client: TestClient):  # noqa: ANN202 - ScanRequest or None
    from sqlalchemy import select

    from app.db import session_factory
    from app.models import ScanJob

    worker = client.app.state.worker

    async def run():  # noqa: ANN202
        async with session_factory()() as session:
            job = (await session.execute(select(ScanJob))).scalars().first()
        return await worker._build_request(job.id)  # noqa: SLF001 - exercised directly

    return client.portal.call(run)  # type: ignore[attr-defined]
