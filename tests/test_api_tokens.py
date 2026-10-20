# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""API tokens: issuing them, and the API with and without them (SPEC 13)."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app.masking import mask_secrets
from app.services.api_tokens import generate, hash_token
from tests.test_settings_api import proxy_client  # noqa: F401 - fixture

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


def _issue(client: TestClient, **payload: object) -> dict:
    response = client.post("/api/tokens", json={"name": "provisioner", **payload})
    assert response.status_code == 201, response.text
    return response.json()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- without a database -------------------------------------------------------


def test_generated_tokens_carry_the_prefix_and_differ() -> None:
    first, second = generate(), generate()

    assert first.startswith("vy_") and second.startswith("vy_")
    assert first != second
    assert len(hash_token(first)) == 64


def test_tokens_are_masked_in_logs() -> None:
    token = generate()

    assert token not in mask_secrets(f"calling with {token} now")


def test_api_without_a_token_works_as_before(client: TestClient) -> None:
    """AUTH_MODE=none: the UI sends no token and must keep working."""
    assert client.get("/api/me").json()["email"] is None


def test_a_foreign_bearer_token_is_ignored(client: TestClient) -> None:
    """A proxy passing its own JWT upstream must not break the UI."""
    response = client.get("/api/me", headers=_bearer("eyJhbGciOiJSUzI1NiJ9.e30.sig"))

    assert response.status_code == 200
    assert response.json()["email"] is None


def test_openapi_documents_the_bearer_scheme(client: TestClient) -> None:
    schemes = client.get("/api/openapi.json").json()["components"]["securitySchemes"]

    assert schemes["HTTPBearer"]["scheme"] == "bearer"


# --- issuing and managing -----------------------------------------------------


def test_token_is_returned_only_when_created(db_client: TestClient) -> None:
    created = _issue(db_client, scope="write")

    assert created["token"].startswith("vy_")
    assert created["token_prefix"] == created["token"][:8]
    assert created["scope"] == "write"
    assert created["active"] is True

    listed = db_client.get("/api/tokens").json()
    assert listed["total"] == 1
    assert "token" not in listed["items"][0]
    assert created["token"] not in str(listed)


def test_token_defaults_to_read_only(db_client: TestClient) -> None:
    assert _issue(db_client)["scope"] == "read"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"name": "  "}, "validation.token_name_required"),
        ({"name": "x" * 129}, "validation.token_name_too_long"),
        ({"name": "ci", "scope": "admin"}, "validation.token_scope_invalid"),
        (
            {"name": "ci", "expires_on": (date.today() - timedelta(days=1)).isoformat()},
            "validation.token_expires_on_in_past",
        ),
    ],
)
def test_invalid_token_requests_are_rejected(db_client: TestClient, payload: dict, code: str) -> None:
    response = db_client.post("/api/tokens", json=payload)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == code


def test_deleted_token_stops_working(db_client: TestClient) -> None:
    created = _issue(db_client)
    assert db_client.get("/api/targets", headers=_bearer(created["token"])).status_code == 200

    assert db_client.delete(f"/api/tokens/{created['id']}").status_code == 204
    assert db_client.delete(f"/api/tokens/{created['id']}").status_code == 404

    response = db_client.get("/api/targets", headers=_bearer(created["token"]))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "auth.token_invalid"
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


# --- calling the API with a token ---------------------------------------------


def test_write_token_creates_a_target_and_is_recorded(db_client: TestClient) -> None:
    token = _issue(db_client, name="gitlab-hook", scope="write")["token"]

    response = db_client.post("/api/targets", json=GROUP_TARGET, headers=_bearer(token))

    assert response.status_code == 201
    assert response.json()["updated_by"] == "token:gitlab-hook"

    used = db_client.get("/api/tokens").json()["items"][0]
    assert used["last_used_at"] is not None


def test_read_token_cannot_change_anything(db_client: TestClient) -> None:
    token = _issue(db_client, name="dashboard", scope="read")["token"]

    assert db_client.get("/api/targets", headers=_bearer(token)).status_code == 200

    response = db_client.post("/api/targets", json=GROUP_TARGET, headers=_bearer(token))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "auth.token_read_only"


def test_token_cannot_manage_tokens(db_client: TestClient) -> None:
    created = _issue(db_client, scope="write")
    headers = _bearer(created["token"])

    for response in (
        db_client.get("/api/tokens", headers=headers),
        db_client.post("/api/tokens", json={"name": "sneaky", "scope": "write"}, headers=headers),
        db_client.delete(f"/api/tokens/{created['id']}", headers=headers),
    ):
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "auth.token_management_forbidden"


def test_unknown_token_is_rejected(db_client: TestClient) -> None:
    response = db_client.get("/api/targets", headers=_bearer(generate()))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "auth.token_invalid"


def test_expired_token_is_rejected(db_client: TestClient) -> None:
    created = _issue(db_client, expires_on=date.today().isoformat())
    headers = _bearer(created["token"])
    # Valid through the last day...
    assert db_client.get("/api/targets", headers=headers).status_code == 200

    # ...and not a day longer.
    from sqlalchemy import update

    from app.db import session_factory
    from app.models import ApiToken

    async def expire() -> None:
        async with session_factory()() as session:
            await session.execute(
                update(ApiToken).values(expires_on=date.today() - timedelta(days=1))
            )
            await session.commit()

    db_client.portal.call(expire)  # type: ignore[attr-defined]

    assert db_client.get("/api/targets", headers=headers).status_code == 401
    assert db_client.get("/api/tokens").json()["items"][0]["active"] is False


# --- proxy-header mode --------------------------------------------------------


def test_proxy_mode_accepts_a_token_without_the_header(proxy_client: TestClient) -> None:  # noqa: F811
    people = {"X-Forwarded-Email": "admin@example.com"}
    created = proxy_client.post(
        "/api/tokens", json={"name": "provisioner", "scope": "write"}, headers=people
    ).json()
    assert created["created_by"] == "admin@example.com"

    response = proxy_client.post("/api/targets", json=GROUP_TARGET, headers=_bearer(created["token"]))

    assert response.status_code == 201
    assert response.json()["updated_by"] == "token:provisioner"


def test_proxy_mode_still_requires_the_header_without_a_token(proxy_client: TestClient) -> None:  # noqa: F811
    response = proxy_client.get("/api/targets")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "auth.header_missing"
