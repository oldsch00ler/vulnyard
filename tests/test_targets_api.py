# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scan target API against a real database (see tests/conftest.py)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.fakes import FakeSource, branch, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}


def _with_projects(client: TestClient) -> FakeSource:
    """Give the fake source a couple of projects with branches."""
    source: FakeSource = client.app.state.source
    source._projects = [  # noqa: SLF001 - test fake
        project("10", "team/app", default_branch="main"),
        project("11", "team/archive-old"),
        project("12", "team/legacy", archived=True),
    ]
    source._branches = {  # noqa: SLF001 - test fake
        "10": [branch("main", is_default=True), branch("develop"), branch("release/1.0")],
        "11": [branch("main", is_default=True)],
    }
    return source


def test_create_resolves_name_from_the_source(db_client: TestClient) -> None:
    response = db_client.post("/api/targets", json=GROUP_TARGET)

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Team"
    assert body["source_path"] == "team"
    assert body["branch_mode"] == "default"
    assert body["schedule_cron"] == "0 2 * * *"
    assert body["enabled"] is True


def test_create_rejects_a_duplicate_target(db_client: TestClient) -> None:
    db_client.post("/api/targets", json=GROUP_TARGET)

    response = db_client.post("/api/targets", json=GROUP_TARGET)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "target.duplicate"


def test_create_rejects_an_invalid_cron(db_client: TestClient) -> None:
    response = db_client.post("/api/targets", json={**GROUP_TARGET, "schedule_cron": "every tuesday"})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.cron_invalid"


def test_list_and_read_a_target(db_client: TestClient) -> None:
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    listed = db_client.get("/api/targets").json()
    assert listed["total"] == 1
    assert listed["items"][0]["id"] == created["id"]

    assert db_client.get(f"/api/targets/{created['id']}").status_code == 200
    assert db_client.get("/api/targets/9999").status_code == 404


def test_update_switches_to_custom_branches(db_client: TestClient) -> None:
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    response = db_client.put(
        f"/api/targets/{created['id']}",
        json={"branch_mode": "custom", "branch_patterns": ["main", "release/*"], "max_branches_per_project": 5},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["branch_mode"] == "custom"
    assert body["branch_patterns"] == ["main", "release/*"]
    assert body["max_branches_per_project"] == 5


def test_update_rejects_an_empty_branch_selection(db_client: TestClient) -> None:
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    response = db_client.put(
        f"/api/targets/{created['id']}",
        json={"branch_mode": "custom", "branch_patterns": [], "include_default_branch": False},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.branch_selection_empty"


def test_null_cron_means_manual_runs_only(db_client: TestClient) -> None:
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    response = db_client.put(f"/api/targets/{created['id']}", json={"schedule_cron": None})

    assert response.json()["schedule_cron"] is None


def test_delete_removes_the_target(db_client: TestClient) -> None:
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    assert db_client.delete(f"/api/targets/{created['id']}").status_code == 204
    assert db_client.get("/api/targets").json()["total"] == 0


def test_preview_reports_projects_branches_and_skips(db_client: TestClient) -> None:
    _with_projects(db_client)

    response = db_client.post(
        "/api/targets/preview",
        json={**GROUP_TARGET, "exclude_patterns": ["*/archive-*"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["project_count"] == 1
    assert body["branch_count"] == 1
    assert body["projects"][0]["path_with_namespace"] == "team/app"
    assert body["projects"][0]["branches"][0] == {
        "branch": "main",
        "is_default_branch": True,
        "commit_sha": body["projects"][0]["branches"][0]["commit_sha"],
    }
    reasons = {item["path_with_namespace"]: item["reason"]["code"] for item in body["skipped"]}
    assert reasons == {
        "team/archive-old": "discovery.skipped.excluded_by_pattern",
        "team/legacy": "discovery.skipped.archived",
    }
    # The reason carries a translated message, not a hardcoded string.
    assert reasons and all(item["reason"]["message"] for item in body["skipped"])


def test_preview_does_not_store_anything(db_client: TestClient) -> None:
    _with_projects(db_client)

    db_client.post("/api/targets/preview", json=GROUP_TARGET)

    assert db_client.get("/api/targets").json()["total"] == 0


def test_source_suggestions_require_a_longer_search(db_client: TestClient) -> None:
    assert db_client.get("/api/source/groups", params={"search": "te"}).status_code == 422
    response = db_client.get("/api/source/groups", params={"search": "team"})
    assert response.status_code == 200
    assert response.json()[0]["path"] == "team"


def test_branch_suggestions_put_the_default_branch_first(db_client: TestClient) -> None:
    _with_projects(db_client)

    response = db_client.get("/api/source/projects/10/branches")

    assert response.status_code == 200
    assert [item["name"] for item in response.json()][0] == "main"


def test_creating_a_target_without_a_schedule_stays_manual(db_client: TestClient) -> None:
    """A null cron at creation time must survive (no column default kicks in)."""
    response = db_client.post("/api/targets", json={**GROUP_TARGET, "schedule_cron": None})

    assert response.status_code == 201
    assert response.json()["schedule_cron"] is None


def test_update_rejects_immutable_fields(db_client: TestClient) -> None:
    """The kind and the source reference of a target cannot be changed."""
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    response = db_client.put(
        f"/api/targets/{created['id']}",
        json={"kind": "project", "source_ref": "42", "source_path": "other/path"},
    )

    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "validation.invalid_request"
    assert body["params"]["fields"] == "kind, source_ref, source_path"


def test_update_accepts_the_changeable_fields_the_form_sends(db_client: TestClient) -> None:
    """What the edit form sends must go through unchanged (regression)."""
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    response = db_client.put(
        f"/api/targets/{created['id']}",
        json={
            "name": "Renamed",
            "include_subgroups": False,
            "branch_mode": "custom",
            "branch_patterns": ["main", "release/*"],
            "include_default_branch": True,
            "max_branches_per_project": 7,
            "schedule_cron": "0 4 * * *",
            "exclude_patterns": ["sandbox/*"],
            "skip_unchanged": False,
            "enabled": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Renamed"
    assert body["include_subgroups"] is False
    assert body["branch_patterns"] == ["main", "release/*"]
    assert body["max_branches_per_project"] == 7
    assert body["schedule_cron"] == "0 4 * * *"
    assert body["exclude_patterns"] == ["sandbox/*"]
    assert body["skip_unchanged"] is False
    assert body["enabled"] is False


def test_update_refuses_to_clear_the_name(db_client: TestClient) -> None:
    created = db_client.post("/api/targets", json=GROUP_TARGET).json()

    response = db_client.put(f"/api/targets/{created['id']}", json={"name": "   "})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.name_empty"
    # The stored name is untouched.
    assert db_client.get(f"/api/targets/{created['id']}").json()["name"] == "Team"
