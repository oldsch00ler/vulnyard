# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""MCP endpoint for coding agents: authentication, read-only tools (SPEC 11.1)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.mcp_server import repository_path
from app.services.kev import KevEntry
from tests.fakes import FakeDependencyTrack
from tests.test_dashboard_api import _finding as dt_finding
from tests.test_dashboard_api import _run_sql
from tests.test_dashboard_api import scanned  # noqa: F401 - fixture
from tests.test_threats import FakeKev

HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def _token(client: TestClient, scope: str = "read") -> str:
    return client.post("/api/tokens", json={"name": f"agent-{scope}", "scope": scope}).json()["token"]


def _rpc(client: TestClient, method: str, params: dict[str, Any] | None = None, token: str | None = None):  # noqa: ANN202
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers=headers,
    )


def _call(client: TestClient, token: str, tool: str, **arguments: Any) -> dict[str, Any]:
    response = _rpc(client, "tools/call", {"name": tool, "arguments": arguments}, token)
    assert response.status_code == 200, response.text
    return response.json()["result"]


def test_repository_is_recognised_from_a_path_or_a_remote() -> None:
    assert repository_path("team/app") == "team/app"
    assert repository_path("https://gitlab.example.com/team/app.git") == "team/app"
    assert repository_path("git@gitlab.example.com:team/sub/app.git") == "team/sub/app"
    assert repository_path("ssh://git@gitlab.example.com:2222/team/app.git") == "team/app"
    assert repository_path("https://gitlab.example.com/team/app/-/tree/main") == "team/app"


# --- authentication ----------------------------------------------------------------


def test_mcp_needs_a_token_even_without_authentication(db_client: TestClient) -> None:
    """AUTH_MODE=none leaves the API open, but an agent always identifies itself."""
    response = _rpc(db_client, "tools/list")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "auth.token_required"


def test_unknown_token_is_rejected(db_client: TestClient) -> None:
    response = _rpc(db_client, "tools/list", token="vy_" + "x" * 43)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "auth.token_invalid"


def test_a_read_only_token_may_use_mcp(db_client: TestClient) -> None:
    """MCP posts every call, yet only reads; read access is enough."""
    token = _token(db_client, "read")

    initialize = _rpc(
        db_client,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
        token,
    )
    assert initialize.status_code == 200, initialize.text
    assert initialize.json()["result"]["serverInfo"]["name"] == "Vulnyard"

    tools = _rpc(db_client, "tools/list", token=token).json()["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert names == {"list_projects", "project_findings", "find_vulnerability", "current_threats", "scan_status"}
    # Every tool declares that it only reads.
    assert all(tool["annotations"]["readOnlyHint"] is True for tool in tools)


def test_a_read_only_token_still_may_not_write_through_the_api(db_client: TestClient) -> None:
    token = _token(db_client, "read")

    response = db_client.post(
        "/api/targets", json={"kind": "group", "source_ref": "1"}, headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403


# --- tools ------------------------------------------------------------------------------


@pytest.fixture
def agent(scanned: TestClient) -> tuple[TestClient, str]:  # noqa: F811 - fixture
    dtrack: FakeDependencyTrack = scanned.app.state.dtrack
    dtrack.findings = {
        "dt-10-main": [
            replace(dt_finding("GHSA-aaaa", "HIGH", source="GITHUB"), aliases=("CVE-2026-0001",)),
            replace(dt_finding("CVE-2026-0002", "LOW", purl="pkg:npm/lodash@4.17.20", component="lodash"),
                    latest_version="4.17.21"),
            dt_finding("CVE-2026-0003", "MEDIUM", suppressed=True),
        ],
        "dt-11-main": [replace(dt_finding("GHSA-aaaa", "HIGH", source="GITHUB", project_uuid="dt-11-main"),
                               aliases=("CVE-2026-0001",))],
    }
    scanned.app.state.kev = FakeKev({"CVE-2026-0001": KevEntry(cve_id="CVE-2026-0001", ransomware=True)})
    return scanned, _token(scanned)


def test_list_projects_finds_repositories(agent: tuple[TestClient, str]) -> None:
    client, token = agent

    result = _call(client, token, "list_projects", search="API")

    assert [p["repository"] for p in result["structuredContent"]["projects"]] == ["team/api"]


def test_project_findings_by_remote_url_worst_first(agent: tuple[TestClient, str]) -> None:
    client, token = agent

    result = _call(client, token, "project_findings", repository="git@gitlab.example.com:team/app.git")

    data = result["structuredContent"]
    assert data["project"]["repository"] == "team/app"
    assert data["project"]["branch"] == "main"
    assert [f["id"] for f in data["findings"]] == ["GHSA-aaaa", "CVE-2026-0002"]
    assert data["findings"][0]["aliases"] == ["CVE-2026-0001"]
    assert data["findings"][1]["latest_version"] == "4.17.21"
    # Ignored findings only on request.
    with_ignored = _call(client, token, "project_findings", repository="team/app", include_ignored=True)
    assert len(with_ignored["structuredContent"]["findings"]) == 3


def test_project_findings_explain_an_unknown_repository_or_branch(agent: tuple[TestClient, str]) -> None:
    client, token = agent

    unknown = _call(client, token, "project_findings", repository="team/nope")
    assert unknown["isError"] is True
    assert "mcp.repository_unknown" in unknown["content"][0]["text"]

    branch = _call(client, token, "project_findings", repository="team/app", branch="release")
    assert branch["isError"] is True
    assert "develop" in branch["content"][0]["text"]


def test_find_vulnerability_by_alias_lists_every_place(agent: tuple[TestClient, str]) -> None:
    client, token = agent

    data = _call(client, token, "find_vulnerability", vulnerability_id="cve-2026-0001")["structuredContent"]

    assert data["found"] is True
    match = data["matches"][0]
    assert match["id"] == "GHSA-aaaa"
    assert match["known_exploited"]["ransomware"] is True
    assert sorted(one["repository"] for one in match["affected"]) == ["team/api", "team/app"]


def test_current_threats_puts_exploited_first(agent: tuple[TestClient, str]) -> None:
    client, token = agent

    data = _call(client, token, "current_threats")["structuredContent"]

    assert data["counts"]["exploited"] == 1
    assert data["threats"][0]["id"] == "GHSA-aaaa"
    assert data["threats"][0]["repositories"] == ["team/api", "team/app"]


def test_scan_status_reports_the_last_error(agent: tuple[TestClient, str]) -> None:
    client, token = agent
    _run_sql(
        client,
        """
        UPDATE scan_jobs SET status = 'failed', error_code = 'trivy.timeout', error_params = '{"seconds": 900}'
         WHERE project_id = (SELECT id FROM projects WHERE path_with_namespace = 'team/api' AND branch = 'main')
        """,
    )

    data = _call(client, token, "scan_status", repository="team/api")["structuredContent"]

    assert data["recent_scans"][0]["status"] == "failed"
    assert "900" in data["recent_scans"][0]["error"]
