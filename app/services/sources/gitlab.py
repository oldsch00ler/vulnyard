# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""GitLab implementation of RepositorySource (SPEC section 10).

Verified against GitLab 17.11 (self-hosted). Notably `GET /projects` is called
without `membership=true`: a group access token is not a member of the
projects, so that filter returns nothing on a self-hosted instance.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from app.config import Settings
from app.constants import SOURCE_GITLAB
from app.errors import SourceError
from app.masking import mask_secrets
from app.services.sources.base import (
    RepositorySource,
    SourceBranch,
    SourceGroup,
    SourceMember,
    SourceProject,
)

logger = logging.getLogger(__name__)

API_PREFIX = "/api/v4"
PER_PAGE = 100
MAX_PAGES = 100  # safety net: at most 10 000 projects per group
REQUEST_TIMEOUT_SECONDS = 30.0

RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1.0
RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

#: GitLab access levels.
DEVELOPER_ACCESS_LEVEL = 30
MAINTAINER_ACCESS_LEVEL = 40

#: Usernames GitLab generates for project and group access tokens. They are
#: members like any other, but they are nobody to notify.
ACCESS_TOKEN_USERNAME = re.compile(r"^(?:project|group)_\d+_bot", re.IGNORECASE)


class GitLabSource(RepositorySource):
    """Read-only GitLab API client."""

    name = SOURCE_GITLAB

    def __init__(self, settings: Settings) -> None:
        self._base_url = settings.gitlab_url.rstrip("/")
        self._token = settings.gitlab_token
        self._client = httpx.AsyncClient(
            base_url=f"{self._base_url}{API_PREFIX}",
            headers={"PRIVATE-TOKEN": self._token, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=settings.ca_bundle or True,
            follow_redirects=True,
        )

    async def close(self) -> None:
        await self._client.aclose()

    # --- API calls -----------------------------------------------------------

    async def version(self) -> str | None:
        payload = await self._get_json("/version")
        return payload.get("version") if isinstance(payload, dict) else None

    async def search_groups(self, search: str, limit: int = 20) -> list[SourceGroup]:
        payload = await self._get_json(
            "/groups",
            params={"search": search, "per_page": min(limit, PER_PAGE), "order_by": "path", "sort": "asc"},
        )
        return [_group(item) for item in _as_list(payload)]

    async def get_group(self, ref: str) -> SourceGroup:
        payload = await self._get_json(f"/groups/{_encode(ref)}")
        return _group(_as_dict(payload))

    async def list_group_projects(self, ref: str, *, include_subgroups: bool) -> list[SourceProject]:
        items = await self._get_paginated(
            f"/groups/{_encode(ref)}/projects",
            params={
                "include_subgroups": _bool(include_subgroups),
                "archived": "false",
                "with_shared": "false",
                "order_by": "path",
                "sort": "asc",
            },
        )
        return [_project(item) for item in items]

    async def search_projects(self, search: str, limit: int = 20) -> list[SourceProject]:
        payload = await self._get_json(
            "/projects",
            params={
                "search": search,
                "per_page": min(limit, PER_PAGE),
                "order_by": "last_activity_at",
                "sort": "desc",
            },
        )
        return [_project(item) for item in _as_list(payload)]

    async def get_project(self, ref: str) -> SourceProject:
        payload = await self._get_json(f"/projects/{_encode(ref)}")
        return _project(_as_dict(payload))

    async def list_branches(self, project_ref: str, search: str | None = None) -> list[SourceBranch]:
        params: dict[str, Any] = {}
        if search:
            params["search"] = search
        items = await self._get_paginated(
            f"/projects/{_encode(project_ref)}/repository/branches", params=params
        )
        return [_branch(item) for item in items]

    async def get_branch(self, project_ref: str, branch: str) -> SourceBranch | None:
        try:
            payload = await self._get_json(
                f"/projects/{_encode(project_ref)}/repository/branches/{_encode(branch)}"
            )
        except SourceError as error:
            if error.code == "source.not_found":
                return None
            raise
        return _branch(_as_dict(payload))

    async def list_maintainers(self, project_ref: str) -> list[SourceMember]:
        """Who is responsible for the repository.

        Verified against GitLab 17.11 on a real instance: most projects have
        their own members (22 of 25 sampled), and those are the repository's
        people. Inherited group membership is a poor substitute — the same
        groups carry 80 to 100 members who have nothing to do with the project —
        so it is used only when the project has no members of its own.

        Within the direct members the most responsible tier wins: Owners and
        Maintainers if there are any, otherwise Developers. GitLab does not
        expose member e-mail addresses here, so notifications use the name and
        the username.
        """
        direct = await self._get_paginated(f"/projects/{_encode(project_ref)}/members")
        responsible = _responsible(direct, inherited=False)
        if responsible:
            return responsible

        inherited = await self._get_paginated(f"/projects/{_encode(project_ref)}/members/all")
        return _responsible(inherited, inherited=True)

    # --- URLs ----------------------------------------------------------------

    def clone_url(self, project: SourceProject) -> str:
        """https://oauth2:<token>@host/<path>.git – contains the token."""
        parts = urlsplit(self._base_url)
        netloc = f"oauth2:{self._token}@{parts.netloc}"
        base_path = parts.path.rstrip("/")
        return urlunsplit((parts.scheme, netloc, f"{base_path}/{project.path_with_namespace}.git", "", ""))

    def web_url(self, project: SourceProject, branch: str | None = None) -> str:
        if branch:
            return f"{project.web_url}/-/tree/{quote(branch, safe='')}"
        return project.web_url

    # --- HTTP plumbing -------------------------------------------------------

    async def _get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = await self._request(path, params)
        try:
            return response.json()
        except ValueError as error:
            raise SourceError("source.invalid_response", detail=self._mask(str(error))) from error

    async def _get_paginated(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Collect all pages using the X-Next-Page header (SPEC 7.1)."""
        collected: list[dict[str, Any]] = []
        page = 1
        for _ in range(MAX_PAGES):
            response = await self._request(path, {**(params or {}), "per_page": PER_PAGE, "page": page})
            try:
                payload = response.json()
            except ValueError as error:
                raise SourceError("source.invalid_response", detail=self._mask(str(error))) from error
            collected.extend(_as_list(payload))
            next_page = (response.headers.get("X-Next-Page") or "").strip()
            if not next_page:
                return collected
            page = int(next_page) if next_page.isdigit() else page + 1
        logger.warning("Pagination limit of %s pages reached for %s", MAX_PAGES, path)
        return collected

    async def _request(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """GET with 3 attempts and exponential backoff on 429/5xx/timeout."""
        last_error: Exception | None = None
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                response = await self._client.get(path, params=params)
            except (httpx.TimeoutException, httpx.TransportError) as error:
                last_error = error
                if attempt == RETRY_ATTEMPTS:
                    raise SourceError("source.unreachable", detail=self._mask(str(error))) from error
                await self._sleep(attempt)
                continue

            if response.status_code in RETRY_STATUS_CODES and attempt < RETRY_ATTEMPTS:
                await self._sleep(attempt)
                continue
            if response.is_success:
                return response
            raise self._http_error(response)

        raise SourceError("source.unreachable", detail=self._mask(str(last_error)))

    @staticmethod
    async def _sleep(attempt: int) -> None:
        await asyncio.sleep(RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))

    def _http_error(self, response: httpx.Response) -> SourceError:
        status = response.status_code
        detail = self._mask(response.text[:500])
        if status == 401:
            return SourceError("source.unauthorized", status_code=401, detail=detail)
        if status == 403:
            return SourceError("source.forbidden", status_code=403, detail=detail)
        if status == 404:
            return SourceError("source.not_found", status_code=404, detail=detail)
        if status == 429:
            return SourceError("source.rate_limited", status_code=429, detail=detail)
        return SourceError("source.http_error", status=status, detail=detail)

    def _mask(self, text: str) -> str:
        return mask_secrets(text, self._token)


# --- mapping of API payloads to our dataclasses ------------------------------


def _group(item: dict[str, Any]) -> SourceGroup:
    return SourceGroup(
        ref=str(item.get("id", "")),
        path=item.get("full_path") or item.get("path") or "",
        name=item.get("name") or item.get("path") or "",
        web_url=item.get("web_url"),
        parent_ref=str(item["parent_id"]) if item.get("parent_id") else None,
    )


def _project(item: dict[str, Any]) -> SourceProject:
    return SourceProject(
        ref=str(item.get("id", "")),
        path_with_namespace=item.get("path_with_namespace") or "",
        name=item.get("name") or "",
        web_url=item.get("web_url") or "",
        default_branch=item.get("default_branch"),
        archived=bool(item.get("archived")),
        empty_repo=bool(item.get("empty_repo")),
        last_activity_at=_datetime(item.get("last_activity_at")),
    )


def _responsible(items: list[dict[str, Any]], *, inherited: bool) -> list[SourceMember]:
    """Pick the most responsible tier out of a member list."""
    members = [_member(item, inherited=inherited) for item in items]
    members = [
        member
        for member in members
        if member.is_active and not ACCESS_TOKEN_USERNAME.match(member.username)
    ]

    maintainers = [m for m in members if m.access_level >= MAINTAINER_ACCESS_LEVEL]
    if maintainers:
        return _sorted(maintainers)

    if inherited:
        # A group developer is not responsible for one specific repository.
        return []
    return _sorted([m for m in members if m.access_level >= DEVELOPER_ACCESS_LEVEL])


def _sorted(members: list[SourceMember]) -> list[SourceMember]:
    return sorted(members, key=lambda member: (-member.access_level, member.name.lower()))


def _member(item: dict[str, Any], *, inherited: bool = False) -> SourceMember:
    return SourceMember(
        name=item.get("name") or item.get("username") or "",
        username=item.get("username") or "",
        access_level=int(item.get("access_level") or 0),
        web_url=item.get("web_url"),
        state=item.get("state"),
        inherited=inherited,
    )


def _branch(item: dict[str, Any]) -> SourceBranch:
    commit = item.get("commit") or {}
    return SourceBranch(
        name=item.get("name") or "",
        commit_sha=commit.get("id"),
        committed_date=_datetime(commit.get("committed_date")),
        is_default=bool(item.get("default")),
        protected=bool(item.get("protected")),
    )


def _datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _as_list(payload: Any) -> list[dict[str, Any]]:
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def _as_dict(payload: Any) -> dict[str, Any]:
    return payload if isinstance(payload, dict) else {}


def _encode(value: str) -> str:
    """URL-encode an id or a path (GitLab wants %2F in paths)."""
    return quote(str(value), safe="")


def _bool(value: bool) -> str:
    return "true" if value else "false"
