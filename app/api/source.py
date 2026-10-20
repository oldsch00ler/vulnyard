# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Autocomplete over the repository source (SPEC section 11)."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.dependencies import SourceDep, SourcesDep
from app.errors import ValidationError
from app.schemas import (
    SourceBranchRead,
    SourceGroupRead,
    SourceLookupRequest,
    SourceProjectRead,
)
from app.config import get_settings
from app.dependencies import LocaleDep
from app.errors import AppError
from app.i18n import t
from app.schemas import ConnectionTestResult
from app.services import targets as target_service
from app.services.sources.base import RepositorySource

router = APIRouter(prefix="/source", tags=["source"])

# GitLab returns nothing for a two character search, so asking for three
# keeps the autocomplete honest (verified against GitLab 17.11).
MIN_SEARCH_LENGTH = 3
SUGGESTION_LIMIT = 20


@router.get("/groups", response_model=list[SourceGroupRead])
async def search_groups(source: SourceDep, search: str = Query(default="")) -> list[SourceGroupRead]:
    _require_search(search)
    groups = await source.search_groups(search.strip(), limit=SUGGESTION_LIMIT)
    return [
        SourceGroupRead(ref=group.ref, path=group.path, name=group.name, web_url=group.web_url)
        for group in groups
    ]


@router.get("/projects", response_model=list[SourceProjectRead])
async def search_projects(source: SourceDep, search: str = Query(default="")) -> list[SourceProjectRead]:
    _require_search(search)
    projects = await source.search_projects(search.strip(), limit=SUGGESTION_LIMIT)
    return [_project(project) for project in projects]


@router.post("/groups", response_model=list[SourceGroupRead])
async def search_groups_with_credentials(
    payload: SourceLookupRequest, sources: SourcesDep
) -> list[SourceGroupRead]:
    """Same as the GET, but usable with credentials a target does not have yet.

    The token travels in the body, never in a query string that would end up in
    logs and browser history.
    """
    _require_search(payload.search)
    groups = await _source_for(payload, sources).search_groups(
        payload.search.strip(), limit=SUGGESTION_LIMIT
    )
    return [
        SourceGroupRead(ref=group.ref, path=group.path, name=group.name, web_url=group.web_url)
        for group in groups
    ]


@router.post("/projects", response_model=list[SourceProjectRead])
async def search_projects_with_credentials(
    payload: SourceLookupRequest, sources: SourcesDep
) -> list[SourceProjectRead]:
    _require_search(payload.search)
    projects = await _source_for(payload, sources).search_projects(
        payload.search.strip(), limit=SUGGESTION_LIMIT
    )
    return [_project(project) for project in projects]


@router.post("/test", response_model=ConnectionTestResult)
async def test_credentials(
    payload: SourceLookupRequest, sources: SourcesDep, locale: LocaleDep
) -> ConnectionTestResult:
    """Check credentials before a target is saved with them."""
    try:
        source = _source_for(payload, sources)
        version = await source.version()
    except AppError as error:
        return ConnectionTestResult(
            ok=False, code=error.code, detail=t(error.code, locale, **error.params)
        )
    url = payload.source_url or get_settings().gitlab_url
    return ConnectionTestResult(
        ok=True,
        version=version,
        detail=t("settings.test.target_source_ok", locale, url=url, version=version or "?"),
    )


@router.get("/projects/{project_ref}/branches", response_model=list[SourceBranchRead])
async def list_branches(
    project_ref: str,
    source: SourceDep,
    search: str = Query(default=""),
) -> list[SourceBranchRead]:
    """Real branches of a project, for the branch picker."""
    branches = await source.list_branches(project_ref, search=search.strip() or None)
    branches.sort(key=lambda branch: (not branch.is_default, branch.name))
    return [
        SourceBranchRead(
            name=branch.name,
            commit_sha=branch.commit_sha,
            is_default=branch.is_default,
            protected=branch.protected,
        )
        for branch in branches[:SUGGESTION_LIMIT]
    ]


def _project(project) -> SourceProjectRead:  # noqa: ANN001 - SourceProject dataclass
    return SourceProjectRead(
        ref=project.ref,
        path_with_namespace=project.path_with_namespace,
        name=project.name,
        web_url=project.web_url,
        default_branch=project.default_branch,
        archived=project.archived,
        empty_repo=project.empty_repo,
    )


def _source_for(payload: SourceLookupRequest, sources: SourcesDep) -> RepositorySource:
    """Client for the credentials in the body, or the configured ones."""
    credentials = target_service.credentials_from_payload(payload)
    return sources.get(credentials or sources.credentials_for(None))


def _require_search(search: str) -> None:
    if len(search.strip()) < MIN_SEARCH_LENGTH:
        raise ValidationError("validation.search_too_short", min=MIN_SEARCH_LENGTH)
