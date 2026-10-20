# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Discovery: project filtering and branch expansion (SPEC 7.1)."""

from __future__ import annotations

import pytest

from app.constants import BRANCH_MODE_CUSTOM, BRANCH_MODE_DEFAULT, TARGET_KIND_GROUP
from app.services.discovery import TargetSpec, discover
from tests.fakes import FakeSource, branch, project


def group_spec(**overrides: object) -> TargetSpec:
    defaults: dict[str, object] = {"kind": TARGET_KIND_GROUP, "source_ref": "1"}
    return TargetSpec(**{**defaults, **overrides})  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_default_mode_takes_only_the_default_branch() -> None:
    source = FakeSource(
        projects=[project("10", "team/app", default_branch="main")],
        branches={"10": [branch("main", is_default=True), branch("develop")]},
    )

    result = await discover(source, group_spec(branch_mode=BRANCH_MODE_DEFAULT))

    assert [p.project.path_with_namespace for p in result.projects] == ["team/app"]
    assert [(b.branch, b.is_default_branch) for b in result.projects[0].branches] == [("main", True)]
    # The default branch is fetched directly, no full branch listing.
    assert source.list_branches_calls == 0


@pytest.mark.asyncio
async def test_archived_and_empty_projects_are_skipped_with_a_reason() -> None:
    source = FakeSource(
        projects=[
            project("10", "team/archived", archived=True),
            project("11", "team/empty", empty_repo=True),
            project("12", "team/app"),
        ],
        branches={"12": [branch("main", is_default=True)]},
    )

    result = await discover(source, group_spec())

    assert [p.project.path_with_namespace for p in result.projects] == ["team/app"]
    reasons = {s.project.path_with_namespace: s.reason.code for s in result.skipped}
    assert reasons == {
        "team/archived": "discovery.skipped.archived",
        "team/empty": "discovery.skipped.empty_repo",
    }


@pytest.mark.asyncio
async def test_exclude_patterns_from_target_and_global_settings() -> None:
    source = FakeSource(
        projects=[
            project("10", "team/app"),
            project("11", "team/archive-old"),
            project("12", "sandbox/toy"),
        ],
        branches={ref: [branch("main", is_default=True)] for ref in ("10", "11", "12")},
    )

    result = await discover(
        source,
        group_spec(exclude_patterns=("*/archive-*",)),
        global_exclude_patterns=("sandbox/*",),
    )

    assert [p.project.path_with_namespace for p in result.projects] == ["team/app"]
    assert {s.reason.params["pattern"] for s in result.skipped} == {"*/archive-*", "sandbox/*"}


@pytest.mark.asyncio
async def test_custom_mode_matches_names_and_globs_and_adds_default_branch() -> None:
    source = FakeSource(
        projects=[project("10", "team/app", default_branch="main")],
        branches={
            "10": [
                branch("main", is_default=True),
                branch("develop"),
                branch("release/1.0"),
                branch("release/2.0"),
                branch("feature/x"),
            ]
        },
    )

    result = await discover(
        source,
        group_spec(
            branch_mode=BRANCH_MODE_CUSTOM,
            branch_patterns=("develop", "release/*"),
            include_default_branch=True,
        ),
    )

    branches = {b.branch for b in result.projects[0].branches}
    assert branches == {"main", "develop", "release/1.0", "release/2.0"}
    assert [b.is_default_branch for b in result.projects[0].branches if b.branch == "main"] == [True]


@pytest.mark.asyncio
async def test_pattern_without_a_match_is_a_note_not_an_error() -> None:
    source = FakeSource(
        projects=[project("10", "team/app", default_branch="main")],
        branches={"10": [branch("main", is_default=True)]},
    )

    result = await discover(
        source,
        group_spec(
            branch_mode=BRANCH_MODE_CUSTOM,
            branch_patterns=("hotfix/*", "missing-branch"),
            include_default_branch=True,
        ),
    )

    codes = {note.code for note in result.projects[0].notes}
    assert codes == {"discovery.branch.pattern_no_match", "discovery.branch.not_found"}
    assert [b.branch for b in result.projects[0].branches] == ["main"]


@pytest.mark.asyncio
async def test_branch_limit_keeps_default_branch_and_newest_commits() -> None:
    source = FakeSource(
        projects=[project("10", "team/app", default_branch="main")],
        branches={
            "10": [
                branch("main", is_default=True, days_ago=20),
                branch("old", days_ago=15),
                branch("newer", days_ago=2),
                branch("newest", days_ago=0),
            ]
        },
    )

    result = await discover(
        source,
        group_spec(
            branch_mode=BRANCH_MODE_CUSTOM,
            branch_patterns=("*",),
            max_branches_per_project=2,
        ),
    )

    assert [b.branch for b in result.projects[0].branches] == ["main", "newest"]
    trimmed = next(note for note in result.projects[0].notes if note.code == "discovery.branches.trimmed")
    assert trimmed.params == {"limit": 2, "dropped": 2}


@pytest.mark.asyncio
async def test_project_without_default_branch_is_skipped() -> None:
    source = FakeSource(projects=[project("10", "team/app", default_branch=None)])

    result = await discover(source, group_spec())

    assert result.projects == []
    assert result.skipped[0].reason.code == "discovery.skipped.no_default_branch"
