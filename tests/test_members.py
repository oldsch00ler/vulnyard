# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Who counts as responsible for a repository (SPEC 9.5).

The shapes here mirror what a real GitLab 17.11 instance returns: most projects
have their own members, and the inherited group membership is large and mostly
irrelevant.
"""

from __future__ import annotations

import httpx
import pytest

from app.config import Settings
from app.services.notifications import build_message
from app.services.sources.gitlab import GitLabSource
from tests.test_notifications import notification


def member_payload(name: str, username: str, access_level: int, state: str = "active") -> dict:
    return {
        "name": name,
        "username": username,
        "access_level": access_level,
        "state": state,
        "web_url": f"https://git.example.com/{username}",
    }


def source_with(direct: list[dict], inherited: list[dict]) -> GitLabSource:
    """GitLab client whose member endpoints answer with the given payloads."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/members/all"):
            return httpx.Response(200, json=inherited, headers={"X-Next-Page": ""})
        if request.url.path.endswith("/members"):
            return httpx.Response(200, json=direct, headers={"X-Next-Page": ""})
        raise AssertionError(f"unexpected request: {request.url}")

    source = GitLabSource(Settings(gitlab_url="https://git.example.com", gitlab_token="glpat-x" * 3))
    source._client = httpx.AsyncClient(  # noqa: SLF001 - swapping the transport for the test
        base_url="https://git.example.com/api/v4",
        transport=httpx.MockTransport(handler),
    )
    return source


GROUP_OWNERS = [
    member_payload(f"Group Person {index}", f"group{index}", 50 if index % 3 == 0 else 40)
    for index in range(12)
]


async def test_direct_maintainers_win_over_inherited_group_members() -> None:
    """The repository's own maintainer, not the twelve owners of the group."""
    source = source_with(
        direct=[
            member_payload("Edvard Lánský", "elansky", 30),
            member_payload("Štěpán Jílek", "sjilek", 40),
            member_payload("Martin Hromádko", "mhromadko", 30),
        ],
        inherited=GROUP_OWNERS,
    )

    members = await source.list_maintainers("1")
    await source.close()

    assert [m.username for m in members] == ["sjilek"]
    assert members[0].inherited is False


async def test_direct_developers_are_used_when_nobody_is_a_maintainer() -> None:
    source = source_with(
        direct=[
            member_payload("Reporter Person", "reporter", 20),
            member_payload("Dev One", "dev1", 30),
            member_payload("Dev Two", "dev2", 30),
        ],
        inherited=GROUP_OWNERS,
    )

    members = await source.list_maintainers("1")
    await source.close()

    # Developers of the project beat owners of the group, and a Reporter is not
    # responsible for anything.
    assert [m.username for m in members] == ["dev1", "dev2"]
    assert all(m.inherited is False for m in members)


async def test_inherited_members_are_the_last_resort_and_are_marked() -> None:
    source = source_with(direct=[], inherited=GROUP_OWNERS)

    members = await source.list_maintainers("1")
    await source.close()

    assert members, "a project without its own members still needs somebody"
    assert all(m.inherited for m in members)
    # Owners first, then maintainers, each group sorted by name.
    assert members[0].access_level == 50


async def test_inherited_developers_are_not_reported() -> None:
    """A group developer is not responsible for one specific repository."""
    source = source_with(
        direct=[],
        inherited=[member_payload("Group Dev", "gdev", 30), member_payload("Guest", "guest", 10)],
    )

    members = await source.list_maintainers("1")
    await source.close()

    assert members == []


async def test_access_token_users_are_skipped() -> None:
    """Project and group access tokens are members, but nobody to notify."""
    source = source_with(
        direct=[
            member_payload("project_1234_bot_abc", "project_1234_bot_abc", 40),
            member_payload("group_77_bot_xyz", "group_77_bot_xyz", 40),
            member_payload("Real Maintainer", "real", 40),
        ],
        inherited=[],
    )

    members = await source.list_maintainers("1")
    await source.close()

    assert [m.username for m in members] == ["real"]


async def test_inactive_members_are_skipped() -> None:
    source = source_with(
        direct=[
            member_payload("Blocked Boss", "blocked", 50, state="blocked"),
            member_payload("Active Maintainer", "active", 40),
        ],
        inherited=[],
    )

    members = await source.list_maintainers("1")
    await source.close()

    assert [m.username for m in members] == ["active"]


# --- how the message labels each case -----------------------------------------


def make_member(name: str, username: str, access_level: int, *, inherited: bool = False):  # noqa: ANN201
    from app.services.sources.base import SourceMember

    return SourceMember(
        name=name,
        username=username,
        access_level=access_level,
        web_url=f"https://git.example.com/{username}",
        state="active",
        inherited=inherited,
    )


def test_message_names_the_role_of_each_person() -> None:
    text = build_message(
        notification(maintainers=(make_member("Štěpán Jílek", "sjilek", 40),))
    )["text"]

    assert "Maintaineři repa:" in text
    assert "Štěpán Jílek (@sjilek, Maintainer)" in text


def test_message_says_when_the_list_is_only_developers() -> None:
    text = build_message(notification(maintainers=(make_member("Dev One", "dev1", 30),)))["text"]

    assert "Členové repa:" in text
    assert "(@dev1, Developer)" in text


def test_message_says_when_the_list_came_from_the_group() -> None:
    text = build_message(
        notification(maintainers=(make_member("Group Owner", "gowner", 50, inherited=True),))
    )["text"]

    assert "Repo nemá vlastní členy, maintaineři skupiny:" in text
    assert "(@gowner, Owner)" in text


@pytest.mark.parametrize("access_level,expected", [(50, "Owner"), (40, "Maintainer"), (30, "Developer")])
def test_role_names_follow_gitlab(access_level: int, expected: str) -> None:
    text = build_message(notification(maintainers=(make_member("X", "x", access_level),)))["text"]

    assert f"(@x, {expected})" in text
