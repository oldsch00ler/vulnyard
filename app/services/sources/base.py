# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Repository source abstraction.

Everything that talks to a repository hosting service goes through
`RepositorySource`. v1 has a single implementation (`GitLabSource`); nothing
outside this package may call the source API directly (SPEC section 2).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class SourceGroup:
    """A group (namespace) of projects in the source."""

    ref: str
    path: str
    name: str
    web_url: str | None = None
    parent_ref: str | None = None


@dataclass(frozen=True, slots=True)
class SourceProject:
    """A repository in the source."""

    ref: str
    path_with_namespace: str
    name: str
    web_url: str
    default_branch: str | None
    archived: bool = False
    empty_repo: bool = False
    last_activity_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SourceMember:
    """A person (or service account) with access to a repository.

    `inherited` means the access comes from a parent group rather than from the
    project itself, which matters for notifications: the people added directly
    to a repository are the ones responsible for it, while a group can carry a
    hundred members who have never seen it.
    """

    name: str
    username: str
    access_level: int
    web_url: str | None = None
    state: str | None = None
    inherited: bool = False

    @property
    def is_active(self) -> bool:
        return self.state in (None, "active")


@dataclass(frozen=True, slots=True)
class SourceBranch:
    """A branch of a repository, including its last commit."""

    name: str
    commit_sha: str | None = None
    committed_date: datetime | None = None
    is_default: bool = False
    protected: bool = False


class RepositorySource(ABC):
    """Read-only view of a repository hosting service."""

    #: Value stored in the `source` columns.
    name: str

    @abstractmethod
    async def close(self) -> None:
        """Release the underlying HTTP client."""

    @abstractmethod
    async def version(self) -> str | None:
        """Version of the source instance, used for the status endpoint."""

    @abstractmethod
    async def search_groups(self, search: str, limit: int = 20) -> list[SourceGroup]:
        """Groups matching the search term (for the autocomplete)."""

    @abstractmethod
    async def get_group(self, ref: str) -> SourceGroup:
        """Detail of one group."""

    @abstractmethod
    async def list_group_projects(self, ref: str, *, include_subgroups: bool) -> list[SourceProject]:
        """All non-archived projects of a group (paginated internally)."""

    @abstractmethod
    async def search_projects(self, search: str, limit: int = 20) -> list[SourceProject]:
        """Projects matching the search term (for the autocomplete)."""

    @abstractmethod
    async def get_project(self, ref: str) -> SourceProject:
        """Detail of one project."""

    @abstractmethod
    async def list_branches(self, project_ref: str, search: str | None = None) -> list[SourceBranch]:
        """Branches of a project (paginated internally)."""

    @abstractmethod
    async def get_branch(self, project_ref: str, branch: str) -> SourceBranch | None:
        """One branch including its last commit, or None if it does not exist."""

    @abstractmethod
    async def list_maintainers(self, project_ref: str) -> list[SourceMember]:
        """People responsible for the repository, most privileged first.

        Members added to the project win over members inherited from a group.
        """

    @abstractmethod
    def clone_url(self, project: SourceProject) -> str:
        """Authenticated HTTPS clone URL. Contains the token – never log it."""

    @abstractmethod
    def web_url(self, project: SourceProject, branch: str | None = None) -> str:
        """Link to the repository (or branch) in the source web UI."""
