# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Repository sources. Only this package may call a source API."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.config import Settings
from app.errors import SourceNotConfiguredError
from app.services.sources.base import (
    RepositorySource,
    SourceBranch,
    SourceGroup,
    SourceMember,
    SourceProject,
)
from app.services.sources.gitlab import GitLabSource

logger = logging.getLogger(__name__)

__all__ = [
    "GitLabSource",
    "RepositorySource",
    "SourceBranch",
    "SourceCredentials",
    "SourceGroup",
    "SourceMember",
    "SourceProject",
    "SourceProvider",
    "create_source",
]


@dataclass(frozen=True, slots=True)
class SourceCredentials:
    """Where to connect and with what. The token is a secret, never logged."""

    url: str
    token: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.url.rstrip("/"), self.token)


def create_source(settings: Settings, credentials: SourceCredentials | None = None) -> RepositorySource:
    """Create a source client for the given credentials, or for the environment.

    Raises SourceNotConfiguredError when nothing is configured, so the API can
    answer with a translated message instead of failing later.
    """
    if credentials is None:
        if not settings.source_configured:
            raise SourceNotConfiguredError("source.not_configured")
        credentials = SourceCredentials(url=settings.gitlab_url, token=settings.gitlab_token)
    if not credentials.url or not credentials.token:
        raise SourceNotConfiguredError("source.not_configured")

    # A per-target client keeps the environment settings for everything else
    # (CA bundle, timeouts) and only swaps the instance and the token.
    scoped = settings.model_copy(update={"gitlab_url": credentials.url, "gitlab_token": credentials.token})
    return GitLabSource(scoped)


class SourceProvider:
    """Hands out source clients, one per distinct set of credentials.

    A scan target can carry its own instance URL and token — it may live on a
    different GitLab, and a token scoped to one group is often preferred over one
    central token. Clients are cached so a run does not open a new HTTP client
    for every job, and they are all closed with the application.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._clients: dict[tuple[str, str], RepositorySource] = {}

    def credentials_for(self, target: object | None) -> SourceCredentials | None:
        """Credentials of a target, falling back to the environment.

        A target may override only the token (same instance, own token) or both.
        """
        url = getattr(target, "source_url", None) or self._settings.gitlab_url
        token = getattr(target, "source_token", None) or self._settings.gitlab_token
        if not url or not token:
            return None
        return SourceCredentials(url=url, token=token)

    def get(self, credentials: SourceCredentials | None) -> RepositorySource:
        """Client for these credentials; created once and reused."""
        if credentials is None:
            raise SourceNotConfiguredError("source.not_configured")
        client = self._clients.get(credentials.key)
        if client is None:
            client = create_source(self._settings, credentials)
            self._clients[credentials.key] = client
        return client

    def for_target(self, target: object) -> RepositorySource:
        """Client a target should be scanned and browsed with."""
        return self.get(self.credentials_for(target))

    def global_source(self) -> RepositorySource | None:
        """Client for the environment credentials, or None when unset."""
        credentials = self.credentials_for(None)
        if credentials is None:
            return None
        return self.get(credentials)

    async def close(self) -> None:
        for client in self._clients.values():
            await client.close()
        self._clients.clear()
