# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import identity_from_request, optional_identity
from app.config import DEFAULT_LOCALE, Settings, get_settings
from app.db import get_session
from app.errors import AppError, SourceNotConfiguredError
from app.i18n import resolve_locale
from app.services.dtrack import DependencyTrackClient
from app.services.notifications import ChatNotifier
from app.services.queue import ScanWorker
from app.services.scheduler import ScanScheduler
from app.services.sources import SourceProvider
from app.services.sources.base import RepositorySource


def settings_dependency() -> Settings:
    return get_settings()


def identity_dependency(request: Request) -> str | None:
    """Caller identity; 401 in proxy-header mode when the header is missing."""
    return identity_from_request(request, get_settings())


def audit_identity_dependency(request: Request) -> str | None:
    """Identity for updated_by/triggered_by; never blocks the request."""
    return optional_identity(request, get_settings())


def locale_dependency(request: Request) -> str:
    """Locale of the request: Accept-Language, otherwise DEFAULT_LOCALE."""
    default = getattr(request.app.state, "default_locale", DEFAULT_LOCALE)
    return resolve_locale(request.headers.get("Accept-Language"), default)


def source_dependency(request: Request) -> RepositorySource:
    """The shared repository source client created at startup."""
    source = getattr(request.app.state, "source", None)
    if source is None:
        raise SourceNotConfiguredError("source.not_configured")
    return source


def worker_dependency(request: Request) -> ScanWorker:
    """The scan worker; scanning must be fully configured to use it."""
    worker = getattr(request.app.state, "worker", None)
    if worker is None or not worker.enabled:
        raise AppError("scan.not_available", status_code=503)
    return worker


def dtrack_dependency(request: Request) -> DependencyTrackClient | None:
    """Dependency-Track client, or None when it is not configured."""
    return getattr(request.app.state, "dtrack", None)


def required_dtrack_dependency(request: Request) -> DependencyTrackClient:
    """Dependency-Track client for endpoints that cannot work without it."""
    client = dtrack_dependency(request)
    if client is None:
        raise AppError("dtrack.not_configured", status_code=503)
    if not client.features.supported:
        raise AppError(
            "dtrack.version_unsupported",
            status_code=503,
            version=client.features.version or "?",
        )
    return client


def source_provider_dependency(request: Request) -> SourceProvider:
    """Provider of source clients; targets may carry their own credentials."""
    provider = getattr(request.app.state, "source_provider", None)
    if provider is None:
        raise SourceNotConfiguredError("source.not_configured")
    return provider


def optional_source_dependency(request: Request) -> RepositorySource | None:
    """Source client for the connection test; None when not configured."""
    return getattr(request.app.state, "source", None)


def notifier_dependency(request: Request) -> ChatNotifier:
    """The chat notifier created at startup."""
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        raise AppError("notify.not_configured", status_code=503)
    return notifier


def scheduler_dependency(request: Request) -> ScanScheduler | None:
    """The scheduler, or None when scanning is not configured."""
    return getattr(request.app.state, "scheduler", None)


SessionDep = Annotated[AsyncSession, Depends(get_session)]
IdentityDep = Annotated["str | None", Depends(identity_dependency)]
AuditIdentityDep = Annotated["str | None", Depends(audit_identity_dependency)]
SettingsDep = Annotated[Settings, Depends(settings_dependency)]
LocaleDep = Annotated[str, Depends(locale_dependency)]
SourceDep = Annotated[RepositorySource, Depends(source_dependency)]
SourceOptionalDep = Annotated["RepositorySource | None", Depends(optional_source_dependency)]
SourcesDep = Annotated[SourceProvider, Depends(source_provider_dependency)]
WorkerDep = Annotated[ScanWorker, Depends(worker_dependency)]
SchedulerDep = Annotated["ScanScheduler | None", Depends(scheduler_dependency)]
DTrackDep = Annotated["DependencyTrackClient | None", Depends(dtrack_dependency)]
RequiredDTrackDep = Annotated[DependencyTrackClient, Depends(required_dtrack_dependency)]
NotifierDep = Annotated[ChatNotifier, Depends(notifier_dependency)]
