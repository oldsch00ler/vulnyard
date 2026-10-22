# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""FastAPI application: API, health check, static SPA and startup checks."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from app import APP_NAME, __version__
from app.api import api_router
from app.auth import TokenRejectedError, UnauthenticatedError, authenticate_request, is_mcp_path
from app.config import DEFAULT_LOCALE, Settings, get_settings
from app.db import dispose_engine, init_engine, run_migrations, session_factory
from app.errors import AppError
from app.i18n import resolve_locale, t
from app.mcp_server import create_mcp_server, mcp_routes
from app.masking import SecretMaskingFilter
from app.schemas import HealthResponse
from app.services.dtrack import MIN_SUPPORTED_VERSION, create_dtrack_client
from app.services.kev import KevCatalog
from app.services.notifications import ChatNotifier
from app.services.queue import ScanWorker
from app.services.scheduler import ScanScheduler
from app.services.sources import SourceProvider
from app.services.tools import LOCAL_TRIVY_PATH, detect_git, detect_trivy
from app.static import FRONTEND_DIST, frontend_available, register_frontend

logger = logging.getLogger("vulnyard")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        force=True,
    )
    # Libraries log their own messages; secrets must not survive any of them.
    masking = SecretMaskingFilter()
    for handler in logging.getLogger().handlers:
        handler.addFilter(masking)


def _apply_timezone(settings: Settings) -> None:
    """Apply TZ; an unknown zone falls back to UTC with a warning."""
    if not settings.timezone_is_valid:
        logger.warning(
            t("startup.timezone.invalid", settings.default_locale, value=settings.tz)
        )
    os.environ["TZ"] = settings.timezone_name
    if hasattr(time, "tzset"):
        time.tzset()


def _log_startup(settings: Settings, app: FastAPI) -> None:
    """Log versions and configuration state (see SPEC section 14)."""
    locale = settings.default_locale
    logger.info(t("startup.app", locale, name=APP_NAME, version=__version__))
    logger.info(t("startup.timezone", locale, timezone=settings.timezone_name))
    logger.info(t("startup.locale", locale, locale=locale))

    trivy = app.state.trivy
    if trivy.available:
        logger.info(t("startup.trivy.found", locale, version=trivy.version or "?", path=trivy.path))
    else:
        logger.warning(t("startup.trivy.missing", locale, fallback=str(LOCAL_TRIVY_PATH)))

    git = app.state.git
    if git.available:
        logger.info(t("startup.git.found", locale, version=git.version or "?", path=git.path))
    else:
        logger.warning(t("startup.git.missing", locale))

    missing = settings.missing_scan_config
    if missing:
        logger.warning(t("startup.config.missing", locale, variables=", ".join(missing)))
    else:
        logger.info(t("startup.config.ok", locale))

    if settings.auth_mode == "none":
        logger.warning(t("startup.auth_mode.none", locale))
    else:
        logger.info(
            t("startup.auth_mode.proxy_header", locale, headers=", ".join(settings.auth_header_names))
        )
        logger.warning(t("startup.auth_mode.proxy_header_warning", locale))

    if settings.ca_bundle:
        if Path(settings.ca_bundle).is_file():
            logger.info(t("startup.ca_bundle.used", locale, path=settings.ca_bundle))
        else:
            # A wrong path would only show up as TLS errors during a scan.
            logger.warning(t("startup.ca_bundle.missing", locale, path=settings.ca_bundle))

    if not frontend_available():
        logger.warning(t("startup.frontend.missing", locale, path=str(FRONTEND_DIST)))



async def _init_dtrack(settings: Settings, app: FastAPI) -> None:
    """Create the Dependency-Track client and detect its version/features."""
    locale = settings.default_locale
    client = create_dtrack_client(settings)
    app.state.dtrack = client
    if client is None:
        logger.warning(t("startup.dtrack.not_configured", locale))
        return

    try:
        features = await client.detect_features()
    except AppError as error:
        logger.warning(
            t("startup.dtrack.unreachable", locale, url=settings.dt_api_url, detail=error.code)
        )
        return

    if not features.supported:
        logger.warning(
            t(
                "startup.dtrack.unsupported",
                locale,
                version=features.version or "?",
                minimum=".".join(str(part) for part in MIN_SUPPORTED_VERSION),
            )
        )
        return
    logger.info(
        t("startup.dtrack.ready", locale, url=settings.dt_api_url, version=features.version or "?")
    )


async def _init_worker(settings: Settings, app: FastAPI) -> ScanWorker:
    """Recover interrupted jobs and start the scan worker."""
    locale = settings.default_locale
    dtrack = getattr(app.state, "dtrack", None)
    if dtrack is not None and not dtrack.features.supported:
        # An unsupported Dependency-Track must not be used for uploads.
        dtrack = None

    notifier = ChatNotifier(settings)
    app.state.notifier = notifier

    worker = ScanWorker(
        settings,
        session_factory(),
        source=getattr(app.state, "source", None),
        source_provider=getattr(app.state, "source_provider", None),
        dtrack=dtrack,
        trivy_available=app.state.trivy.available and app.state.git.available,
        notifier=notifier,
    )
    app.state.worker = worker

    await worker.recover()
    await worker.start()

    if worker.running:
        logger.info(t("startup.worker.started", locale, concurrency=worker.concurrency))
    else:
        reasons = []
        if getattr(app.state, "source", None) is None:
            reasons.append("GITLAB_TOKEN")
        if dtrack is None:
            reasons.append("Dependency-Track")
        if not app.state.trivy.available:
            reasons.append("Trivy")
        if not app.state.git.available:
            reasons.append("git")
        logger.warning(t("startup.worker.disabled", locale, reason=", ".join(reasons) or "?"))
    return worker


async def _backfill_snapshots(settings: Settings, dtrack: object) -> None:
    """Fill the trend from Dependency-Track history for projects without snapshots."""
    from app.services.snapshots import backfill

    try:
        async with session_factory()() as session:
            written = await backfill(session, dtrack)  # type: ignore[arg-type]
    except AppError as error:
        logger.warning("Could not backfill metric snapshots: %s", error.code)
        return
    if written:
        logger.info(t("startup.snapshots.backfilled", settings.default_locale, count=written))


async def _init_scheduler(settings: Settings, app: FastAPI, worker: ScanWorker) -> ScanScheduler:
    """Register the cron jobs of the targets and the daily housekeeping."""
    dtrack = getattr(app.state, "dtrack", None)
    if dtrack is not None and not dtrack.features.supported:
        dtrack = None

    scheduler = ScanScheduler(
        settings,
        session_factory(),
        worker=worker,
        source_provider=getattr(app.state, "source_provider", None),
        dtrack=dtrack,
    )
    app.state.scheduler = scheduler
    await scheduler.start()

    if dtrack is not None:
        await _backfill_snapshots(settings, dtrack)

    locale = settings.default_locale
    if scheduler.running:
        logger.info(
            t("startup.scheduler.started", locale, targets=scheduler.scheduled_targets)
        )
    elif not worker.enabled:
        logger.info(t("startup.scheduler.disabled", locale))
    # Otherwise the scheduler itself already said why it stayed off (another
    # instance holds the lock), so there is nothing to add here.
    return scheduler


async def _init_source(settings: Settings, app: FastAPI) -> None:
    """Create the source provider and log whether the default instance answers."""
    locale = settings.default_locale
    provider = SourceProvider(settings)
    app.state.source_provider = provider

    if not settings.source_configured:
        app.state.source = None
        # Targets can still carry their own credentials, so this is not fatal.
        logger.warning(t("startup.source.not_configured", locale))
        return

    source = provider.global_source()
    app.state.source = source
    if source is None:
        return
    try:
        version = await source.version()
    except AppError as error:
        # An unreachable source must not stop the application (SPEC 3.1).
        logger.warning(
            t("startup.source.unreachable", locale, url=settings.gitlab_url, detail=error.code)
        )
        return
    logger.info(t("startup.source.ready", locale, url=settings.gitlab_url, version=version or "?"))


async def _shutdown(app: FastAPI) -> None:
    """Stop the scheduler and worker, release the clients and the engine."""
    scheduler = getattr(app.state, "scheduler", None)
    if scheduler is not None:
        await scheduler.stop()
        app.state.scheduler = None
    worker = getattr(app.state, "worker", None)
    if worker is not None:
        await worker.stop()
    provider = getattr(app.state, "source_provider", None)
    if provider is not None:
        await provider.close()
        app.state.source_provider = None
    app.state.source = None
    dtrack = getattr(app.state, "dtrack", None)
    if dtrack is not None:
        await dtrack.close()
        app.state.dtrack = None
    notifier = getattr(app.state, "notifier", None)
    if notifier is not None:
        await notifier.close()
        app.state.notifier = None
    kev = getattr(app.state, "kev", None)
    if kev is not None:
        await kev.close()
        app.state.kev = None
    await dispose_engine()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    _configure_logging(settings.log_level)
    _apply_timezone(settings)

    app.state.settings = settings
    app.state.default_locale = settings.default_locale
    app.state.trivy = detect_trivy(settings)
    app.state.git = detect_git()
    app.state.source = None
    app.state.source_provider = None
    app.state.dtrack = None
    app.state.worker = None
    app.state.scheduler = None
    app.state.notifier = None
    # Fetched lazily by the threats page, so it costs nothing until used.
    app.state.kev = KevCatalog(settings)

    # DATABASE_URL is the only mandatory variable – without it we stop with a
    # clear message instead of failing later on the first query.
    if not settings.database_url:
        logger.error(t("config.database_url.missing", settings.default_locale))
        raise SystemExit(1)

    _log_startup(settings, app)

    engine = init_engine(settings)
    try:
        logger.info(t("startup.database.migrating", settings.default_locale))
        await run_migrations(engine)
        logger.info(t("startup.database.ready", settings.default_locale))

        await _init_source(settings, app)
        await _init_dtrack(settings, app)
        worker = await _init_worker(settings, app)
        await _init_scheduler(settings, app, worker)
    except BaseException:
        # Startup failed – let go of the engine and the clients we opened.
        await _shutdown(app)
        raise

    try:
        # Stateless MCP still needs the SDK's task group for its requests.
        async with app.state.mcp_server.session_manager.run():
            yield
    finally:
        await _shutdown(app)


def create_app() -> FastAPI:
    app = FastAPI(
        title=APP_NAME,
        version=__version__,
        description="Central scanning of GitLab repositories with Trivy and Dependency-Track",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    def _locale(request: Request) -> str:
        default = getattr(request.app.state, "default_locale", DEFAULT_LOCALE)
        return resolve_locale(request.headers.get("Accept-Language"), default)

    def _error_response(status_code: int, code: str, message: str, params: dict | None = None) -> JSONResponse:
        """Error shape from SPEC section 11."""
        return JSONResponse(
            status_code=status_code,
            content={"error": {"code": code, "params": params or {}, "message": message}},
        )

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        locale = _locale(request)
        if exc.detail:
            logger.warning("%s: %s", exc.code, exc.detail)
        return _error_response(
            exc.status_code, exc.code, t(exc.code, locale, **exc.params), exc.params
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = ", ".join(".".join(str(part) for part in error["loc"][1:]) for error in exc.errors())
        params = {"fields": fields}
        return _error_response(
            422,
            "validation.invalid_request",
            t("validation.invalid_request", _locale(request), **params),
            params,
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and "code" in detail:
            return _error_response(
                exc.status_code, detail["code"], detail.get("message", ""), detail.get("params")
            )
        return _error_response(exc.status_code, f"http_{exc.status_code}", str(detail))

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # The technical detail goes to the log, the user gets a translated message.
        logger.exception("Unhandled error while handling %s %s", request.method, request.url.path)
        return _error_response(500, "error.internal", t("error.internal", _locale(request)))

    @app.middleware("http")
    async def require_identity(request: Request, call_next):  # noqa: ANN001, ANN202
        """Authenticate /api/* and /mcp before they reach a route (SPEC section 13).

        An API token is checked in every mode. Without one, proxy-header mode
        requires the identity header: a missing header means the authenticating
        proxy was bypassed. `/health` stays open: the platform health check does
        not go through the proxy, and it exposes nothing.
        """
        if request.url.path.startswith("/api/") or is_mcp_path(request.url.path):
            try:
                await authenticate_request(request, get_settings())
            except AppError as error:
                response = _error_response(
                    error.status_code,
                    error.code,
                    t(error.code, _locale(request), **error.params),
                    error.params,
                )
                if isinstance(error, TokenRejectedError):
                    response.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
                elif isinstance(error, UnauthenticatedError) and is_mcp_path(request.url.path):
                    response.headers["WWW-Authenticate"] = "Bearer"
                return response
        return await call_next(request)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    async def health(response: Response) -> HealthResponse:
        """Health check – must not be cached and must not touch external services."""
        response.headers["Cache-Control"] = "no-store"
        return HealthResponse(status="ok")

    app.include_router(api_router)

    # Read-only MCP endpoint for coding agents (SPEC 11.1).
    app.state.mcp_server = create_mcp_server()
    app.router.routes.extend(mcp_routes(app.state.mcp_server))

    # Registered last: the SPA catch-all must not shadow /health and /api/*.
    register_frontend(app)
    return app


app = create_app()
