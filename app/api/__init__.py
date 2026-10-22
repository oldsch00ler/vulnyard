# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""REST API routers."""

from fastapi import APIRouter, Security
from fastapi.security import HTTPBearer

from app.api import (
    dashboard,
    ignores,
    projects,
    runs,
    settings,
    source,
    status,
    targets,
    threats,
    tokens,
    vulnerabilities,
)

# Only documents the scheme, so that /api/docs offers "Authorize": the real
# check happens in the middleware (app.auth), before any route runs.
bearer_scheme = HTTPBearer(
    auto_error=False,
    description="API token created in Settings (`vy_...`).",
)

api_router = APIRouter(prefix="/api", dependencies=[Security(bearer_scheme)])
api_router.include_router(status.router)
api_router.include_router(targets.router)
api_router.include_router(source.router)
api_router.include_router(runs.router)
api_router.include_router(projects.router)
api_router.include_router(dashboard.router)
api_router.include_router(ignores.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(threats.router)
api_router.include_router(settings.router)
api_router.include_router(tokens.router)
