# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Serving of the built React SPA (frontend/dist) with an SPA fallback."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from app.config import APP_ROOT, DEFAULT_LOCALE
from app.i18n import t

logger = logging.getLogger(__name__)

FRONTEND_DIST = APP_ROOT / "frontend" / "dist"
INDEX_FILE = "index.html"

# Hashed asset files can be cached aggressively, index.html must not be.
_IMMUTABLE_DIRS = ("assets/",)


def frontend_available(dist_dir: Path = FRONTEND_DIST) -> bool:
    return (dist_dir / INDEX_FILE).is_file()


def register_frontend(app: FastAPI, dist_dir: Path = FRONTEND_DIST) -> None:
    """Register the catch-all route that serves the SPA.

    Must be registered last: `/health` and `/api/*` are matched before it.
    """

    @app.get("/{full_path:path}", include_in_schema=False, response_model=None)
    async def serve_spa(full_path: str, request: Request) -> FileResponse | JSONResponse:
        # Unknown API paths must stay JSON instead of returning the SPA shell.
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail=t("error.not_found", _locale(request)))

        index_file = dist_dir / INDEX_FILE
        if not index_file.is_file():
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "frontend_not_built",
                        "params": {},
                        "message": t("error.frontend_not_built", _locale(request)),
                    }
                },
            )

        candidate = _safe_path(dist_dir, full_path)
        if candidate is not None:
            headers = (
                {"Cache-Control": "public, max-age=31536000, immutable"}
                if full_path.startswith(_IMMUTABLE_DIRS)
                else None
            )
            return FileResponse(candidate, headers=headers)

        # Unknown path = client-side route, hand over index.html.
        return FileResponse(index_file, headers={"Cache-Control": "no-cache"})


def _safe_path(dist_dir: Path, relative: str) -> Path | None:
    """Resolve `relative` inside `dist_dir`; None if it is not a file in there."""
    if not relative:
        return None
    try:
        resolved = (dist_dir / relative).resolve()
        root = dist_dir.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(root) or not resolved.is_file():
        return None
    return resolved


def _locale(request: Request) -> str:
    return getattr(request.app.state, "default_locale", DEFAULT_LOCALE)
