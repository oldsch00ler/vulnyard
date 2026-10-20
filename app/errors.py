# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Application errors as codes with parameters (SPEC sections 11 and 15)."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """An error that the API returns as {"error": {code, params, message}}.

    The text is never part of the exception: the message is rendered from the
    catalogue for the locale of the request.
    """

    status_code = 400

    def __init__(
        self,
        code: str,
        *,
        status_code: int | None = None,
        detail: str | None = None,
        **params: Any,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.params = params
        self.detail = detail
        if status_code is not None:
            self.status_code = status_code


class NotFoundError(AppError):
    status_code = 404


class ConflictError(AppError):
    status_code = 409


class ValidationError(AppError):
    status_code = 422


class SourceError(AppError):
    """Error while talking to the repository source (GitLab)."""

    status_code = 502


class SourceNotConfiguredError(SourceError):
    status_code = 503
