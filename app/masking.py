# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Masking of secrets in log output, error messages and subprocess output."""

from __future__ import annotations

import logging
import re

MASK = "***"

# https://user:password@host/... and https://oauth2:token@host/...
_CREDENTIALS_IN_URL = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^/\s:@]+):(?P<secret>[^/\s@]+)@")

# Tokens that look like a GitLab token, or one of our own API tokens, even if
# we do not know their value.
_TOKEN_LIKE = re.compile(
    r"\b(?:glpat|gldt|glrt|glsoat|glptt|gloas)-[A-Za-z0-9_\-]{8,}\b|\bvy_[A-Za-z0-9_\-]{20,}"
)

# Query parameters that carry a secret. A Google Chat webhook holds its key and
# token in the query string, and httpx logs whole request URLs.
_SECRET_QUERY_PARAM = re.compile(
    r"(?P<name>\b(?:key|token|api[_-]?key|access[_-]?token|private[_-]?token)=)[^&\s\"']+",
    re.IGNORECASE,
)

# Minimum length of a value we are willing to search for; masking a two
# character "secret" would corrupt unrelated text.
_MIN_SECRET_LENGTH = 6


def mask_url_credentials(text: str) -> str:
    """Replace the password part of any URL credentials with the mask."""
    return _CREDENTIALS_IN_URL.sub(lambda m: f"{m.group('scheme')}{m.group('user')}:{MASK}@", text)


def mask_query_secrets(text: str) -> str:
    """Replace the value of secret-carrying query parameters with the mask."""
    return _SECRET_QUERY_PARAM.sub(lambda m: f"{m.group('name')}{MASK}", text)


def mask_secrets(text: str, *secrets: str | None) -> str:
    """Mask the given secret values, URL credentials and token-like strings.

    Used on everything that can end up in a log, an API response or the job
    error detail (SPEC section 13).
    """
    if not text:
        return text
    masked = text
    for secret in secrets:
        if secret and len(secret) >= _MIN_SECRET_LENGTH:
            masked = masked.replace(secret, MASK)
    masked = mask_url_credentials(masked)
    masked = mask_query_secrets(masked)
    return _TOKEN_LIKE.sub(MASK, masked)


class SecretMaskingFilter(logging.Filter):
    """Masks secrets in every log record, ours and the libraries' alike.

    Our own messages go through `mask_secrets`, but httpx logs the full request
    URL on its own logger - and a chat webhook carries its key and token there.
    Attached to the root handler, this covers both (SPEC section 13).
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - logging API
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken format string is not ours to fix
            return True
        masked = mask_secrets(message)
        if masked != message:
            record.msg = masked
            record.args = ()
        return True
