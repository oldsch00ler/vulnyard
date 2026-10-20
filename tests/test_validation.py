# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Validation of branches, patterns and cron expressions."""

from __future__ import annotations

import pytest

from app.masking import SecretMaskingFilter, mask_secrets
from app.validation import (
    is_valid_branch_name,
    is_valid_branch_pattern,
    is_valid_cron,
    is_valid_path_pattern,
)


@pytest.mark.parametrize("branch", ["main", "develop", "release/1.0", "feature/JIRA-1_x"])
def test_valid_branch_names(branch: str) -> None:
    assert is_valid_branch_name(branch)


@pytest.mark.parametrize(
    "branch",
    ["", "-force", "--upload-pack=evil", "with space", "a..b", "tip.lock", "/leading", "trailing/", "star*"],
)
def test_invalid_branch_names(branch: str) -> None:
    assert not is_valid_branch_name(branch)


@pytest.mark.parametrize("pattern", ["main", "release/*", "feature/*", "v?.*"])
def test_valid_branch_patterns(pattern: str) -> None:
    assert is_valid_branch_pattern(pattern)


@pytest.mark.parametrize("pattern", ["", "-evil", "with space", "..", "a b"])
def test_invalid_branch_patterns(pattern: str) -> None:
    assert not is_valid_branch_pattern(pattern)


@pytest.mark.parametrize("pattern", ["sandbox/*", "*/archive-*", "team/app"])
def test_valid_path_patterns(pattern: str) -> None:
    assert is_valid_path_pattern(pattern)


@pytest.mark.parametrize("expression", ["0 2 * * *", "*/15 * * * *", "0 6 * * mon-fri"])
def test_valid_cron_expressions(expression: str) -> None:
    assert is_valid_cron(expression)


@pytest.mark.parametrize("expression", ["", "nonsense", "0 2 * *", "99 2 * * *"])
def test_invalid_cron_expressions(expression: str) -> None:
    assert not is_valid_cron(expression)


def test_masking_hides_tokens_and_url_credentials() -> None:
    token = "glpat-ABCDEFGHIJ1234567890"
    text = f"clone https://oauth2:{token}@gitlab.example.com/team/app.git failed"

    masked = mask_secrets(text, token)

    assert token not in masked
    assert "oauth2:***@gitlab.example.com" in masked


def test_masking_works_without_knowing_the_token() -> None:
    masked = mask_secrets("fatal: authentication failed for glpat-SECRETVALUE123456")

    assert "glpat-SECRETVALUE123456" not in masked


def test_masking_ignores_short_values() -> None:
    # A two character "secret" must not corrupt unrelated text.
    assert mask_secrets("main branch", "in") == "main branch"


def test_masking_hides_webhook_key_and_token_in_a_url() -> None:
    url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=keyvalue123&token=tokenvalue456"

    masked = mask_secrets(f"HTTP Request: POST {url} \"HTTP/1.1 200 OK\"")

    assert "keyvalue123" not in masked
    assert "tokenvalue456" not in masked
    # The address itself stays readable, only the values go.
    assert "chat.googleapis.com/v1/spaces/AAAA/messages?key=***&token=***" in masked


def test_log_filter_masks_a_libraries_own_message() -> None:
    """httpx logs whole request URLs, so the filter has to catch those too."""
    import logging

    record = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="HTTP Request: POST %s \"HTTP/1.1 200 OK\"",
        args=("https://chat.googleapis.com/v1/spaces/AAAA/messages?key=keyvalue123",),
        exc_info=None,
    )

    assert SecretMaskingFilter().filter(record) is True
    assert "keyvalue123" not in record.getMessage()
    assert "key=***" in record.getMessage()
