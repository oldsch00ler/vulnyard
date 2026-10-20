# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Validation of values that reach a subprocess or the scheduler."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from apscheduler.triggers.cron import CronTrigger

# Git branch names: no leading dash (would look like an option to git), no
# whitespace, no characters git forbids anyway (SPEC section 13).
_FORBIDDEN_BRANCH_CHARS = re.compile(r"[\s~^:?*\[\\\x00-\x1f\x7f]")
MAX_BRANCH_LENGTH = 255
MAX_PATTERN_LENGTH = 255


def is_valid_branch_name(branch: str) -> bool:
    """Whether the string is safe to hand to `git clone --branch`."""
    if not branch or len(branch) > MAX_BRANCH_LENGTH:
        return False
    if branch.startswith("-") or branch.startswith("/") or branch.endswith("/"):
        return False
    if branch.startswith(".") or branch.endswith(".") or branch.endswith(".lock"):
        return False
    if ".." in branch or "//" in branch or "@{" in branch:
        return False
    return not _FORBIDDEN_BRANCH_CHARS.search(branch)


def is_valid_branch_pattern(pattern: str) -> bool:
    """A branch name or a glob pattern (`release/*`) as used in the UI."""
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        return False
    if pattern.startswith("-"):
        return False
    # The glob characters * ? [ ] are allowed here, unlike in a branch name.
    without_glob = pattern.replace("*", "x").replace("?", "x").replace("[", "x").replace("]", "x")
    return is_valid_branch_name(without_glob)


def is_valid_path_pattern(pattern: str) -> bool:
    """Glob pattern over a project path (`sandbox/*`, `*/archive-*`)."""
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        return False
    return not re.search(r"[\s\x00-\x1f\x7f]", pattern)


def is_valid_source_url(url: str) -> bool:
    """Whether the string is a usable base URL of a source instance."""
    if not url or len(url) > 512:
        return False
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def is_valid_webhook_url(url: str) -> bool:
    """Whether the string is an https URL we are willing to POST to."""
    if not url or len(url) > 1024:
        return False
    parts = urlsplit(url)
    return parts.scheme == "https" and bool(parts.netloc)


def is_valid_cron(expression: str) -> bool:
    """Whether APScheduler can build a trigger from the expression.

    Validated with the same parser the scheduler uses, so anything accepted
    here can really be scheduled.
    """
    try:
        CronTrigger.from_crontab(expression)
    except (ValueError, TypeError):
        return False
    return True
