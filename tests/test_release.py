# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Versioning and the generated changelog (scripts/release.py)."""

from __future__ import annotations

import importlib.util
import json
import re
import sys

import pytest

from app import __version__
from app.config import APP_ROOT

_spec = importlib.util.spec_from_file_location("release", APP_ROOT / "scripts" / "release.py")
release = importlib.util.module_from_spec(_spec)
# Registered first: dataclasses look their module up while being defined.
sys.modules["release"] = release
_spec.loader.exec_module(release)  # type: ignore[union-attr]


def test_version_is_the_same_everywhere() -> None:
    package = json.loads((APP_ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((APP_ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))

    assert package["version"] == __version__
    assert lock["version"] == __version__
    assert lock["packages"][""]["version"] == __version__


def test_changelog_matches_the_version() -> None:
    changelog = APP_ROOT / "CHANGELOG.md"
    latest = re.search(r"^## \[([^\]]+)\]", changelog.read_text(encoding="utf-8"), re.M)
    if latest is None:
        pytest.skip("no release yet")
    assert latest.group(1) == __version__


@pytest.mark.parametrize(
    ("subject", "message", "section", "text"),
    [
        ("Add Google Chat notifications", "", "Added", "Add Google Chat notifications"),
        ("Fix editing a scan target from the UI.", "", "Fixed", "Fix editing a scan target from the UI"),
        ("Remove the legacy endpoint", "", "Removed", "Remove the legacy endpoint"),
        ("Make the trend tooltip readable", "", "Changed", "Make the trend tooltip readable"),
        ("feat(api): bulk-create targets", "", "Added", "**api:** Bulk-create targets"),
        ("fix: trend legend", "", "Fixed", "Trend legend"),
        ("feat!: drop AUTH_MODE=none", "", "Breaking changes", "Drop AUTH_MODE=none"),
        ("Rename a setting", "body\n\nBREAKING CHANGE: renamed", "Breaking changes", "Rename a setting"),
        ("Mask secrets in logs", "x\n\nChangelog: security\n", "Security", "Mask secrets in logs"),
    ],
)
def test_commits_land_in_their_section(subject: str, message: str, section: str, text: str) -> None:
    entry = release.classify(subject, message)

    assert entry is not None
    assert (entry.section, entry.text) == (section, text)


@pytest.mark.parametrize(
    ("subject", "message"),
    [
        ("chore: tidy", ""),
        ("docs: typo", ""),
        ("Release v1.2.0", ""),
        ("Initial commit", ""),
        ("Refresh fixtures", "x\n\nChangelog: skip"),
    ],
)
def test_internal_commits_are_left_out(subject: str, message: str) -> None:
    assert release.classify(subject, message) is None


@pytest.mark.parametrize(
    ("base", "sections", "expected"),
    [
        ("1.2.3", ["Fixed"], "1.2.4"),
        ("1.2.3", ["Added", "Fixed"], "1.3.0"),
        ("1.2.3", ["Breaking changes"], "2.0.0"),
        ("0.4.1", ["Breaking changes"], "0.5.0"),
        ("1.2.3", [], "1.2.4"),
    ],
)
def test_next_version_follows_semver(base: str, sections: list[str], expected: str) -> None:
    entries = [release.Entry(section, "x") for section in sections]

    assert release.next_version(base, entries) == expected
