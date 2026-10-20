# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Discovery of the external binaries the scanner needs (Trivy, git)."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.config import APP_ROOT, Settings

# Trivy installed by scripts/install-trivy.sh next to the application.
LOCAL_TRIVY_PATH = APP_ROOT / ".bin" / "trivy"

_VERSION_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class ToolInfo:
    """Result of looking up one external binary."""

    name: str
    path: str | None = None
    version: str | None = None

    @property
    def available(self) -> bool:
        return self.path is not None


def resolve_trivy_path(settings: Settings) -> str | None:
    """Locate Trivy: TRIVY_BIN, then ./.bin/trivy, then PATH."""
    if settings.trivy_bin:
        candidate = Path(settings.trivy_bin)
        return str(candidate) if _is_executable(candidate) else None
    if _is_executable(LOCAL_TRIVY_PATH):
        return str(LOCAL_TRIVY_PATH)
    return shutil.which("trivy")


def resolve_git_path() -> str | None:
    return shutil.which("git")


def detect_trivy(settings: Settings) -> ToolInfo:
    path = resolve_trivy_path(settings)
    if path is None:
        return ToolInfo(name="trivy")
    # `trivy --version` prints "Version: 0.74.0" followed by database details.
    raw = _run_version(path, "--version")
    version = None
    if raw:
        match = re.search(r"Version:\s*(\S+)", raw)
        version = match.group(1) if match else raw.splitlines()[0].strip()
    return ToolInfo(name="trivy", path=path, version=version)


def detect_git() -> ToolInfo:
    path = resolve_git_path()
    if path is None:
        return ToolInfo(name="git")
    # `git --version` prints "git version 2.55.0".
    raw = _run_version(path, "--version")
    version = None
    if raw:
        match = re.search(r"git version\s*(\S+)", raw)
        version = match.group(1) if match else raw.splitlines()[0].strip()
    return ToolInfo(name="git", path=path, version=version)


def _is_executable(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _run_version(executable: str, *args: str) -> str | None:
    """Run `executable args` without a shell and return its output."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            [executable, *args],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or completed.stderr or "").strip()
    return output or None
