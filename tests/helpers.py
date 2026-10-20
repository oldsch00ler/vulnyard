# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Helpers for the scan pipeline tests: a stub Trivy and a local-repo source."""

from __future__ import annotations

import json
from pathlib import Path

from tests.fakes import FakeSource, project

CYCLONEDX_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {"type": "library", "name": "left-pad", "version": "1.3.0"},
        {"type": "library", "name": "requests", "version": "2.32.3"},
    ],
}


def make_trivy(
    tmp_path: Path,
    *,
    sbom: object = CYCLONEDX_SBOM,
    exit_code: int = 0,
    raw: str | None = None,
) -> Path:
    """Stub that behaves like `trivy fs --output <file>`."""
    script = tmp_path / "trivy-stub.sh"
    payload = raw if raw is not None else json.dumps(sbom)
    script.write_text(
        "#!/usr/bin/env bash\n"
        "output=''\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output" ]; then output="$2"; shift; fi\n'
        "  shift\n"
        "done\n"
        f"if [ -n \"$output\" ] && [ {exit_code} -eq 0 ]; then cat > \"$output\" <<'SBOM'\n"
        f"{payload}\n"
        "SBOM\n"
        "fi\n"
        f"echo 'trivy stub finished'\nexit {exit_code}\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


class LocalSource(FakeSource):
    """Fake source cloning from a local directory instead of over HTTPS."""

    def __init__(self, repo: Path) -> None:
        super().__init__(
            projects=[project("10", "team/app", default_branch="main")],
            branches={},
        )
        self._repo = repo

    def clone_url(self, source_project: object) -> str:  # noqa: ARG002 - fixed repository
        return f"file://{self._repo}"
