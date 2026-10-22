# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scan pipeline (SPEC 7.3).

The tests clone a real local git repository and use a stub Trivy, so the whole
pipeline runs without network access and without a Trivy installation.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from app.config import Settings
from app.services.scanner import ScanRequest, Scanner
from tests.fakes import FakeDependencyTrack, FakeSource, project
from tests.helpers import CYCLONEDX_SBOM, LocalSource, make_trivy


def settings_for(trivy: Path, **overrides: object) -> Settings:
    return Settings(
        database_url="postgresql://vulnyard:secret@localhost:5432/vulnyard",
        gitlab_token="glpat-TESTTOKEN1234567890",
        dt_api_url="https://dtrack.example.com",
        dt_api_key="odt_testkey_1234567890",
        trivy_bin=str(trivy),
        scan_timeout_seconds=120,
        **overrides,  # type: ignore[arg-type]
    )


def request_for(
    job_id: int = 1, branch: str = "main", clone_url: str = "file:///nonexistent"
) -> ScanRequest:
    return ScanRequest(
        job_id=job_id,
        project=project("10", "team/app", default_branch="main"),
        branch=branch,
        is_default_branch=branch == "main",
        clone_url=clone_url,
        dt_parent_uuid="parent-1",
        source_group_path="team",
    )


def request_for_repo(repo: Path, **kwargs: object) -> ScanRequest:
    """Request cloning from a local repository."""
    return request_for(clone_url=f"file://{repo}", **kwargs)  # type: ignore[arg-type]


async def test_successful_scan_uploads_the_sbom_and_records_the_project(
    git_repository: Path, tmp_path: Path
) -> None:
    dtrack = FakeDependencyTrack()
    scanner = Scanner(settings_for(make_trivy(tmp_path)), dtrack)  # type: ignore[arg-type]

    outcome = await scanner.run(request_for_repo(git_repository))

    assert outcome.error_code is None
    assert outcome.components_count == 2
    assert outcome.sbom_bytes and outcome.sbom_bytes > 0
    assert outcome.commit_sha and len(outcome.commit_sha) == 40
    assert outcome.dt_project_uuid == "dt-uuid-1"

    upload = dtrack.uploads[0]
    assert upload.project_name == "team/app"
    assert upload.project_version == "main"
    assert upload.parent_uuid == "parent-1"
    # The default branch is the latest version in Dependency-Track (SPEC 9.2).
    assert upload.is_latest is True
    assert upload.tags == ("vulnyard", "source-group:team")
    assert json.loads(upload.bom)["bomFormat"] == "CycloneDX"
    assert dtrack.refreshed == ["dt-uuid-1"]


async def test_existing_tags_are_merged_not_replaced(git_repository: Path, tmp_path: Path) -> None:
    dtrack = FakeDependencyTrack()
    dtrack.existing_tags = ("manual-tag",)
    scanner = Scanner(settings_for(make_trivy(tmp_path)), dtrack)  # type: ignore[arg-type]

    await scanner.run(request_for_repo(git_repository))

    assert dtrack.tag_merges == [("dt-uuid-1", ("manual-tag", "vulnyard", "source-group:team"))]


async def test_non_default_branch_is_not_marked_as_latest(git_repository: Path, tmp_path: Path) -> None:
    subprocess.run(["git", "branch", "release/1.0"], cwd=git_repository, check=True, capture_output=True)
    dtrack = FakeDependencyTrack()
    scanner = Scanner(settings_for(make_trivy(tmp_path)), dtrack)  # type: ignore[arg-type]

    outcome = await scanner.run(request_for_repo(git_repository, branch="release/1.0"))

    assert outcome.error_code is None
    assert dtrack.uploads[0].is_latest is False
    assert dtrack.uploads[0].project_version == "release/1.0"


async def test_missing_branch_is_reported_as_a_translatable_error(
    git_repository: Path, tmp_path: Path
) -> None:
    scanner = Scanner(settings_for(make_trivy(tmp_path)), FakeDependencyTrack())  # type: ignore[arg-type]

    outcome = await scanner.run(request_for_repo(git_repository, branch="does-not-exist"))

    assert outcome.error_code == "clone.branch_not_found"
    assert outcome.error_params == {"branch": "does-not-exist"}


async def test_unsafe_branch_name_is_refused_before_cloning(
    git_repository: Path, tmp_path: Path
) -> None:
    scanner = Scanner(settings_for(make_trivy(tmp_path)), FakeDependencyTrack())  # type: ignore[arg-type]

    outcome = await scanner.run(request_for_repo(git_repository, branch="--upload-pack=evil"))

    assert outcome.error_code == "scan.branch_invalid"


async def test_failing_trivy_is_reported(git_repository: Path, tmp_path: Path) -> None:
    scanner = Scanner(settings_for(make_trivy(tmp_path, exit_code=1)), FakeDependencyTrack())  # type: ignore[arg-type]

    outcome = await scanner.run(request_for_repo(git_repository))

    assert outcome.error_code == "trivy.failed"
    assert outcome.log_tail and "trivy stub finished" in outcome.log_tail


async def test_invalid_sbom_is_reported(git_repository: Path, tmp_path: Path) -> None:
    scanner = Scanner(
        settings_for(make_trivy(tmp_path, raw="not json at all")), FakeDependencyTrack()  # type: ignore[arg-type]
    )

    outcome = await scanner.run(request_for_repo(git_repository))

    assert outcome.error_code == "sbom.invalid"


async def test_sbom_in_another_format_is_refused(git_repository: Path, tmp_path: Path) -> None:
    scanner = Scanner(
        settings_for(make_trivy(tmp_path, sbom={"bomFormat": "SPDX"})), FakeDependencyTrack()  # type: ignore[arg-type]
    )

    outcome = await scanner.run(request_for_repo(git_repository))

    assert outcome.error_code == "sbom.not_cyclonedx"


async def test_empty_sbom_is_not_an_error(git_repository: Path, tmp_path: Path) -> None:
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    scanner = Scanner(settings_for(make_trivy(tmp_path, sbom=sbom)), FakeDependencyTrack())  # type: ignore[arg-type]

    outcome = await scanner.run(request_for_repo(git_repository))

    assert outcome.error_code is None
    assert outcome.components_count == 0


async def test_clone_failure_never_leaks_the_token(tmp_path: Path) -> None:
    """A failing clone must not put the token into the error or the log tail."""
    token = "glpat-SUPERSECRETVALUE123"

    settings = settings_for(make_trivy(tmp_path))
    settings = Settings(**{**settings.model_dump(), "gitlab_token": token})
    scanner = Scanner(settings, FakeDependencyTrack())  # type: ignore[arg-type]

    # Port 1 refuses immediately, so the clone fails fast.
    outcome = await scanner.run(
        request_for(clone_url=f"https://oauth2:{token}@127.0.0.1:1/team/app.git")
    )

    assert outcome.error_code in {"clone.failed", "clone.unauthorized", "clone.timeout"}
    haystack = f"{outcome.error_detail or ''}{outcome.log_tail or ''}"
    # git redacts the credentials itself, our masking is the second line of
    # defence (see test_masking_* for output that does contain the token).
    assert token not in haystack
    assert "oauth2:" not in haystack


async def test_temporary_directory_is_always_removed(git_repository: Path, tmp_path: Path) -> None:
    from app.services.scanner import TEMP_DIR_PREFIX, _temp_root

    scanner = Scanner(settings_for(make_trivy(tmp_path)), FakeDependencyTrack())  # type: ignore[arg-type]

    await scanner.run(request_for_repo(git_repository, job_id=42))

    leftovers = list(Path(_temp_root()).glob(f"{TEMP_DIR_PREFIX}42-*"))
    assert leftovers == []


async def test_cancelling_during_processing_stops_the_job(
    git_repository: Path, tmp_path: Path
) -> None:
    """A cancelled job must not finish while waiting for Dependency-Track."""
    import asyncio

    from app.services.dtrack import ProcessingAborted
    from app.services.scanner import ScanCancelled

    class SlowDependencyTrack(FakeDependencyTrack):
        """Keeps reporting "still processing" until the caller gives up."""

        async def wait_for_processing(self, token: str, **kwargs: object) -> None:
            should_stop = kwargs.get("should_stop")
            for _ in range(50):
                if callable(should_stop) and should_stop():
                    raise ProcessingAborted
                await asyncio.sleep(0.05)
            raise AssertionError("the wait was never cancelled")

    dtrack = SlowDependencyTrack()
    scanner = Scanner(settings_for(make_trivy(tmp_path)), dtrack)  # type: ignore[arg-type]

    async def cancel_soon() -> None:
        await asyncio.sleep(0.3)
        await scanner.cancel(7)

    with pytest.raises(ScanCancelled):
        await asyncio.gather(scanner.run(request_for_repo(git_repository, job_id=7)), cancel_soon())

    # The BOM was already uploaded; only our waiting stopped.
    assert len(dtrack.uploads) == 1


async def test_metrics_refresh_waits_until_dependency_track_recomputed() -> None:
    """The refresh only requests a computation; the new lastOccurrence says it ran."""
    from datetime import UTC, datetime

    from app.services.dtrack import DependencyTrackClient, DTMetrics

    client = DependencyTrackClient(
        Settings(dt_api_url="https://dtrack.example.com", dt_api_key="odt_testkey_1234567890")
    )
    old = datetime(2026, 1, 1, tzinfo=UTC)
    new = datetime(2026, 1, 2, tzinfo=UTC)
    answers = [DTMetrics(high=0, last_occurrence=old)] * 3 + [DTMetrics(high=2, last_occurrence=new)]
    reads: list[str] = []
    refreshed: list[str] = []

    async def current(uuid: str) -> DTMetrics:
        reads.append(uuid)
        return answers[min(len(reads) - 1, len(answers) - 1)]

    async def refresh(uuid: str) -> None:
        refreshed.append(uuid)

    client.current_project_metrics = current  # type: ignore[method-assign]
    client.refresh_project_metrics = refresh  # type: ignore[method-assign]
    try:
        assert await client.refresh_project_metrics_and_wait("p", poll_interval_seconds=0) is True
        # Baseline, two stale polls, then the fresh one.
        assert len(reads) == 4
        assert refreshed == ["p"]

        # A new project has no metrics until the first computation finishes.
        reads.clear()
        answers[:] = [None, None, DTMetrics(high=1, last_occurrence=new)]  # type: ignore[list-item]
        assert await client.refresh_project_metrics_and_wait("p", poll_interval_seconds=0) is True
        assert len(reads) == 3

        # Never recomputed: give up after the timeout instead of hanging.
        answers[:] = [DTMetrics(last_occurrence=old)]
        assert (
            await client.refresh_project_metrics_and_wait(
                "p", poll_interval_seconds=0.01, timeout_seconds=0.05
            )
            is False
        )
    finally:
        await client.close()
