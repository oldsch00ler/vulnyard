# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""One scan job: clone → Trivy → CycloneDX → Dependency-Track (SPEC 7.3).

Subprocesses are always started without a shell, with an explicit argument
list, a timeout and a temporary directory that is removed in `finally`.
Everything that could contain the source token is masked before it is logged
or stored.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import Settings
from app.constants import (
    JOB_CLONING,
    JOB_PROCESSING,
    JOB_SCANNING,
    JOB_UPLOADING,
)
from app.errors import AppError
from app.masking import mask_secrets
from app.services.dtrack import DependencyTrackClient, ProcessingAborted
from app.services.sources.base import SourceProject
from app.services.tools import resolve_trivy_path
from app.validation import is_valid_branch_name

logger = logging.getLogger(__name__)

#: Prefix of the temporary directories; recovery cleans leftovers by it.
TEMP_DIR_PREFIX = "vulnyard-scan-"
#: How long we wait after SIGTERM before sending SIGKILL.
KILL_GRACE_SECONDS = 10
#: How many lines of the captured output we keep on a job.
LOG_TAIL_LINES = 50
#: Tag marking the projects created by this application (SPEC 9.3).
VULNYARD_TAG = "vulnyard"


class ScanCancelled(Exception):
    """Raised when a job is cancelled while running."""


@dataclass(slots=True)
class ScanRequest:
    """Everything one job needs, resolved before the work starts."""

    job_id: int
    project: SourceProject
    branch: str
    is_default_branch: bool
    #: Authenticated clone URL built with the credentials of this job's target.
    clone_url: str
    dt_parent_uuid: str | None = None
    source_group_path: str | None = None
    #: Extra secrets to mask in output (the target's own token).
    secrets: tuple[str, ...] = ()


@dataclass(slots=True)
class ScanOutcome:
    """Result of a job – either success or a translatable error."""

    commit_sha: str | None = None
    components_count: int | None = None
    sbom_bytes: int | None = None
    dt_upload_token: str | None = None
    dt_project_uuid: str | None = None
    error_code: str | None = None
    error_params: dict[str, Any] = field(default_factory=dict)
    error_detail: str | None = None
    log_tail: str | None = None

    @property
    def failed(self) -> bool:
        return self.error_code is not None


class Scanner:
    """Runs the scan pipeline for a single project+branch."""

    def __init__(
        self,
        settings: Settings,
        dtrack: DependencyTrackClient,
        *,
        on_status: Any | None = None,
    ) -> None:
        self._settings = settings
        self._dtrack = dtrack
        self._on_status = on_status
        self._processes: dict[int, asyncio.subprocess.Process] = {}
        self._cancelled: set[int] = set()

    async def cancel(self, job_id: int) -> None:
        """Ask a running job to stop: SIGTERM, then SIGKILL after the grace period."""
        self._cancelled.add(job_id)
        process = self._processes.get(job_id)
        if process is None or process.returncode is not None:
            return
        await _terminate(process)

    async def run(self, request: ScanRequest) -> ScanOutcome:
        """Run the whole pipeline; never raises for an expected failure."""
        outcome = ScanOutcome()
        if not is_valid_branch_name(request.branch):
            outcome.error_code = "scan.branch_invalid"
            outcome.error_params = {"branch": request.branch}
            return outcome

        trivy_bin = resolve_trivy_path(self._settings)
        if trivy_bin is None:
            outcome.error_code = "scan.trivy_missing"
            return outcome

        if request.job_id in self._cancelled:
            raise ScanCancelled

        work_dir = Path(tempfile.mkdtemp(prefix=f"{TEMP_DIR_PREFIX}{request.job_id}-", dir=_temp_root()))
        clone_dir = work_dir / "repo"
        sbom_path = work_dir / "sbom.json"
        cache_dir = Path(_temp_root()) / "trivy-cache"

        try:
            await self._status(request.job_id, JOB_CLONING)
            commit_sha = await self._clone(request, clone_dir, outcome)
            if outcome.failed:
                return outcome
            outcome.commit_sha = commit_sha

            await self._status(request.job_id, JOB_SCANNING)
            await self._trivy(request, trivy_bin, clone_dir, sbom_path, cache_dir, outcome)
            if outcome.failed:
                return outcome

            sbom = self._read_sbom(sbom_path, outcome)
            if outcome.failed or sbom is None:
                return outcome

            await self._status(request.job_id, JOB_UPLOADING)
            await self._upload(request, sbom_path, outcome)
            if outcome.failed:
                return outcome

            await self._status(request.job_id, JOB_PROCESSING)
            await self._finish_in_dtrack(request, outcome)
            return outcome
        except ScanCancelled:
            raise
        except AppError as error:
            outcome.error_code = error.code
            outcome.error_params = dict(error.params)
            outcome.error_detail = self._mask(error.detail or "")
            return outcome
        except Exception as error:  # noqa: BLE001 - one job must not kill the worker
            logger.exception("Unexpected error in job %s", request.job_id)
            outcome.error_code = "scan.unexpected_error"
            outcome.error_detail = self._mask(f"{type(error).__name__}: {error}")
            return outcome
        finally:
            self._processes.pop(request.job_id, None)
            self._cancelled.discard(request.job_id)
            shutil.rmtree(work_dir, ignore_errors=True)

    # --- pipeline steps ------------------------------------------------------

    async def _clone(self, request: ScanRequest, clone_dir: Path, outcome: ScanOutcome) -> str | None:
        """Shallow clone of a single branch; the token never reaches the log."""
        command = [
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            request.branch,
            "--no-tags",
            request.clone_url,
            str(clone_dir),
        ]
        env = {"GIT_TERMINAL_PROMPT": "0"}
        if self._settings.ca_bundle:
            env["GIT_SSL_CAINFO"] = self._settings.ca_bundle

        result = await self._run_process(request.job_id, command, env=env, secrets=request.secrets)
        if result.timed_out:
            outcome.error_code = "clone.timeout"
            outcome.error_params = {"seconds": self._settings.scan_timeout_seconds}
            outcome.log_tail = self._tail(result.output)
            return None
        if result.returncode != 0:
            output = result.output
            lowered = output.lower()
            if "could not find remote branch" in lowered or "remote branch" in lowered and "not found" in lowered:
                outcome.error_code = "clone.branch_not_found"
                outcome.error_params = {"branch": request.branch}
            elif "authentication failed" in lowered or "403" in lowered:
                outcome.error_code = "clone.unauthorized"
            else:
                outcome.error_code = "clone.failed"
            outcome.error_detail = self._mask(output[-1000:], request)
            outcome.log_tail = self._tail(output)
            return None

        return await self._head_commit(request.job_id, clone_dir)

    async def _head_commit(self, job_id: int, clone_dir: Path) -> str | None:
        result = await self._run_process(job_id, ["git", "rev-parse", "HEAD"], cwd=clone_dir, timeout=60)
        if result.returncode != 0:
            return None
        return result.output.strip().splitlines()[0] if result.output.strip() else None

    async def _trivy(
        self,
        request: ScanRequest,
        trivy_bin: str,
        clone_dir: Path,
        sbom_path: Path,
        cache_dir: Path,
        outcome: ScanOutcome,
    ) -> None:
        """Generate the CycloneDX SBOM. No vulnerability scanning – that is DT's job."""
        timeout = self._settings.scan_timeout_seconds
        command = [
            trivy_bin,
            "fs",
            str(clone_dir),
            "--format",
            "cyclonedx",
            "--output",
            str(sbom_path),
            "--cache-dir",
            str(cache_dir),
            "--skip-dirs",
            ".git",
            "--quiet",
            "--timeout",
            f"{timeout}s",
        ]
        if self._settings.trivy_offline:
            command.append("--offline-scan")

        env: dict[str, str] = {}
        if self._settings.ca_bundle:
            env["SSL_CERT_FILE"] = self._settings.ca_bundle

        result = await self._run_process(request.job_id, command, env=env, secrets=request.secrets)
        if result.timed_out:
            outcome.error_code = "trivy.timeout"
            outcome.error_params = {"seconds": timeout}
            outcome.log_tail = self._tail(result.output)
            return
        if result.returncode != 0:
            outcome.error_code = "trivy.failed"
            outcome.error_detail = self._mask(result.output[-1000:])
            outcome.log_tail = self._tail(result.output)

    def _read_sbom(self, sbom_path: Path, outcome: ScanOutcome) -> dict[str, Any] | None:
        """Validate the SBOM and count its components (an empty one is fine)."""
        if not sbom_path.is_file():
            outcome.error_code = "sbom.missing"
            return None
        try:
            raw = sbom_path.read_bytes()
            document = json.loads(raw)
        except (OSError, ValueError) as error:
            outcome.error_code = "sbom.invalid"
            outcome.error_detail = self._mask(str(error))
            return None

        if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
            outcome.error_code = "sbom.not_cyclonedx"
            return None

        components = document.get("components")
        outcome.components_count = len(components) if isinstance(components, list) else 0
        outcome.sbom_bytes = len(raw)
        return document

    async def _upload(self, request: ScanRequest, sbom_path: Path, outcome: ScanOutcome) -> None:
        tags = [VULNYARD_TAG]
        if request.source_group_path:
            tags.append(f"source-group:{request.source_group_path}")

        outcome.dt_upload_token = await self._dtrack.upload_bom(
            project_name=request.project.path_with_namespace,
            project_version=request.branch,
            bom=sbom_path.read_bytes(),
            parent_uuid=request.dt_parent_uuid,
            is_latest=request.is_default_branch,
            tags=tuple(tags),
        )

    async def _finish_in_dtrack(self, request: ScanRequest, outcome: ScanOutcome) -> None:
        """Wait for processing, find the project, merge tags, refresh metrics."""
        if outcome.dt_upload_token:
            try:
                await self._dtrack.wait_for_processing(
                    outcome.dt_upload_token,
                    should_stop=lambda: request.job_id in self._cancelled,
                )
            except ProcessingAborted as error:
                raise ScanCancelled from error

        project = await self._dtrack.lookup_project(
            request.project.path_with_namespace, request.branch
        )
        if project is None:
            outcome.error_code = "dtrack.project_not_found"
            outcome.error_params = {
                "name": request.project.path_with_namespace,
                "version": request.branch,
            }
            return

        outcome.dt_project_uuid = project.uuid

        tags = [VULNYARD_TAG]
        if request.source_group_path:
            tags.append(f"source-group:{request.source_group_path}")
        await self._dtrack.merge_project_tags(project, tuple(tags))

        await self._dtrack.refresh_project_metrics(project.uuid)

    # --- subprocess helpers --------------------------------------------------

    @dataclass(slots=True)
    class ProcessResult:
        returncode: int
        output: str
        timed_out: bool = False

    async def _run_process(
        self,
        job_id: int,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
        secrets: tuple[str, ...] = (),
    ) -> ProcessResult:
        """Run a command without a shell, with a timeout and cancellation."""
        if job_id in self._cancelled:
            raise ScanCancelled

        process_env = {**os.environ, **(env or {})}
        logger.debug("Running %s", mask_secrets(" ".join(command), *self._all_secrets(secrets)))

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(cwd) if cwd else None,
            env=process_env,
        )
        self._processes[job_id] = process

        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=timeout or self._settings.scan_timeout_seconds
            )
        except TimeoutError:
            await _terminate(process)
            return self.ProcessResult(returncode=-1, output="", timed_out=True)
        finally:
            self._processes.pop(job_id, None)

        if job_id in self._cancelled:
            raise ScanCancelled

        return self.ProcessResult(
            returncode=process.returncode or 0,
            output=mask_secrets(
                (stdout or b"").decode("utf-8", errors="replace"), *self._all_secrets(secrets)
            ),
        )

    def _all_secrets(self, extra: tuple[str, ...]) -> tuple[str | None, ...]:
        """Everything that must never show up in output."""
        return (self._settings.gitlab_token, self._settings.dt_api_key, *extra)

    async def _status(self, job_id: int, status: str) -> None:
        if self._on_status is not None:
            await self._on_status(job_id, status)

    def _mask(self, text: str, request: ScanRequest | None = None) -> str:
        extra = request.secrets if request is not None else ()
        return mask_secrets(
            text, self._settings.gitlab_token, self._settings.dt_api_key, *extra
        )

    @staticmethod
    def _tail(output: str) -> str | None:
        if not output:
            return None
        return "\n".join(output.splitlines()[-LOG_TAIL_LINES:])


async def _terminate(process: asyncio.subprocess.Process) -> None:
    """SIGTERM, then SIGKILL after the grace period (SPEC section 8)."""
    try:
        process.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=KILL_GRACE_SECONDS)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _temp_root() -> str:
    return os.environ.get("TMPDIR") or tempfile.gettempdir()


def cleanup_leftover_directories() -> int:
    """Remove temporary directories left behind by a previous process."""
    removed = 0
    root = Path(_temp_root())
    if not root.is_dir():
        return 0
    for path in root.glob(f"{TEMP_DIR_PREFIX}*"):
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
    return removed
