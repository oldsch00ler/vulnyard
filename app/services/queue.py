# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Scan worker over the `scan_jobs` table (SPEC section 8).

The table is the queue: jobs are claimed with `FOR UPDATE SKIP LOCKED`, so a
job is never picked twice, and the number of parallel scans is limited by the
stored setting, read again on every pass so a change applies without a restart.
A job that is interrupted by a restart is failed during recovery.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.errors import AppError
from app.constants import (
    JOB_ACTIVE_STATUSES,
    JOB_CANCELLED,
    JOB_CLONING,
    JOB_DONE,
    JOB_FAILED,
    JOB_QUEUED,
    RUN_CANCELLED,
    RUN_DONE,
    RUN_FAILED,
    RUN_RUNNING,
    TARGET_KIND_GROUP,
)
from app.i18n import t
from app.models import MetricSnapshot, Project, ScanJob, ScanRun, ScanTarget, TargetProject
from app.services import runs as run_service
from app.services.dashboard import invalidate_cache
from app.services.app_settings import (
    get_notification_config,
    get_scan_concurrency,
    should_send_alert,
)
from app.services.dtrack import DependencyTrackClient
from app.services.ignores import apply_rules as apply_ignore_rules
from app.services.snapshots import take_snapshot
from app.services.notifications import (
    SEVERITIES,
    ChatNotifier,
    FailureAlert,
    FindingsNotification,
    NotificationTarget,
    severity_counts,
)
from app.services.scanner import (
    ScanCancelled,
    ScanRequest,
    Scanner,
    cleanup_leftover_directories,
)
from app.services.sources import SourceProvider
from app.services.sources.base import RepositorySource, SourceProject

logger = logging.getLogger(__name__)

#: How often the worker looks for new jobs when nothing woke it up.
POLL_INTERVAL_SECONDS = 5.0
#: Tag marking our projects in Dependency-Track.
VULNYARD_TAG = "vulnyard"


class ScanWorker:
    """Background worker processing queued scan jobs."""

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        *,
        source: RepositorySource | None,
        dtrack: DependencyTrackClient | None,
        trivy_available: bool = True,
        notifier: ChatNotifier | None = None,
        source_provider: SourceProvider | None = None,
    ) -> None:
        self._settings = settings
        self._sessions = sessions
        self._source = source
        self._source_provider = source_provider
        self._dtrack = dtrack
        self._trivy_available = trivy_available
        self._notifier = notifier
        # Refreshed from the database before every dispatch.
        self._concurrency = max(1, settings.scan_concurrency)
        self._wakeup = asyncio.Event()
        self._tasks: dict[int, asyncio.Task[None]] = {}
        self._loop_task: asyncio.Task[None] | None = None
        self._running = False
        self._scanner: Scanner | None = None
        # Parent project UUID per target, resolved once per process. The lock
        # keeps parallel jobs of one target from creating it twice.
        self._parent_uuids: dict[int, str] = {}
        self._parent_locks: dict[int, asyncio.Lock] = {}

    # --- lifecycle -----------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._running

    @property
    def concurrency(self) -> int:
        """Parallel scans allowed, as last read from the settings."""
        return self._concurrency

    @property
    def active_jobs(self) -> int:
        return len(self._tasks)

    @property
    def enabled(self) -> bool:
        """Whether the worker can scan at all (source, Dependency-Track, Trivy).

        A source counts as available when the environment has credentials or a
        provider exists that can build one from a target's own credentials.
        """
        has_source = self._source is not None or self._source_provider is not None
        return has_source and self._dtrack is not None and self._trivy_available

    async def start(self) -> None:
        if self._running:
            return
        if not self.enabled:
            logger.info(
                "Scan worker not started: source, Dependency-Track or Trivy is not available"
            )
            return
        assert self._dtrack is not None  # noqa: S101 - checked above
        self._scanner = Scanner(self._settings, self._dtrack, on_status=self._set_job_status)
        await self._load_concurrency()
        self._running = True
        self._loop_task = asyncio.create_task(self._loop(), name="vulnyard-scan-worker")
        logger.info("Scan worker started (concurrency %s)", self._concurrency)

    async def stop(self) -> None:
        self._running = False
        self._wakeup.set()
        if self._loop_task is not None:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - shutting down
                pass
            self._loop_task = None
        for task in list(self._tasks.values()):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()

    def notify(self) -> None:
        """Wake the worker up after new jobs were queued."""
        self._wakeup.set()

    # --- recovery ------------------------------------------------------------

    async def recover(self) -> None:
        """Fail jobs interrupted by a restart and clean up after them."""
        async with self._sessions() as session:
            result = await session.execute(
                update(ScanJob)
                .where(ScanJob.status.in_(JOB_ACTIVE_STATUSES))
                .values(
                    status=JOB_FAILED,
                    error_code="job.interrupted",
                    error_params={},
                    finished_at=datetime.now(UTC),
                )
                .returning(ScanJob.run_id)
            )
            run_ids = {row[0] for row in result.all()}
            await session.commit()

            for run_id in run_ids:
                await run_service.refresh_run_counters(session, run_id)

            # Runs whose jobs are all finished but that stayed "running".
            unfinished = (
                await session.execute(select(ScanRun.id).where(ScanRun.status == RUN_RUNNING))
            ).scalars()
            for run_id in list(unfinished):
                await run_service.refresh_run_counters(session, run_id)

        removed = cleanup_leftover_directories()
        if run_ids or removed:
            logger.info(
                t(
                    "startup.recovery",
                    self._settings.default_locale,
                    jobs=len(run_ids),
                    directories=removed,
                )
            )

    # --- main loop -----------------------------------------------------------

    async def _loop(self) -> None:
        while self._running:
            try:
                dispatched = await self._dispatch_available()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the loop must survive anything
                logger.exception("Scan worker loop failed")
                dispatched = 0

            if dispatched:
                continue

            self._wakeup.clear()
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout=POLL_INTERVAL_SECONDS)
            except TimeoutError:
                pass

    async def _dispatch_available(self) -> int:
        """Claim and start as many jobs as the concurrency limit allows.

        Lowering the limit never stops running jobs; new ones simply wait until
        fewer than the new limit are running.
        """
        await self._load_concurrency()
        started = 0
        while self._running and len(self._tasks) < self._concurrency:
            job_id = await self._claim_job()
            if job_id is None:
                return started
            task = asyncio.create_task(self._process(job_id), name=f"vulnyard-scan-job-{job_id}")
            self._tasks[job_id] = task
            task.add_done_callback(lambda _task, job_id=job_id: self._finish_task(job_id))
            started += 1
        return started

    def _finish_task(self, job_id: int) -> None:
        self._tasks.pop(job_id, None)
        self._wakeup.set()

    async def _load_concurrency(self) -> None:
        """Read the limit from the settings; keep the last one if that fails."""
        try:
            async with self._sessions() as session:
                limit = await get_scan_concurrency(session, self._settings.scan_concurrency)
        except Exception:  # noqa: BLE001 - a settings read must not stop scanning
            logger.warning("Could not read the scan concurrency, keeping %s", self._concurrency)
            return
        if limit != self._concurrency:
            logger.info("Scan concurrency changed from %s to %s", self._concurrency, limit)
            self._concurrency = limit

    async def _claim_job(self) -> int | None:
        """Take the oldest queued job; SKIP LOCKED keeps claims exclusive."""
        async with self._sessions() as session, session.begin():
            job = (
                await session.execute(
                    select(ScanJob)
                    .where(ScanJob.status == JOB_QUEUED)
                    .order_by(ScanJob.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
            ).scalar_one_or_none()
            if job is None:
                return None
            job.status = JOB_CLONING
            job.started_at = datetime.now(UTC)
            return job.id

    # --- one job -------------------------------------------------------------

    async def _process(self, job_id: int) -> None:
        started = datetime.now(UTC)
        try:
            request = await self._build_request(job_id)
            if request is None:
                return
            assert self._scanner is not None  # noqa: S101 - set in start()
            outcome = await self._scanner.run(request)
            await self._store_outcome(job_id, outcome, started)
        except ScanCancelled:
            await self._mark_cancelled(job_id)
        except asyncio.CancelledError:
            await self._mark_cancelled(job_id)
            raise
        except AppError as error:
            # Failures outside the pipeline itself (for example resolving the
            # parent project in Dependency-Track) keep their own code.
            await self._store_failure(job_id, error.code, error.detail, params=error.params)
        except Exception as error:  # noqa: BLE001 - never lose the worker over one job
            logger.exception("Job %s failed unexpectedly", job_id)
            await self._store_failure(job_id, "scan.unexpected_error", f"{type(error).__name__}")

    async def _build_request(self, job_id: int) -> ScanRequest | None:
        """Load the job, its project and the Dependency-Track parent project."""
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(ScanJob, Project)
                    .join(Project, Project.id == ScanJob.project_id)
                    .where(ScanJob.id == job_id)
                )
            ).first()
            if row is None:
                logger.warning("Job %s disappeared before it started", job_id)
                return None
            job, project = row

            target = await self._target_for(session, job, project)
            parent_uuid = await self._parent_uuid(session, target)

            source_project = SourceProject(
                ref=project.source_project_id,
                path_with_namespace=project.path_with_namespace,
                name=project.name,
                web_url=project.web_url,
                default_branch=project.default_branch,
            )

            source = self._source_for(target)
            if source is None:
                await self._store_failure(job_id, "source.not_configured")
                return None

            return ScanRequest(
                job_id=job_id,
                project=source_project,
                branch=project.branch,
                is_default_branch=project.is_default_branch,
                # Built with this target's credentials; it carries the token.
                clone_url=source.clone_url(source_project),
                dt_parent_uuid=parent_uuid,
                # Tag with the top-level group of the project path (SPEC 9.3).
                source_group_path=project.path_with_namespace.split("/")[0] or None,
                secrets=self._secrets_of(target),
            )

    def _source_for(self, target: ScanTarget | None) -> RepositorySource | None:
        """Client for this target: its own credentials, else the environment."""
        if self._source_provider is not None:
            try:
                return self._source_provider.for_target(target) if target else self._source_provider.global_source()
            except AppError as error:
                logger.warning("No source client for target %s: %s", getattr(target, "id", None), error.code)
                return None
        return self._source

    @staticmethod
    def _secrets_of(target: ScanTarget | None) -> tuple[str, ...]:
        """The target's own token, so it can be masked in any output."""
        token = getattr(target, "source_token", None)
        return (token,) if token else ()

    async def _target_for(
        self, session: AsyncSession, job: ScanJob, project: Project
    ) -> ScanTarget | None:
        """Target this job belongs to: the run's target, else a linked group target."""
        run = await session.get(ScanRun, job.run_id)
        if run is not None and run.target_id is not None:
            return await session.get(ScanTarget, run.target_id)

        return (
            await session.execute(
                select(ScanTarget)
                .join(TargetProject, TargetProject.target_id == ScanTarget.id)
                .where(TargetProject.project_id == project.id, ScanTarget.kind == TARGET_KIND_GROUP)
                .order_by(ScanTarget.id)
                .limit(1)
            )
        ).scalar_one_or_none()

    async def _parent_uuid(self, session: AsyncSession, target: ScanTarget | None) -> str | None:
        """Parent (collection) project of a group target in DT (SPEC 9.2)."""
        if target is None or target.kind != TARGET_KIND_GROUP or self._dtrack is None:
            return None
        if target.dt_parent_uuid:
            return target.dt_parent_uuid

        lock = self._parent_locks.setdefault(target.id, asyncio.Lock())
        async with lock:
            if target.id in self._parent_uuids:
                return self._parent_uuids[target.id]

            parent = await self._dtrack.ensure_collection_project(
                target.source_path, tags=(VULNYARD_TAG,)
            )
            self._parent_uuids[target.id] = parent.uuid

            fresh = await session.get(ScanTarget, target.id)
            if fresh is not None:
                fresh.dt_parent_uuid = parent.uuid
                await session.commit()
            return parent.uuid

    # --- persistence of job state -------------------------------------------

    async def _set_job_status(self, job_id: int, status: str) -> None:
        async with self._sessions() as session:
            await session.execute(update(ScanJob).where(ScanJob.id == job_id).values(status=status))
            await session.commit()

    async def _store_outcome(self, job_id: int, outcome, started: datetime) -> None:  # noqa: ANN001
        finished = datetime.now(UTC)
        async with self._sessions() as session:
            job = await session.get(ScanJob, job_id)
            if job is None:
                return
            job.status = JOB_FAILED if outcome.failed else JOB_DONE
            job.commit_sha = outcome.commit_sha
            job.components_count = outcome.components_count
            job.sbom_bytes = outcome.sbom_bytes
            job.dt_upload_token = outcome.dt_upload_token
            job.error_code = outcome.error_code
            job.error_params = outcome.error_params or None
            job.error_detail = outcome.error_detail
            job.log_tail = outcome.log_tail
            job.finished_at = finished
            job.duration_ms = int((finished - started).total_seconds() * 1000)

            project = await session.get(Project, job.project_id)
            if project is not None:
                project.last_scan_at = finished
                project.last_scan_status = job.status
                if outcome.commit_sha:
                    project.last_commit_sha = outcome.commit_sha
                if not outcome.failed and outcome.commit_sha:
                    project.last_scanned_sha = outcome.commit_sha
                if outcome.dt_project_uuid:
                    project.dt_project_uuid = outcome.dt_project_uuid

            await session.commit()
            run = await run_service.refresh_run_counters(session, job.run_id)

            # The dashboard must not keep showing metrics from before the scan.
            invalidate_cache()

            if not outcome.failed and project is not None:
                # Before the notification and the baseline: a new scan brings new
                # component versions, and an ignored finding must not be counted
                # or reported as if it were news.
                await self._apply_ignore_rules(session, project)
                await self._notify(session, job, project)
                await self._remember_metrics(session, project)

            if run is not None and run.status in (RUN_DONE, RUN_FAILED):
                await self._refresh_todays_snapshot(session)
                await self._alert_if_scanning_is_broken(job.run_id)

            if outcome.failed:
                logger.warning(
                    "Job %s (%s@%s) failed: %s",
                    job_id,
                    project.path_with_namespace if project else "?",
                    project.branch if project else "?",
                    outcome.error_code,
                )
            else:
                logger.info(
                    "Job %s (%s@%s) done in %s ms, %s components",
                    job_id,
                    project.path_with_namespace if project else "?",
                    project.branch if project else "?",
                    job.duration_ms,
                    outcome.components_count,
                )

    async def _apply_ignore_rules(self, session: AsyncSession, project: Project) -> None:
        """Suppress in Dependency-Track what the ignore rules cover.

        Best effort: a rule that cannot be applied is logged, the scan still
        counts as a success. The daily pass tries again.
        """
        if self._dtrack is None or not project.dt_project_uuid:
            return
        try:
            outcome = await apply_ignore_rules(session, self._dtrack, project_ids=[project.id])
        except Exception:  # noqa: BLE001 - ignoring must never fail a scan
            logger.exception("Ignore rules for project %s failed", project.id)
            return
        if outcome.suppressed or outcome.reverted:
            logger.info(
                "Ignore rules for %s@%s: %s suppressed, %s taken back",
                project.path_with_namespace,
                project.branch,
                outcome.suppressed,
                outcome.reverted,
            )

    async def _refresh_todays_snapshot(self, session: AsyncSession) -> None:
        """Re-take today's snapshot at the end of a run.

        The snapshot is written once in the morning, but the dashboard cards read
        Dependency-Track live. Without this the trend's last point would contradict
        the numbers right above it for the rest of the day. Earlier days are
        history and stay as they were.
        """
        if self._dtrack is None:
            return
        try:
            await take_snapshot(session, self._dtrack)
        except AppError as error:
            logger.warning("Could not refresh today's metric snapshot: %s", error.code)

    async def _notify(self, session: AsyncSession, job: ScanJob, project: Project) -> None:
        """Tell the chat about a freshly scanned project that has findings.

        Best effort: anything that goes wrong here is logged and the scan is
        still a success.
        """
        if self._notifier is None or self._dtrack is None or not project.dt_project_uuid:
            return

        try:
            enabled, global_webhook, min_severity = await get_notification_config(session)
            target = await self._target_for(session, job, project)
            webhook = (target.notify_webhook_url if target else None) or global_webhook

            # A target with its own webhook sends even when the global switch is
            # off; that is the point of setting it per target.
            if not webhook:
                logger.info(
                    "No chat message for %s@%s: no webhook is set",
                    project.path_with_namespace,
                    project.branch,
                )
                return
            if not enabled and not (target and target.notify_webhook_url):
                logger.info(
                    "No chat message for %s@%s: notifications are turned off in the settings",
                    project.path_with_namespace,
                    project.branch,
                )
                return

            metrics = await self._dtrack.current_project_metrics(project.dt_project_uuid)
            if metrics is None:
                return

            previous = project.last_metrics if isinstance(project.last_metrics, dict) else None
            if previous is None:
                previous = await self._metrics_before_this_scan(session, project)

            maintainers: tuple = ()
            source = self._source_for(target)
            if source is not None:
                try:
                    found = await source.list_maintainers(project.source_project_id)
                    maintainers = tuple(found)
                except AppError as error:
                    logger.warning(
                        "Could not read maintainers of %s: %s",
                        project.path_with_namespace,
                        error.code,
                    )

            dtrack_url = None
            if self._settings.effective_dt_ui_url:
                dtrack_url = (
                    f"{self._settings.effective_dt_ui_url}/projects/{project.dt_project_uuid}"
                )

            sent = await self._notifier.notify_findings(
                NotificationTarget(webhook_url=webhook, min_severity=min_severity),
                FindingsNotification(
                    path_with_namespace=project.path_with_namespace,
                    branch=project.branch,
                    metrics=metrics,
                    maintainers=maintainers,
                    repository_url=project.web_url,
                    dtrack_url=dtrack_url,
                    target_name=target.name if target else None,
                    previous=previous,
                ),
                locale=self._settings.default_locale,
            )
            if not sent:
                # Saying why keeps "nothing arrived" answerable from the log.
                logger.info(
                    "No chat message for %s@%s: nothing at or above %s "
                    "(critical %s, high %s, medium %s, low %s, unassigned %s)",
                    project.path_with_namespace,
                    project.branch,
                    min_severity,
                    metrics.critical,
                    metrics.high,
                    metrics.medium,
                    metrics.low,
                    metrics.unassigned,
                )
        except Exception:  # noqa: BLE001 - a notification must never fail a scan
            logger.exception("Chat notification for job %s failed", job.id)

    async def _metrics_before_this_scan(
        self, session: AsyncSession, project: Project
    ) -> dict[str, int] | None:
        """Baseline for a project that has not been scanned since the upgrade.

        `projects.last_metrics` is written by every scan, but it starts out empty
        for projects that existed before it was added - and then the first scan
        after a fix has nothing to compare against, so the good news is lost. The
        daily snapshot is the same data one day old, which is exactly the "before"
        we are missing.
        """
        snapshot = (
            await session.execute(
                select(MetricSnapshot)
                .where(MetricSnapshot.project_id == project.id)
                .order_by(MetricSnapshot.date.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if snapshot is None:
            return None
        return {severity: getattr(snapshot, severity) for severity in SEVERITIES}

    async def _remember_metrics(self, session: AsyncSession, project: Project) -> None:
        """Store the current counts as the baseline for the next scan's delta."""
        if self._dtrack is None or not project.dt_project_uuid:
            return
        try:
            metrics = await self._dtrack.current_project_metrics(project.dt_project_uuid)
        except AppError:
            return
        if metrics is None:
            return

        fresh = await session.get(Project, project.id)
        if fresh is None:
            return
        fresh.last_metrics = severity_counts(metrics)
        fresh.last_metrics_at = datetime.now(UTC)
        await session.commit()

    async def _alert_if_scanning_is_broken(self, run_id: int) -> None:
        """One message when a run failed for a systemic reason (SPEC 9.5).

        Silence looks the same as "no vulnerabilities", so a rejected token or an
        unreachable Dependency-Track has to be said out loud.
        """
        if self._notifier is None:
            return
        async with self._sessions() as session:
            failure = await run_service.systemic_failure(session, run_id)
            if failure is None:
                return
            code, params, failed, total = failure

            enabled, webhook, _ = await get_notification_config(session)
            if not webhook or not enabled:
                return
            if not await should_send_alert(session, code):
                return

            await self._notifier.notify_failure(
                webhook,
                FailureAlert(code=code, params=params, run_id=run_id, failed=failed, total=total),
                locale=self._settings.default_locale,
            )

    async def _store_failure(
        self,
        job_id: int,
        code: str,
        detail: str | None = None,
        *,
        params: dict[str, object] | None = None,
    ) -> None:
        async with self._sessions() as session:
            job = await session.get(ScanJob, job_id)
            if job is None:
                return
            job.status = JOB_FAILED
            job.error_code = code
            job.error_params = params or None
            job.error_detail = detail
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await run_service.refresh_run_counters(session, job.run_id)

    async def _mark_cancelled(self, job_id: int) -> None:
        async with self._sessions() as session:
            job = await session.get(ScanJob, job_id)
            if job is None:
                return
            job.status = JOB_CANCELLED
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await run_service.refresh_run_counters(session, job.run_id)

    # --- cancellation --------------------------------------------------------

    async def cancel_run(self, run_id: int) -> int:
        """Cancel the queued jobs of a run and stop the running ones."""
        cancelled = 0
        async with self._sessions() as session:
            result = await session.execute(
                update(ScanJob)
                .where(ScanJob.run_id == run_id, ScanJob.status == JOB_QUEUED)
                .values(status=JOB_CANCELLED, finished_at=datetime.now(UTC))
                .returning(ScanJob.id)
            )
            cancelled += len(result.all())

            active = (
                await session.execute(
                    select(ScanJob.id).where(
                        ScanJob.run_id == run_id, ScanJob.status.in_(JOB_ACTIVE_STATUSES)
                    )
                )
            ).scalars()
            active_ids = list(active)

            run = await session.get(ScanRun, run_id)
            if run is not None:
                run.status = RUN_CANCELLED
                run.finished_at = datetime.now(UTC)
            await session.commit()

        for job_id in active_ids:
            if self._scanner is not None:
                await self._scanner.cancel(job_id)
            cancelled += 1
        return cancelled
