# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Cron scheduling of scans and of the daily housekeeping (SPEC section 8)."""

from __future__ import annotations

import logging
from zoneinfo import ZoneInfo

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker

from app.config import Settings
from app.constants import TRIGGER_SCHEDULE
from app.errors import AppError
from app.i18n import t
from app.models import ScanTarget
from app.services import runs as run_service
from app.services.app_settings import get_global_exclude_patterns
from app.services.queue import ScanWorker
from app.services.dtrack import DependencyTrackClient
from app.services.ignores import apply_rules, revert_expired
from app.services.retention import purge_old_runs, purge_old_snapshots
from app.services.snapshots import take_snapshot
from app.services.sources import SourceProvider

logger = logging.getLogger(__name__)

#: Postgres advisory lock id; only the holder runs the scheduler. The worker
#: does not need one, it claims jobs with FOR UPDATE SKIP LOCKED.
SCHEDULER_LOCK_ID = 8472031

TARGET_JOB_PREFIX = "target-"
RETENTION_JOB_ID = "retention"
SNAPSHOT_JOB_ID = "snapshot"
IGNORES_JOB_ID = "ignores"

#: A missed run still starts if the process was down for less than an hour.
MISFIRE_GRACE_SECONDS = 3600
#: Daily housekeeping time (local time of the configured TZ).
RETENTION_HOUR = 4
RETENTION_MINUTE = 30
#: Daily metric snapshot for the trend (SPEC section 8).
SNAPSHOT_HOUR = 5
SNAPSHOT_MINUTE = 0
#: Ignore rules are re-applied daily, so that an end date takes effect even
#: for a project that is not scanned that day.
IGNORES_HOUR = 5
IGNORES_MINUTE = 30


class ScanScheduler:
    """Registers a cron job per target plus the daily retention job."""

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        *,
        worker: ScanWorker,
        source_provider: SourceProvider | None = None,
        dtrack: DependencyTrackClient | None = None,
    ) -> None:
        self._settings = settings
        self._sessions = sessions
        self._worker = worker
        self._sources = source_provider
        self._dtrack = dtrack
        self._lock_connection: AsyncConnection | None = None
        self._scheduler = AsyncIOScheduler(
            timezone=ZoneInfo(settings.timezone_name),
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": MISFIRE_GRACE_SECONDS,
            },
        )

    # --- lifecycle -----------------------------------------------------------

    @property
    def running(self) -> bool:
        return bool(self._scheduler.running)

    @property
    def scheduled_targets(self) -> int:
        return len([job for job in self._scheduler.get_jobs() if job.id.startswith(TARGET_JOB_PREFIX)])

    async def start(self) -> None:
        if self._scheduler.running:
            return
        if not self._worker.enabled:
            logger.info("Scheduler not started: scanning is not available")
            return
        if not await self._acquire_lock():
            # Another container already schedules; two of them would create
            # duplicate runs for every cron expression.
            logger.warning(t("startup.scheduler.locked", self._settings.default_locale))
            return

        self._scheduler.add_job(
            self._run_retention,
            CronTrigger(hour=RETENTION_HOUR, minute=RETENTION_MINUTE),
            id=RETENTION_JOB_ID,
            replace_existing=True,
        )
        if self._dtrack is not None:
            self._scheduler.add_job(
                self._run_snapshot,
                CronTrigger(hour=SNAPSHOT_HOUR, minute=SNAPSHOT_MINUTE),
                id=SNAPSHOT_JOB_ID,
                replace_existing=True,
            )
            self._scheduler.add_job(
                self._run_ignores,
                CronTrigger(hour=IGNORES_HOUR, minute=IGNORES_MINUTE),
                id=IGNORES_JOB_ID,
                replace_existing=True,
            )
        await self.sync_targets()
        self._scheduler.start()

    async def stop(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
        await self._release_lock()

    async def _acquire_lock(self) -> bool:
        """Take the advisory lock, holding its connection for our lifetime."""
        engine = self._sessions.kw.get("bind")
        if engine is None:
            return True
        connection = await engine.connect()
        try:
            acquired = bool(
                await connection.scalar(select(func.pg_try_advisory_lock(SCHEDULER_LOCK_ID)))
            )
        except SQLAlchemyError:
            await connection.close()
            logger.warning("Could not take the scheduler lock, starting anyway")
            return True
        if not acquired:
            await connection.close()
            return False
        self._lock_connection = connection
        return True

    async def _release_lock(self) -> None:
        if self._lock_connection is None:
            return
        try:
            await self._lock_connection.scalar(
                select(func.pg_advisory_unlock(SCHEDULER_LOCK_ID))
            )
        except SQLAlchemyError:
            pass
        finally:
            await self._lock_connection.close()
            self._lock_connection = None

    # --- target jobs ---------------------------------------------------------

    async def sync_targets(self) -> int:
        """Register a job for every enabled target with a cron expression."""
        async with self._sessions() as session:
            targets = list(
                (
                    await session.execute(
                        select(ScanTarget).where(
                            ScanTarget.enabled.is_(True), ScanTarget.schedule_cron.is_not(None)
                        )
                    )
                ).scalars()
            )

        wanted = {f"{TARGET_JOB_PREFIX}{target.id}" for target in targets}
        for job in self._scheduler.get_jobs():
            if job.id.startswith(TARGET_JOB_PREFIX) and job.id not in wanted:
                job.remove()

        for target in targets:
            self._add_target_job(target)
        return len(targets)

    def _add_target_job(self, target: ScanTarget) -> None:
        if not target.schedule_cron:
            return
        try:
            trigger = CronTrigger.from_crontab(
                target.schedule_cron, timezone=ZoneInfo(self._settings.timezone_name)
            )
        except (ValueError, TypeError):
            # Validation happens in the API; a stored broken expression must
            # not take the scheduler down.
            logger.warning(
                "Target %s has an invalid cron expression, not scheduling it", target.id
            )
            return
        self._scheduler.add_job(
            self._run_target,
            trigger,
            args=[target.id],
            id=f"{TARGET_JOB_PREFIX}{target.id}",
            name=f"scan target {target.id}",
            replace_existing=True,
        )

    def next_run_time(self) -> str | None:
        """ISO timestamp of the next scheduled scan, if any."""
        times = [
            job.next_run_time
            for job in self._scheduler.get_jobs()
            if job.id.startswith(TARGET_JOB_PREFIX) and job.next_run_time is not None
        ]
        return min(times).isoformat() if times else None

    # --- job bodies ----------------------------------------------------------

    async def _run_target(self, target_id: int) -> None:
        """Create a scheduled run for one target."""
        if self._sources is None:
            logger.warning("Skipping scheduled scan of target %s: no source", target_id)
            return
        async with self._sessions() as session:
            target = await session.get(ScanTarget, target_id)
            if target is None or not target.enabled:
                return
            try:
                run = await run_service.create_run_for_targets(
                    session,
                    self._sources,
                    [target],
                    trigger=TRIGGER_SCHEDULE,
                    global_exclude_patterns=await get_global_exclude_patterns(session),
                )
            except AppError as error:
                logger.warning(
                    "Scheduled scan of target %s failed during discovery: %s", target_id, error.code
                )
                return
        logger.info(
            "Scheduled scan of target %s queued as run %s (%s jobs)", target_id, run.id, run.total
        )
        self._worker.notify()

    async def _run_retention(self) -> None:
        async with self._sessions() as session:
            await purge_old_runs(session)
            await purge_old_snapshots(session)

    async def _run_ignores(self) -> None:
        """Re-apply the ignore rules and let the expired ones go (SPEC 12.4)."""
        if self._dtrack is None:
            return
        async with self._sessions() as session:
            try:
                applied = await apply_rules(session, self._dtrack)
                expired = await revert_expired(session, self._dtrack)
            except AppError as error:
                logger.warning("Daily pass over the ignore rules failed: %s", error.code)
                return
            if applied.suppressed or applied.reverted or expired.reverted:
                logger.info(
                    "Ignore rules: %s suppressed, %s taken back (%s of them expired)",
                    applied.suppressed,
                    applied.reverted + expired.reverted,
                    expired.reverted,
                )

    async def _run_snapshot(self) -> None:
        """Store today's metrics of every scanned project (SPEC 9.4)."""
        if self._dtrack is None:
            return
        async with self._sessions() as session:
            try:
                await take_snapshot(session, self._dtrack)
            except AppError as error:
                logger.warning("Daily metric snapshot failed: %s", error.code)
