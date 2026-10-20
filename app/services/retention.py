# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Retention of scan history (SPEC section 8)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import JOB_ACTIVE_STATUSES, JOB_QUEUED
from app.models import MetricSnapshot, ScanJob, ScanRun
from app.services.app_settings import (
    DEFAULT_HISTORY_RETENTION_DAYS,
    KEY_HISTORY_RETENTION_DAYS,
    get_value,
)

logger = logging.getLogger(__name__)

#: Never delete history younger than this, whatever the setting says.
MIN_RETENTION_DAYS = 1

#: The longest trend window the dashboard offers, plus a month of slack. Metric
#: snapshots are kept at least this long, whatever the history retention says,
#: so shortening the retention cannot empty the 180 day trend.
MIN_SNAPSHOT_RETENTION_DAYS = 210


async def retention_days(session: AsyncSession) -> int:
    """Configured retention in days (the UI setting wins over the default)."""
    value = await get_value(session, KEY_HISTORY_RETENTION_DAYS, DEFAULT_HISTORY_RETENTION_DAYS)
    try:
        days = int(value)
    except (TypeError, ValueError):
        return DEFAULT_HISTORY_RETENTION_DAYS
    return max(MIN_RETENTION_DAYS, days)


async def snapshot_retention_days(session: AsyncSession) -> int:
    """How long metric snapshots are kept (never less than the trend needs)."""
    return max(await retention_days(session), MIN_SNAPSHOT_RETENTION_DAYS)


async def purge_old_snapshots(session: AsyncSession) -> int:
    """Delete metric snapshots older than the snapshot retention.

    Without this they accumulate one row per project and day forever, which
    makes the trend query slower every year.
    """
    days = await snapshot_retention_days(session)
    cutoff = (datetime.now(UTC) - timedelta(days=days)).date()

    result = await session.execute(
        delete(MetricSnapshot).where(MetricSnapshot.date < cutoff).returning(MetricSnapshot.id)
    )
    removed = len(result.all())
    await session.commit()
    if removed:
        logger.info("Retention removed %s metric snapshots older than %s days", removed, days)
    return removed


async def purge_old_runs(session: AsyncSession) -> int:
    """Delete runs (and their jobs, by cascade) older than the retention.

    Runs that are still queued or being worked on are never deleted.
    """
    days = await retention_days(session)
    cutoff = datetime.now(UTC) - timedelta(days=days)

    stale = (
        await session.execute(
            select(ScanRun.id).where(
                ScanRun.created_at < cutoff,
                ~ScanRun.id.in_(
                    select(ScanJob.run_id).where(
                        ScanJob.status.in_((JOB_QUEUED, *JOB_ACTIVE_STATUSES))
                    )
                ),
            )
        )
    ).scalars()
    run_ids = list(stale)
    if not run_ids:
        return 0

    await session.execute(delete(ScanRun).where(ScanRun.id.in_(run_ids)))
    await session.commit()
    logger.info("Retention removed %s runs older than %s days", len(run_ids), days)
    return len(run_ids)
