# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Daily snapshots of Dependency-Track metrics used for the trend (SPEC 9.4)."""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import MetricSnapshot, Project
from app.services.dashboard import dtrack_projects
from app.services.dtrack import DependencyTrackClient, DTMetrics

logger = logging.getLogger(__name__)

#: How many days of history we try to backfill on the first run.
BACKFILL_DAYS = 90


async def take_snapshot(
    session: AsyncSession, dtrack: DependencyTrackClient, *, today: date | None = None
) -> int:
    """Store today's metrics of every scanned project (one row per project)."""
    day = today or datetime.now(UTC).date()
    dt_projects = await dtrack_projects(dtrack)

    projects = list(
        (
            await session.execute(
                select(Project).where(Project.dt_project_uuid.is_not(None))
            )
        ).scalars()
    )

    written = 0
    for project in projects:
        dt_project = dt_projects.get(project.dt_project_uuid or "")
        if dt_project is None or dt_project.metrics is None:
            continue
        await _upsert(session, project.id, day, dt_project.metrics)
        written += 1

    await session.commit()
    if written:
        logger.info("Stored metric snapshots for %s projects (%s)", written, day)
    return written


async def backfill(session: AsyncSession, dtrack: DependencyTrackClient) -> int:
    """Fill the trend with history from Dependency-Track for new projects.

    Runs once per project: only projects without any snapshot are asked for
    their history, so a fresh installation shows a trend right away.
    """
    projects = list(
        (
            await session.execute(
                select(Project)
                .where(Project.dt_project_uuid.is_not(None))
                .where(
                    ~select(MetricSnapshot.id)
                    .where(MetricSnapshot.project_id == Project.id)
                    .exists()
                )
            )
        ).scalars()
    )

    written = 0
    for project in projects:
        history = await dtrack.project_metrics_history(project.dt_project_uuid or "", BACKFILL_DAYS)
        for metrics in history:
            if metrics.last_occurrence is None:
                continue
            await _upsert(session, project.id, metrics.last_occurrence.date(), metrics)
            written += 1
    await session.commit()
    if written:
        logger.info("Backfilled %s metric snapshots from Dependency-Track", written)
    return written


async def _upsert(session: AsyncSession, project_id: int, day: date, metrics: DTMetrics) -> None:
    existing = (
        await session.execute(
            select(MetricSnapshot).where(
                MetricSnapshot.project_id == project_id, MetricSnapshot.date == day
            )
        )
    ).scalar_one_or_none()

    values = {
        "critical": metrics.critical,
        "high": metrics.high,
        "medium": metrics.medium,
        "low": metrics.low,
        "unassigned": metrics.unassigned,
        "components": metrics.components,
        "vulnerable_components": metrics.vulnerable_components,
        "inherited_risk_score": metrics.inherited_risk_score,
        "suppressed": metrics.suppressed,
    }

    if existing is None:
        session.add(MetricSnapshot(project_id=project_id, date=day, **values))
        return
    for field, value in values.items():
        setattr(existing, field, value)
