# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Global settings stored in the database (SPEC section 5).

Values here take precedence over the defaults of the optional environment
variables. The Settings page (milestone 6) edits them; for now only the
readers that other services need are implemented.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Setting

KEY_GLOBAL_EXCLUDE_PATTERNS = "global_exclude_patterns"
KEY_DEFAULT_SCHEDULE_CRON = "default_schedule_cron"
KEY_SCAN_CONCURRENCY = "scan_concurrency"
KEY_HISTORY_RETENTION_DAYS = "history_retention_days"
KEY_NOTIFICATIONS_ENABLED = "notifications_enabled"
KEY_NOTIFICATION_WEBHOOK_URL = "notification_webhook_url"
KEY_NOTIFICATION_MIN_SEVERITY = "notification_min_severity"
KEY_NOTIFICATION_LAST_ALERT = "notification_last_alert"

DEFAULT_HISTORY_RETENTION_DAYS = 90
MAX_SCAN_CONCURRENCY = 16


async def get_value(session: AsyncSession, key: str, default: Any = None) -> Any:
    result = await session.execute(select(Setting.value).where(Setting.key == key))
    value = result.scalar_one_or_none()
    return default if value is None else value


async def set_value(session: AsyncSession, key: str, value: Any, updated_by: str | None = None) -> None:
    setting = await session.get(Setting, key)
    if setting is None:
        session.add(Setting(key=key, value=value, updated_by=updated_by))
    else:
        setting.value = value
        setting.updated_by = updated_by


async def get_scan_concurrency(session: AsyncSession, default: int) -> int:
    """Number of parallel scans: the stored value, else the environment default."""
    value = await get_value(session, KEY_SCAN_CONCURRENCY, default)
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return min(max(1, number), MAX_SCAN_CONCURRENCY)


async def get_notification_config(session: AsyncSession) -> tuple[bool, str | None, str]:
    """(enabled, global webhook, minimum severity) for chat notifications."""
    from app.services.notifications import DEFAULT_MIN_SEVERITY

    enabled = bool(await get_value(session, KEY_NOTIFICATIONS_ENABLED, False))
    webhook = await get_value(session, KEY_NOTIFICATION_WEBHOOK_URL, None)
    severity = await get_value(session, KEY_NOTIFICATION_MIN_SEVERITY, DEFAULT_MIN_SEVERITY)
    return enabled, (str(webhook) if webhook else None), str(severity or DEFAULT_MIN_SEVERITY)


async def should_send_alert(
    session: AsyncSession, code: str, *, cooldown_hours: int = 6
) -> bool:
    """Whether to send an alert about `code` now.

    The same problem is reported once per cooldown window; a different problem
    is always reported.
    """
    from datetime import UTC, datetime, timedelta

    stored = await get_value(session, KEY_NOTIFICATION_LAST_ALERT, None)
    now = datetime.now(UTC)

    if isinstance(stored, dict) and stored.get("code") == code:
        try:
            sent_at = datetime.fromisoformat(str(stored.get("at")))
        except (TypeError, ValueError):
            sent_at = None
        if sent_at is not None and now - sent_at < timedelta(hours=cooldown_hours):
            return False

    await set_value(
        session, KEY_NOTIFICATION_LAST_ALERT, {"code": code, "at": now.isoformat()}
    )
    await session.commit()
    return True


async def get_global_exclude_patterns(session: AsyncSession) -> tuple[str, ...]:
    """Glob patterns excluded from every target."""
    value = await get_value(session, KEY_GLOBAL_EXCLUDE_PATTERNS, [])
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if str(item).strip())
