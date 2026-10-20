# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Global settings and connection tests (SPEC 11, 12.7)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query

from app import APP_NAME, __version__
from app.dependencies import (
    AuditIdentityDep,
    DTrackDep,
    LocaleDep,
    NotifierDep,
    SessionDep,
    SettingsDep,
    SourceOptionalDep,
)
from app.errors import AppError, ValidationError
from app.i18n import t
from app.schemas import (
    ConnectionTestResult,
    EnvironmentOverview,
    EnvironmentVariableState,
    NotificationSettings,
    SettingsRead,
    SettingsWrite,
)
from app.services import app_settings
from app.services import targets as target_service
from app.services.dtrack import MIN_SUPPORTED_VERSION
from app.services.notifications import (
    SEVERITIES,
    ChatNotifier,
    NotificationError,
    build_test_message,
    mask_webhook,
)
from app.validation import is_valid_cron, is_valid_path_pattern, is_valid_webhook_url

router = APIRouter(prefix="/settings", tags=["settings"])

logger = logging.getLogger(__name__)

MAX_CONCURRENCY = 16
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650
MAX_PATTERNS = 50

#: Variables shown as "set / missing"; values are never returned.
REPORTED_VARIABLES = (
    ("DATABASE_URL", True),
    ("GITLAB_URL", False),
    ("GITLAB_TOKEN", True),
    ("DT_API_URL", True),
    ("DT_API_KEY", True),
    ("DT_UI_URL", False),
    ("AUTH_MODE", False),
    ("AUTH_HEADERS", False),
    ("CA_BUNDLE", False),
    ("TRIVY_BIN", False),
    ("TRIVY_OFFLINE", False),
    ("TZ", False),
    ("DEFAULT_LOCALE", False),
    ("LOG_LEVEL", False),
)


@router.get("", response_model=SettingsRead)
async def read_settings(session: SessionDep, settings: SettingsDep) -> SettingsRead:
    """Settings editable in the UI, with the environment defaults as fallback."""
    return SettingsRead(
        scan_concurrency=await app_settings.get_value(
            session, app_settings.KEY_SCAN_CONCURRENCY, settings.scan_concurrency
        ),
        default_schedule_cron=await app_settings.get_value(
            session, app_settings.KEY_DEFAULT_SCHEDULE_CRON, None
        ),
        history_retention_days=await app_settings.get_value(
            session,
            app_settings.KEY_HISTORY_RETENTION_DAYS,
            app_settings.DEFAULT_HISTORY_RETENTION_DAYS,
        ),
        global_exclude_patterns=list(await app_settings.get_global_exclude_patterns(session)),
        notifications=await _notifications(session),
        environment=_environment(settings),
    )


@router.put("", response_model=SettingsRead)
async def write_settings(
    payload: SettingsWrite,
    session: SessionDep,
    settings: SettingsDep,
    identity: AuditIdentityDep,
) -> SettingsRead:
    """Store the settings; a changed concurrency applies after a restart."""
    data = payload.model_dump(exclude_unset=True)

    if "scan_concurrency" in data and data["scan_concurrency"] is not None:
        if not 1 <= int(data["scan_concurrency"]) <= MAX_CONCURRENCY:
            raise ValidationError("validation.concurrency_out_of_range", min=1, max=MAX_CONCURRENCY)
        await app_settings.set_value(
            session, app_settings.KEY_SCAN_CONCURRENCY, int(data["scan_concurrency"]), identity
        )

    if "default_schedule_cron" in data:
        expression = (data["default_schedule_cron"] or "").strip() or None
        if expression and not is_valid_cron(expression):
            raise ValidationError("validation.cron_invalid", expression=expression)
        await app_settings.set_value(
            session, app_settings.KEY_DEFAULT_SCHEDULE_CRON, expression, identity
        )

    if "history_retention_days" in data and data["history_retention_days"] is not None:
        days = int(data["history_retention_days"])
        if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
            raise ValidationError(
                "validation.retention_out_of_range", min=MIN_RETENTION_DAYS, max=MAX_RETENTION_DAYS
            )
        await app_settings.set_value(
            session, app_settings.KEY_HISTORY_RETENTION_DAYS, days, identity
        )

    if "global_exclude_patterns" in data and data["global_exclude_patterns"] is not None:
        patterns = [str(item).strip() for item in data["global_exclude_patterns"] if str(item).strip()]
        if len(patterns) > MAX_PATTERNS:
            raise ValidationError("validation.too_many_patterns", max=MAX_PATTERNS)
        for pattern in patterns:
            if not is_valid_path_pattern(pattern):
                raise ValidationError("validation.path_pattern_invalid", pattern=pattern)
        await app_settings.set_value(
            session, app_settings.KEY_GLOBAL_EXCLUDE_PATTERNS, patterns, identity
        )

    if "notifications_enabled" in data and data["notifications_enabled"] is not None:
        await app_settings.set_value(
            session,
            app_settings.KEY_NOTIFICATIONS_ENABLED,
            bool(data["notifications_enabled"]),
            identity,
        )

    if "notification_webhook_url" in data:
        webhook = (data["notification_webhook_url"] or "").strip() or None
        if webhook and not is_valid_webhook_url(webhook):
            raise ValidationError("validation.webhook_invalid")
        await app_settings.set_value(
            session, app_settings.KEY_NOTIFICATION_WEBHOOK_URL, webhook, identity
        )

    if "notification_min_severity" in data and data["notification_min_severity"] is not None:
        severity = str(data["notification_min_severity"]).lower()
        if severity not in SEVERITIES:
            raise ValidationError("validation.min_severity_invalid", severity=severity)
        await app_settings.set_value(
            session, app_settings.KEY_NOTIFICATION_MIN_SEVERITY, severity, identity
        )

    await session.commit()
    return await read_settings(session, settings)


@router.post("/test-webhook", response_model=ConnectionTestResult)
async def test_webhook(
    session: SessionDep,
    settings: SettingsDep,
    notifier: NotifierDep,
    locale: LocaleDep,
    target_id: int | None = Query(default=None),
) -> ConnectionTestResult:
    """Send a test message to the global webhook, or to a target's own one."""
    _, global_webhook, _ = await app_settings.get_notification_config(session)

    webhook = global_webhook
    if target_id is not None:
        target = await target_service.get_target(session, target_id)
        webhook = target.notify_webhook_url or global_webhook

    if not webhook:
        return _failure("notify.not_configured", locale)

    try:
        # The chat is shared, so the message speaks its language, not the requester's.
        await notifier.send(webhook, build_test_message(settings.default_locale))
    except NotificationError as error:
        return ConnectionTestResult(
            ok=False, code="notify.failed", detail=t("notify.failed", locale, detail=str(error))
        )
    return ConnectionTestResult(ok=True, detail=t("settings.notifications.sent", locale))


async def _notifications(session) -> NotificationSettings:  # noqa: ANN001 - AsyncSession
    enabled, webhook, severity = await app_settings.get_notification_config(session)
    return NotificationSettings(
        enabled=enabled,
        webhook_configured=bool(webhook),
        webhook_url_masked=mask_webhook(webhook),
        min_severity=severity,
    )


@router.post("/test-source", response_model=ConnectionTestResult)
async def test_source(
    source: SourceOptionalDep, settings: SettingsDep, locale: LocaleDep
) -> ConnectionTestResult:
    """Ask the repository source for its version (SPEC 12.7)."""
    if source is None:
        return _failure("source.not_configured", locale)
    try:
        version = await source.version()
    except AppError as error:
        return _failure(error.code, locale, **error.params)
    return ConnectionTestResult(
        ok=True,
        detail=t("settings.test.source_ok", locale, url=settings.gitlab_url, version=version or "?"),
        version=version,
    )


@router.post("/test-dtrack", response_model=ConnectionTestResult)
async def test_dtrack(
    dtrack: DTrackDep, settings: SettingsDep, locale: LocaleDep
) -> ConnectionTestResult:
    """Ask Dependency-Track for its version and check that we support it."""
    if dtrack is None:
        return _failure("dtrack.not_configured", locale)
    try:
        features = await dtrack.detect_features()
    except AppError as error:
        return _failure(error.code, locale, **error.params)

    if not features.supported:
        return ConnectionTestResult(
            ok=False,
            code="dtrack.version_unsupported",
            detail=t(
                "dtrack.version_unsupported",
                locale,
                version=features.version or "?",
                minimum=".".join(str(part) for part in MIN_SUPPORTED_VERSION),
            ),
            version=features.version,
        )

    return ConnectionTestResult(
        ok=True,
        detail=t(
            "settings.test.dtrack_ok", locale, url=settings.dt_api_url, version=features.version or "?"
        ),
        version=features.version,
    )


def _failure(code: str, locale: str, **params: object) -> ConnectionTestResult:
    return ConnectionTestResult(ok=False, code=code, detail=t(code, locale, **params))


def _environment(settings) -> EnvironmentOverview:  # noqa: ANN001 - Settings
    """Which variables are set. Values are never exposed, only names."""
    values = {
        "DATABASE_URL": settings.database_url,
        "GITLAB_URL": settings.gitlab_url,
        "GITLAB_TOKEN": settings.gitlab_token,
        "DT_API_URL": settings.dt_api_url,
        "DT_API_KEY": settings.dt_api_key,
        "DT_UI_URL": settings.dt_ui_url,
        "AUTH_MODE": settings.auth_mode,
        "AUTH_HEADERS": settings.auth_headers,
        "CA_BUNDLE": settings.ca_bundle,
        "TRIVY_BIN": settings.trivy_bin,
        "TRIVY_OFFLINE": str(settings.trivy_offline).lower(),
        "TZ": settings.tz,
        "DEFAULT_LOCALE": settings.default_locale,
        "LOG_LEVEL": settings.log_level,
    }
    return EnvironmentOverview(
        app_name=APP_NAME,
        app_version=__version__,
        variables=[
            EnvironmentVariableState(name=name, set=bool(values.get(name)), secret=secret)
            for name, secret in REPORTED_VARIABLES
        ],
    )
