# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Chat notifications about findings (Google Chat incoming webhooks).

A webhook URL contains a key and a token, so it is treated as a secret: it is
never logged, never returned by the API in full, and it is masked in errors.
The notification is best effort — a chat that does not answer must never fail a
scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.config import DEFAULT_LOCALE, Settings
from app.i18n import t
from app.masking import mask_secrets
from app.services.dtrack import DTMetrics
from app.services.sources.base import SourceMember

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 15.0

#: Severities in the order they are written into a message.
SEVERITIES = ("critical", "high", "medium", "low", "unassigned")
#: How many maintainers are listed before the message says "and others".
MAX_LISTED_MAINTAINERS = 5

#: Only findings at this severity or worse trigger a message.
DEFAULT_MIN_SEVERITY = "high"
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

#: Google Chat replies to the thread with this key and starts one when it does
#: not exist yet, so all messages about one repository stay together.
MESSAGE_REPLY_OPTION = "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
#: Thread keys are per space; this prefix keeps ours recognisable.
THREAD_KEY_PREFIX = "vulnyard"
#: Google Chat accepts up to 4000 characters, we stay far below that.
MAX_THREAD_KEY_LENGTH = 200


class NotificationError(Exception):
    """The chat did not accept the message."""


@dataclass(frozen=True, slots=True)
class NotificationTarget:
    """Where to send, and under which conditions."""

    webhook_url: str
    min_severity: str = DEFAULT_MIN_SEVERITY


@dataclass(frozen=True, slots=True)
class FindingsNotification:
    """Everything one message needs."""

    path_with_namespace: str
    branch: str
    metrics: DTMetrics
    maintainers: tuple[SourceMember, ...] = ()
    repository_url: str | None = None
    dtrack_url: str | None = None
    target_name: str | None = None
    #: Severity counts at the end of the previous scan; None on the first one.
    previous: dict[str, int] | None = None


@dataclass(frozen=True, slots=True)
class FailureAlert:
    """Scanning itself is broken, not a project."""

    code: str
    params: dict[str, object]
    run_id: int
    failed: int
    total: int


def severity_counts(metrics: DTMetrics) -> dict[str, int]:
    """Counts in a shape that can be stored and compared later."""
    return {severity: getattr(metrics, severity) for severity in SEVERITIES}


def severity_delta(metrics: DTMetrics, previous: dict[str, int] | None) -> dict[str, int]:
    """Change per severity since the previous scan; empty when nothing moved."""
    if previous is None:
        return {}
    current = severity_counts(metrics)
    return {
        severity: current[severity] - int(previous.get(severity, 0))
        for severity in SEVERITIES
        if current[severity] - int(previous.get(severity, 0)) != 0
    }


def counts_above(metrics: DTMetrics, min_severity: str) -> int:
    """How many findings are at `min_severity` or worse."""
    threshold = SEVERITY_ORDER.get(min_severity.lower(), SEVERITY_ORDER[DEFAULT_MIN_SEVERITY])
    return sum(
        getattr(metrics, severity)
        for severity in SEVERITIES
        if SEVERITY_ORDER[severity] <= threshold
    )


def should_notify(metrics: DTMetrics, min_severity: str) -> bool:
    return counts_above(metrics, min_severity) > 0


def is_resolved(
    metrics: DTMetrics, previous: dict[str, int] | None, min_severity: str
) -> bool:
    """Whether this scan cleared everything that was worth reporting.

    Good news deserves a message too: without this, a project that was fixed
    simply goes quiet, which is indistinguishable from nobody scanning it.
    """
    if previous is None or should_notify(metrics, min_severity):
        return False
    threshold = SEVERITY_ORDER.get(min_severity.lower(), SEVERITY_ORDER[DEFAULT_MIN_SEVERITY])
    had = sum(
        int(previous.get(severity, 0))
        for severity in SEVERITIES
        if SEVERITY_ORDER[severity] <= threshold
    )
    return had > 0


def thread_key(path_with_namespace: str, source: str = "gitlab") -> str:
    """Stable key grouping every message about one repository into one thread.

    Derived from the repository path, so it survives restarts without storing
    anything, and it deliberately ignores the branch: all branches of a
    repository belong to the same conversation.
    """
    key = f"{THREAD_KEY_PREFIX}/{source}/{path_with_namespace}"
    return key[:MAX_THREAD_KEY_LENGTH]


def build_message(notification: FindingsNotification, locale: str = DEFAULT_LOCALE) -> dict[str, object]:
    """Google Chat payload. Text formatting: *bold*, `code`, <url|label>."""
    headline = t(
        "notify.headline",
        locale,
        project=notification.path_with_namespace,
        branch=notification.branch,
    )
    lines = [headline, _counts_line(notification, locale)]

    lines.append(_change_line(notification, locale))

    if notification.target_name:
        lines.append(t("notify.target", locale, target=notification.target_name))

    lines.append(_maintainers_line(notification.maintainers, locale))

    links = _links_line(notification, locale)
    if links:
        lines.append(links)

    return {
        "text": "\n".join(lines),
        # Keeps the repository's messages in one thread instead of starting a
        # new conversation every time.
        "thread": {"threadKey": thread_key(notification.path_with_namespace)},
    }


def _change_line(notification: FindingsNotification, locale: str) -> str:
    """What moved since the previous scan – the question people actually ask."""
    if notification.previous is None:
        return t("notify.first_scan", locale)

    delta = severity_delta(notification.metrics, notification.previous)
    if not delta:
        return t("notify.unchanged", locale)

    parts = [
        t(
            "notify.delta_count",
            locale,
            sign="+" if count > 0 else "−",
            count=abs(count),
            severity=t(f"notify.severity.{severity}", locale),
        )
        for severity, count in delta.items()
    ]
    return t("notify.changed", locale, changes=", ".join(parts))


def build_alert_message(alert: FailureAlert, locale: str = DEFAULT_LOCALE) -> dict[str, object]:
    """Message about scanning being broken, kept in its own thread."""
    lines = [
        t("notify.alert.headline", locale),
        t(alert.code, locale, **alert.params),
        t("notify.alert.summary", locale, run=alert.run_id, failed=alert.failed, total=alert.total),
    ]
    return {
        "text": "\n".join(lines),
        "thread": {"threadKey": f"{THREAD_KEY_PREFIX}/alerts"},
    }


def build_resolved_message(
    notification: FindingsNotification, locale: str = DEFAULT_LOCALE
) -> dict[str, object]:
    """Message about a repository that no longer has reportable findings."""
    lines = [
        t(
            "notify.resolved.headline",
            locale,
            project=notification.path_with_namespace,
            branch=notification.branch,
        ),
        _change_line(notification, locale),
    ]

    # Say what is still there, so "clean" is not mistaken for "zero findings".
    remaining = _counts_line(notification, locale, only_when_any=True)
    if remaining:
        lines.append(t("notify.resolved.remaining", locale, counts=remaining))
    else:
        lines.append(t("notify.resolved.nothing_left", locale))

    if notification.target_name:
        lines.append(t("notify.target", locale, target=notification.target_name))

    lines.append(_maintainers_line(notification.maintainers, locale))
    links = _links_line(notification, locale)
    if links:
        lines.append(links)

    return {
        "text": "\n".join(lines),
        "thread": {"threadKey": thread_key(notification.path_with_namespace)},
    }


def _counts_line(
    notification: FindingsNotification, locale: str, *, only_when_any: bool = False
) -> str:
    counts = " · ".join(
        t(
            "notify.severity_count",
            locale,
            severity=t(f"notify.severity.{severity}", locale),
            count=getattr(notification.metrics, severity),
        )
        for severity in SEVERITIES
        if getattr(notification.metrics, severity)
    )
    if counts:
        return counts
    return "" if only_when_any else t("notify.no_counts", locale)


def _links_line(notification: FindingsNotification, locale: str) -> str:
    links = []
    if notification.repository_url:
        links.append(f"<{notification.repository_url}|{t('notify.link.repository', locale)}>")
    if notification.dtrack_url:
        links.append(f"<{notification.dtrack_url}|{t('notify.link.dtrack', locale)}>")
    return " · ".join(links)


def build_test_message(locale: str = DEFAULT_LOCALE) -> dict[str, object]:
    return {"text": t("notify.test", locale)}


def with_reply_option(webhook_url: str) -> str:
    """Add messageReplyOption, keeping the key and token already in the URL.

    Without it Google Chat ignores the thread key of an existing thread and
    posts a new message instead of a reply.
    """
    parts = urlsplit(webhook_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["messageReplyOption"] = MESSAGE_REPLY_OPTION
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


#: GitLab access levels, for naming the role in a message.
ROLE_NAMES = {50: "Owner", 40: "Maintainer", 30: "Developer", 20: "Reporter", 10: "Guest"}
MAINTAINER_ACCESS_LEVEL = 40


def _maintainers_line(maintainers: tuple[SourceMember, ...], locale: str) -> str:
    """People to talk to, with a label saying where the list came from."""
    if not maintainers:
        return t("notify.maintainers_unknown", locale)

    listed = maintainers[:MAX_LISTED_MAINTAINERS]
    names = ", ".join(_maintainer(member) for member in listed)
    remaining = len(maintainers) - len(listed)
    if remaining > 0:
        names = t("notify.maintainers_more", locale, names=names, count=remaining)

    if all(member.inherited for member in maintainers):
        # Nobody is added to the repository itself, so these are group members.
        return t("notify.maintainers_inherited", locale, maintainers=names)
    if max(member.access_level for member in maintainers) >= MAINTAINER_ACCESS_LEVEL:
        return t("notify.maintainers", locale, maintainers=names)
    return t("notify.members", locale, maintainers=names)


def _maintainer(member: SourceMember) -> str:
    """Name, username and role; GitLab does not expose member e-mail addresses."""
    role = ROLE_NAMES.get(member.access_level, str(member.access_level))
    label = f"{member.name} (@{member.username}, {role})" if member.username else f"{member.name} ({role})"
    return f"<{member.web_url}|{label}>" if member.web_url else label


def mask_webhook(url: str | None) -> str | None:
    """Webhook URL without its secrets, safe for the API and the UI."""
    if not url:
        return None
    parts = urlsplit(url)
    path = parts.path
    if len(path) > 40:
        path = f"{path[:28]}…{path[-8:]}"
    query = "?…" if parts.query else ""
    return f"{parts.scheme}://{parts.netloc}{path}{query}"


class ChatNotifier:
    """Sends messages to a chat webhook."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=settings.ca_bundle or True,
            headers={"Content-Type": "application/json; charset=UTF-8"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def send(self, webhook_url: str, payload: dict[str, object]) -> None:
        """POST the payload; raises NotificationError with a masked detail.

        A payload carrying a thread key is sent with the reply option, so the
        message lands in that repository's thread.
        """
        url = with_reply_option(webhook_url) if payload.get("thread") else webhook_url
        try:
            response = await self._client.post(url, json=payload)
        except (httpx.TimeoutException, httpx.TransportError) as error:
            # Some transport errors carry no message at all, so name the type.
            detail = self._mask(str(error)) or type(error).__name__
            raise NotificationError(detail) from error

        if not response.is_success:
            raise NotificationError(
                f"HTTP {response.status_code}: {self._mask(response.text[:300])}"
            )

    async def notify_failure(
        self, webhook_url: str, alert: FailureAlert, *, locale: str = DEFAULT_LOCALE
    ) -> bool:
        """Tell the chat that scanning is not working. Never raises."""
        try:
            await self.send(webhook_url, build_alert_message(alert, locale))
        except NotificationError as error:
            logger.warning("Chat alert about %s failed: %s", alert.code, error)
            return False
        logger.info("Chat alert sent: %s (run %s)", alert.code, alert.run_id)
        return True

    async def notify_findings(
        self,
        target: NotificationTarget,
        notification: FindingsNotification,
        *,
        locale: str = DEFAULT_LOCALE,
    ) -> bool:
        """Send a message when the findings reach the threshold.

        Returns whether a message was sent. Never raises: a chat problem is
        logged and the scan continues.
        """
        if should_notify(notification.metrics, target.min_severity):
            payload = build_message(notification, locale)
        elif is_resolved(notification.metrics, notification.previous, target.min_severity):
            payload = build_resolved_message(notification, locale)
        else:
            return False

        try:
            await self.send(target.webhook_url, payload)
        except NotificationError as error:
            logger.warning(
                "Chat notification for %s@%s failed: %s",
                notification.path_with_namespace,
                notification.branch,
                error,
            )
            return False
        logger.info(
            "Chat notification sent for %s@%s",
            notification.path_with_namespace,
            notification.branch,
        )
        return True

    def _mask(self, text: str) -> str:
        return mask_secrets(text, self._settings.gitlab_token, self._settings.dt_api_key)
