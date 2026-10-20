# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Chat notifications: message content, thresholds, webhook resolution."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.services.dtrack import DTMetrics
from app.services.notifications import (
    ChatNotifier,
    FindingsNotification,
    NotificationTarget,
    build_message,
    build_test_message,
    counts_above,
    mask_webhook,
    should_notify,
)
from tests.fakes import FakeDependencyTrack, FakeSource, branch, member, project

GROUP_TARGET = {"kind": "group", "source_ref": "1"}
WEBHOOK = "https://chat.googleapis.com/v1/spaces/AAAA1234/messages?key=secretkey&token=secrettoken"
OTHER_WEBHOOK = "https://chat.googleapis.com/v1/spaces/BBBB5678/messages?key=otherkey&token=othertoken"


def notification(**overrides: object) -> FindingsNotification:
    defaults: dict[str, object] = {
        "path_with_namespace": "team/app",
        "branch": "main",
        "metrics": DTMetrics(critical=2, high=3, medium=1, low=0, unassigned=1),
        "maintainers": (
            member("Jan Novák", "jnovak", access_level=50),
            member("Eva Malá", "emala"),
        ),
        "repository_url": "https://git.example.com/team/app",
        "dtrack_url": "https://dtrack.example.com/projects/uuid-1",
        "target_name": "Team",
    }
    return FindingsNotification(**{**defaults, **overrides})  # type: ignore[arg-type]


# --- message ------------------------------------------------------------------


def test_message_names_the_repository_branch_and_maintainers() -> None:
    text = build_message(notification())["text"]

    assert "team/app" in text
    assert "main" in text
    assert "kritické: 2" in text
    assert "vysoké: 3" in text
    # Severities with no findings are left out.
    assert "nízké" not in text
    # The role is part of the name, so nobody has to guess who to talk to.
    assert "Jan Novák (@jnovak, Owner)" in text
    assert "Eva Malá (@emala, Maintainer)" in text
    assert "Cíl skenování: Team" in text
    # Links use the Google Chat <url|label> syntax.
    assert "<https://git.example.com/team/app|Repozitář>" in text
    assert "<https://dtrack.example.com/projects/uuid-1|Dependency-Track>" in text


def test_message_says_so_when_no_maintainer_is_known() -> None:
    text = build_message(notification(maintainers=()))["text"]

    assert "Členy repa se nepodařilo zjistit" in text


def test_message_lists_at_most_five_maintainers() -> None:
    many = tuple(member(f"Člověk {index}", f"user{index}") for index in range(8))

    text = build_message(notification(maintainers=many))["text"]

    assert "a další 3" in text
    # Each listed maintainer appears once as "@username" (plus once in their link).
    assert text.count("(@user") == 5


def test_test_message_is_recognisable() -> None:
    assert "testovací" in build_test_message()["text"].lower()


# --- thresholds ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("metrics", "minimum", "expected"),
    [
        (DTMetrics(critical=1), "critical", True),
        (DTMetrics(high=2), "critical", False),
        (DTMetrics(high=2), "high", True),
        (DTMetrics(medium=5), "high", False),
        (DTMetrics(low=1), "low", True),
        (DTMetrics(), "low", False),
        (DTMetrics(unassigned=3), "unassigned", True),
    ],
)
def test_threshold_decides_whether_to_notify(
    metrics: DTMetrics, minimum: str, expected: bool
) -> None:
    assert should_notify(metrics, minimum) is expected


def test_counts_above_adds_up_the_worse_severities() -> None:
    metrics = DTMetrics(critical=1, high=2, medium=4, low=8)

    assert counts_above(metrics, "critical") == 1
    assert counts_above(metrics, "high") == 3
    assert counts_above(metrics, "medium") == 7


# --- secrets ------------------------------------------------------------------


def test_masked_webhook_keeps_no_key_or_token() -> None:
    masked = mask_webhook(WEBHOOK)

    assert masked is not None
    assert "secretkey" not in masked
    assert "secrettoken" not in masked
    assert masked.startswith("https://chat.googleapis.com/")
    assert mask_webhook(None) is None


# --- sending ------------------------------------------------------------------


class RecordingNotifier(ChatNotifier):
    """Notifier that records instead of sending."""

    def __init__(self) -> None:
        from app.config import Settings

        super().__init__(Settings())
        self.sent: list[tuple[str, dict[str, str]]] = []
        self.fail = False

    async def send(self, webhook_url: str, payload: dict[str, str]) -> None:
        from app.services.notifications import NotificationError

        if self.fail:
            raise NotificationError("HTTP 404: not found")
        self.sent.append((webhook_url, payload))


async def test_nothing_is_sent_below_the_threshold() -> None:
    notifier = RecordingNotifier()

    sent = await notifier.notify_findings(
        NotificationTarget(webhook_url=WEBHOOK, min_severity="critical"),
        notification(metrics=DTMetrics(medium=9)),
    )

    assert sent is False
    assert notifier.sent == []
    await notifier.close()


async def test_a_failing_chat_is_reported_but_not_raised() -> None:
    notifier = RecordingNotifier()
    notifier.fail = True

    sent = await notifier.notify_findings(
        NotificationTarget(webhook_url=WEBHOOK), notification()
    )

    assert sent is False
    await notifier.close()


# --- webhook resolution through the API ---------------------------------------


def test_global_webhook_is_stored_and_returned_masked(db_client: TestClient) -> None:
    response = db_client.put(
        "/api/settings",
        json={
            "notifications_enabled": True,
            "notification_webhook_url": WEBHOOK,
            "notification_min_severity": "critical",
        },
    )

    assert response.status_code == 200
    notifications = response.json()["notifications"]
    assert notifications["enabled"] is True
    assert notifications["webhook_configured"] is True
    assert notifications["min_severity"] == "critical"
    assert "secretkey" not in response.text
    assert "secrettoken" not in response.text


def test_invalid_webhook_and_severity_are_refused(db_client: TestClient) -> None:
    plain_http = db_client.put("/api/settings", json={"notification_webhook_url": "http://chat.example.com/x"})
    assert plain_http.status_code == 422
    assert plain_http.json()["error"]["code"] == "validation.webhook_invalid"

    bad_severity = db_client.put("/api/settings", json={"notification_min_severity": "nightmare"})
    assert bad_severity.status_code == 422
    assert bad_severity.json()["error"]["code"] == "validation.min_severity_invalid"


def test_webhook_can_be_cleared(db_client: TestClient) -> None:
    db_client.put("/api/settings", json={"notification_webhook_url": WEBHOOK})

    body = db_client.put("/api/settings", json={"notification_webhook_url": ""}).json()

    assert body["notifications"]["webhook_configured"] is False
    assert body["notifications"]["webhook_url_masked"] is None


def test_target_can_have_its_own_webhook(db_client: TestClient) -> None:
    created = db_client.post(
        "/api/targets", json={**GROUP_TARGET, "notify_webhook_url": OTHER_WEBHOOK}
    ).json()

    assert created["notify_webhook_configured"] is True
    assert created["notify_webhook_url_masked"] is not None
    assert "otherkey" not in db_client.get("/api/targets").text

    cleared = db_client.put(f"/api/targets/{created['id']}", json={"notify_webhook_url": ""}).json()
    assert cleared["notify_webhook_configured"] is False


def test_target_webhook_must_be_https(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/targets", json={**GROUP_TARGET, "notify_webhook_url": "ftp://chat.example.com"}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation.webhook_invalid"


def test_test_webhook_endpoint_reports_a_missing_configuration(db_client: TestClient) -> None:
    body = db_client.post("/api/settings/test-webhook").json()

    assert body["ok"] is False
    assert body["code"] == "notify.not_configured"


# --- the worker decides where to send -----------------------------------------


def _scanned(client: TestClient, **target_fields: object) -> tuple[FakeSource, int]:
    source: FakeSource = client.app.state.source
    source._projects = [project("10", "team/app", default_branch="main")]  # noqa: SLF001
    source._branches = {"10": [branch("main", is_default=True)]}  # noqa: SLF001
    source.maintainers = {"10": [member("Jan Novák", "jnovak", access_level=50)]}
    target_id = client.post("/api/targets", json={**GROUP_TARGET, **target_fields}).json()["id"]
    client.post(f"/api/targets/{target_id}/scan")
    _run_sql(client, "UPDATE projects SET dt_project_uuid = 'dt-10-main'")

    dtrack: FakeDependencyTrack = client.app.state.dtrack
    dtrack.metrics_by_uuid = {"dt-10-main": DTMetrics(critical=2, high=1)}  # type: ignore[attr-defined]
    return source, target_id


def test_worker_uses_the_target_webhook_over_the_global_one(scan_client: TestClient) -> None:
    notifier = _attach_notifier(scan_client)
    _scanned(scan_client, notify_webhook_url=OTHER_WEBHOOK)
    scan_client.put("/api/settings", json={"notifications_enabled": True, "notification_webhook_url": WEBHOOK})

    _notify_first_job(scan_client)

    assert [url for url, _ in notifier.sent] == [OTHER_WEBHOOK]
    text = notifier.sent[0][1]["text"]
    assert "team/app" in text
    assert "Jan Novák (@jnovak, Owner)" in text


def test_worker_falls_back_to_the_global_webhook(scan_client: TestClient) -> None:
    notifier = _attach_notifier(scan_client)
    _scanned(scan_client)
    scan_client.put("/api/settings", json={"notifications_enabled": True, "notification_webhook_url": WEBHOOK})

    _notify_first_job(scan_client)

    assert [url for url, _ in notifier.sent] == [WEBHOOK]


def test_nothing_is_sent_while_notifications_are_off(scan_client: TestClient) -> None:
    notifier = _attach_notifier(scan_client)
    _scanned(scan_client)
    scan_client.put("/api/settings", json={"notification_webhook_url": WEBHOOK})

    _notify_first_job(scan_client)

    assert notifier.sent == []


def test_a_target_webhook_sends_even_when_the_global_switch_is_off(scan_client: TestClient) -> None:
    notifier = _attach_notifier(scan_client)
    _scanned(scan_client, notify_webhook_url=OTHER_WEBHOOK)

    _notify_first_job(scan_client)

    assert [url for url, _ in notifier.sent] == [OTHER_WEBHOOK]


# --- helpers ------------------------------------------------------------------


def _attach_notifier(client: TestClient) -> RecordingNotifier:
    notifier = RecordingNotifier()
    client.app.state.worker._notifier = notifier  # noqa: SLF001 - wiring for the test
    return notifier


def _notify_first_job(client: TestClient) -> None:
    """Run the worker's notification step for the first job of the run."""
    from app.db import session_factory
    from app.models import Project, ScanJob

    worker = client.app.state.worker

    async def run() -> None:
        async with session_factory()() as session:
            job = (await session.execute(__import__("sqlalchemy").select(ScanJob))).scalars().first()
            project = await session.get(Project, job.project_id)
            await worker._notify(session, job, project)  # noqa: SLF001 - exercised directly

    client.portal.call(run)  # type: ignore[attr-defined]


def _run_sql(client: TestClient, statement: str, params: dict[str, object] | None = None) -> None:
    from sqlalchemy import text

    from app.db import session_factory

    async def execute() -> None:
        async with session_factory()() as session:
            await session.execute(text(statement), params or {})
            await session.commit()

    client.portal.call(execute)  # type: ignore[attr-defined]


async def test_real_http_post_carries_the_google_chat_payload() -> None:
    """The notifier really POSTs JSON; verified against a local server."""
    import asyncio
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from app.config import Settings

    received: list[tuple[str, dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            received.append((self.headers.get("Content-Type", ""), body))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/webhook"

    notifier = ChatNotifier(Settings())
    try:
        await notifier.send(url, build_message(notification()))
        # The handler runs in another thread; give it a moment.
        for _ in range(20):
            if received:
                break
            await asyncio.sleep(0.05)
    finally:
        await notifier.close()
        server.shutdown()

    assert len(received) == 1
    content_type, payload = received[0]
    assert "application/json" in content_type
    assert "team/app" in payload["text"]
    assert "Jan Novák (@jnovak, Owner)" in payload["text"]


async def test_a_rejecting_chat_raises_with_a_masked_detail() -> None:
    """An error from the chat must not carry our tokens."""
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from app.config import Settings
    from app.services.notifications import NotificationError

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            body = json.dumps({"error": "space not found glpat-SECRETTOKEN12345"}).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()

    notifier = ChatNotifier(Settings(gitlab_token="glpat-SECRETTOKEN12345"))
    try:
        with pytest.raises(NotificationError) as raised:
            await notifier.send(f"http://127.0.0.1:{server.server_port}/webhook", {"text": "x"})
    finally:
        await notifier.close()
        server.shutdown()

    assert "404" in str(raised.value)
    assert "glpat-SECRETTOKEN12345" not in str(raised.value)



async def test_a_transport_error_without_a_message_still_says_what_happened() -> None:
    """An unreachable chat must produce a usable message, not an empty one."""
    from app.config import Settings
    from app.services.notifications import NotificationError

    notifier = ChatNotifier(Settings())
    try:
        # Port 1 refuses immediately.
        with pytest.raises(NotificationError) as raised:
            await notifier.send("http://127.0.0.1:1/webhook", {"text": "x"})
    finally:
        await notifier.close()

    assert str(raised.value)


# --- threading (one conversation per repository) -------------------------------


def test_every_message_about_one_repository_carries_the_same_thread_key() -> None:
    from app.services.notifications import thread_key

    first = build_message(notification(branch="main"))
    later = build_message(notification(branch="release/1.0"))

    assert first["thread"] == {"threadKey": thread_key("team/app")}
    # Branches of one repository belong to the same conversation.
    assert first["thread"] == later["thread"]
    # A different repository gets its own thread.
    assert build_message(notification(path_with_namespace="team/api"))["thread"] != first["thread"]


def test_thread_key_is_stable_and_recognisable() -> None:
    from app.services.notifications import thread_key

    assert thread_key("team/app") == "vulnyard/gitlab/team/app"
    assert thread_key("team/app") == thread_key("team/app")
    assert len(thread_key("x" * 500)) <= 200


def test_reply_option_is_added_without_losing_the_key_and_token() -> None:
    from urllib.parse import parse_qs, urlsplit

    from app.services.notifications import MESSAGE_REPLY_OPTION, with_reply_option

    url = with_reply_option(WEBHOOK)
    query = parse_qs(urlsplit(url).query)

    assert query["key"] == ["secretkey"]
    assert query["token"] == ["secrettoken"]
    assert query["messageReplyOption"] == [MESSAGE_REPLY_OPTION]
    # The space stays the same.
    assert urlsplit(url).path == urlsplit(WEBHOOK).path


async def test_threaded_message_is_posted_with_the_reply_option() -> None:
    """Verified against a local server: URL and body carry the threading bits."""
    import asyncio
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    from urllib.parse import parse_qs, urlsplit

    from app.config import Settings
    from app.services.notifications import MESSAGE_REPLY_OPTION

    seen: list[tuple[str, dict]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            seen.append((self.path, body))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}/v1/spaces/AAA/messages?key=k&token=t"

    notifier = ChatNotifier(Settings())
    try:
        await notifier.send(base, build_message(notification()))
        await notifier.send(base, build_test_message())
        for _ in range(20):
            if len(seen) == 2:
                break
            await asyncio.sleep(0.05)
    finally:
        await notifier.close()
        server.shutdown()

    findings_path, findings_body = seen[0]
    query = parse_qs(urlsplit(findings_path).query)
    assert query["messageReplyOption"] == [MESSAGE_REPLY_OPTION]
    assert query["key"] == ["k"] and query["token"] == ["t"]
    assert findings_body["thread"]["threadKey"] == "vulnyard/gitlab/team/app"

    # The test message is a one-off, so it does not join any thread.
    test_path, test_body = seen[1]
    assert "messageReplyOption" not in test_path
    assert "thread" not in test_body


# --- good news (a repository that got fixed) ----------------------------------


def test_a_fixed_repository_is_announced() -> None:
    from app.services.notifications import build_resolved_message, is_resolved

    previous = {"critical": 2, "high": 5, "medium": 3, "low": 0, "unassigned": 0}
    now = DTMetrics()

    assert is_resolved(now, previous, "high") is True
    text = build_resolved_message(notification(metrics=now, previous=previous))["text"]
    assert "je zase čisté" in text
    assert "Od posledního skenu: kritické −2, vysoké −5, střední −3." in text
    assert "nehlásí žádné nálezy" in text
    # The good news lands in the repository's own thread, like everything else.
    assert build_resolved_message(notification(metrics=now, previous=previous))["thread"] == {
        "threadKey": "vulnyard/gitlab/team/app"
    }


def test_the_message_says_what_is_left_below_the_threshold() -> None:
    from app.services.notifications import build_resolved_message

    previous = {"critical": 1, "high": 2, "medium": 3, "low": 0, "unassigned": 0}
    now = DTMetrics(medium=3, low=1)

    text = build_resolved_message(notification(metrics=now, previous=previous))["text"]

    assert "Zbývá pod nastavenou hranicí: střední: 3 · nízké: 1." in text


@pytest.mark.parametrize(
    ("previous", "now", "minimum", "expected"),
    [
        # Was reportable, now is not: good news.
        ({"critical": 1, "high": 0, "medium": 0, "low": 0, "unassigned": 0}, DTMetrics(), "high", True),
        ({"critical": 0, "high": 3, "medium": 0, "low": 0, "unassigned": 0}, DTMetrics(medium=4), "high", True),
        # Never reached the threshold, so nothing was ever reported.
        ({"critical": 0, "high": 0, "medium": 9, "low": 0, "unassigned": 0}, DTMetrics(), "high", False),
        # Still reportable: that is the ordinary findings message, not this one.
        ({"critical": 2, "high": 0, "medium": 0, "low": 0, "unassigned": 0}, DTMetrics(critical=1), "high", False),
        # First scan of a clean repository is not news.
        (None, DTMetrics(), "high", False),
    ],
)
def test_when_the_good_news_message_applies(
    previous: dict[str, int] | None, now: DTMetrics, minimum: str, expected: bool
) -> None:
    from app.services.notifications import is_resolved

    assert is_resolved(now, previous, minimum) is expected


async def test_the_notifier_sends_the_good_news() -> None:
    notifier = RecordingNotifier()

    sent = await notifier.notify_findings(
        NotificationTarget(webhook_url=WEBHOOK, min_severity="high"),
        notification(
            metrics=DTMetrics(low=1),
            previous={"critical": 0, "high": 4, "medium": 0, "low": 1, "unassigned": 0},
        ),
    )

    assert sent is True
    assert "je zase čisté" in notifier.sent[0][1]["text"]
    await notifier.close()


async def test_a_repository_that_stays_clean_says_nothing() -> None:
    notifier = RecordingNotifier()

    sent = await notifier.notify_findings(
        NotificationTarget(webhook_url=WEBHOOK, min_severity="high"),
        notification(
            metrics=DTMetrics(medium=2),
            previous={"critical": 0, "high": 0, "medium": 2, "low": 0, "unassigned": 0},
        ),
    )

    assert sent is False
    assert notifier.sent == []
    await notifier.close()


def test_the_log_says_why_no_message_was_sent(scan_client: TestClient, caplog) -> None:  # noqa: ANN001
    """"Nothing arrived" has to be answerable from the log."""
    import logging

    notifier = RecordingNotifier()
    scan_client.app.state.worker._notifier = notifier  # noqa: SLF001 - wiring for the test
    _scanned(scan_client, notify_webhook_url=OTHER_WEBHOOK)
    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    # A scan that finds nothing worth reporting.
    dtrack.metrics_by_uuid = {"dt-10-main": DTMetrics(medium=2)}  # type: ignore[attr-defined]

    with caplog.at_level(logging.INFO, logger="app.services.queue"):
        _notify_first_job(scan_client)

    assert notifier.sent == []
    logged = [record.getMessage() for record in caplog.records]
    assert any(
        "No chat message for team/app@main" in message and "nothing at or above high" in message
        for message in logged
    ), logged


def test_yesterdays_snapshot_is_the_baseline_when_no_scan_has_set_one(
    scan_client: TestClient,
) -> None:
    """A repository fixed before the first delta-aware scan still gets good news.

    `projects.last_metrics` is empty for projects scanned by an older build, and
    without a fallback the very scan that sees the fix has nothing to compare to.
    """
    notifier = _attach_notifier(scan_client)
    _scanned(scan_client, notify_webhook_url=OTHER_WEBHOOK)
    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.metrics_by_uuid = {"dt-10-main": DTMetrics()}  # type: ignore[attr-defined]
    # No scan has written a baseline, but yesterday's snapshot knows about the findings.
    _run_sql(scan_client, "UPDATE projects SET last_metrics = NULL, last_metrics_at = NULL")
    _run_sql(
        scan_client,
        "INSERT INTO metric_snapshots (date, project_id, critical, high, medium, low,"
        " unassigned, components, vulnerable_components, suppressed)"
        " SELECT CURRENT_DATE - 1, id, 0, 2, 9, 2, 0, 129, 3, 0 FROM projects",
    )

    _notify_first_job(scan_client)

    assert [url for url, _ in notifier.sent] == [OTHER_WEBHOOK]
    assert "je zase čisté" in notifier.sent[0][1]["text"]


def test_without_a_snapshot_a_clean_first_scan_stays_quiet(scan_client: TestClient) -> None:
    """Nothing to compare against means we cannot claim an improvement."""
    notifier = _attach_notifier(scan_client)
    _scanned(scan_client, notify_webhook_url=OTHER_WEBHOOK)
    dtrack: FakeDependencyTrack = scan_client.app.state.dtrack
    dtrack.metrics_by_uuid = {"dt-10-main": DTMetrics()}  # type: ignore[attr-defined]
    _run_sql(scan_client, "UPDATE projects SET last_metrics = NULL, last_metrics_at = NULL")

    _notify_first_job(scan_client)

    assert notifier.sent == []
