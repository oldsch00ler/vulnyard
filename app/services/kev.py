# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""CISA catalog of Known Exploited Vulnerabilities (KEV).

Vulnerabilities attackers are known to use, keyed by CVE id. The catalog is a
public JSON file updated a few times a week; it is fetched lazily, at most once
a day, and kept in memory. When it cannot be fetched the last good copy stays
in use, and without any copy the threats page simply works without it - an
installation without internet access sets KEV_FEED_URL to an empty value.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx

from app.config import Settings
from app.masking import mask_secrets

logger = logging.getLogger(__name__)

#: A successful copy is fresh for a day; CISA adds entries a few times a week.
REFRESH_INTERVAL = timedelta(hours=24)
#: After a failure, try again sooner than a day but not on every page load.
RETRY_INTERVAL = timedelta(hours=1)
REQUEST_TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True, slots=True)
class KevEntry:
    """One known exploited vulnerability."""

    cve_id: str
    name: str = ""
    vendor: str = ""
    product: str = ""
    date_added: date | None = None
    #: Deadline US federal agencies have for fixing it; a useful urgency hint.
    due_date: date | None = None
    #: CISA knows of ransomware campaigns using it.
    ransomware: bool = False
    required_action: str = ""


@dataclass(frozen=True, slots=True)
class KevStatus:
    """What the threats page says about the catalog."""

    enabled: bool
    available: bool
    count: int = 0
    fetched_at: datetime | None = None
    released_at: datetime | None = None
    #: Set when the last attempt failed; the previous copy may still be in use.
    error_code: str | None = None


class KevCatalog:
    """The catalog, fetched on demand and refreshed daily."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._url = settings.kev_feed_url
        self._entries: dict[str, KevEntry] = {}
        self._fetched_at: datetime | None = None
        self._released_at: datetime | None = None
        self._attempted_at: datetime | None = None
        self._error_code: str | None = None
        self._lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=settings.ca_bundle or True,
            follow_redirects=True,
        )

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    async def close(self) -> None:
        await self._client.aclose()

    async def entries(self) -> dict[str, KevEntry]:
        """Entries by upper-case CVE id; refreshed first when due."""
        if self.enabled and self._due():
            async with self._lock:
                # Another request may have refreshed it while we waited.
                if self._due():
                    await self._refresh()
        return self._entries

    def status(self) -> KevStatus:
        return KevStatus(
            enabled=self.enabled,
            available=bool(self._entries),
            count=len(self._entries),
            fetched_at=self._fetched_at,
            released_at=self._released_at,
            error_code=self._error_code,
        )

    def _due(self) -> bool:
        now = datetime.now(UTC)
        if self._attempted_at is None:
            return True
        if self._error_code is not None:
            return now - self._attempted_at >= RETRY_INTERVAL
        return now - self._attempted_at >= REFRESH_INTERVAL

    async def _refresh(self) -> None:
        self._attempted_at = datetime.now(UTC)
        try:
            response = await self._client.get(self._url)
            response.raise_for_status()
            entries, released = parse_catalog(response.json())
        except (httpx.HTTPError, ValueError) as error:
            self._error_code = "kev.unavailable"
            logger.warning(
                "Known exploited vulnerabilities catalog unavailable, %s: %s",
                "keeping the previous copy" if self._entries else "the threats page works without it",
                mask_secrets(str(error) or type(error).__name__),
            )
            return

        if not entries:
            # An empty answer is a broken download, not good news.
            self._error_code = "kev.unavailable"
            logger.warning("Known exploited vulnerabilities catalog was empty; keeping the previous copy")
            return

        self._entries = entries
        self._released_at = released
        self._fetched_at = self._attempted_at
        self._error_code = None
        logger.info("Known exploited vulnerabilities catalog loaded: %s entries", len(entries))


def parse_catalog(payload: Any) -> tuple[dict[str, KevEntry], datetime | None]:
    """Entries by CVE id and the release time of the catalog."""
    if not isinstance(payload, dict):
        raise ValueError("unexpected catalog shape")
    items = payload.get("vulnerabilities")
    if not isinstance(items, list):
        raise ValueError("catalog has no vulnerabilities list")

    entries: dict[str, KevEntry] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            name=str(item.get("vulnerabilityName") or ""),
            vendor=str(item.get("vendorProject") or ""),
            product=str(item.get("product") or ""),
            date_added=_date(item.get("dateAdded")),
            due_date=_date(item.get("dueDate")),
            ransomware=str(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
            required_action=str(item.get("requiredAction") or ""),
        )
    return entries, _datetime(payload.get("dateReleased"))


def _date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def _datetime(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
