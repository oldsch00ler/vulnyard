# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Withdrawn advisories (SPEC 9.8).

GitHub sometimes withdraws an advisory - it was a mistake, a duplicate, not a
vulnerability after all. Dependency-Track 4.x skips a withdrawn advisory when it
mirrors, but keeps the copy it already has and goes on matching it, so the
finding would stay in our counts and notifications forever.

The application therefore asks the upstream itself: OSV for GHSA and OSV ids
(it carries `withdrawn`), the CVE Program's API for CVE ids (OSV drops a
rejected CVE, and a missing record says nothing). A withdrawn advisory gets an
automatic global ignore rule, and the usual ignore machinery suppresses it in
Dependency-Track. A CVE alias of a withdrawn GHSA is left alone unless the CVE
itself is rejected - somebody else may still stand behind it.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.constants import ANALYSIS_FALSE_POSITIVE, ANY_COMPONENT, IGNORE_ORIGIN_WITHDRAWN
from app.errors import AppError
from app.masking import mask_secrets
from app.models import AdvisoryStatus, IgnoreRule, Project
from app.services.dtrack import DependencyTrackClient, DTFinding
from app.services.ignores import revert_rule

logger = logging.getLogger(__name__)

#: Dependency-Track sources whose ids the upstreams below know.
CHECKED_SOURCES = frozenset({"GITHUB", "OSV", "NVD"})
#: The daily pass asks again about everything checked before this; a little
#: under a day, so that yesterday's check never just misses the cut.
RECHECK_INTERVAL = timedelta(hours=20)
#: Both APIs are free public services; be polite.
MAX_PARALLEL_REQUESTS = 4
REQUEST_TIMEOUT_SECONDS = 15.0


@dataclass(slots=True)
class WithdrawnOutcome:
    checked: int = 0
    failed: int = 0
    rules_added: int = 0
    rules_removed: int = 0


class AdvisoryLookup:
    """Asks OSV and the CVE Program whether an advisory was withdrawn."""

    def __init__(self, settings: Settings) -> None:
        self._osv_url = settings.osv_api_url.rstrip("/")
        self._cve_url = settings.cve_api_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=settings.ca_bundle or True,
            follow_redirects=True,
        )

    @property
    def enabled(self) -> bool:
        return bool(self._osv_url or self._cve_url)

    async def close(self) -> None:
        await self._client.aclose()

    def handles(self, vuln_id: str, source: str) -> bool:
        if source.upper() not in CHECKED_SOURCES:
            return False
        if _is_cve(vuln_id):
            return bool(self._cve_url)
        return bool(self._osv_url)

    async def withdrawn_at(self, vuln_id: str) -> datetime | None:
        """When the advisory was withdrawn, or None if it stands.

        Raises httpx.HTTPError or ValueError when the upstream cannot answer;
        an unknown id is an answer ("not withdrawn"), not an error.
        """
        if _is_cve(vuln_id):
            return await self._cve_rejected_at(vuln_id.strip().upper())
        return await self._osv_withdrawn_at(_osv_id(vuln_id))

    async def _osv_withdrawn_at(self, vuln_id: str) -> datetime | None:
        response = await self._client.get(f"{self._osv_url}/v1/vulns/{quote(vuln_id, safe='')}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return parse_osv(response.json())

    async def _cve_rejected_at(self, cve_id: str) -> datetime | None:
        response = await self._client.get(f"{self._cve_url}/cve/{quote(cve_id, safe='')}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return parse_cve_record(response.json())


def parse_osv(payload: Any) -> datetime | None:
    """`withdrawn` of an OSV record."""
    if not isinstance(payload, dict):
        raise ValueError("unexpected OSV record")
    return _datetime(payload.get("withdrawn"))


def parse_cve_record(payload: Any) -> datetime | None:
    """When a CVE record was rejected (`cveMetadata.state` REJECTED)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("cveMetadata"), dict):
        raise ValueError("unexpected CVE record")
    metadata = payload["cveMetadata"]
    if str(metadata.get("state") or "").upper() != "REJECTED":
        return None
    return (
        _datetime(metadata.get("dateRejected"))
        or _datetime(metadata.get("dateUpdated"))
        or datetime.now(UTC)
    )


async def sync_withdrawn(
    session: AsyncSession,
    dtrack: DependencyTrackClient,
    lookup: AdvisoryLookup,
    *,
    project_ids: list[int] | None = None,
    recheck: bool = True,
    now: datetime | None = None,
) -> WithdrawnOutcome:
    """Look up the advisories of our findings and keep the automatic rules in line.

    After a scan only ids never seen before are looked up (`recheck=False`);
    the daily pass asks about all of them again, because an advisory can be
    withdrawn - or restored - at any time. Applying the rules to Dependency-Track
    is left to the caller, which runs the ignore rules right after anyway.
    """
    outcome = WithdrawnOutcome()
    if not lookup.enabled:
        return outcome
    now = now or datetime.now(UTC)

    candidates = await _candidate_ids(session, dtrack, lookup, project_ids)
    if not candidates:
        return outcome

    rows = await session.execute(
        select(AdvisoryStatus).where(AdvisoryStatus.vuln_id.in_(list(candidates)))
    )
    known = {status.vuln_id: status for status in rows.scalars()}
    due = [
        key
        for key in sorted(candidates)
        if key not in known or (recheck and known[key].checked_at <= now - RECHECK_INTERVAL)
    ]

    semaphore = asyncio.Semaphore(MAX_PARALLEL_REQUESTS)
    errors: list[str] = []

    async def one(key: str) -> tuple[str, datetime | None] | None:
        async with semaphore:
            try:
                return key, await lookup.withdrawn_at(candidates[key])
            except (httpx.HTTPError, ValueError) as error:
                errors.append(mask_secrets(str(error) or type(error).__name__))
                return None

    for result in await asyncio.gather(*(one(key) for key in due)):
        if result is None:
            outcome.failed += 1
            continue
        key, withdrawn_at = result
        outcome.checked += 1
        status = known.get(key)
        if status is None:
            status = AdvisoryStatus(vuln_id=key, dismissed=False)
            session.add(status)
            known[key] = status
        elif withdrawn_at is None:
            # Restored upstream: a later withdrawal is a new decision again.
            status.dismissed = False
        status.withdrawn_at = withdrawn_at
        status.checked_at = now
        if withdrawn_at is not None:
            logger.info("Advisory %s was withdrawn upstream on %s", key, withdrawn_at.date())
    await session.commit()

    if errors:
        # One line, not one per id: an unreachable upstream fails them all.
        logger.warning(
            "Withdrawn advisory lookup failed for %s ids, the last known state stays: %s",
            len(errors),
            errors[0],
        )

    await _reconcile_rules(session, dtrack, outcome)
    return outcome


async def dismiss(session: AsyncSession, rule: IgnoreRule) -> None:
    """An automatic rule was deleted by hand; do not make it again."""
    if rule.origin != IGNORE_ORIGIN_WITHDRAWN:
        return
    status = await session.get(AdvisoryStatus, rule.vuln_id)
    if status is not None:
        status.dismissed = True


async def withdrawn_dates(session: AsyncSession, vuln_ids: list[str]) -> dict[str, datetime]:
    """Withdrawal dates by upper-case id, for showing next to the rules."""
    if not vuln_ids:
        return {}
    rows = await session.execute(
        select(AdvisoryStatus).where(
            AdvisoryStatus.vuln_id.in_([vuln_id.upper() for vuln_id in vuln_ids]),
            AdvisoryStatus.withdrawn_at.is_not(None),
        )
    )
    return {status.vuln_id: status.withdrawn_at for status in rows.scalars() if status.withdrawn_at}


# --- internals ----------------------------------------------------------------


async def _candidate_ids(
    session: AsyncSession,
    dtrack: DependencyTrackClient,
    lookup: AdvisoryLookup,
    project_ids: list[int] | None,
) -> dict[str, str]:
    """Vulnerability ids of our findings worth asking about: upper case -> as DT has it."""
    query = select(Project).where(Project.dt_project_uuid.is_not(None))
    if project_ids is not None:
        if not project_ids:
            return {}
        query = query.where(Project.id.in_(project_ids))
    projects = list((await session.execute(query)).scalars())

    candidates: dict[str, str] = {}
    for project in projects:
        try:
            # Suppressed ones too: a withdrawn advisory we already suppressed has
            # to be noticed when it is restored.
            findings: list[DTFinding] = await dtrack.project_findings(
                str(project.dt_project_uuid), suppressed=True
            )
        except AppError as error:
            logger.warning(
                "Withdrawn advisories of %s@%s not checked: %s",
                project.path_with_namespace,
                project.branch,
                error.code,
            )
            continue
        for finding in findings:
            if lookup.handles(finding.vuln_id, finding.source):
                candidates.setdefault(finding.vuln_id.strip().upper(), finding.vuln_id.strip())
    return candidates


async def _reconcile_rules(
    session: AsyncSession, dtrack: DependencyTrackClient, outcome: WithdrawnOutcome
) -> None:
    """One global rule per withdrawn advisory; none for one that stands again."""
    withdrawn = {
        status.vuln_id
        for status in (
            await session.execute(
                select(AdvisoryStatus).where(
                    AdvisoryStatus.withdrawn_at.is_not(None),
                    AdvisoryStatus.dismissed.is_(False),
                )
            )
        ).scalars()
    }
    global_rules = list(
        (
            await session.execute(
                select(IgnoreRule).where(
                    IgnoreRule.target_id.is_(None), IgnoreRule.purl_pattern == ANY_COMPONENT
                )
            )
        ).scalars()
    )
    covered = {rule.vuln_id.upper() for rule in global_rules}

    for rule in global_rules:
        if rule.origin == IGNORE_ORIGIN_WITHDRAWN and rule.vuln_id.upper() not in withdrawn:
            await revert_rule(session, dtrack, rule)
            await session.delete(rule)
            outcome.rules_removed += 1
            logger.info("Advisory %s stands again; its automatic ignore rule was removed", rule.vuln_id)

    for vuln_id in sorted(withdrawn - covered):
        # Not via the analysis state the UI offers by default: a withdrawn
        # advisory is a false positive, not "does not affect us".
        session.add(
            IgnoreRule(
                vuln_id=vuln_id,
                purl_pattern=ANY_COMPONENT,
                target_id=None,
                analysis_state=ANALYSIS_FALSE_POSITIVE,
                reason="",
                origin=IGNORE_ORIGIN_WITHDRAWN,
            )
        )
        outcome.rules_added += 1
        logger.info("Advisory %s is withdrawn; added an automatic ignore rule", vuln_id)
    await session.commit()


def _is_cve(vuln_id: str) -> bool:
    return vuln_id.strip().upper().startswith("CVE-")


def _osv_id(vuln_id: str) -> str:
    """OSV ids are case-sensitive; a GHSA id has a lower-case tail."""
    cleaned = vuln_id.strip()
    if cleaned.upper().startswith("GHSA-"):
        return "GHSA-" + cleaned[5:].lower()
    return cleaned


def _datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
