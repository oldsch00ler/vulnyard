# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""EPSS for findings reported under a GHSA or OSV id (SPEC 9.7).

Dependency-Track stores the mirrored EPSS scores only on NVD vulnerabilities.
A finding attributed through GitHub Advisories or OSV therefore has no EPSS of
its own, although its CVE alias has one - and with those sources enabled that
is most findings. The score is read from the NVD record of the alias instead.

Scores change about once a day, so they are cached for a day, including "no
score", so that a page load does not turn into one request per CVE.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import replace

from app.errors import AppError
from app.services.dtrack import DependencyTrackClient, DTFinding

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 24 * 3600
#: How many CVEs are asked about at once.
CONCURRENCY = 8

Score = tuple[float | None, float | None]

#: CVE id -> (expiry on the monotonic clock, score or None).
_cache: dict[str, tuple[float, Score | None]] = {}


def invalidate_cache() -> None:
    _cache.clear()


def cve_ids(finding: DTFinding) -> list[str]:
    ids = {finding.vuln_id, *finding.aliases}
    return sorted(value.upper() for value in ids if value.upper().startswith("CVE-"))


async def with_epss(dtrack: DependencyTrackClient, findings: list[DTFinding]) -> list[DTFinding]:
    """The findings, those without EPSS completed from their CVE alias."""
    wanted = {cve for finding in findings if finding.epss_score is None for cve in cve_ids(finding)}
    if not wanted:
        return findings
    scores = await _scores(dtrack, wanted)

    completed = []
    for finding in findings:
        if finding.epss_score is not None:
            completed.append(finding)
            continue
        # Several CVE aliases are rare; the highest score is the honest one.
        known = [scores[cve] for cve in cve_ids(finding) if scores.get(cve) and scores[cve][0] is not None]
        if not known:
            completed.append(finding)
            continue
        score, percentile = max(known, key=lambda item: item[0] or 0.0)
        completed.append(replace(finding, epss_score=score, epss_percentile=percentile))
    return completed


async def _scores(dtrack: DependencyTrackClient, cves: set[str]) -> dict[str, Score | None]:
    now = time.monotonic()
    result: dict[str, Score | None] = {}
    missing = []
    for cve in cves:
        entry = _cache.get(cve)
        if entry is not None and entry[0] > now:
            result[cve] = entry[1]
        else:
            missing.append(cve)
    if not missing:
        return result

    semaphore = asyncio.Semaphore(CONCURRENCY)
    failures = 0

    async def one(cve: str) -> None:
        nonlocal failures
        async with semaphore:
            try:
                score = await dtrack.nvd_epss(cve)
            except AppError:
                # Not cached: an unreachable Dependency-Track is asked again next time.
                failures += 1
                return
        result[cve] = score
        _cache[cve] = (time.monotonic() + CACHE_TTL_SECONDS, score)

    await asyncio.gather(*(one(cve) for cve in sorted(missing)))
    if failures:
        logger.warning("EPSS of %s of %s CVEs could not be read from Dependency-Track", failures, len(missing))
    return result
