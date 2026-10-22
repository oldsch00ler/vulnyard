# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Current threats: the vulnerabilities of our projects that need attention first.

Severity says how bad a vulnerability would be; it does not say whether anybody
is using it. A threat is a vulnerability that is

* known to be exploited (it is in the CISA KEV catalog),
* likely to be exploited soon (EPSS at or above a threshold), or
* new in our projects and critical or high.

They are ordered by that evidence: exploited first (ransomware use first among
those), then by EPSS, severity and how recent it is.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.services.kev import KevEntry
from app.services.vulnerabilities import GroupedVulnerability

EXPLOITED = "exploited"
LIKELY = "likely"
NEW = "new"
REASONS = (EXPLOITED, LIKELY, NEW)

#: EPSS is a probability of exploitation in the next 30 days; 10 % puts a
#: vulnerability roughly into the top few percent of all CVEs.
DEFAULT_EPSS_THRESHOLD = 0.1
DEFAULT_NEW_DAYS = 7
#: "New" alone is not a threat; new and serious is.
NEW_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


@dataclass(frozen=True, slots=True)
class Threat:
    vulnerability: GroupedVulnerability
    reasons: tuple[str, ...]
    cve_ids: tuple[str, ...]
    kev: KevEntry | None = None


def cve_ids(vulnerability: GroupedVulnerability) -> tuple[str, ...]:
    """CVE ids of a vulnerability: its own id and those among its aliases.

    The KEV catalog knows CVEs only, while Dependency-Track often reports a
    GHSA or OSV id with the CVE as an alias.
    """
    ids = {vulnerability.vuln_id, *vulnerability.aliases}
    return tuple(sorted(value.upper() for value in ids if value.upper().startswith("CVE-")))


def select(
    vulnerabilities: list[GroupedVulnerability],
    kev: dict[str, KevEntry],
    *,
    now: datetime,
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD,
    new_days: int = DEFAULT_NEW_DAYS,
) -> list[Threat]:
    """The threats among the vulnerabilities, most urgent first."""
    new_since = now - timedelta(days=new_days)
    threats: list[Threat] = []
    for vulnerability in vulnerabilities:
        cves = cve_ids(vulnerability)
        entry = next((kev[cve] for cve in cves if cve in kev), None)

        reasons: list[str] = []
        if entry is not None:
            reasons.append(EXPLOITED)
        if vulnerability.epss_score is not None and vulnerability.epss_score >= epss_threshold:
            reasons.append(LIKELY)
        first_seen = vulnerability.first_seen
        if (
            first_seen is not None
            and first_seen >= new_since
            and vulnerability.severity.upper() in NEW_SEVERITIES
        ):
            reasons.append(NEW)

        if reasons:
            threats.append(
                Threat(vulnerability=vulnerability, reasons=tuple(reasons), cve_ids=cves, kev=entry)
            )

    threats.sort(key=_urgency)
    return threats


def _urgency(threat: Threat) -> tuple[int, int, float, int, float, str]:
    vulnerability = threat.vulnerability
    first_seen = vulnerability.first_seen
    return (
        0 if threat.kev is not None else 1,
        0 if threat.kev is not None and threat.kev.ransomware else 1,
        -(vulnerability.epss_score or 0.0),
        vulnerability.severity_rank,
        -(first_seen.timestamp() if first_seen else 0.0),
        vulnerability.vuln_id,
    )
