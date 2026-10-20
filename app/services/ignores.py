# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Ignore rules: findings we have decided not to act on.

A rule names a vulnerability and, optionally, a component pattern
(`pkg:npm/express@5.*`), and holds either for one scan target or for everything
we scan. Dependency-Track can only suppress one finding at a time - per project,
component and vulnerability - so a rule is expanded here and applied finding by
finding. Suppression is pushed to DT rather than only hidden locally, because the
dashboard, the trend and the chat notifications all read DT's metrics.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import date

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import ANY_COMPONENT
from app.errors import AppError
from app.models import IgnoreApplication, IgnoreRule, Project, TargetProject
from app.services.dtrack import DependencyTrackClient, DTFinding

logger = logging.getLogger(__name__)

#: Comment written into the Dependency-Track analysis, so that somebody reading
#: it there knows where the suppression came from.
COMMENT_PREFIX = "Vulnyard"

#: Dependency-Track recomputes project metrics asynchronously, so after a change
#: we wait - briefly - for them to catch up. Everything downstream (the dashboard,
#: the trend, the chat notification) reads those metrics.
METRICS_SETTLE_ATTEMPTS = 3
METRICS_SETTLE_INTERVAL_SECONDS = 1.0


@dataclass(slots=True)
class IgnoreOutcome:
    """What applying the rules changed."""

    suppressed: int = 0
    reverted: int = 0
    failed: int = 0
    projects: int = 0
    #: Codes of the errors hit, for the log and the API response.
    errors: list[str] = field(default_factory=list)


def is_active(rule: IgnoreRule, *, today: date | None = None) -> bool:
    """A rule without an end date holds forever; otherwise up to and including it."""
    if rule.expires_on is None:
        return True
    return rule.expires_on >= (today or date.today())


def matches(rule: IgnoreRule, finding: DTFinding) -> bool:
    """Does this rule cover this finding?

    The vulnerability has to be the same one; the pattern then narrows the rule to
    some components. `*` (the default) means any component, which is what "ignore
    this vulnerability for anything here" needs.
    """
    if finding.vuln_id.strip().upper() != rule.vuln_id.strip().upper():
        return False
    pattern = (rule.purl_pattern or ANY_COMPONENT).strip()
    if pattern in ("", ANY_COMPONENT):
        return True
    # purl type and namespace are lower case by specification, but a human types
    # whatever they read in the UI.
    return fnmatch.fnmatchcase((finding.purl or "").lower(), pattern.lower())


def rule_comment(rule: IgnoreRule) -> str:
    """Analysis comment for Dependency-Track; says who suppressed it and why."""
    scope = "global" if rule.target_id is None else f"target {rule.target_id}"
    parts = [f"{COMMENT_PREFIX}: ignore rule #{rule.id} ({scope})"]
    if rule.purl_pattern and rule.purl_pattern != ANY_COMPONENT:
        parts.append(f"pattern {rule.purl_pattern}")
    if rule.expires_on:
        parts.append(f"until {rule.expires_on.isoformat()}")
    if rule.reason:
        parts.append(rule.reason)
    return " - ".join(parts)


async def active_rules(session: AsyncSession, *, today: date | None = None) -> list[IgnoreRule]:
    rows = await session.execute(select(IgnoreRule).order_by(IgnoreRule.id))
    return [rule for rule in rows.scalars() if is_active(rule, today=today)]


async def rules_per_project(
    session: AsyncSession, rules: list[IgnoreRule], project_ids: list[int]
) -> dict[int, list[IgnoreRule]]:
    """Which rules hold for which project: the global ones plus its targets'."""
    global_rules = [rule for rule in rules if rule.target_id is None]
    scoped = [rule for rule in rules if rule.target_id is not None]

    per_project: dict[int, list[IgnoreRule]] = {
        project_id: list(global_rules) for project_id in project_ids
    }
    if scoped and project_ids:
        target_ids = {rule.target_id for rule in scoped}
        rows = await session.execute(
            select(TargetProject.project_id, TargetProject.target_id).where(
                TargetProject.project_id.in_(project_ids),
                TargetProject.target_id.in_(target_ids),
            )
        )
        by_target: dict[int, list[IgnoreRule]] = {}
        for rule in scoped:
            by_target.setdefault(int(rule.target_id or 0), []).append(rule)
        for project_id, target_id in rows.all():
            per_project.setdefault(project_id, []).extend(by_target.get(target_id, []))

    # Deterministic order so that a finding covered by two rules always lands on
    # the same one.
    for project_id, found in per_project.items():
        per_project[project_id] = sorted({rule.id: rule for rule in found}.values(), key=lambda r: r.id)
    return per_project


def first_match(rules: list[IgnoreRule], finding: DTFinding) -> IgnoreRule | None:
    for rule in rules:
        if matches(rule, finding):
            return rule
    return None


async def apply_rules(
    session: AsyncSession,
    dtrack: DependencyTrackClient,
    *,
    project_ids: list[int] | None = None,
    today: date | None = None,
) -> IgnoreOutcome:
    """Bring Dependency-Track in line with the rules, both ways.

    Findings newly covered by a rule get suppressed; findings we suppressed before
    but that no rule covers any more (the rule was narrowed, or it expired) get
    their suppression taken back. Idempotent, so it can run after every scan.
    """
    outcome = IgnoreOutcome()
    rules = await active_rules(session, today=today)

    query = select(Project).where(Project.dt_project_uuid.is_not(None))
    if project_ids is not None:
        if not project_ids:
            return outcome
        query = query.where(Project.id.in_(project_ids))
    projects = list((await session.execute(query)).scalars())
    if not projects:
        return outcome

    per_project = await rules_per_project(session, rules, [project.id for project in projects])
    #: Projects whose metrics have to be recomputed once the changes are in.
    changed: set[str] = set()

    for project in projects:
        outcome.projects += 1
        project_rules = per_project.get(project.id, [])
        existing = await _applications_of(session, project.id)

        if not project_rules and not existing:
            continue

        try:
            # Suppressed findings are included: we have to see what we suppressed
            # earlier to be able to take it back.
            findings = await dtrack.project_findings(
                str(project.dt_project_uuid), suppressed=True
            )
        except AppError as error:
            outcome.failed += 1
            outcome.errors.append(error.code)
            logger.warning(
                "Ignore rules for %s@%s skipped: %s",
                project.path_with_namespace,
                project.branch,
                error.code,
            )
            continue

        wanted: dict[tuple[str, str], tuple[IgnoreRule, DTFinding]] = {}
        for finding in findings:
            if not finding.dt_component_uuid or not finding.dt_vulnerability_uuid:
                continue
            rule = first_match(project_rules, finding)
            if rule is not None:
                wanted[(finding.dt_component_uuid, finding.dt_vulnerability_uuid)] = (rule, finding)

        before = outcome.suppressed + outcome.reverted
        await _suppress_missing(session, dtrack, project, wanted, existing, outcome)
        await _revert_stale(session, dtrack, wanted, existing, outcome)
        if outcome.suppressed + outcome.reverted > before:
            changed.add(str(project.dt_project_uuid))

    await session.commit()
    # Waiting on each project in turn would add up over a big rule; the requests
    # are independent, so they go together.
    await asyncio.gather(*(settle_metrics(dtrack, uuid) for uuid in sorted(changed)))
    return outcome


async def settle_metrics(dtrack: DependencyTrackClient, project_uuid: str) -> None:
    """Wait, briefly, until Dependency-Track's metrics know about a suppression.

    `/metrics/project/{uuid}/refresh` only *requests* a recomputation, so reading
    the metrics straight after would still report what we just suppressed - and a
    chat notification would announce a vulnerability somebody just chose to ignore.
    Bounded on purpose: if it takes longer, the numbers are right again after the
    next scan or the daily pass, which beats holding the caller.
    """
    try:
        before = await dtrack.current_project_metrics(project_uuid)
        await dtrack.refresh_project_metrics(project_uuid)
    except AppError as error:
        logger.warning("Could not refresh metrics of %s: %s", project_uuid, error.code)
        return
    if before is None:
        # Nothing to compare against, so waiting would only cost time.
        return

    for _ in range(METRICS_SETTLE_ATTEMPTS):
        await asyncio.sleep(METRICS_SETTLE_INTERVAL_SECONDS)
        try:
            current = await dtrack.current_project_metrics(project_uuid)
        except AppError:
            return
        if current is None or current.suppressed != before.suppressed:
            return
    logger.info("Metrics of %s have not caught up with the suppression yet", project_uuid)


async def revert_rule(
    session: AsyncSession, dtrack: DependencyTrackClient, rule: IgnoreRule
) -> IgnoreOutcome:
    """Take back every suppression this rule made, so it can be deleted."""
    outcome = IgnoreOutcome()
    rows = await session.execute(
        select(IgnoreApplication).where(IgnoreApplication.rule_id == rule.id)
    )
    touched: set[str] = set()
    for application in rows.scalars():
        if await _unsuppress(dtrack, application, outcome):
            touched.add(application.dt_project_uuid)
            await session.delete(application)
    await session.commit()
    await asyncio.gather(*(settle_metrics(dtrack, uuid) for uuid in sorted(touched)))
    return outcome


async def revert_expired(
    session: AsyncSession, dtrack: DependencyTrackClient, *, today: date | None = None
) -> IgnoreOutcome:
    """Rules past their end date stop holding; the rule row stays as history."""
    outcome = IgnoreOutcome()
    rows = await session.execute(select(IgnoreRule).where(IgnoreRule.expires_on.is_not(None)))
    for rule in rows.scalars():
        if is_active(rule, today=today):
            continue
        result = await revert_rule(session, dtrack, rule)
        outcome.reverted += result.reverted
        outcome.failed += result.failed
        outcome.errors.extend(result.errors)
    return outcome


# --- internals ----------------------------------------------------------------


async def _applications_of(
    session: AsyncSession, project_id: int
) -> dict[tuple[str, str], IgnoreApplication]:
    rows = await session.execute(
        select(IgnoreApplication).where(IgnoreApplication.project_id == project_id)
    )
    return {
        (application.dt_component_uuid, application.dt_vulnerability_uuid): application
        for application in rows.scalars()
    }


async def _suppress_missing(
    session: AsyncSession,
    dtrack: DependencyTrackClient,
    project: Project,
    wanted: dict[tuple[str, str], tuple[IgnoreRule, DTFinding]],
    existing: dict[tuple[str, str], IgnoreApplication],
    outcome: IgnoreOutcome,
) -> None:
    for key, (rule, finding) in wanted.items():
        known = existing.get(key)
        if known is not None and known.rule_id == rule.id and finding.suppressed:
            continue
        try:
            await dtrack.set_analysis(
                project_uuid=str(project.dt_project_uuid),
                component_uuid=finding.dt_component_uuid or "",
                vulnerability_uuid=finding.dt_vulnerability_uuid or "",
                suppressed=True,
                analysis_state=rule.analysis_state,
                comment=rule_comment(rule),
            )
        except AppError as error:
            outcome.failed += 1
            outcome.errors.append(error.code)
            logger.warning(
                "Could not suppress %s in %s: %s",
                finding.vuln_id,
                project.path_with_namespace,
                error.code,
            )
            continue

        if known is None:
            session.add(
                IgnoreApplication(
                    rule_id=rule.id,
                    project_id=project.id,
                    dt_project_uuid=str(project.dt_project_uuid),
                    dt_component_uuid=finding.dt_component_uuid or "",
                    dt_vulnerability_uuid=finding.dt_vulnerability_uuid or "",
                    purl=finding.purl,
                )
            )
        else:
            known.rule_id = rule.id
            known.purl = finding.purl
        outcome.suppressed += 1
        logger.info(
            "Suppressed %s in %s (%s) by rule #%s",
            finding.vuln_id,
            project.path_with_namespace,
            finding.purl or finding.component_name,
            rule.id,
        )


async def _revert_stale(
    session: AsyncSession,
    dtrack: DependencyTrackClient,
    wanted: dict[tuple[str, str], tuple[IgnoreRule, DTFinding]],
    existing: dict[tuple[str, str], IgnoreApplication],
    outcome: IgnoreOutcome,
) -> None:
    for key, application in existing.items():
        if key in wanted:
            continue
        if await _unsuppress(dtrack, application, outcome):
            await session.delete(application)


async def _unsuppress(
    dtrack: DependencyTrackClient, application: IgnoreApplication, outcome: IgnoreOutcome
) -> bool:
    try:
        await dtrack.set_analysis(
            project_uuid=application.dt_project_uuid,
            component_uuid=application.dt_component_uuid,
            vulnerability_uuid=application.dt_vulnerability_uuid,
            suppressed=False,
            analysis_state="NOT_SET",
            comment=f"{COMMENT_PREFIX}: ignore rule no longer holds",
        )
    except AppError as error:
        outcome.failed += 1
        outcome.errors.append(error.code)
        logger.warning("Could not take back a suppression: %s", error.code)
        return False
    outcome.reverted += 1
    return True
