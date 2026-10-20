# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Discovery of projects and branches of a target (SPEC 7.1).

Pure read-only logic shared by the preview endpoint and (from milestone 3) by
the scan runs; it never writes to the database.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch

from app.constants import (
    BRANCH_MODE_CUSTOM,
    BRANCH_MODE_DEFAULT,
    DEFAULT_MAX_BRANCHES,
    TARGET_KIND_GROUP,
)
from app.services.sources.base import RepositorySource, SourceBranch, SourceProject

logger = logging.getLogger(__name__)

# How many projects we ask for branches in parallel.
BRANCH_FETCH_CONCURRENCY = 5

GLOB_CHARACTERS = ("*", "?", "[")


@dataclass(frozen=True, slots=True)
class BranchSelection:
    """Branch selection of a target, or of one project that overrides it."""

    branch_mode: str = BRANCH_MODE_DEFAULT
    branch_patterns: tuple[str, ...] = ()
    include_default_branch: bool = True


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """The part of a target that drives discovery (a row or a preview request)."""

    kind: str
    source_ref: str
    include_subgroups: bool = True
    branch_mode: str = BRANCH_MODE_DEFAULT
    branch_patterns: tuple[str, ...] = ()
    include_default_branch: bool = True
    max_branches_per_project: int = DEFAULT_MAX_BRANCHES
    exclude_patterns: tuple[str, ...] = ()


@dataclass(slots=True)
class Note:
    """A translatable note about a discovery decision."""

    code: str
    params: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class DiscoveredBranch:
    branch: str
    is_default_branch: bool
    commit_sha: str | None = None


@dataclass(slots=True)
class DiscoveredProject:
    project: SourceProject
    branches: list[DiscoveredBranch] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)


@dataclass(slots=True)
class SkippedProject:
    project: SourceProject
    reason: Note


@dataclass(slots=True)
class DiscoveryResult:
    projects: list[DiscoveredProject] = field(default_factory=list)
    skipped: list[SkippedProject] = field(default_factory=list)
    warnings: list[Note] = field(default_factory=list)

    @property
    def branch_count(self) -> int:
        return sum(len(project.branches) for project in self.projects)


async def discover(
    source: RepositorySource,
    spec: TargetSpec,
    *,
    global_exclude_patterns: tuple[str, ...] = (),
    overrides: Mapping[str, BranchSelection] | None = None,
) -> DiscoveryResult:
    """Find the projects and branches a target would scan.

    `overrides` maps a project reference in the source to a branch selection
    that wins over the target's own (SPEC 6, `project_branch_overrides`).
    """
    result = DiscoveryResult()

    projects = await _list_projects(source, spec)
    exclude_patterns = tuple(spec.exclude_patterns) + tuple(global_exclude_patterns)

    candidates: list[SourceProject] = []
    for project in projects:
        skip = _skip_reason(project, exclude_patterns)
        if skip is not None:
            result.skipped.append(SkippedProject(project=project, reason=skip))
        else:
            candidates.append(project)

    discovered = await _expand_branches(source, spec, candidates, overrides or {})
    for item in discovered:
        if item.branches:
            result.projects.append(item)
        else:
            # Nothing to scan – report it as skipped with the reason we found.
            reason = item.notes[0] if item.notes else Note("discovery.skipped.no_branch")
            result.skipped.append(SkippedProject(project=item.project, reason=reason))

    return result


async def _list_projects(source: RepositorySource, spec: TargetSpec) -> list[SourceProject]:
    if spec.kind == TARGET_KIND_GROUP:
        return await source.list_group_projects(spec.source_ref, include_subgroups=spec.include_subgroups)
    return [await source.get_project(spec.source_ref)]


def _skip_reason(project: SourceProject, exclude_patterns: tuple[str, ...]) -> Note | None:
    """Why the project is not scanned at all (SPEC 7.1 step 3)."""
    if project.archived:
        return Note("discovery.skipped.archived")
    if project.empty_repo:
        return Note("discovery.skipped.empty_repo")
    pattern = matching_pattern(project.path_with_namespace, exclude_patterns)
    if pattern is not None:
        return Note("discovery.skipped.excluded_by_pattern", {"pattern": pattern})
    return None


def matching_pattern(path: str, patterns: tuple[str, ...] | list[str]) -> str | None:
    """The first glob pattern that matches the project path, if any."""
    for pattern in patterns:
        if pattern and fnmatch(path, pattern):
            return pattern
    return None


async def _expand_branches(
    source: RepositorySource,
    spec: TargetSpec,
    projects: list[SourceProject],
    overrides: Mapping[str, BranchSelection],
) -> list[DiscoveredProject]:
    """Resolve the branch selection for every project (SPEC 7.1 step 4)."""
    semaphore = asyncio.Semaphore(BRANCH_FETCH_CONCURRENCY)

    async def resolve(project: SourceProject) -> DiscoveredProject:
        async with semaphore:
            selection = overrides.get(project.ref) or selection_of(spec)
            return await _branches_for_project(source, spec, project, selection)

    return list(await asyncio.gather(*(resolve(project) for project in projects)))


def selection_of(spec: TargetSpec) -> BranchSelection:
    """Branch selection stored on the target itself."""
    return BranchSelection(
        branch_mode=spec.branch_mode,
        branch_patterns=tuple(spec.branch_patterns),
        include_default_branch=spec.include_default_branch,
    )


async def _branches_for_project(
    source: RepositorySource,
    spec: TargetSpec,
    project: SourceProject,
    selection: BranchSelection,
) -> DiscoveredProject:
    discovered = DiscoveredProject(project=project)

    if selection.branch_mode != BRANCH_MODE_CUSTOM:
        if not project.default_branch:
            discovered.notes.append(Note("discovery.skipped.no_default_branch"))
            return discovered
        branch = await source.get_branch(project.ref, project.default_branch)
        if branch is None:
            discovered.notes.append(
                Note("discovery.skipped.branch_not_found", {"branch": project.default_branch})
            )
            return discovered
        discovered.branches.append(
            DiscoveredBranch(branch=branch.name, is_default_branch=True, commit_sha=branch.commit_sha)
        )
        return discovered

    matched, notes = await _match_custom_branches(source, selection, project)
    discovered.notes.extend(notes)

    selected, trimmed = _apply_branch_limit(matched, spec.max_branches_per_project)
    if trimmed:
        discovered.notes.append(
            Note(
                "discovery.branches.trimmed",
                {"limit": spec.max_branches_per_project, "dropped": trimmed},
            )
        )
        logger.warning(
            "Branch limit %s reached for %s, %s branches dropped",
            spec.max_branches_per_project,
            project.path_with_namespace,
            trimmed,
        )

    discovered.branches = [
        DiscoveredBranch(
            branch=branch.name,
            is_default_branch=branch.name == project.default_branch,
            commit_sha=branch.commit_sha,
        )
        for branch in selected
    ]
    return discovered


async def _match_custom_branches(
    source: RepositorySource,
    selection: BranchSelection,
    project: SourceProject,
) -> tuple[list[SourceBranch], list[Note]]:
    """Branches matching the patterns, plus the default branch when wanted."""
    notes: list[Note] = []
    exact = [p for p in selection.branch_patterns if not any(c in p for c in GLOB_CHARACTERS)]
    globs = [p for p in selection.branch_patterns if any(c in p for c in GLOB_CHARACTERS)]

    matched: dict[str, SourceBranch] = {}

    # Exact names can be fetched one by one instead of listing every branch.
    for name in exact:
        branch = await source.get_branch(project.ref, name)
        if branch is None:
            # A pattern matching nothing is not an error (SPEC 7.1 step 4).
            notes.append(Note("discovery.branch.not_found", {"branch": name}))
        else:
            matched[branch.name] = branch

    if globs:
        all_branches = await source.list_branches(project.ref)
        for pattern in globs:
            hits = [branch for branch in all_branches if fnmatch(branch.name, pattern)]
            if not hits:
                notes.append(Note("discovery.branch.pattern_no_match", {"pattern": pattern}))
            for branch in hits:
                matched[branch.name] = branch

    if selection.include_default_branch and project.default_branch and project.default_branch not in matched:
        branch = await source.get_branch(project.ref, project.default_branch)
        if branch is not None:
            matched[branch.name] = branch

    return list(matched.values()), notes


def _apply_branch_limit(branches: list[SourceBranch], limit: int) -> tuple[list[SourceBranch], int]:
    """Keep the default branch first, then the most recently committed ones."""
    if limit <= 0 or len(branches) <= limit:
        return branches, 0

    def sort_key(branch: SourceBranch) -> tuple[int, float]:
        recency = branch.committed_date.timestamp() if branch.committed_date else 0.0
        return (0 if branch.is_default else 1, -recency)

    ordered = sorted(branches, key=sort_key)
    return ordered[:limit], len(ordered) - limit
