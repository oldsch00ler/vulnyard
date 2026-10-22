# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""In-memory RepositorySource used by the tests (no network access)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime

from app.errors import AppError
from app.services.dtrack import (
    DTAffectedProject,
    DTFeatures,
    DTFinding,
    DTGroupedVulnerability,
    DTMetrics,
    DTProject,
    parse_version,
)
from app.services.sources.base import (
    RepositorySource,
    SourceBranch,
    SourceGroup,
    SourceMember,
    SourceProject,
)


def project(
    ref: str,
    path: str,
    *,
    default_branch: str | None = "main",
    archived: bool = False,
    empty_repo: bool = False,
) -> SourceProject:
    return SourceProject(
        ref=ref,
        path_with_namespace=path,
        name=path.rsplit("/", 1)[-1],
        web_url=f"https://git.example.com/{path}",
        default_branch=default_branch,
        archived=archived,
        empty_repo=empty_repo,
    )


def member(name: str, username: str, access_level: int = 40) -> SourceMember:
    return SourceMember(
        name=name,
        username=username,
        access_level=access_level,
        web_url=f"https://git.example.com/{username}",
        state="active",
    )


def branch(
    name: str, *, is_default: bool = False, days_ago: int = 0, sha: str | None = None
) -> SourceBranch:
    return SourceBranch(
        name=name,
        commit_sha=sha or f"{abs(hash(name)):040x}"[:40],
        committed_date=datetime(2026, 1, 1, tzinfo=UTC).replace(day=max(1, 28 - days_ago)),
        is_default=is_default,
    )


class FakeSource(RepositorySource):
    """Source with a fixed set of groups, projects and branches."""

    name = "gitlab"

    def __init__(
        self,
        projects: list[SourceProject] | None = None,
        branches: dict[str, list[SourceBranch]] | None = None,
        groups: list[SourceGroup] | None = None,
    ) -> None:
        self._projects = projects or []
        self._branches = branches or {}
        self._groups = groups or [SourceGroup(ref="1", path="team", name="Team")]
        self.closed = False
        self.maintainers: dict[str, list[SourceMember]] = {}
        # Call counters, so the tests can assert we do not hammer the API.
        self.list_branches_calls = 0
        self.get_branch_calls = 0

    async def close(self) -> None:
        self.closed = True

    async def version(self) -> str | None:
        return "17.11.1"

    async def search_groups(self, search: str, limit: int = 20) -> list[SourceGroup]:
        return [group for group in self._groups if search.lower() in group.path.lower()][:limit]

    async def get_group(self, ref: str) -> SourceGroup:
        return next(group for group in self._groups if group.ref == ref)

    async def list_group_projects(self, ref: str, *, include_subgroups: bool) -> list[SourceProject]:
        return list(self._projects)

    async def search_projects(self, search: str, limit: int = 20) -> list[SourceProject]:
        return [p for p in self._projects if search.lower() in p.path_with_namespace.lower()][:limit]

    async def get_project(self, ref: str) -> SourceProject:
        return next(p for p in self._projects if p.ref == ref)

    async def list_branches(self, project_ref: str, search: str | None = None) -> list[SourceBranch]:
        self.list_branches_calls += 1
        branches = self._branches.get(project_ref, [])
        if search:
            branches = [b for b in branches if search in b.name]
        return list(branches)

    async def get_branch(self, project_ref: str, branch_name: str) -> SourceBranch | None:
        self.get_branch_calls += 1
        for candidate in self._branches.get(project_ref, []):
            if candidate.name == branch_name:
                return candidate
        return None

    async def list_maintainers(self, project_ref: str) -> list[SourceMember]:
        return list(self.maintainers.get(project_ref, []))

    def clone_url(self, project: SourceProject) -> str:
        return f"https://oauth2:token@git.example.com/{project.path_with_namespace}.git"

    def web_url(self, project: SourceProject, branch_name: str | None = None) -> str:
        return project.web_url if not branch_name else f"{project.web_url}/-/tree/{branch_name}"


class FakeSourceProvider:
    """Hands out fake sources and records which credentials were asked for.

    Mirrors app.services.sources.SourceProvider closely enough for the API and
    the worker, so tests can assert that a target's own token was used.
    """

    def __init__(self, default: "FakeSource", settings: object | None = None) -> None:
        self.default = default
        self.settings = settings
        #: Per credentials key, so a test can give another instance its own fake.
        self.by_token: dict[str, FakeSource] = {}
        self.requested: list[tuple[str, str]] = []
        self.closed = False

    def credentials_for(self, target: object | None):  # noqa: ANN201 - SourceCredentials
        from app.services.sources import SourceCredentials

        url = getattr(target, "source_url", None) or "https://git.example.com"
        token = getattr(target, "source_token", None) or "glpat-environment-token"
        return SourceCredentials(url=url, token=token)

    def get(self, credentials):  # noqa: ANN001, ANN201
        if credentials is None:
            from app.errors import SourceNotConfiguredError

            raise SourceNotConfiguredError("source.not_configured")
        self.requested.append((credentials.url, credentials.token))
        return self.by_token.get(credentials.token, self.default)

    def for_target(self, target: object):  # noqa: ANN201
        return self.get(self.credentials_for(target))

    def global_source(self):  # noqa: ANN201
        return self.get(self.credentials_for(None))

    async def close(self) -> None:
        self.closed = True


@dataclass
class UploadCall:
    """One recorded BOM upload."""

    project_name: str
    project_version: str
    bom: bytes
    parent_uuid: str | None
    is_latest: bool
    tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalysisCall:
    """One PUT /v1/analysis the code under test made."""

    project_uuid: str
    component_uuid: str
    vulnerability_uuid: str
    suppressed: bool
    analysis_state: str | None = None
    comment: str | None = None


class FakeDependencyTrack:
    """Dependency-Track stand-in recording what the scanner sent."""

    def __init__(self, *, version: str = "4.13.6", lookup_uuid: str = "dt-uuid-1") -> None:
        self._features = DTFeatures(version=version, version_tuple=parse_version(version))
        self._lookup_uuid = lookup_uuid
        # Read side: what the instance would report back.
        self.projects: list[DTProject] = []
        self.findings: dict[str, list[DTFinding]] = {}
        self.grouped: list[DTGroupedVulnerability] = []
        self.affected: dict[str, list[DTAffectedProject]] = {}
        self.history: dict[str, list[DTMetrics]] = {}
        self.list_projects_calls = 0
        self.uploads: list[UploadCall] = []
        self.tag_merges: list[tuple[str, tuple[str, ...]]] = []
        self.refreshed: list[str] = []
        # Suppressions written through PUT /v1/analysis, newest last.
        self.analyses: list[AnalysisCall] = []
        self.analysis_fails = False
        self.collection_projects: list[str] = []
        self.existing_tags: tuple[str, ...] = ()
        self.closed = False

    @property
    def features(self) -> DTFeatures:
        return self._features

    async def detect_features(self) -> DTFeatures:
        return self._features

    async def close(self) -> None:
        self.closed = True

    async def upload_bom(
        self,
        *,
        project_name: str,
        project_version: str,
        bom: bytes,
        parent_uuid: str | None = None,
        is_latest: bool = False,
        tags: tuple[str, ...] = (),
    ) -> str:
        self.uploads.append(
            UploadCall(
                project_name=project_name,
                project_version=project_version,
                bom=bom,
                parent_uuid=parent_uuid,
                is_latest=is_latest,
                tags=tags,
            )
        )
        return "token-1"

    async def wait_for_processing(self, token: str, **_kwargs: object) -> None:
        return None

    async def is_token_processing(self, token: str) -> bool:
        return False

    async def lookup_project(self, name: str, version: str) -> DTProject:
        return DTProject(uuid=self._lookup_uuid, name=name, version=version, tags=self.existing_tags)

    async def merge_project_tags(self, project: DTProject, tags: tuple[str, ...]) -> tuple[str, ...]:
        merged = tuple(dict.fromkeys((*project.tags, *tags)))
        self.tag_merges.append((project.uuid, merged))
        return merged

    async def refresh_project_metrics(self, uuid: str) -> None:
        self.refreshed.append(uuid)

    async def refresh_project_metrics_and_wait(self, uuid: str, **_kwargs: object) -> bool:
        self.refreshed.append(uuid)
        return True

    async def set_analysis(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        suppressed: bool,
        analysis_state: str | None = None,
        comment: str | None = None,
    ) -> None:
        if self.analysis_fails:
            raise AppError("dtrack.http_error", status_code=502, status=502)
        self.analyses.append(
            AnalysisCall(
                project_uuid=project_uuid,
                component_uuid=component_uuid,
                vulnerability_uuid=vulnerability_uuid,
                suppressed=suppressed,
                analysis_state=analysis_state,
                comment=comment,
            )
        )
        # Keep the read side honest: a suppressed finding reports as suppressed.
        for uuid, findings in self.findings.items():
            if uuid != project_uuid:
                continue
            self.findings[uuid] = [
                replace(finding, suppressed=suppressed)
                if finding.dt_component_uuid == component_uuid
                and finding.dt_vulnerability_uuid == vulnerability_uuid
                else finding
                for finding in findings
            ]

    async def ensure_collection_project(self, name: str, *, tags: tuple[str, ...] = ()) -> DTProject:
        self.collection_projects.append(name)
        return DTProject(uuid=f"parent-{len(self.collection_projects)}", name=name, tags=tags)

    # --- read side -----------------------------------------------------------

    async def list_projects(self, *, page_size: int = 100, max_pages: int = 50) -> list[DTProject]:
        self.list_projects_calls += 1
        return list(self.projects)

    async def project_findings(self, uuid: str, *, suppressed: bool = False) -> list[DTFinding]:
        findings = self.findings.get(uuid, [])
        return [f for f in findings if suppressed or not f.suppressed]

    async def grouped_findings(
        self,
        *,
        severity: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> tuple[list[DTGroupedVulnerability], int]:
        items = self.grouped
        if severity:
            items = [item for item in items if item.severity == severity]
        if search:
            items = [item for item in items if search.lower() in item.vuln_id.lower()]
        start = (page - 1) * page_size
        return items[start : start + page_size], len(items)

    async def projects_for_vulnerability(self, source: str, vuln_id: str) -> list[DTAffectedProject]:
        return list(self.affected.get(f"{source}/{vuln_id}", []))

    async def project_metrics_history(self, uuid: str, days: int) -> list[DTMetrics]:
        return list(self.history.get(uuid, []))

    async def current_project_metrics(self, uuid: str) -> DTMetrics | None:
        by_uuid = getattr(self, "metrics_by_uuid", {})
        if uuid in by_uuid:
            return by_uuid[uuid]
        project = next((p for p in self.projects if p.uuid == uuid), None)
        return project.metrics if project else None
