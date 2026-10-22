# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""MCP server: developers ask their coding agent, the agent asks Vulnyard (SPEC 11.1).

Served at `/mcp` over Streamable HTTP, stateless and with plain JSON answers, so
any MCP client (Claude Code, Cursor, VS Code…) can use it and it runs behind a
proxy or in several replicas without sessions. Every call needs an API token;
`app.auth` checks it before the request gets here.

**Read-only by design.** No tool starts a scan, ignores a finding or changes
anything, whatever the token's scope - an agent must never act on its own.

Answers are compact on purpose: they end up in the agent's context window.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import ToolAnnotations
from sqlalchemy import func, select
from starlette.requests import Request
from starlette.routing import BaseRoute

from app import APP_NAME, __version__
from app.auth import MCP_PATH, token_principal
from app.db import session_factory
from app.errors import AppError
from app.i18n import t
from app.models import Project, ScanJob
from app.services import threats as threat_service
from app.services import vulnerabilities as vulnerability_service
from app.services.dtrack import DependencyTrackClient
from app.services.kev import KevCatalog, KevEntry

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNASSIGNED": 4}
MAX_LIMIT = 200

INSTRUCTIONS = """\
Vulnyard scans the organisation's Git repositories (SBOM via Trivy, analysis in
Dependency-Track). Use it to answer questions about known vulnerabilities in our
code: what a repository has and how to fix it, where a CVE is used, what is
actively exploited right now, and whether scanning works. It is read-only.
Identify a repository by its path (group/project) or by its git remote URL."""

#: Every tool only reads; clients may show this and skip confirmations.
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


def create_mcp_server() -> MCPServer:
    server = MCPServer(
        name=APP_NAME,
        version=__version__,
        instructions=INSTRUCTIONS,
        # Tools are listed once; nothing to listen for.
        subscriptions=False,
    )

    @server.tool(annotations=READ_ONLY)
    async def list_projects(ctx: Context, search: str = "", limit: int = 50) -> dict[str, Any]:
        """List the repositories Vulnyard scans, with finding counts per severity.

        Use it to find the exact repository path. `search` matches a part of the
        path, case-insensitively. Only default branches are listed.
        """
        _log_call(ctx, "list_projects")
        limit = _clamp(limit)
        async with session_factory()() as session:
            query = select(Project).where(Project.is_default_branch.is_(True), Project.excluded.is_(False))
            if search.strip():
                query = query.where(func.lower(Project.path_with_namespace).contains(search.strip().lower()))
            projects = list(
                (await session.execute(query.order_by(Project.path_with_namespace).limit(limit + 1))).scalars()
            )
        return {
            "projects": [_project_summary(project) for project in projects[:limit]],
            "truncated": len(projects) > limit,
        }

    @server.tool(annotations=READ_ONLY)
    async def project_findings(
        ctx: Context,
        repository: str,
        branch: str | None = None,
        min_severity: str | None = None,
        include_ignored: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Known vulnerabilities of one repository, worst first, with upgrade hints.

        `repository` is the path (group/project) or a git remote URL. Without
        `branch` the default branch is used. `latest_version`, when present, is
        a newer version of the component - a hint for the upgrade, not a
        guaranteed fix. Ignored findings were deliberately accepted by the team.
        """
        _log_call(ctx, "project_findings")
        dtrack = _dtrack(ctx)
        project = await _find_project(ctx, repository, branch)
        if not project.dt_project_uuid:
            raise _error(ctx, "mcp.project_not_scanned", repository=project.path_with_namespace)
        try:
            findings = await dtrack.project_findings(str(project.dt_project_uuid), suppressed=include_ignored)
        except AppError as error:
            raise _error(ctx, error.code, **error.params) from error

        threshold = SEVERITY_ORDER.get((min_severity or "").upper(), len(SEVERITY_ORDER))
        selected = sorted(
            (f for f in findings if SEVERITY_ORDER.get(f.severity.upper(), 4) <= threshold),
            key=lambda f: (SEVERITY_ORDER.get(f.severity.upper(), 4), -(f.cvss_v3_score or 0), f.vuln_id),
        )
        limit = _clamp(limit)
        return {
            "project": _project_summary(project),
            "findings": [
                _drop_empty(
                    {
                        "id": f.vuln_id,
                        "aliases": list(f.aliases),
                        "severity": f.severity,
                        "cvss": f.cvss_v3_score,
                        "epss": f.epss_score,
                        "component": f.component_name,
                        "version": f.component_version,
                        "purl": f.purl,
                        "latest_version": _upgrade_hint(f.component_version, f.latest_version),
                        "ignored": f.suppressed or None,
                    }
                )
                for f in selected[:limit]
            ],
            "total": len(selected),
            "truncated": len(selected) > limit,
        }

    @server.tool(annotations=READ_ONLY)
    async def find_vulnerability(ctx: Context, vulnerability_id: str) -> dict[str, Any]:
        """Where our repositories have a vulnerability (CVE, GHSA, OSV… ids and aliases).

        Lists every affected repository and branch with the component and its
        version, and says whether it is ignored and whether it is known to be
        exploited (CISA KEV).
        """
        _log_call(ctx, "find_vulnerability")
        dtrack = _dtrack(ctx)
        wanted = vulnerability_id.strip().upper()
        if not wanted:
            raise _error(ctx, "mcp.vulnerability_id_missing")
        async with session_factory()() as session:
            groups = await vulnerability_service.grouped(session, dtrack, include_suppressed=True)
        matches = [g for g in groups if g.vuln_id.upper() == wanted or wanted in {a.upper() for a in g.aliases}]
        kev = await _kev(ctx).entries()
        return {
            "vulnerability_id": wanted,
            "found": bool(matches),
            "matches": [
                _drop_empty(
                    {
                        "id": group.vuln_id,
                        "source": group.source,
                        "aliases": sorted(group.aliases),
                        "severity": group.severity,
                        "cvss": group.cvss_v3_score,
                        "epss": group.epss_score,
                        "known_exploited": _kev_summary(_kev_entry(group, kev), detailed=True),
                        "affected": [
                            _drop_empty(
                                {
                                    "repository": one.project.path_with_namespace,
                                    "branch": one.project.branch,
                                    "component": one.component_name,
                                    "version": one.component_version,
                                    "purl": one.purl,
                                    "latest_version": _upgrade_hint(one.component_version, one.latest_version),
                                    "ignored": one.suppressed or None,
                                }
                            )
                            for one in group.affected
                        ],
                    }
                )
                for group in matches
            ],
        }

    @server.tool(annotations=READ_ONLY)
    async def current_threats(
        ctx: Context,
        reason: str | None = None,
        epss_threshold: float = threat_service.DEFAULT_EPSS_THRESHOLD,
        new_days: int = threat_service.DEFAULT_NEW_DAYS,
        limit: int = 25,
    ) -> dict[str, Any]:
        """Vulnerabilities in our repositories to fix first, most urgent first.

        A threat is known to be exploited (CISA KEV), likely to be exploited
        (EPSS at or above `epss_threshold`, 0-1), or critical/high and new in the
        last `new_days` days. `reason` narrows it to "exploited", "likely" or
        "new". Ignored findings are left out.
        """
        _log_call(ctx, "current_threats")
        dtrack = _dtrack(ctx)
        if not 0.0 <= epss_threshold <= 1.0 or not 1 <= new_days <= 365:
            raise _error(ctx, "mcp.threshold_invalid")
        async with session_factory()() as session:
            groups = await vulnerability_service.grouped(session, dtrack, include_suppressed=False)
        catalog = _kev(ctx)
        threats = threat_service.select(
            groups,
            await catalog.entries(),
            now=datetime.now(UTC),
            epss_threshold=epss_threshold,
            new_days=new_days,
        )
        counts = {name: sum(1 for th in threats if name in th.reasons) for name in threat_service.REASONS}
        if reason in threat_service.REASONS:
            threats = [th for th in threats if reason in th.reasons]
        limit = _clamp(limit)
        status = catalog.status()
        return {
            "counts": counts,
            "known_exploited_catalog": "available" if status.available else ("off" if not status.enabled else "unavailable"),
            "threats": [
                _drop_empty(
                    {
                        "id": th.vulnerability.vuln_id,
                        "cves": list(th.cve_ids),
                        "reasons": list(th.reasons),
                        "severity": th.vulnerability.severity,
                        "epss": th.vulnerability.epss_score,
                        "known_exploited": _kev_summary(th.kev),
                        "first_seen": _iso(th.vulnerability.first_seen),
                        "repositories": sorted({one.project.path_with_namespace for one in th.vulnerability.affected}),
                    }
                )
                for th in threats[:limit]
            ],
            "total": len(threats),
            "truncated": len(threats) > limit,
        }

    @server.tool(annotations=READ_ONLY)
    async def scan_status(ctx: Context, repository: str, branch: str | None = None) -> dict[str, Any]:
        """When a repository was last scanned, how it went and why it failed.

        Use it when findings look outdated or missing.
        """
        _log_call(ctx, "scan_status")
        project = await _find_project(ctx, repository, branch)
        locale = _locale(ctx)
        async with session_factory()() as session:
            jobs = list(
                (
                    await session.execute(
                        select(ScanJob).where(ScanJob.project_id == project.id).order_by(ScanJob.id.desc()).limit(5)
                    )
                ).scalars()
            )
        return {
            "project": _project_summary(project),
            "recent_scans": [
                _drop_empty(
                    {
                        "status": job.status,
                        "started_at": _iso(job.started_at),
                        "finished_at": _iso(job.finished_at),
                        "commit": job.commit_sha,
                        "skipped": t(job.skip_reason, locale) if job.skip_reason else None,
                        "error": t(job.error_code, locale, **(job.error_params or {})) if job.error_code else None,
                    }
                )
                for job in jobs
            ],
        }

    return server


def mcp_routes(server: MCPServer) -> list[BaseRoute]:
    """The `/mcp` route, to be added to the FastAPI app.

    DNS-rebinding protection (Host/Origin allow-list) is meant for servers on
    localhost; ours runs under whatever host name the deployment gives it, and
    every call carries a bearer token a browser page cannot attach.
    """
    app = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    return list(app.routes)


# --- helpers ---------------------------------------------------------------------


def _request(ctx: Context) -> Request:
    request = ctx.request_context.request
    if not isinstance(request, Request):  # pragma: no cover - only HTTP is served
        raise ToolError("Vulnyard MCP is served over HTTP only")
    return request


def _locale(ctx: Context) -> str:
    return _request(ctx).app.state.settings.default_locale


def _error(ctx: Context, code: str, **params: object) -> ToolError:
    """An anticipated failure, worded for the agent from the message catalog."""
    return ToolError(f"{code}: {t(code, _locale(ctx), **params)}")


def _dtrack(ctx: Context) -> DependencyTrackClient:
    client = getattr(_request(ctx).app.state, "dtrack", None)
    if client is None:
        raise _error(ctx, "dtrack.not_configured")
    if not client.features.supported:
        raise _error(ctx, "dtrack.version_unsupported", version=client.features.version or "?")
    return client


def _kev(ctx: Context) -> KevCatalog:
    return _request(ctx).app.state.kev


def _log_call(ctx: Context, tool: str) -> None:
    """Who asked what: the audit trail of agent access."""
    principal = token_principal(_request(ctx))
    logger.info("MCP %s called by token %s", tool, principal.name if principal else "?")


async def _find_project(ctx: Context, repository: str, branch: str | None) -> Project:
    """The project for a path or a git remote URL; the default branch unless given."""
    path = repository_path(repository)
    if not path:
        raise _error(ctx, "mcp.repository_missing")
    async with session_factory()() as session:
        candidates = list(
            (
                await session.execute(
                    select(Project).where(func.lower(Project.path_with_namespace) == path.lower())
                )
            ).scalars()
        )
    if not candidates:
        raise _error(ctx, "mcp.repository_unknown", repository=path)
    if branch:
        chosen = next((p for p in candidates if p.branch == branch), None)
        if chosen is None:
            scanned = ", ".join(sorted(p.branch for p in candidates))
            raise _error(ctx, "mcp.branch_unknown", branch=branch, branches=scanned)
        return chosen
    return next((p for p in candidates if p.is_default_branch), candidates[0])


def repository_path(value: str) -> str:
    """`group/project` from a path, an HTTPS URL or an SSH remote (`git@host:group/project.git`)."""
    text = value.strip()
    if "://" in text:
        text = urlsplit(text).path
    elif "@" in text and ":" in text.split("@", 1)[1]:
        text = text.split("@", 1)[1].split(":", 1)[1]
    text = text.strip("/")
    # A GitLab web URL may point inside the project: group/project/-/tree/main.
    text = text.split("/-/", 1)[0]
    return text.removesuffix(".git").strip("/")


def _project_summary(project: Project) -> dict[str, Any]:
    return _drop_empty(
        {
            "repository": project.path_with_namespace,
            "branch": project.branch,
            "default_branch": project.is_default_branch,
            "url": project.web_url,
            "last_scan_at": _iso(project.last_scan_at),
            "last_scan_status": project.last_scan_status,
            "findings": project.last_metrics if isinstance(project.last_metrics, dict) else None,
        }
    )


def _kev_entry(group: vulnerability_service.GroupedVulnerability, kev: dict[str, KevEntry]) -> KevEntry | None:
    return next((kev[cve] for cve in threat_service.cve_ids(group) if cve in kev), None)


def _kev_summary(entry: KevEntry | None, *, detailed: bool = False) -> dict[str, Any] | None:
    """What CISA says; the long required-action text only for a single vulnerability."""
    if entry is None:
        return None
    return _drop_empty(
        {
            "cve": entry.cve_id,
            "name": entry.name,
            "added": entry.date_added.isoformat() if entry.date_added else None,
            "ransomware": entry.ransomware or None,
            "required_action": entry.required_action if detailed else None,
        }
    )


def _upgrade_hint(version: str | None, latest: str | None) -> str | None:
    """The newest version, only when it differs from the one in use."""
    return latest if latest and latest != version else None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _clamp(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


def _drop_empty(data: dict[str, Any]) -> dict[str, Any]:
    """Leave out empty values: every token counts in the agent's context."""
    return {key: value for key, value in data.items() if value not in (None, [], "")}
