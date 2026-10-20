# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Dependency-Track API client (SPEC section 9).

Endpoints and parameters were verified against the OpenAPI document of a real
Dependency-Track 4.13.6 instance (`<DT_API_URL>/api/openapi.json`):

* ``POST /api/v1/bom`` – multipart with ``projectName``, ``projectVersion``,
  ``autoCreate``, ``parentUUID``, ``isLatest``, ``projectTags``, ``bom``;
  answers ``{"token": "..."}``
* ``GET /api/v1/event/token/{uuid}`` – ``{"processing": bool}``
* ``GET /api/v1/project/lookup?name=&version=`` – the project
* ``PATCH /api/v1/project/{uuid}`` – partial update, ``tags`` replaces the
  whole collection, so tags are merged by us before sending
* ``PUT /api/v1/project`` – creates a project (201)
* ``GET /api/v1/metrics/project/{uuid}/current|days/{n}|refresh``
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote as _quote

import httpx

from app.config import Settings
from app.errors import AppError
from app.masking import mask_secrets

logger = logging.getLogger(__name__)

API_PREFIX = "/api/v1"
REQUEST_TIMEOUT_SECONDS = 60.0
UPLOAD_TIMEOUT_SECONDS = 180.0

RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1.0
RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

#: Minimum supported version; below this scanning is refused (SPEC section 9).
MIN_SUPPORTED_VERSION = (4, 12)
#: Collection projects and isLatest are used from this version on.
COLLECTION_PROJECT_VERSION = (4, 12)
#: Aggregation over the latest versions of children only.
COLLECTION_LOGIC_LATEST = "AGGREGATE_LATEST_VERSION_CHILDREN"


class DependencyTrackError(AppError):
    status_code = 502


class ProcessingAborted(Exception):
    """The caller asked to stop waiting for Dependency-Track (job cancelled)."""


@dataclass(frozen=True, slots=True)
class DTFeatures:
    """What the detected Dependency-Track version supports."""

    version: str | None
    version_tuple: tuple[int, ...] = ()

    @property
    def supported(self) -> bool:
        return self.version_tuple >= MIN_SUPPORTED_VERSION

    @property
    def supports_is_latest(self) -> bool:
        return self.version_tuple >= COLLECTION_PROJECT_VERSION

    @property
    def supports_collection_projects(self) -> bool:
        return self.version_tuple >= COLLECTION_PROJECT_VERSION


@dataclass(frozen=True, slots=True)
class DTMetrics:
    """Current metrics of one project as Dependency-Track reports them."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unassigned: int = 0
    components: int = 0
    vulnerable_components: int = 0
    vulnerabilities: int = 0
    suppressed: int = 0
    inherited_risk_score: float | None = None
    findings_total: int = 0
    last_occurrence: datetime | None = None

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unassigned


@dataclass(frozen=True, slots=True)
class DTFinding:
    """One finding of a project (vulnerability in a component)."""

    vuln_id: str
    source: str
    severity: str
    severity_rank: int | None = None
    cvss_v3_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cwe: str | None = None
    published: datetime | None = None
    component_name: str = ""
    component_version: str | None = None
    purl: str | None = None
    latest_version: str | None = None
    suppressed: bool = False
    attributed_on: datetime | None = None

    # Identity in Dependency-Track; an analysis is written per project, component
    # and vulnerability, so suppressing a finding needs all three.
    dt_project_uuid: str | None = None
    dt_component_uuid: str | None = None
    dt_vulnerability_uuid: str | None = None


@dataclass(frozen=True, slots=True)
class DTGroupedVulnerability:
    """A vulnerability with the number of projects it affects."""

    vuln_id: str
    source: str
    severity: str
    cvss_v3_score: float | None = None
    affected_project_count: int = 0
    published: datetime | None = None


@dataclass(frozen=True, slots=True)
class DTAffectedProject:
    """Project affected by a vulnerability, as returned by Dependency-Track."""

    uuid: str
    name: str
    version: str | None = None


@dataclass(slots=True)
class DTProject:
    """The subset of a Dependency-Track project we care about."""

    uuid: str
    name: str
    version: str | None = None
    tags: tuple[str, ...] = ()
    is_latest: bool = False
    parent_uuid: str | None = None
    metrics: DTMetrics | None = None
    last_bom_import: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def parse_version(value: str | None) -> tuple[int, ...]:
    """'4.13.6' -> (4, 13, 6); unparseable input gives an empty tuple."""
    if not value:
        return ()
    parts: list[int] = []
    for chunk in value.split("."):
        digits = "".join(character for character in chunk if character.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


class DependencyTrackClient:
    """Read/write client for the Dependency-Track REST API."""

    def __init__(self, settings: Settings) -> None:
        self._base_url = settings.dt_api_url.rstrip("/")
        self._api_key = settings.dt_api_key
        self._client = httpx.AsyncClient(
            base_url=f"{self._base_url}{API_PREFIX}",
            headers={"X-Api-Key": self._api_key, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=settings.ca_bundle or True,
            follow_redirects=True,
        )
        self._features: DTFeatures | None = None

    async def close(self) -> None:
        await self._client.aclose()

    # --- version and features ------------------------------------------------

    async def detect_features(self) -> DTFeatures:
        """Read the version once and derive the feature flags from it."""
        if self._features is not None:
            return self._features
        # /api/version sits next to /api/v1, so it needs the absolute URL.
        payload = await self._request_json("GET", f"{self._base_url}/api/version")
        version = payload.get("version") if isinstance(payload, dict) else None
        self._features = DTFeatures(version=version, version_tuple=parse_version(version))
        return self._features

    @property
    def features(self) -> DTFeatures:
        return self._features or DTFeatures(version=None)

    # --- BOM upload and processing -------------------------------------------

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
        """Upload a CycloneDX BOM and return the processing token."""
        data: dict[str, str] = {
            "projectName": project_name,
            "projectVersion": project_version,
            "autoCreate": "true",
        }
        if parent_uuid:
            data["parentUUID"] = parent_uuid
        if is_latest and self.features.supports_is_latest:
            data["isLatest"] = "true"
        if tags:
            # The field is a plain string in the API; tags are merged again
            # after the upload, so an instance ignoring it changes nothing.
            data["projectTags"] = ",".join(tags)

        payload = await self._request_json(
            "POST",
            "/bom",
            data=data,
            files={"bom": ("bom.json", bom, "application/json")},
            timeout=UPLOAD_TIMEOUT_SECONDS,
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        if not token:
            raise DependencyTrackError("dtrack.upload_no_token")
        return str(token)

    async def is_token_processing(self, token: str) -> bool:
        payload = await self._request_json("GET", f"/event/token/{token}")
        return bool(payload.get("processing")) if isinstance(payload, dict) else False

    async def wait_for_processing(
        self,
        token: str,
        *,
        poll_interval_seconds: float = 3.0,
        timeout_seconds: float = 600.0,
        should_stop: Callable[[], bool] | None = None,
    ) -> None:
        """Poll until Dependency-Track finished processing the BOM.

        `should_stop` lets the caller abort the wait (a cancelled job); the BOM
        itself is already uploaded and Dependency-Track keeps processing it.
        """
        waited = 0.0
        while waited < timeout_seconds:
            if should_stop is not None and should_stop():
                raise ProcessingAborted
            if not await self.is_token_processing(token):
                return
            await asyncio.sleep(poll_interval_seconds)
            waited += poll_interval_seconds
        raise DependencyTrackError("dtrack.processing_timeout", seconds=int(timeout_seconds))

    # --- projects ------------------------------------------------------------

    async def lookup_project(self, name: str, version: str) -> DTProject | None:
        try:
            payload = await self._request_json(
                "GET", "/project/lookup", params={"name": name, "version": version}
            )
        except DependencyTrackError as error:
            if error.code == "dtrack.not_found":
                return None
            raise
        return _project(payload) if isinstance(payload, dict) else None

    async def get_project(self, uuid: str) -> DTProject | None:
        try:
            payload = await self._request_json("GET", f"/project/{uuid}")
        except DependencyTrackError as error:
            if error.code == "dtrack.not_found":
                return None
            raise
        return _project(payload) if isinstance(payload, dict) else None

    async def find_project_by_name(self, name: str) -> DTProject | None:
        """First project with the given name (used for the group parent)."""
        payload = await self._request_json(
            "GET", "/project", params={"name": name, "pageSize": 100, "pageNumber": 1}
        )
        if not isinstance(payload, list):
            return None
        for item in payload:
            if isinstance(item, dict) and item.get("name") == name:
                return _project(item)
        return None

    async def create_project(
        self,
        *,
        name: str,
        version: str | None = None,
        parent_uuid: str | None = None,
        collection_logic: str | None = None,
        tags: tuple[str, ...] = (),
    ) -> DTProject:
        body: dict[str, Any] = {"name": name, "active": True}
        if version:
            body["version"] = version
        if parent_uuid:
            body["parent"] = {"uuid": parent_uuid}
        if collection_logic and self.features.supports_collection_projects:
            body["collectionLogic"] = collection_logic
        if tags:
            body["tags"] = [{"name": tag} for tag in tags]

        payload = await self._request_json("PUT", "/project", json=body)
        if not isinstance(payload, dict) or not payload.get("uuid"):
            raise DependencyTrackError("dtrack.project_not_created", name=name)
        return _project(payload)

    async def ensure_collection_project(self, name: str, *, tags: tuple[str, ...] = ()) -> DTProject:
        """Find or create the parent project of a group (SPEC 9.2).

        Two parallel jobs of the same group can both find it missing, so a 409
        from the create call means somebody else won the race, not an error.
        """
        existing = await self.find_project_by_name(name)
        if existing is not None:
            return existing
        try:
            return await self.create_project(
                name=name, collection_logic=COLLECTION_LOGIC_LATEST, tags=tags
            )
        except DependencyTrackError as error:
            if error.code != "dtrack.conflict":
                raise
            created_meanwhile = await self.find_project_by_name(name)
            if created_meanwhile is None:
                raise
            return created_meanwhile

    async def merge_project_tags(self, project: DTProject, tags: tuple[str, ...]) -> tuple[str, ...]:
        """Add the tags to a project, keeping the ones already there (SPEC 9.3)."""
        missing = [tag for tag in tags if tag not in project.tags]
        if not missing:
            return project.tags
        merged = tuple(dict.fromkeys((*project.tags, *missing)))
        await self._request_json(
            "PATCH", f"/project/{project.uuid}", json={"tags": [{"name": tag} for tag in merged]}
        )
        return merged

    async def list_projects(self, *, page_size: int = 100, max_pages: int = 50) -> list[DTProject]:
        """Every project of the instance including its current metrics.

        One paged request replaces asking for the metrics project by project.
        """
        collected: list[DTProject] = []
        for page in range(1, max_pages + 1):
            payload = await self._request_json(
                "GET",
                "/project",
                params={"pageSize": page_size, "pageNumber": page, "excludeInactive": "true"},
            )
            if not isinstance(payload, list) or not payload:
                break
            collected.extend(_project(item) for item in payload if isinstance(item, dict))
            if len(payload) < page_size:
                break
        return collected

    # --- findings ------------------------------------------------------------

    async def project_findings(self, uuid: str, *, suppressed: bool = False) -> list[DTFinding]:
        """Findings of one project (SPEC 9.4)."""
        payload = await self._request_json(
            "GET",
            f"/finding/project/{uuid}",
            params={"suppressed": "true" if suppressed else "false"},
        )
        if not isinstance(payload, list):
            return []
        return [_finding(item) for item in payload if isinstance(item, dict)]

    async def grouped_findings(
        self,
        *,
        severity: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> tuple[list[DTGroupedVulnerability], int]:
        """Portfolio findings grouped per vulnerability, plus the total count."""
        params: dict[str, Any] = {"pageNumber": page, "pageSize": page_size, "showInactive": "false"}
        if severity:
            params["severity"] = severity
        if search:
            # Dependency-Track searches one field at a time.
            params["textSearchField"] = "vulnerability"
            params["textSearchInput"] = search
        response = await self._request("GET", "/finding/grouped", params=params)
        try:
            payload = response.json()
        except ValueError:
            return [], 0
        total = int(response.headers.get("X-Total-Count") or 0)
        items = [
            _grouped(item) for item in payload if isinstance(item, dict)
        ] if isinstance(payload, list) else []
        return items, total

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
        """Suppress or un-suppress one finding (`PUT /v1/analysis`).

        Dependency-Track has no pattern or portfolio form of this: an analysis is
        written per project, component and vulnerability, so a rule that covers a
        pattern is applied one finding at a time.
        """
        body: dict[str, Any] = {
            "project": project_uuid,
            "component": component_uuid,
            "vulnerability": vulnerability_uuid,
            "suppressed": suppressed,
            "isSuppressed": suppressed,
        }
        if analysis_state:
            body["analysisState"] = analysis_state
        if comment:
            body["comment"] = comment
        await self._request_json("PUT", "/analysis", json=body)

    async def projects_for_vulnerability(self, source: str, vuln_id: str) -> list[DTAffectedProject]:
        """Projects affected by one vulnerability."""
        payload = await self._request_json(
            "GET", f"/vulnerability/source/{source}/vuln/{_quote(vuln_id)}/projects"
        )
        if not isinstance(payload, list):
            return []
        return [
            DTAffectedProject(
                uuid=str(item.get("uuid", "")),
                name=str(item.get("name", "")),
                version=item.get("version"),
            )
            for item in payload
            if isinstance(item, dict) and item.get("uuid")
        ]

    # --- metrics -------------------------------------------------------------

    async def refresh_project_metrics(self, uuid: str) -> None:
        await self._request_json("GET", f"/metrics/project/{uuid}/refresh")

    async def current_project_metrics(self, uuid: str) -> DTMetrics | None:
        payload = await self._request_json("GET", f"/metrics/project/{uuid}/current")
        return _metrics(payload) if isinstance(payload, dict) else None

    async def project_metrics_history(self, uuid: str, days: int) -> list[DTMetrics]:
        """Daily metrics of the last `days` days, used to backfill snapshots."""
        payload = await self._request_json("GET", f"/metrics/project/{uuid}/days/{days}")
        if not isinstance(payload, list):
            return []
        return [_metrics(item) for item in payload if isinstance(item, dict)]

    # --- HTTP plumbing -------------------------------------------------------

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        response = await self._request(
            method, path, params=params, json=json, data=data, files=files, timeout=timeout
        )
        if response.status_code == 204 or not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            # Some endpoints answer with plain text (for example a refresh).
            return {}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """Request with 3 attempts and exponential backoff on 429/5xx/timeout."""
        last_error: Exception | None = None
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                response = await self._client.request(
                    method,
                    path,
                    params=params,
                    json=json,
                    data=data,
                    files=files,
                    timeout=timeout or REQUEST_TIMEOUT_SECONDS,
                )
            except (httpx.TimeoutException, httpx.TransportError) as error:
                last_error = error
                if attempt == RETRY_ATTEMPTS:
                    raise DependencyTrackError(
                        "dtrack.unreachable", detail=self._mask(str(error))
                    ) from error
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
                continue

            if response.status_code in RETRY_STATUS_CODES and attempt < RETRY_ATTEMPTS:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
                continue
            if response.is_success:
                return response
            raise self._http_error(response)

        raise DependencyTrackError("dtrack.unreachable", detail=self._mask(str(last_error)))

    def _http_error(self, response: httpx.Response) -> DependencyTrackError:
        status = response.status_code
        detail = self._mask(response.text[:500])
        if status == 401:
            return DependencyTrackError("dtrack.unauthorized", status_code=502, detail=detail)
        if status == 403:
            return DependencyTrackError("dtrack.forbidden", status_code=502, detail=detail)
        if status == 404:
            return DependencyTrackError("dtrack.not_found", status_code=502, detail=detail)
        if status == 409:
            return DependencyTrackError("dtrack.conflict", status_code=502, detail=detail)
        if status == 400:
            match = re.search(r"Unrecognized specVersion ([0-9.]+)", detail)
            if match:
                # Trivy emits a CycloneDX version this instance cannot read.
                return DependencyTrackError(
                    "dtrack.bom_spec_version_unsupported",
                    status_code=502,
                    detail=detail,
                    version=match.group(1),
                )
            return DependencyTrackError("dtrack.bom_invalid", status_code=502, detail=detail)
        return DependencyTrackError("dtrack.http_error", status=status, detail=detail)

    def _mask(self, text: str) -> str:
        return mask_secrets(text, self._api_key)


def _metrics(payload: dict[str, Any]) -> DTMetrics:
    return DTMetrics(
        critical=int(payload.get("critical") or 0),
        high=int(payload.get("high") or 0),
        medium=int(payload.get("medium") or 0),
        low=int(payload.get("low") or 0),
        unassigned=int(payload.get("unassigned") or 0),
        components=int(payload.get("components") or 0),
        vulnerable_components=int(payload.get("vulnerableComponents") or 0),
        vulnerabilities=int(payload.get("vulnerabilities") or 0),
        suppressed=int(payload.get("suppressed") or 0),
        inherited_risk_score=payload.get("inheritedRiskScore"),
        findings_total=int(payload.get("findingsTotal") or 0),
        last_occurrence=_epoch_ms(payload.get("lastOccurrence")),
    )


def _finding(payload: dict[str, Any]) -> DTFinding:
    vulnerability = payload.get("vulnerability") or {}
    component = payload.get("component") or {}
    analysis = payload.get("analysis") or {}
    attribution = payload.get("attribution") or {}
    return DTFinding(
        vuln_id=str(vulnerability.get("vulnId", "")),
        source=str(vulnerability.get("source", "")),
        severity=str(vulnerability.get("severity", "UNASSIGNED")),
        severity_rank=vulnerability.get("severityRank"),
        cvss_v3_score=vulnerability.get("cvssV3BaseScore"),
        epss_score=vulnerability.get("epssScore"),
        epss_percentile=vulnerability.get("epssPercentile"),
        cwe=_cwe(vulnerability),
        published=_epoch_ms(vulnerability.get("published")),
        component_name=str(component.get("name", "")),
        component_version=component.get("version"),
        purl=component.get("purl"),
        latest_version=component.get("latestVersion"),
        suppressed=bool(analysis.get("isSuppressed")),
        attributed_on=_epoch_ms(attribution.get("attributedOn")),
        dt_project_uuid=component.get("project"),
        dt_component_uuid=component.get("uuid"),
        dt_vulnerability_uuid=vulnerability.get("uuid"),
    )


def _grouped(payload: dict[str, Any]) -> DTGroupedVulnerability:
    vulnerability = payload.get("vulnerability") or {}
    return DTGroupedVulnerability(
        vuln_id=str(vulnerability.get("vulnId", "")),
        source=str(vulnerability.get("source", "")),
        severity=str(vulnerability.get("severity", "UNASSIGNED")),
        cvss_v3_score=vulnerability.get("cvssV3BaseScore"),
        affected_project_count=int(vulnerability.get("affectedProjectCount") or 0),
        published=_epoch_ms(vulnerability.get("published")),
    )


def _cwe(vulnerability: dict[str, Any]) -> str | None:
    cwes = vulnerability.get("cwes")
    if isinstance(cwes, list) and cwes and isinstance(cwes[0], dict):
        cwe_id = cwes[0].get("cweId")
        return f"CWE-{cwe_id}" if cwe_id else None
    cwe_id = vulnerability.get("cweId")
    return f"CWE-{cwe_id}" if cwe_id else None


def _epoch_ms(value: Any) -> datetime | None:
    """Dependency-Track sends timestamps as epoch milliseconds."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _project(payload: dict[str, Any]) -> DTProject:
    parent = payload.get("parent") or {}
    metrics = payload.get("metrics")
    return DTProject(
        uuid=str(payload.get("uuid", "")),
        name=str(payload.get("name", "")),
        version=payload.get("version"),
        tags=tuple(
            str(tag.get("name"))
            for tag in payload.get("tags") or []
            if isinstance(tag, dict) and tag.get("name")
        ),
        is_latest=bool(payload.get("isLatest")),
        parent_uuid=parent.get("uuid") if isinstance(parent, dict) else None,
        metrics=_metrics(metrics) if isinstance(metrics, dict) else None,
        last_bom_import=_epoch_ms(payload.get("lastBomImport")),
        raw=payload,
    )


def create_dtrack_client(settings: Settings) -> DependencyTrackClient | None:
    """Client for the configured instance, or None when not configured."""
    if not settings.dtrack_configured:
        return None
    return DependencyTrackClient(settings)
