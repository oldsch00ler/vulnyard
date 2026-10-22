# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Pydantic schemas of the REST API."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.constants import (
    ANY_COMPONENT,
    API_TOKEN_SCOPE_READ,
    BRANCH_MODE_DEFAULT,
    DEFAULT_ANALYSIS_STATE,
    DEFAULT_MAX_BRANCHES,
    DEFAULT_SCHEDULE_CRON,
    SOURCE_GITLAB,
)


class AppInfo(BaseModel):
    name: str
    version: str


class ToolStatus(BaseModel):
    available: bool
    path: str | None = None
    version: str | None = None


class ToolsStatus(BaseModel):
    trivy: ToolStatus
    git: ToolStatus


class ConfigStatus(BaseModel):
    complete: bool
    missing: list[str]
    scanning_enabled: bool


class SourceStatus(BaseModel):
    kind: str
    url: str
    configured: bool
    reachable: bool | None = None
    version: str | None = None


class DependencyTrackStatus(BaseModel):
    configured: bool
    ui_url: str | None = None
    reachable: bool | None = None
    version: str | None = None
    supported: bool | None = None
    minimum_version: str | None = None


class SchedulerStatus(BaseModel):
    running: bool
    scheduled_targets: int
    next_run_at: datetime | None = None


class WorkerStatus(BaseModel):
    running: bool
    # None when the job counts could not be read from the database.
    active_jobs: int | None = None
    queued_jobs: int | None = None


class RuntimeConfig(BaseModel):
    """Runtime configuration the frontend needs; nothing is baked in at build time."""

    dt_ui_url: str | None = None
    source_url: str | None = None
    auth_mode: str
    default_locale: str
    available_locales: list[str]


class StatusResponse(BaseModel):
    app: AppInfo
    config: ConfigStatus
    tools: ToolsStatus
    source: SourceStatus
    dtrack: DependencyTrackStatus
    scheduler: SchedulerStatus
    worker: WorkerStatus
    runtime: RuntimeConfig


class HealthResponse(BaseModel):
    status: str


class IdentityResponse(BaseModel):
    """Identity of the caller; null when the app runs without one."""

    email: str | None = None
    auth_mode: str


# --- Repository source suggestions (autocomplete) -----------------------------


class SourceGroupRead(BaseModel):
    ref: str
    path: str
    name: str
    web_url: str | None = None


class SourceProjectRead(BaseModel):
    ref: str
    path_with_namespace: str
    name: str
    web_url: str
    default_branch: str | None = None
    archived: bool = False
    empty_repo: bool = False


class SourceLookupRequest(BaseModel):
    """Search plus optional credentials, for a target that is not saved yet."""

    search: str = ""
    source_url: str | None = None
    source_token: str | None = None


class SourceBranchRead(BaseModel):
    name: str
    commit_sha: str | None = None
    is_default: bool = False
    protected: bool = False


# --- Scan targets -------------------------------------------------------------


class TargetSelection(BaseModel):
    """The part of a target that decides what gets scanned."""

    kind: str
    source_ref: str
    # Own instance and token; empty means the ones from the environment. A
    # target can live on a different GitLab, or use a token scoped to it.
    source_url: str | None = None
    source_token: str | None = None
    include_subgroups: bool = True
    branch_mode: str = BRANCH_MODE_DEFAULT
    branch_patterns: list[str] = Field(default_factory=list)
    include_default_branch: bool = True
    max_branches_per_project: int = DEFAULT_MAX_BRANCHES
    exclude_patterns: list[str] = Field(default_factory=list)


class TargetCreate(TargetSelection):
    # Filled in from the source when omitted.
    name: str | None = None
    source_path: str | None = None
    source: str = SOURCE_GITLAB
    schedule_cron: str | None = DEFAULT_SCHEDULE_CRON
    skip_unchanged: bool = True
    enabled: bool = True
    # Own chat webhook; null or empty means "use the global one".
    notify_webhook_url: str | None = None


class TargetUpdate(BaseModel):
    """Full update of a target; every field is optional."""

    name: str | None = None
    include_subgroups: bool | None = None
    branch_mode: str | None = None
    branch_patterns: list[str] | None = None
    include_default_branch: bool | None = None
    max_branches_per_project: int | None = None
    schedule_cron: str | None = None
    # Explicit null for schedule_cron means "manual runs only", so we need to
    # know whether the caller sent the field at all.
    exclude_patterns: list[str] | None = None
    skip_unchanged: bool | None = None
    enabled: bool | None = None
    notify_webhook_url: str | None = None
    source_url: str | None = None
    source_token: str | None = None

    model_config = {"extra": "forbid"}


class TargetRead(BaseModel):
    id: int
    name: str
    source: str
    kind: str
    source_ref: str
    source_path: str
    include_subgroups: bool
    branch_mode: str
    branch_patterns: list[str]
    include_default_branch: bool
    max_branches_per_project: int
    schedule_cron: str | None
    exclude_patterns: list[str]
    skip_unchanged: bool
    enabled: bool
    dt_parent_uuid: str | None
    # The webhook is never returned in full (it carries a key and a token).
    notify_webhook_configured: bool = False
    notify_webhook_url_masked: str | None = None
    # Which instance this target uses, and whether it has its own token. The
    # token itself is never part of a response.
    source_url: str | None = None
    source_url_effective: str | None = None
    source_token_configured: bool = False
    created_at: datetime
    updated_at: datetime
    updated_by: str | None

    model_config = {"from_attributes": True}


class TargetList(BaseModel):
    items: list[TargetRead]
    total: int


# --- Discovery preview --------------------------------------------------------


class PreviewRequest(TargetSelection):
    """Discovery without saving anything (POST /api/targets/preview)."""


class NoteRead(BaseModel):
    """Translatable note: a code with parameters plus the rendered message."""

    code: str
    params: dict[str, Any] = Field(default_factory=dict)
    message: str


class PreviewBranch(BaseModel):
    branch: str
    is_default_branch: bool
    commit_sha: str | None = None


class PreviewProject(BaseModel):
    source_ref: str
    path_with_namespace: str
    name: str
    web_url: str
    default_branch: str | None = None
    branches: list[PreviewBranch]
    notes: list[NoteRead] = Field(default_factory=list)


class PreviewSkipped(BaseModel):
    source_ref: str
    path_with_namespace: str
    name: str
    web_url: str
    reason: NoteRead


class PreviewResponse(BaseModel):
    projects: list[PreviewProject]
    skipped: list[PreviewSkipped]
    warnings: list[NoteRead] = Field(default_factory=list)
    project_count: int
    branch_count: int
    skipped_count: int


# --- Scan runs and jobs -------------------------------------------------------


class JobRead(BaseModel):
    id: int
    project_id: int
    path_with_namespace: str
    name: str
    branch: str
    is_default_branch: bool
    web_url: str
    status: str
    commit_sha: str | None = None
    components_count: int | None = None
    sbom_bytes: int | None = None
    dt_project_uuid: str | None = None
    # Why the job was skipped (translatable code plus rendered text).
    skip_reason: str | None = None
    skip_message: str | None = None
    error_code: str | None = None
    error_params: dict[str, Any] = Field(default_factory=dict)
    # Translated error text; the code and params stay for the UI and the log.
    error_message: str | None = None
    error_detail: str | None = None
    log_tail: str | None = None
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None


class RunRead(BaseModel):
    id: int
    trigger: str
    target_id: int | None = None
    target_name: str | None = None
    triggered_by: str | None = None
    status: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    total: int
    succeeded: int
    failed: int
    skipped: int


class RunDetail(RunRead):
    jobs: list[JobRead] = Field(default_factory=list)


class RunList(BaseModel):
    items: list[RunRead]
    total: int


# --- Per-project branch override ----------------------------------------------


class BranchOverrideWrite(BaseModel):
    branch_mode: str = BRANCH_MODE_DEFAULT
    branch_patterns: list[str] = Field(default_factory=list)
    include_default_branch: bool = True


class BranchOverrideRead(BranchOverrideWrite):
    source: str
    source_project_id: str
    path_with_namespace: str
    updated_at: datetime
    updated_by: str | None = None


# --- Dashboard ----------------------------------------------------------------


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unassigned: int = 0


class ScanStateRead(BaseModel):
    last_run_id: int | None = None
    last_run_status: str | None = None
    last_run_finished_at: datetime | None = None
    failed_jobs_24h: int = 0
    next_run_at: datetime | None = None


class DashboardSummary(BaseModel):
    severities: SeverityCounts
    findings_total: int
    projects_total: int
    projects_scanned: int
    projects_vulnerable: int
    components: int
    vulnerable_components: int
    scan_state: ScanStateRead


class TrendPoint(BaseModel):
    date: date
    critical: int
    high: int
    medium: int
    low: int
    unassigned: int
    projects: int


class TrendResponse(BaseModel):
    days: int
    points: list[TrendPoint]
    target_id: int | None = None


class TargetSummaryRead(BaseModel):
    """Totals of one scan target and how they moved over the window."""

    target_id: int
    name: str
    kind: str
    source_path: str
    enabled: bool
    projects_total: int
    projects_vulnerable: int
    severities: SeverityCounts
    findings_total: int
    components: int
    vulnerable_components: int
    risk_score: float
    change: int | None = None


class TargetSummaryList(BaseModel):
    days: int
    items: list[TargetSummaryRead]


# --- Projects -----------------------------------------------------------------


class ProjectListItem(BaseModel):
    id: int
    source: str
    source_project_id: str
    path_with_namespace: str
    name: str
    branch: str
    is_default_branch: bool
    web_url: str
    targets: list[str] = Field(default_factory=list)
    severities: SeverityCounts
    findings_total: int = 0
    components: int = 0
    vulnerable_components: int = 0
    risk_score: float | None = None
    last_scan_at: datetime | None = None
    last_scan_status: str | None = None
    dt_project_uuid: str | None = None
    excluded: bool = False


class ProjectList(BaseModel):
    items: list[ProjectListItem]
    total: int
    page: int
    page_size: int


class ProjectBranchSummary(BaseModel):
    id: int
    branch: str
    is_default_branch: bool
    last_scan_at: datetime | None = None


class ProjectDetail(ProjectListItem):
    default_branch: str | None = None
    last_commit_sha: str | None = None
    last_scanned_sha: str | None = None
    dt_last_import: datetime | None = None
    branches: list[ProjectBranchSummary] = Field(default_factory=list)
    branch_override: BranchOverrideWrite | None = None


class ProjectPatch(BaseModel):
    excluded: bool | None = None

    model_config = {"extra": "forbid"}


class FindingRead(BaseModel):
    vuln_id: str
    source: str
    severity: str
    cvss_v3_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cwe: str | None = None
    published: datetime | None = None
    component_name: str
    component_version: str | None = None
    purl: str | None = None
    latest_version: str | None = None
    suppressed: bool = False
    attributed_on: datetime | None = None


class FindingList(BaseModel):
    items: list[FindingRead]
    total: int


class ProjectHistoryItem(BaseModel):
    job_id: int
    run_id: int
    status: str
    commit_sha: str | None = None
    components_count: int | None = None
    skip_reason: str | None = None
    skip_message: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None


class ProjectHistory(BaseModel):
    items: list[ProjectHistoryItem]
    snapshots: list[TrendPoint] = Field(default_factory=list)


# --- Vulnerabilities ----------------------------------------------------------


class VulnerabilityItem(BaseModel):
    vuln_id: str
    source: str
    severity: str
    cvss_v3_score: float | None = None
    epss_score: float | None = None
    #: Only our own projects are counted; a shared Dependency-Track holds others.
    affected_project_count: int = 0
    published: datetime | None = None
    #: True when every occurrence is suppressed by an ignore rule.
    ignored: bool = False


class VulnerabilityList(BaseModel):
    items: list[VulnerabilityItem]
    total: int
    page: int
    page_size: int


# --- Threats -------------------------------------------------------------------


class KevInfo(BaseModel):
    """What the CISA KEV catalog says about an exploited vulnerability."""

    cve_id: str
    name: str = ""
    date_added: date | None = None
    due_date: date | None = None
    ransomware: bool = False
    required_action: str = ""


class ThreatItem(BaseModel):
    vuln_id: str
    source: str
    severity: str
    cvss_v3_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    #: Why it is listed: "exploited", "likely", "new".
    reasons: list[str]
    cve_ids: list[str] = Field(default_factory=list)
    kev: KevInfo | None = None
    #: When it first showed up in one of our projects.
    first_seen: datetime | None = None
    affected_project_count: int = 0
    #: A newer version of an affected component exists (not necessarily a fix).
    newer_version_available: bool = False


class KevFeedStatus(BaseModel):
    enabled: bool
    available: bool
    count: int = 0
    fetched_at: datetime | None = None
    released_at: datetime | None = None
    error_code: str | None = None


class ThreatCounts(BaseModel):
    exploited: int = 0
    likely: int = 0
    new: int = 0


class ThreatList(BaseModel):
    items: list[ThreatItem]
    total: int
    page: int
    page_size: int
    counts: ThreatCounts
    kev: KevFeedStatus
    #: False when no finding carries EPSS: Dependency-Track does not mirror it.
    epss_available: bool
    epss_threshold: float
    new_days: int


class AffectedProject(BaseModel):
    dt_project_uuid: str
    dt_name: str
    dt_version: str | None = None
    # Filled in when the Dependency-Track project is one of ours.
    project_id: int | None = None
    path_with_namespace: str | None = None
    branch: str | None = None
    web_url: str | None = None
    is_default_branch: bool | None = None


class AffectedProjectList(BaseModel):
    items: list[AffectedProject]
    #: One entry per affected component, so a reader sees what to upgrade.
    components: list[AffectedComponent] = Field(default_factory=list)
    total: int
    ours: int


class AffectedComponent(BaseModel):
    """A component of one of our projects that carries the vulnerability."""

    project_id: int
    path_with_namespace: str
    branch: str
    web_url: str
    is_default_branch: bool
    component_name: str
    component_version: str | None = None
    purl: str | None = None
    latest_version: str | None = None
    suppressed: bool = False


# --- Ignore rules -------------------------------------------------------------


class IgnoreRuleBase(BaseModel):
    vuln_id: str
    purl_pattern: str = ANY_COMPONENT
    #: null = the whole application.
    target_id: int | None = None
    analysis_state: str = DEFAULT_ANALYSIS_STATE
    reason: str = ""
    expires_on: date | None = None


class IgnoreRuleCreate(IgnoreRuleBase):
    pass


class IgnoreRuleUpdate(BaseModel):
    """Everything optional; only the sent fields change."""

    purl_pattern: str | None = None
    analysis_state: str | None = None
    reason: str | None = None
    expires_on: date | None = None
    clear_expiry: bool = False


class IgnoreRuleRead(IgnoreRuleBase):
    id: int
    target_name: str | None = None
    active: bool = True
    #: How many findings this rule really suppresses in Dependency-Track.
    applied_count: int = 0
    created_at: datetime
    created_by: str | None = None


class IgnoreRuleList(BaseModel):
    items: list[IgnoreRuleRead]
    total: int


class IgnoreApplyResult(BaseModel):
    """Outcome of pushing the rules to Dependency-Track."""

    suppressed: int = 0
    reverted: int = 0
    failed: int = 0
    projects: int = 0
    errors: list[str] = Field(default_factory=list)


# --- Settings -----------------------------------------------------------------


class EnvironmentVariableState(BaseModel):
    """Whether a variable is set. The value is never part of the response."""

    name: str
    set: bool
    secret: bool = False


class EnvironmentOverview(BaseModel):
    app_name: str
    app_version: str
    variables: list[EnvironmentVariableState]


class NotificationSettings(BaseModel):
    """Chat notifications. The webhook is returned masked, never in full."""

    enabled: bool = False
    webhook_configured: bool = False
    webhook_url_masked: str | None = None
    min_severity: str = "high"


class SettingsRead(BaseModel):
    scan_concurrency: int
    default_schedule_cron: str | None = None
    history_retention_days: int
    global_exclude_patterns: list[str] = Field(default_factory=list)
    notifications: NotificationSettings
    environment: EnvironmentOverview


class SettingsWrite(BaseModel):
    scan_concurrency: int | None = None
    default_schedule_cron: str | None = None
    history_retention_days: int | None = None
    global_exclude_patterns: list[str] | None = None
    notifications_enabled: bool | None = None
    # Full URL on write, empty string clears it.
    notification_webhook_url: str | None = None
    notification_min_severity: str | None = None

    model_config = {"extra": "forbid"}


class ConnectionTestResult(BaseModel):
    ok: bool
    detail: str
    code: str | None = None
    version: str | None = None


# --- API tokens ---------------------------------------------------------------


class ApiTokenCreate(BaseModel):
    name: str
    scope: str = API_TOKEN_SCOPE_READ
    # null = until somebody deletes it; otherwise valid up to and including that day.
    expires_on: date | None = None

    model_config = {"extra": "forbid"}


class ApiTokenRead(BaseModel):
    """A token as listed: never the token itself, only its first characters."""

    id: int
    name: str
    token_prefix: str
    scope: str
    expires_on: date | None
    active: bool
    last_used_at: datetime | None
    created_at: datetime
    created_by: str | None


class ApiTokenCreated(ApiTokenRead):
    """Response to creating a token - the only time the token is returned."""

    token: str


class ApiTokenList(BaseModel):
    items: list[ApiTokenRead]
    total: int
