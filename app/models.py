# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""SQLAlchemy models (see SPEC section 6).

Enum-like columns are plain strings with the allowed values in
`app.constants`; that keeps migrations free of database enum types.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.constants import (
    ANY_COMPONENT,
    API_TOKEN_SCOPE_READ,
    BRANCH_MODE_DEFAULT,
    DEFAULT_ANALYSIS_STATE,
    DEFAULT_MAX_BRANCHES,
    SOURCE_GITLAB,
)


class Base(DeclarativeBase):
    pass


def _utcnow_column(**kwargs: Any) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), **kwargs)


class ScanTarget(Base):
    """What should be scanned: a group or a single project of a source."""

    __tablename__ = "scan_targets"
    __table_args__ = (
        UniqueConstraint("source", "kind", "source_ref", name="uq_scan_targets_source_ref"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32), default=SOURCE_GITLAB)
    kind: Mapped[str] = mapped_column(String(16))

    # Identification in the source: numeric/string id plus the full path for display.
    source_ref: Mapped[str] = mapped_column(String(255))
    source_path: Mapped[str] = mapped_column(String(512))
    include_subgroups: Mapped[bool] = mapped_column(Boolean, default=True)

    # Own credentials for this target; null means "use GITLAB_URL / GITLAB_TOKEN".
    # A target can live on a different instance, and teams often prefer a token
    # scoped to one group over one central token for everything.
    source_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_token: Mapped[str | None] = mapped_column(String(512), nullable=True)

    branch_mode: Mapped[str] = mapped_column(String(16), default=BRANCH_MODE_DEFAULT)
    branch_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    include_default_branch: Mapped[bool] = mapped_column(Boolean, default=True)
    max_branches_per_project: Mapped[int] = mapped_column(Integer, default=DEFAULT_MAX_BRANCHES)

    # null = manual runs only. No column default on purpose: SQLAlchemy would
    # apply it to an explicit None as well and NULL could never be stored.
    schedule_cron: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exclude_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    skip_unchanged: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Parent (collection) project of the group in Dependency-Track.
    dt_parent_uuid: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Chat webhook for this target; null = use the global one from settings.
    notify_webhook_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_at: Mapped[datetime] = _utcnow_column()
    updated_at: Mapped[datetime] = _utcnow_column(onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class Project(Base):
    """A discovered project; one row = project + branch."""

    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("source", "source_project_id", "branch", name="uq_projects_source_branch"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), default=SOURCE_GITLAB)
    source_project_id: Mapped[str] = mapped_column(String(64), index=True)
    path_with_namespace: Mapped[str] = mapped_column(String(512), index=True)
    name: Mapped[str] = mapped_column(String(255))
    web_url: Mapped[str] = mapped_column(String(1024))
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)

    branch: Mapped[str] = mapped_column(String(255))
    is_default_branch: Mapped[bool] = mapped_column(Boolean, default=False)

    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    empty_repo: Mapped[bool] = mapped_column(Boolean, default=False)
    # Manual exclusion from the UI.
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)

    last_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scanned_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_status: Mapped[str | None] = mapped_column(String(16), nullable=True)

    dt_project_uuid: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Severity counts seen at the end of the previous scan, so a notification can
    # say what is new rather than repeating the whole state.
    last_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    last_metrics_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    first_seen_at: Mapped[datetime] = _utcnow_column()
    last_seen_at: Mapped[datetime] = _utcnow_column()

    targets: Mapped[list[TargetProject]] = relationship(back_populates="project", cascade="all, delete-orphan")


class ProjectBranchOverride(Base):
    """Per-project override of the branch selection; wins over the target."""

    __tablename__ = "project_branch_overrides"

    source: Mapped[str] = mapped_column(String(32), primary_key=True, default=SOURCE_GITLAB)
    source_project_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    branch_mode: Mapped[str] = mapped_column(String(16), default=BRANCH_MODE_DEFAULT)
    branch_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    include_default_branch: Mapped[bool] = mapped_column(Boolean, default=True)

    updated_at: Mapped[datetime] = _utcnow_column(onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class TargetProject(Base):
    """M:N – one project can belong to several targets, it is scanned once."""

    __tablename__ = "target_projects"

    target_id: Mapped[int] = mapped_column(
        ForeignKey("scan_targets.id", ondelete="CASCADE"), primary_key=True
    )
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )

    project: Mapped[Project] = relationship(back_populates="targets")


class ScanRun(Base):
    """One run – manual or scheduled."""

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trigger: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_targets.id", ondelete="SET NULL"), nullable=True
    )
    triggered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    status: Mapped[str] = mapped_column(String(16), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    total: Mapped[int] = mapped_column(Integer, default=0)
    succeeded: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = _utcnow_column(index=True)


class ScanJob(Base):
    """One project+branch in a run; the table doubles as the queue."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    status: Mapped[str] = mapped_column(String(16), index=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    components_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sbom_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    dt_upload_token: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Why a job was skipped, as a translatable code (for example unchanged commit).
    skip_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Translatable error (code + parameters) plus technical detail without secrets.
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_params: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_tail: Mapped[str | None] = mapped_column(Text, nullable=True)

    queued_at: Mapped[datetime] = _utcnow_column()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


class MetricSnapshot(Base):
    """Daily snapshot of Dependency-Track metrics, used for the trend."""

    __tablename__ = "metric_snapshots"
    __table_args__ = (UniqueConstraint("date", "project_id", name="uq_metric_snapshots_date_project"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    date: Mapped[date] = mapped_column(Date, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    unassigned: Mapped[int] = mapped_column(Integer, default=0)
    components: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_components: Mapped[int] = mapped_column(Integer, default=0)
    inherited_risk_score: Mapped[float | None] = mapped_column(nullable=True)
    suppressed: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = _utcnow_column()


class IgnoreRule(Base):
    """A vulnerability we have decided not to act on, and where.

    `target_id` null means the rule holds for every project we scan; otherwise it
    holds for the projects of that one target. `purl_pattern` narrows the rule to
    matching components (glob, e.g. `pkg:npm/express@5.*`); `*` means any.
    Suppression is pushed to Dependency-Track either way, because our counts,
    trends and notifications all read DT's metrics - a finding hidden only here
    would still be counted there.
    """

    __tablename__ = "ignore_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Vulnerability as Dependency-Track names it, e.g. CVE-2024-47764.
    vuln_id: Mapped[str] = mapped_column(String(128), index=True)
    purl_pattern: Mapped[str] = mapped_column(String(512), default=ANY_COMPONENT)

    # null = the whole application.
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_targets.id", ondelete="CASCADE"), nullable=True, index=True
    )

    analysis_state: Mapped[str] = mapped_column(String(32), default=DEFAULT_ANALYSIS_STATE)
    # Why we ignore it; ends up in the Dependency-Track analysis comment.
    reason: Mapped[str] = mapped_column(Text, default="")

    # null = until somebody deletes the rule.
    expires_on: Mapped[date | None] = mapped_column(Date, nullable=True)

    created_at: Mapped[datetime] = _utcnow_column()
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    applications: Mapped[list[IgnoreApplication]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )


class IgnoreApplication(Base):
    """One suppression we really sent to Dependency-Track for a rule.

    Kept so that a deleted or expired rule can be taken back exactly where it was
    applied - Dependency-Track has no way to ask "what did Vulnyard suppress".
    """

    __tablename__ = "ignore_applications"
    __table_args__ = (
        UniqueConstraint(
            "rule_id",
            "dt_component_uuid",
            "dt_vulnerability_uuid",
            name="uq_ignore_applications_rule_component_vuln",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(
        ForeignKey("ignore_rules.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )

    dt_project_uuid: Mapped[str] = mapped_column(String(64))
    dt_component_uuid: Mapped[str] = mapped_column(String(64))
    dt_vulnerability_uuid: Mapped[str] = mapped_column(String(64))
    # For the UI and the log; the uuids alone say nothing to a reader.
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True)

    applied_at: Mapped[datetime] = _utcnow_column()

    rule: Mapped[IgnoreRule] = relationship(back_populates="applications")


class ApiToken(Base):
    """A token another system uses to call the API (`Authorization: Bearer`).

    Only the SHA-256 of the token is stored; the token itself is shown once,
    when it is created. `token_prefix` is its first few characters, so that a
    person can tell which entry belongs to the token in their config.
    """

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_prefix: Mapped[str] = mapped_column(String(16))
    scope: Mapped[str] = mapped_column(String(16), default=API_TOKEN_SCOPE_READ)

    # null = until somebody deletes the token; otherwise valid up to and
    # including that day, like an ignore rule.
    expires_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = _utcnow_column()
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class Setting(Base):
    """Global settings editable in the UI (key/value)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = _utcnow_column(onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
