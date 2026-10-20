# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Values of the enum-like string columns (see SPEC section 6)."""

from __future__ import annotations

from typing import Final, Literal

# Repository sources. v1 has GitLab only, the column exists so that another
# source can be added later without a data migration.
SOURCE_GITLAB: Final = "gitlab"
SOURCES: Final = (SOURCE_GITLAB,)
SourceName = Literal["gitlab"]

# scan_targets.kind
TARGET_KIND_GROUP: Final = "group"
TARGET_KIND_PROJECT: Final = "project"
TARGET_KINDS: Final = (TARGET_KIND_GROUP, TARGET_KIND_PROJECT)
TargetKind = Literal["group", "project"]

# scan_targets.branch_mode / project_branch_overrides.branch_mode
BRANCH_MODE_DEFAULT: Final = "default"
BRANCH_MODE_CUSTOM: Final = "custom"
BRANCH_MODES: Final = (BRANCH_MODE_DEFAULT, BRANCH_MODE_CUSTOM)
BranchMode = Literal["default", "custom"]

# scan_runs.trigger
TRIGGER_SCHEDULE: Final = "schedule"
TRIGGER_MANUAL: Final = "manual"
TRIGGERS: Final = (TRIGGER_SCHEDULE, TRIGGER_MANUAL)

# scan_runs.status
RUN_QUEUED: Final = "queued"
RUN_RUNNING: Final = "running"
RUN_DONE: Final = "done"
RUN_FAILED: Final = "failed"
RUN_CANCELLED: Final = "cancelled"
RUN_STATUSES: Final = (RUN_QUEUED, RUN_RUNNING, RUN_DONE, RUN_FAILED, RUN_CANCELLED)

# scan_jobs.status
JOB_QUEUED: Final = "queued"
JOB_CLONING: Final = "cloning"
JOB_SCANNING: Final = "scanning"
JOB_UPLOADING: Final = "uploading"
JOB_PROCESSING: Final = "processing"
JOB_DONE: Final = "done"
JOB_SKIPPED: Final = "skipped"
JOB_FAILED: Final = "failed"
JOB_CANCELLED: Final = "cancelled"
JOB_STATUSES: Final = (
    JOB_QUEUED,
    JOB_CLONING,
    JOB_SCANNING,
    JOB_UPLOADING,
    JOB_PROCESSING,
    JOB_DONE,
    JOB_SKIPPED,
    JOB_FAILED,
    JOB_CANCELLED,
)
# Statuses of a job that is being worked on right now.
JOB_ACTIVE_STATUSES: Final = (JOB_CLONING, JOB_SCANNING, JOB_UPLOADING, JOB_PROCESSING)

# Default cron of a new target: every day at 02:00.
DEFAULT_SCHEDULE_CRON: Final = "0 2 * * *"
# Safety net against a pattern that would match hundreds of branches.
DEFAULT_MAX_BRANCHES: Final = 10

# ignore_rules.analysis_state – the Dependency-Track analysis state a suppressed
# finding is given. DT knows more values; these are the ones that mean "we looked
# at it and it does not apply to us".
ANALYSIS_NOT_AFFECTED: Final = "NOT_AFFECTED"
ANALYSIS_FALSE_POSITIVE: Final = "FALSE_POSITIVE"
ANALYSIS_RESOLVED: Final = "RESOLVED"
ANALYSIS_STATES: Final = (ANALYSIS_NOT_AFFECTED, ANALYSIS_FALSE_POSITIVE, ANALYSIS_RESOLVED)
DEFAULT_ANALYSIS_STATE: Final = ANALYSIS_NOT_AFFECTED

# Pattern that matches any component of the scope.
ANY_COMPONENT: Final = "*"

# api_tokens.scope – what a machine caller may do. `write` includes `read`;
# managing the tokens themselves is never allowed with a token.
API_TOKEN_SCOPE_READ: Final = "read"
API_TOKEN_SCOPE_WRITE: Final = "write"
API_TOKEN_SCOPES: Final = (API_TOKEN_SCOPE_READ, API_TOKEN_SCOPE_WRITE)
# Every token starts with this, so it is recognisable in a leaked config or
# log, and so that a bearer token meant for someone else (an identity proxy
# passing its own JWT upstream) is never mistaken for ours.
API_TOKEN_PREFIX: Final = "vy_"
