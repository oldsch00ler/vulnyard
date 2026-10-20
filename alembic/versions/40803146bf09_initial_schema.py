# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""initial schema

Revision ID: 40803146bf09
Revises: 
Create Date: 2026-09-26 19:21:19.337802+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '40803146bf09'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('project_branch_overrides',
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('source_project_id', sa.String(length=64), nullable=False),
    sa.Column('branch_mode', sa.String(length=16), nullable=False),
    sa.Column('branch_patterns', sa.ARRAY(sa.Text()), nullable=False),
    sa.Column('include_default_branch', sa.Boolean(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_by', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('source', 'source_project_id')
    )
    op.create_table('projects',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('source_project_id', sa.String(length=64), nullable=False),
    sa.Column('path_with_namespace', sa.String(length=512), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('web_url', sa.String(length=1024), nullable=False),
    sa.Column('default_branch', sa.String(length=255), nullable=True),
    sa.Column('branch', sa.String(length=255), nullable=False),
    sa.Column('is_default_branch', sa.Boolean(), nullable=False),
    sa.Column('archived', sa.Boolean(), nullable=False),
    sa.Column('empty_repo', sa.Boolean(), nullable=False),
    sa.Column('excluded', sa.Boolean(), nullable=False),
    sa.Column('last_commit_sha', sa.String(length=64), nullable=True),
    sa.Column('last_scanned_sha', sa.String(length=64), nullable=True),
    sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_scan_status', sa.String(length=16), nullable=True),
    sa.Column('dt_project_uuid', sa.String(length=64), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source', 'source_project_id', 'branch', name='uq_projects_source_branch')
    )
    op.create_index(op.f('ix_projects_path_with_namespace'), 'projects', ['path_with_namespace'], unique=False)
    op.create_index(op.f('ix_projects_source_project_id'), 'projects', ['source_project_id'], unique=False)
    op.create_table('scan_targets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('source_ref', sa.String(length=255), nullable=False),
    sa.Column('source_path', sa.String(length=512), nullable=False),
    sa.Column('include_subgroups', sa.Boolean(), nullable=False),
    sa.Column('branch_mode', sa.String(length=16), nullable=False),
    sa.Column('branch_patterns', sa.ARRAY(sa.Text()), nullable=False),
    sa.Column('include_default_branch', sa.Boolean(), nullable=False),
    sa.Column('max_branches_per_project', sa.Integer(), nullable=False),
    sa.Column('schedule_cron', sa.String(length=128), nullable=True),
    sa.Column('exclude_patterns', sa.ARRAY(sa.Text()), nullable=False),
    sa.Column('skip_unchanged', sa.Boolean(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('dt_parent_uuid', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_by', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source', 'kind', 'source_ref', name='uq_scan_targets_source_ref')
    )
    op.create_table('settings',
    sa.Column('key', sa.String(length=128), nullable=False),
    sa.Column('value', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_by', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('metric_snapshots',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('date', sa.Date(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('critical', sa.Integer(), nullable=False),
    sa.Column('high', sa.Integer(), nullable=False),
    sa.Column('medium', sa.Integer(), nullable=False),
    sa.Column('low', sa.Integer(), nullable=False),
    sa.Column('unassigned', sa.Integer(), nullable=False),
    sa.Column('components', sa.Integer(), nullable=False),
    sa.Column('vulnerable_components', sa.Integer(), nullable=False),
    sa.Column('inherited_risk_score', sa.Double(), nullable=True),
    sa.Column('suppressed', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('date', 'project_id', name='uq_metric_snapshots_date_project')
    )
    op.create_index(op.f('ix_metric_snapshots_date'), 'metric_snapshots', ['date'], unique=False)
    op.create_index(op.f('ix_metric_snapshots_project_id'), 'metric_snapshots', ['project_id'], unique=False)
    op.create_table('scan_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('trigger', sa.String(length=16), nullable=False),
    sa.Column('target_id', sa.Integer(), nullable=True),
    sa.Column('triggered_by', sa.String(length=255), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('total', sa.Integer(), nullable=False),
    sa.Column('succeeded', sa.Integer(), nullable=False),
    sa.Column('failed', sa.Integer(), nullable=False),
    sa.Column('skipped', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_runs_created_at'), 'scan_runs', ['created_at'], unique=False)
    op.create_index(op.f('ix_scan_runs_status'), 'scan_runs', ['status'], unique=False)
    op.create_table('target_projects',
    sa.Column('target_id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('target_id', 'project_id')
    )
    op.create_table('scan_jobs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('run_id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('commit_sha', sa.String(length=64), nullable=True),
    sa.Column('components_count', sa.Integer(), nullable=True),
    sa.Column('sbom_bytes', sa.BigInteger(), nullable=True),
    sa.Column('dt_upload_token', sa.String(length=64), nullable=True),
    sa.Column('error_code', sa.String(length=128), nullable=True),
    sa.Column('error_params', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('error_detail', sa.Text(), nullable=True),
    sa.Column('log_tail', sa.Text(), nullable=True),
    sa.Column('queued_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['run_id'], ['scan_runs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_jobs_project_id'), 'scan_jobs', ['project_id'], unique=False)
    op.create_index(op.f('ix_scan_jobs_run_id'), 'scan_jobs', ['run_id'], unique=False)
    op.create_index(op.f('ix_scan_jobs_status'), 'scan_jobs', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scan_jobs_status'), table_name='scan_jobs')
    op.drop_index(op.f('ix_scan_jobs_run_id'), table_name='scan_jobs')
    op.drop_index(op.f('ix_scan_jobs_project_id'), table_name='scan_jobs')
    op.drop_table('scan_jobs')
    op.drop_table('target_projects')
    op.drop_index(op.f('ix_scan_runs_status'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_created_at'), table_name='scan_runs')
    op.drop_table('scan_runs')
    op.drop_index(op.f('ix_metric_snapshots_project_id'), table_name='metric_snapshots')
    op.drop_index(op.f('ix_metric_snapshots_date'), table_name='metric_snapshots')
    op.drop_table('metric_snapshots')
    op.drop_table('settings')
    op.drop_table('scan_targets')
    op.drop_index(op.f('ix_projects_source_project_id'), table_name='projects')
    op.drop_index(op.f('ix_projects_path_with_namespace'), table_name='projects')
    op.drop_table('projects')
    op.drop_table('project_branch_overrides')
