# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""ignore rules

Revision ID: c4f1a9d2e7b8
Revises: 92c1348a8202
Create Date: 2026-09-29 10:40:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = 'c4f1a9d2e7b8'
down_revision: str | None = '92c1348a8202'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'ignore_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vuln_id', sa.String(length=128), nullable=False),
        sa.Column('purl_pattern', sa.String(length=512), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=True),
        sa.Column('analysis_state', sa.String(length=32), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expires_on', sa.Date(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_ignore_rules_vuln_id'), 'ignore_rules', ['vuln_id'])
    op.create_index(op.f('ix_ignore_rules_target_id'), 'ignore_rules', ['target_id'])

    op.create_table(
        'ignore_applications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('rule_id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('dt_project_uuid', sa.String(length=64), nullable=False),
        sa.Column('dt_component_uuid', sa.String(length=64), nullable=False),
        sa.Column('dt_vulnerability_uuid', sa.String(length=64), nullable=False),
        sa.Column('purl', sa.String(length=512), nullable=True),
        sa.Column('applied_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['rule_id'], ['ignore_rules.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'rule_id',
            'dt_component_uuid',
            'dt_vulnerability_uuid',
            name='uq_ignore_applications_rule_component_vuln',
        ),
    )
    op.create_index(op.f('ix_ignore_applications_rule_id'), 'ignore_applications', ['rule_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_ignore_applications_rule_id'), table_name='ignore_applications')
    op.drop_table('ignore_applications')
    op.drop_index(op.f('ix_ignore_rules_target_id'), table_name='ignore_rules')
    op.drop_index(op.f('ix_ignore_rules_vuln_id'), table_name='ignore_rules')
    op.drop_table('ignore_rules')
