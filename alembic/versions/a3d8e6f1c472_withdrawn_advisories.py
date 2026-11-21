# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""withdrawn advisories

Revision ID: a3d8e6f1c472
Revises: e5a7c3b91d20
Create Date: 2026-11-21 10:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = 'a3d8e6f1c472'
down_revision: str | None = 'e5a7c3b91d20'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'advisory_statuses',
        sa.Column('vuln_id', sa.String(length=128), nullable=False),
        sa.Column('withdrawn_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('dismissed', sa.Boolean(), server_default='false', nullable=False),
        sa.PrimaryKeyConstraint('vuln_id'),
    )
    op.add_column(
        'ignore_rules',
        sa.Column('origin', sa.String(length=16), server_default='manual', nullable=False),
    )


def downgrade() -> None:
    op.drop_column('ignore_rules', 'origin')
    op.drop_table('advisory_statuses')
