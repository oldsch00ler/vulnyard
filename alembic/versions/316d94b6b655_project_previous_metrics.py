# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""project previous metrics

Revision ID: 316d94b6b655
Revises: 70835a31bdba
Create Date: 2026-09-27 05:45:45.535636+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '316d94b6b655'
down_revision: str | None = '70835a31bdba'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('projects', sa.Column('last_metrics', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('projects', sa.Column('last_metrics_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('projects', 'last_metrics_at')
    op.drop_column('projects', 'last_metrics')
