# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""target source credentials

Revision ID: 92c1348a8202
Revises: 316d94b6b655
Create Date: 2026-09-27 08:11:43.641240+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = '92c1348a8202'
down_revision: str | None = '316d94b6b655'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('scan_targets', sa.Column('source_url', sa.String(length=512), nullable=True))
    op.add_column('scan_targets', sa.Column('source_token', sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column('scan_targets', 'source_token')
    op.drop_column('scan_targets', 'source_url')
