# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""job skip reason

Revision ID: 7cd4fe150b3b
Revises: 40803146bf09
Create Date: 2026-09-26 22:25:37.191772+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = '7cd4fe150b3b'
down_revision: str | None = '40803146bf09'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('scan_jobs', sa.Column('skip_reason', sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column('scan_jobs', 'skip_reason')
