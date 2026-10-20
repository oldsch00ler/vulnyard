# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""target notification webhook

Revision ID: 70835a31bdba
Revises: 7cd4fe150b3b
Create Date: 2026-09-27 04:56:54.936564+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = '70835a31bdba'
down_revision: str | None = '7cd4fe150b3b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('scan_targets', sa.Column('notify_webhook_url', sa.String(length=1024), nullable=True))


def downgrade() -> None:
    op.drop_column('scan_targets', 'notify_webhook_url')
