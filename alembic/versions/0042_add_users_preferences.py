"""Add JSONB preferences column to users.

US #165 — stores arbitrary per-user UI/UX preferences (theme, language, …).
NOT NULL with a server default of ``'{}'`` so existing rows backfill to an
empty object and the column is never NULL for downstream readers.

Revision ID: 0042
Revises: 0041
Create Date: 2026-06-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0042"
down_revision: str = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "preferences",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "preferences")
