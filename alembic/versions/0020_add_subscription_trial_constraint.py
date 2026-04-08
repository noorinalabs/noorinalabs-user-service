"""Add partial unique index to prevent concurrent active trials.

Revision ID: 0020
Revises: 0001
Create Date: 2026-04-08
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0020"
down_revision: str = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_subscriptions_one_active_trial",
        "subscriptions",
        ["user_id"],
        unique=True,
        postgresql_where="plan = 'trial' AND status = 'active'",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_subscriptions_one_active_trial",
        table_name="subscriptions",
    )
