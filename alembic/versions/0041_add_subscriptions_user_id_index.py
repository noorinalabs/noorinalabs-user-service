"""Add index on subscriptions.user_id.

The subscriptions table only had a partial unique index covering
(user_id) WHERE plan='trial' AND status='active'. Equality lookups by
user_id alone — get_current_subscription, get_subscription_status,
start_trial, cancel_subscription — could not use it and fell back to a
sequential scan. This adds a plain B-tree index on user_id.

Revision ID: 0041
Revises: 0040
Create Date: 2026-05-14
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0041"
down_revision: str = "0040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_subscriptions_user_id",
        "subscriptions",
        ["user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_subscriptions_user_id", table_name="subscriptions")
