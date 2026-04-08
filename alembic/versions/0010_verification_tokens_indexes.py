"""Add indexes to verification_tokens for rate limiting and user lookups.

Revision ID: 0010
Revises: 0001
Create Date: 2026-04-08
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_verification_tokens_user_id",
        "verification_tokens",
        ["user_id"],
    )
    op.create_index(
        "ix_verification_tokens_rate_limit",
        "verification_tokens",
        ["user_id", "token_type", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_verification_tokens_rate_limit", table_name="verification_tokens")
    op.drop_index("ix_verification_tokens_user_id", table_name="verification_tokens")
