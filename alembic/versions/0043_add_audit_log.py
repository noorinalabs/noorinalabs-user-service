"""Add audit_log table — user-service#200.

Append-only, immutable audit trail of admin actions. Producer half of the
cross-repo audit-log relocation (consumer sibling: isnad-graph#1140); the owner
decided the relational record lives in user-service Postgres. The field shape
mirrors the isnad-graph ``:AUDIT_LOG`` Neo4j node exactly.

No foreign key on ``actor_id`` / ``target_user_id``: an audit entry must outlive
the user it references (immutable historical record, not a live relationship).
``gen_random_uuid()`` is a built-in on PostgreSQL 16 — no pgcrypto extension
needed.

Revision ID: 0043
Revises: 0042
Create Date: 2026-06-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0043"
down_revision: str = "0042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "actor_name",
            sa.Text(),
            nullable=False,
            server_default=sa.text("''"),
        ),
        sa.Column("target_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "details",
            sa.Text(),
            nullable=False,
            server_default=sa.text("''"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    # Hot read path is "latest first", so the created_at index is descending.
    op.create_index(
        "ix_audit_log_created_at",
        "audit_log",
        [sa.text("created_at DESC")],
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_created_at", table_name="audit_log")
    op.drop_table("audit_log")
