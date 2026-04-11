"""Initial schema — users, roles, sessions, subscriptions, oauth, verification tokens.

Revision ID: 0001
Revises:
Create Date: 2026-04-07
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Enums
subscription_plan = sa.Enum(
    "free", "trial", "researcher", "institutional", name="subscription_plan"
)
subscription_status = sa.Enum(
    "active", "expired", "cancelled", "suspended", name="subscription_status"
)
token_type = sa.Enum(
    "email_verification", "password_reset", "magic_link", name="token_type"
)


def upgrade() -> None:
    # --- users ---
    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.UUID(),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("avatar_url", sa.String(512), nullable=True),
        sa.Column("locale", sa.String(10), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # --- roles ---
    op.create_table(
        "roles",
        sa.Column(
            "id",
            sa.UUID(),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_roles_name", "roles", ["name"], unique=True)

    # --- user_roles ---
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("role_id", sa.UUID(), sa.ForeignKey("roles.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("granted_by", sa.UUID(), sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
    )

    # --- sessions ---
    op.create_table(
        "sessions",
        sa.Column(
            "id",
            sa.UUID(),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    # --- subscriptions ---
    op.create_table(
        "subscriptions",
        sa.Column(
            "id",
            sa.UUID(),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("plan", subscription_plan, nullable=False),
        sa.Column("status", subscription_status, nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # --- verification_tokens ---
    op.create_table(
        "verification_tokens",
        sa.Column(
            "id",
            sa.UUID(),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column("token_type", token_type, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_verification_tokens_token_hash", "verification_tokens", ["token_hash"], unique=True
    )
    op.create_index(
        "ix_verification_tokens_lookup",
        "verification_tokens",
        ["token_hash", "expires_at"],
    )

    # --- oauth_accounts ---
    op.create_table(
        "oauth_accounts",
        sa.Column(
            "id",
            sa.UUID(),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("provider_account_id", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_oauth_accounts_provider_account",
        "oauth_accounts",
        ["provider", "provider_account_id"],
        unique=True,
    )

    # --- Seed default roles ---
    roles_table = sa.table(
        "roles",
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
    )
    op.bulk_insert(
        roles_table,
        [
            {"name": "admin", "description": "Full platform administration access"},
            {"name": "researcher", "description": "Access to research tools and datasets"},
            {"name": "reader", "description": "Read-only access to public content"},
            {"name": "trial", "description": "Time-limited trial access"},
        ],
    )


def downgrade() -> None:
    op.drop_table("oauth_accounts")
    op.drop_table("verification_tokens")
    op.drop_table("subscriptions")
    op.drop_table("sessions")
    op.drop_table("user_roles")
    op.drop_table("roles")
    op.drop_table("users")

    subscription_plan.drop(op.get_bind())  # type: ignore[arg-type]
    subscription_status.drop(op.get_bind())  # type: ignore[arg-type]
    token_type.drop(op.get_bind())  # type: ignore[arg-type]
