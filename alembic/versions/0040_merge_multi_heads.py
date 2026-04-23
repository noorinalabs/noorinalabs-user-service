"""Merge multi-heads to single head.

Revision ID: 0040
Revises: 0003, 0020, 0030
Create Date: 2026-04-22

No-op merge migration collapsing three parallel branches (session
last_active, subscription trial constraint, TOTP secrets) into a single
head so `alembic upgrade head` (singular) succeeds without the
`heads`/`head` workaround.
"""

from collections.abc import Sequence

revision: str = "0040"
down_revision: tuple[str, ...] = ("0003", "0020", "0030")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
