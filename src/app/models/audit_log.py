"""Audit log model — user-service#200.

Append-only, immutable record of admin actions. This is the producer half of the
cross-repo audit-log relocation (consumer sibling: isnad-graph#1140); the owner
decided the relational ``audit_log`` table lives in user-service Postgres.

The field shape mirrors the isnad-graph ``:AUDIT_LOG`` Neo4j node exactly so the
relocation is a drop-in: keys ``id, action, actor_id, actor_name, details,
created_at`` plus a nullable ``target_user_id``.

Design notes:
- **No foreign key** on ``actor_id`` / ``target_user_id``. Audit entries must
  survive user deletion — they are an immutable historical record, not a live
  relationship. A FK + ``ON DELETE`` would either erase or block the record.
- **Append-only.** There are no UPDATE or DELETE code paths in the service or
  router; the table is written once and read thereafter.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column

from src.app.models.user import Base


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        # Hot read path is "latest first", so the created_at index is descending.
        Index("ix_audit_log_created_at", text("created_at DESC")),
        Index("ix_audit_log_action", "action"),
    )

    # Python-side default mirrors the User/Subscription convention; the Postgres
    # server default (gen_random_uuid()) is applied by the migration.
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    # No FK — audit records outlive the users they reference.
    actor_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    actor_name: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=text("''")
    )
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    details: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=text("''")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
