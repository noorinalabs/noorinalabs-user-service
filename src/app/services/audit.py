"""Audit log business logic — user-service#200.

Append-only: this module exposes a create and a (paginated) read path only. There
is deliberately no update or delete — an audit record is written once and is then
immutable (see ``models.audit_log`` for the rationale).
"""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.models.audit_log import AuditLog
from src.app.schemas.audit import AuditLogCreate


async def create_entry(db: AsyncSession, data: AuditLogCreate) -> AuditLog:
    """Insert one audit entry and return it with server-side fields populated.

    The caller is responsible for committing the session.
    """
    entry = AuditLog(
        action=data.action,
        actor_id=data.actor_id,
        actor_name=data.actor_name,
        target_user_id=data.target_user_id,
        details=data.details,
    )
    db.add(entry)
    await db.flush()
    # Load the server-defaulted columns (id is set client-side; created_at and
    # the empty-string defaults come from the database).
    await db.refresh(entry)
    return entry


async def list_entries(
    db: AsyncSession,
    *,
    page: int,
    limit: int,
    action: str | None = None,
) -> tuple[list[AuditLog], int]:
    """Return one page of audit entries (newest first) plus the total count.

    ``action``, when given, is an exact-match filter applied to both the page
    query and the count so ``total`` reflects the filtered set.
    """
    filters = []
    if action is not None:
        filters.append(AuditLog.action == action)

    count_stmt = select(func.count()).select_from(AuditLog)
    page_stmt = select(AuditLog)
    for f in filters:
        count_stmt = count_stmt.where(f)
        page_stmt = page_stmt.where(f)

    total = (await db.execute(count_stmt)).scalar_one()
    result = await db.execute(
        page_stmt.order_by(AuditLog.created_at.desc()).offset((page - 1) * limit).limit(limit)
    )
    return list(result.scalars().all()), int(total)
