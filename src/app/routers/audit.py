"""Audit log endpoints — user-service#200.

Admin-gated create + list for the relational audit trail. The producer half of
the cross-repo relocation consumed by isnad-graph#1140: isnad-graph's admin
layer forwards the admin's user-service-issued JWT here (user-service is the
token issuer, so it validates its own token via the shared admin RBAC
dependency).
"""

from fastapi import APIRouter, Query, status

from src.app.dependencies import AdminUserDep, DbDep
from src.app.schemas.audit import AuditLogCreate, AuditLogListResponse, AuditLogRead
from src.app.services import audit as audit_svc

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.post("", response_model=AuditLogRead, status_code=status.HTTP_201_CREATED)
async def create_audit_entry(
    data: AuditLogCreate,
    _admin: AdminUserDep,
    db: DbDep,
) -> AuditLogRead:
    """Record a single audit entry (admin only)."""
    entry = await audit_svc.create_entry(db, data)
    await db.commit()
    return AuditLogRead.model_validate(entry)


@router.get("", response_model=AuditLogListResponse)
async def list_audit_entries(
    _admin: AdminUserDep,
    db: DbDep,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    action: str | None = Query(default=None),
) -> AuditLogListResponse:
    """List audit entries newest-first, offset-paginated (admin only)."""
    items, total = await audit_svc.list_entries(db, page=page, limit=limit, action=action)
    return AuditLogListResponse(
        items=[AuditLogRead.model_validate(e) for e in items],
        total=total,
        page=page,
        limit=limit,
    )
