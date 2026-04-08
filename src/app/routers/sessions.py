"""Session management routes — US #7."""

import uuid

from fastapi import APIRouter, HTTPException, Request, status

from src.app.dependencies import CurrentUserDep, DbDep, RedisDep
from src.app.schemas.session import (
    RevokeAllResponse,
    SessionCreateResponse,
    SessionListResponse,
    SessionResponse,
)
from src.app.services.session import (
    create_session,
    list_user_sessions,
    revoke_all_sessions,
    revoke_session,
)
from src.app.services.token import _hash_token, create_refresh_token

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.post(
    "",
    response_model=SessionCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_session(
    request: Request,
    user: CurrentUserDep,
    db: DbDep,
    redis: RedisDep,
) -> SessionCreateResponse:
    """Create a new session for the authenticated user."""
    token = create_refresh_token()
    token_hash = _hash_token(token)
    session = await create_session(
        db=db,
        redis=redis,
        user_id=user.id,
        token_hash=token_hash,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return SessionCreateResponse(
        session_id=session.id,
        expires_at=session.expires_at,
    )


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    user: CurrentUserDep,
    db: DbDep,
    redis: RedisDep,
) -> SessionListResponse:
    """List all active sessions for the current user."""
    sessions = await list_user_sessions(db=db, redis=redis, user_id=user.id)
    return SessionListResponse(
        sessions=[SessionResponse(**s) for s in sessions],
        count=len(sessions),
    )


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_single_session(
    session_id: uuid.UUID,
    user: CurrentUserDep,
    db: DbDep,
    redis: RedisDep,
) -> None:
    """Revoke a specific session."""
    revoked = await revoke_session(db=db, redis=redis, session_id=session_id, user_id=user.id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already revoked",
        )


@router.delete("", response_model=RevokeAllResponse)
async def revoke_all_user_sessions(
    user: CurrentUserDep,
    db: DbDep,
    redis: RedisDep,
) -> RevokeAllResponse:
    """Revoke all sessions for the current user (logout everywhere)."""
    count = await revoke_all_sessions(db=db, redis=redis, user_id=user.id)
    return RevokeAllResponse(revoked_count=count)
