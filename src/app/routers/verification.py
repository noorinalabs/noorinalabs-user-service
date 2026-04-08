"""Verification routes — US #8."""

from fastapi import APIRouter, HTTPException, status

from src.app.dependencies import CurrentUserDep, DbDep, SettingsDep
from src.app.schemas.verification import (
    VerificationConfirmRequest,
    VerificationConfirmResponse,
    VerificationSendRequest,
    VerificationSendResponse,
    VerificationStatusResponse,
)
from src.app.services.verification import (
    check_rate_limit,
    confirm_verification_token,
    create_verification_token,
    get_latest_verification_token,
    send_verification_email,
)

router = APIRouter(prefix="/verification", tags=["verification"])


@router.post(
    "/send",
    response_model=VerificationSendResponse,
    status_code=status.HTTP_200_OK,
)
async def send_verification(
    body: VerificationSendRequest,
    user: CurrentUserDep,
    db: DbDep,
    settings: SettingsDep,
) -> VerificationSendResponse:
    """Send a verification email to the current user."""
    if user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified",
        )

    if body.email != user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email does not match authenticated user",
        )

    within_limit = await check_rate_limit(db, user.id, settings)
    if not within_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded — max 3 verification emails per hour",
        )

    raw_token = await create_verification_token(db, user.id, settings)
    await db.commit()

    await send_verification_email(user.email, raw_token, settings)

    return VerificationSendResponse(message="Verification email sent")


@router.post(
    "/confirm",
    response_model=VerificationConfirmResponse,
    status_code=status.HTTP_200_OK,
)
async def confirm_verification(
    body: VerificationConfirmRequest,
    db: DbDep,
) -> VerificationConfirmResponse:
    """Confirm an email verification token."""
    user = await confirm_verification_token(db, body.token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used verification token",
        )
    await db.commit()
    return VerificationConfirmResponse(
        message="Email verified successfully",
        email_verified=True,
    )


@router.get(
    "/status",
    response_model=VerificationStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def verification_status(
    user: CurrentUserDep,
    db: DbDep,
) -> VerificationStatusResponse:
    """Check the current user's email verification status."""
    latest_token = await get_latest_verification_token(db, user.id)
    return VerificationStatusResponse(
        user_id=user.id,
        email=user.email,
        email_verified=user.email_verified,
        verification_sent_at=latest_token.created_at if latest_token else None,
    )
