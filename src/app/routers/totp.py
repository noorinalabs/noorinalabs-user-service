"""TOTP routes — US #10."""

from fastapi import APIRouter, HTTPException, status

from src.app.dependencies import CurrentUserDep, DbDep, SettingsDep
from src.app.schemas.totp import (
    TOTPDisableRequest,
    TOTPDisableResponse,
    TOTPSetupResponse,
    TOTPStatusResponse,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
)
from src.app.services.totp import (
    disable_totp,
    get_totp_secret,
    is_2fa_enabled,
    setup_totp,
    verify_totp_setup,
)

router = APIRouter(prefix="/api/v1/2fa", tags=["2fa"])


@router.post(
    "/setup",
    response_model=TOTPSetupResponse,
    status_code=status.HTTP_200_OK,
)
async def totp_setup(
    user: CurrentUserDep,
    db: DbDep,
    settings: SettingsDep,
) -> TOTPSetupResponse:
    """Generate a TOTP secret and provisioning URI for 2FA setup."""
    try:
        secret, uri, recovery_codes = await setup_totp(db, user.id, user.email, settings)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    await db.commit()
    return TOTPSetupResponse(
        secret=secret,
        provisioning_uri=uri,
        recovery_codes=recovery_codes,
    )


@router.post(
    "/verify",
    response_model=TOTPVerifyResponse,
    status_code=status.HTTP_200_OK,
)
async def totp_verify(
    body: TOTPVerifyRequest,
    user: CurrentUserDep,
    db: DbDep,
    settings: SettingsDep,
) -> TOTPVerifyResponse:
    """Verify a TOTP code to enable 2FA."""
    success = await verify_totp_setup(db, user.id, body.code, settings)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code or 2FA not in setup state",
        )
    await db.commit()
    return TOTPVerifyResponse(
        message="2FA enabled successfully",
        two_factor_enabled=True,
    )


@router.post(
    "/disable",
    response_model=TOTPDisableResponse,
    status_code=status.HTTP_200_OK,
)
async def totp_disable(
    body: TOTPDisableRequest,
    user: CurrentUserDep,
    db: DbDep,
    settings: SettingsDep,
) -> TOTPDisableResponse:
    """Disable 2FA — requires a valid TOTP code or recovery code."""
    success = await disable_totp(db, user.id, body.code, settings)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code or 2FA not enabled",
        )
    await db.commit()
    return TOTPDisableResponse(
        message="2FA disabled successfully",
        two_factor_enabled=False,
    )


@router.get(
    "/status",
    response_model=TOTPStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def totp_status(
    user: CurrentUserDep,
    db: DbDep,
) -> TOTPStatusResponse:
    """Check 2FA status for the current user."""
    secret = await get_totp_secret(db, user.id)
    return TOTPStatusResponse(two_factor_enabled=is_2fa_enabled(secret))
