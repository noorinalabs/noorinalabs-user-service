"""TOTP schemas — US #10."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TOTPSetupResponse(BaseModel):
    """Response after initiating 2FA setup — contains secret and provisioning URI."""

    model_config = ConfigDict(frozen=True)

    secret: str
    provisioning_uri: str
    recovery_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    """Request to verify a TOTP code and enable 2FA."""

    model_config = ConfigDict(frozen=True)

    code: str = Field(min_length=6, max_length=6)


class TOTPVerifyResponse(BaseModel):
    """Response after successfully enabling 2FA."""

    model_config = ConfigDict(frozen=True)

    message: str
    two_factor_enabled: bool


class TOTPDisableRequest(BaseModel):
    """Request to disable 2FA — requires current TOTP code."""

    model_config = ConfigDict(frozen=True)

    code: str = Field(min_length=6, max_length=8)


class TOTPDisableResponse(BaseModel):
    """Response after disabling 2FA."""

    model_config = ConfigDict(frozen=True)

    message: str
    two_factor_enabled: bool


class TOTPStatusResponse(BaseModel):
    """2FA status for user profile."""

    model_config = ConfigDict(frozen=True)

    two_factor_enabled: bool
