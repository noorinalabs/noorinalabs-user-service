"""TOTP routes — US #10."""

from fastapi import APIRouter

router = APIRouter(prefix="/totp", tags=["totp"])
