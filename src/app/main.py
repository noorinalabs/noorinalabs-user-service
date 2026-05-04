from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.app.config import Settings, get_settings
from src.app.database import close_db, close_redis, init_db, init_redis
from src.app.middleware.cors import add_cors_middleware
from src.app.middleware.security import add_security_headers
from src.app.routers import (
    auth,
    health,
    roles,
    sessions,
    subscriptions,
    totp,
    users,
    verification,
    well_known,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    await init_db()
    await init_redis()
    yield
    await close_redis()
    await close_db()


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = get_settings()

    # Disable interactive docs and the OpenAPI spec in production only.
    # Staging keeps them enabled for QA against testing-mode OAuth allowlist
    # users (deploy#244 runbook); local dev inherits the staging shape.
    is_prod = settings.ENVIRONMENT == "production"
    application = FastAPI(
        title="NoorinALabs User Service",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if is_prod else "/docs",
        redoc_url=None if is_prod else "/redoc",
        openapi_url=None if is_prod else "/openapi.json",
    )

    add_cors_middleware(application)
    add_security_headers(application)

    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(roles.router)
    application.include_router(sessions.router)
    application.include_router(well_known.router)
    application.include_router(verification.router)
    application.include_router(subscriptions.router)
    application.include_router(totp.router)

    return application


app = create_app()
