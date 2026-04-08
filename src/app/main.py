from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.config import get_settings
from src.app.middleware.cors import add_cors_middleware
from src.app.middleware.security import add_security_headers
from src.app.routers import auth, health, sessions, users

_async_session_factory: async_sessionmaker[AsyncSession] | None = None


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    assert _async_session_factory is not None, "Database not initialized"
    async with _async_session_factory() as session:
        yield session


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _async_session_factory
    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    _async_session_factory = async_sessionmaker(engine, expire_on_commit=False)
    yield
    await engine.dispose()
    _async_session_factory = None


def create_app() -> FastAPI:
    application = FastAPI(
        title="NoorinALabs User Service",
        version="0.1.0",
        lifespan=lifespan,
    )

    add_cors_middleware(application)
    add_security_headers(application)

    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(sessions.router)

    return application


app = create_app()
