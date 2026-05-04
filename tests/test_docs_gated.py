"""Tests for env-keyed disable of FastAPI docs endpoints.

In production, /docs, /redoc, and /openapi.json must return 404. In all other
environments (staging, test, development) they must return 200. The OpenAPI
JSON spec is the underlying leak — Swagger UI just renders it.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from src.app.config import Settings
from src.app.main import create_app


def _make_settings(environment: str) -> Settings:
    return Settings(ENVIRONMENT=environment)  # type: ignore[call-arg]


async def _client_for(environment: str) -> AsyncGenerator[AsyncClient, None]:
    app = create_app(settings=_make_settings(environment))
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_production_returns_404(path: str) -> None:
    async for client in _client_for("production"):
        response = await client.get(path)
        assert response.status_code == 404, f"{path} should be 404 in production"


@pytest.mark.parametrize(
    "environment",
    ["staging", "test", "development"],
)
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_non_production_returns_200(environment: str, path: str) -> None:
    async for client in _client_for(environment):
        response = await client.get(path)
        assert response.status_code == 200, (
            f"{path} should be 200 in ENVIRONMENT={environment}"
        )


async def test_default_environment_serves_docs() -> None:
    """Verify the no-arg create_app() path (which uses get_settings()) still serves
    docs in the default development environment — guards against accidentally
    locking docs out of local dev."""
    app = create_app()
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/openapi.json")
        assert response.status_code == 200
