from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from src.app.main import create_app


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
