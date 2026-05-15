"""HTTP-level tests for the session management router (US#56 missing coverage).

`test_session_service.py` exercises the service layer directly; this module
covers the router contract — auth gating, status codes, response schemas, and
the create/list/revoke/revoke-all round trips — through the ASGI app with a
FakeRedis wired into the `get_redis` dependency.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from httpx import AsyncClient

from src.app.models.user import User
from tests.conftest import FakeRedis, auth_header

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def regular_user(db_session: Any) -> User:
    """A plain active user — session endpoints need no role, just authentication."""
    user = User(
        email="sessions@test.com",
        display_name="Session User",
        email_verified=True,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture
def session_client(client_factory: Callable[..., Any], fake_redis: FakeRedis) -> AsyncClient:
    """A client with a FakeRedis bound to `get_redis`."""
    return client_factory(redis=fake_redis)


class TestCreateSession:
    async def test_create_returns_201_with_token(
        self, session_client: AsyncClient, regular_user: User
    ) -> None:
        async with session_client as client:
            resp = await client.post("/api/v1/sessions", headers=auth_header(regular_user))
        assert resp.status_code == 201
        body = resp.json()
        assert "session_id" in body
        assert body["refresh_token"]
        assert "expires_at" in body

    async def test_create_requires_auth(self, session_client: AsyncClient) -> None:
        async with session_client as client:
            resp = await client.post("/api/v1/sessions")
        assert resp.status_code == 422  # missing Authorization header

    async def test_create_rejects_bad_token(self, session_client: AsyncClient) -> None:
        async with session_client as client:
            resp = await client.post(
                "/api/v1/sessions",
                headers={"Authorization": "Bearer not-a-real-token"},
            )
        assert resp.status_code == 401


class TestListSessions:
    async def test_list_empty(self, session_client: AsyncClient, regular_user: User) -> None:
        async with session_client as client:
            resp = await client.get("/api/v1/sessions", headers=auth_header(regular_user))
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 0
        assert body["sessions"] == []

    async def test_list_reflects_created_session(
        self, session_client: AsyncClient, regular_user: User
    ) -> None:
        async with session_client as client:
            headers = auth_header(regular_user)
            await client.post("/api/v1/sessions", headers=headers)
            resp = await client.get("/api/v1/sessions", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 1
        assert len(body["sessions"]) == 1

    async def test_list_requires_auth(self, session_client: AsyncClient) -> None:
        async with session_client as client:
            resp = await client.get("/api/v1/sessions")
        assert resp.status_code == 422


class TestRevokeSession:
    async def test_revoke_existing_returns_204(
        self, session_client: AsyncClient, regular_user: User
    ) -> None:
        async with session_client as client:
            headers = auth_header(regular_user)
            created = await client.post("/api/v1/sessions", headers=headers)
            session_id = created.json()["session_id"]
            resp = await client.delete(f"/api/v1/sessions/{session_id}", headers=headers)
        assert resp.status_code == 204

    async def test_revoke_unknown_returns_404(
        self, session_client: AsyncClient, regular_user: User
    ) -> None:
        async with session_client as client:
            resp = await client.delete(
                f"/api/v1/sessions/{uuid.uuid4()}", headers=auth_header(regular_user)
            )
        assert resp.status_code == 404


class TestRevokeAllSessions:
    async def test_revoke_all_returns_count(
        self, session_client: AsyncClient, regular_user: User
    ) -> None:
        async with session_client as client:
            headers = auth_header(regular_user)
            await client.post("/api/v1/sessions", headers=headers)
            await client.post("/api/v1/sessions", headers=headers)
            resp = await client.delete("/api/v1/sessions", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["revoked_count"] == 2

    async def test_revoke_all_with_no_sessions(
        self, session_client: AsyncClient, regular_user: User
    ) -> None:
        async with session_client as client:
            resp = await client.delete("/api/v1/sessions", headers=auth_header(regular_user))
        assert resp.status_code == 200
        assert resp.json()["revoked_count"] == 0
