"""Tests for User CRUD API and role management endpoints.

Shared fixtures (RSA keygen, token helpers, db_engine/db_session/seed_roles/
admin_user/regular_user/client) live in tests/conftest.py — see US#56.
"""

import uuid

import pytest
from httpx import AsyncClient

from src.app.models.role import Role
from src.app.models.user import User
from tests.conftest import auth_header as _auth_header


class TestGetMe:
    @pytest.mark.asyncio
    async def test_returns_current_user(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get("/api/v1/users/me", headers=_auth_header(regular_user))
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "reader@test.com"
        assert data["display_name"] == "Regular User"

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/users/me")
        assert resp.status_code in (401, 422)


class TestPatchMe:
    @pytest.mark.asyncio
    async def test_update_display_name(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.patch(
            "/api/v1/users/me",
            headers=_auth_header(regular_user),
            json={"display_name": "New Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "New Name"

    @pytest.mark.asyncio
    async def test_update_avatar_url(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.patch(
            "/api/v1/users/me",
            headers=_auth_header(regular_user),
            json={"avatar_url": "https://example.com/avatar.png"},
        )
        assert resp.status_code == 200
        assert resp.json()["avatar_url"] == "https://example.com/avatar.png"


class TestGetUserById:
    @pytest.mark.asyncio
    async def test_admin_can_get_user(
        self, client: AsyncClient, admin_user: User, regular_user: User
    ) -> None:
        resp = await client.get(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "reader@test.com"

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(regular_user),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_not_found(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.get(
            f"/api/v1/users/{uuid.uuid4()}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 404


class TestListUsers:
    @pytest.mark.asyncio
    async def test_admin_can_list(
        self, client: AsyncClient, admin_user: User, regular_user: User
    ) -> None:
        resp = await client.get("/api/v1/users", headers=_auth_header(admin_user))
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) >= 2

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get("/api/v1/users", headers=_auth_header(regular_user))
        assert resp.status_code == 403


class TestDeleteUser:
    @pytest.mark.asyncio
    async def test_admin_soft_deletes(
        self, client: AsyncClient, admin_user: User, regular_user: User
    ) -> None:
        resp = await client.delete(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.delete(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(regular_user),
        )
        assert resp.status_code == 403


class TestRoleEndpoints:
    @pytest.mark.asyncio
    async def test_list_roles(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.get("/api/v1/roles", headers=_auth_header(admin_user))
        assert resp.status_code == 200
        names = {r["name"] for r in resp.json()}
        assert "admin" in names
        assert "researcher" in names

    @pytest.mark.asyncio
    async def test_get_user_roles(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.get(
            f"/api/v1/users/{admin_user.id}/roles",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 200
        names = [r["name"] for r in resp.json()]
        assert "admin" in names

    @pytest.mark.asyncio
    async def test_assign_and_remove_role(
        self,
        client: AsyncClient,
        admin_user: User,
        regular_user: User,
        seed_roles: dict[str, Role],
    ) -> None:
        researcher_role_id = str(seed_roles["researcher"].id)

        # Assign researcher role
        resp = await client.post(
            f"/api/v1/users/{regular_user.id}/roles",
            headers=_auth_header(admin_user),
            json={"role_id": researcher_role_id},
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "researcher"

        # Remove researcher role
        resp = await client.delete(
            f"/api/v1/users/{regular_user.id}/roles/{researcher_role_id}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_assign_role_non_admin_forbidden(
        self,
        client: AsyncClient,
        regular_user: User,
        seed_roles: dict[str, Role],
    ) -> None:
        resp = await client.post(
            f"/api/v1/users/{regular_user.id}/roles",
            headers=_auth_header(regular_user),
            json={"role_id": str(seed_roles["researcher"].id)},
        )
        assert resp.status_code == 403
