"""Tests for auth-endpoint rate limiting — US #55.

Covers the rate_limit service directly (limit-hit -> 429, fail-open paths,
bucket isolation, toggle) and an integration check through the /auth/token/validate
endpoint that a per-IP limit produces a 429 once the window budget is spent.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Request, status
from httpx import ASGITransport, AsyncClient
from redis.exceptions import RedisError

from src.app.config import Settings
from src.app.database import get_db_session, get_redis_optional
from src.app.main import create_app
from src.app.services.rate_limit import check_rate_limit, enforce_ip_rate_limit
from src.app.services.token import create_access_token


def _test_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "JWT_PRIVATE_KEY": "",
        "JWT_PUBLIC_KEY": "",
        "AUTH_RATE_LIMIT_ENABLED": True,
        "AUTH_MAX_LOGIN_ATTEMPTS": 3,
        "AUTH_LOCKOUT_DURATION_MINUTES": 15,
    }
    base.update(overrides)
    return Settings(**base)


class _FakeRedis:
    """In-memory async Redis stand-in implementing incr/expire for the limiter.

    Tracks per-key TTL state so tests can assert a key is NOT left orphaned
    without an expiry. `fail_expire_until` lets a test simulate a transient
    Redis blip where EXPIRE raises for the first N calls then recovers.
    """

    def __init__(self, fail_expire_until: int = 0) -> None:
        self._counts: dict[str, int] = {}
        # key -> TTL seconds; absence means "no TTL set" (orphaned key).
        self.ttls: dict[str, int] = {}
        self.expire_calls: list[tuple[str, int]] = []
        self._fail_expire_until = fail_expire_until
        self._expire_attempts = 0

    async def incr(self, key: str) -> int:
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self._expire_attempts += 1
        if self._expire_attempts <= self._fail_expire_until:
            raise RedisError("transient blip during EXPIRE")
        self.expire_calls.append((key, seconds))
        self.ttls[key] = seconds
        return True


class _BrokenRedis:
    """Async Redis stand-in whose incr always raises — exercises fail-open."""

    async def incr(self, key: str) -> int:
        raise RedisError("connection refused")

    async def expire(self, key: str, seconds: int) -> bool:  # pragma: no cover
        raise RedisError("connection refused")


def _request_with_ip(ip: str) -> Request:
    """Minimal ASGI scope Request carrying a client IP."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/auth/token/validate",
        "headers": [],
        "client": (ip, 12345),
    }
    return Request(scope)


class TestCheckRateLimitService:
    async def test_allows_up_to_limit_then_429(self) -> None:
        redis = _FakeRedis()
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=3)

        # First 3 are allowed.
        for _ in range(3):
            await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")

        # 4th exceeds the limit.
        with pytest.raises(HTTPException) as exc_info:
            await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Retry-After" in (exc_info.value.headers or {})

    async def test_expire_reasserted_on_every_call(self) -> None:
        redis = _FakeRedis()
        settings = _test_settings()
        window = settings.AUTH_LOCKOUT_DURATION_MINUTES * 60

        await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")

        # EXPIRE is re-asserted on EVERY call (not just the first), each time with
        # the full window length. This is what makes the limiter self-healing:
        # an orphaned key (EXPIRE missed earlier) gets its TTL back next call.
        assert redis.expire_calls == [("auth_rl:token:1.2.3.4", window)] * 3

    async def test_no_orphaned_key_when_expire_fails_then_recovers(self) -> None:
        """A transient EXPIRE failure must not permanently lock out an identifier.

        Regression test for the INCR/EXPIRE split: if EXPIRE raises on the first
        hit, the key was previously left with no TTL — once Redis recovered it
        INCR'd forever and the identifier was permanently 429'd. With EXPIRE
        re-asserted every call, the next successful call restores the TTL.
        """
        # EXPIRE fails on the first call (transient blip), succeeds afterwards.
        redis = _FakeRedis(fail_expire_until=1)
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=5)
        key = "auth_rl:token:1.2.3.4"
        window = settings.AUTH_LOCKOUT_DURATION_MINUTES * 60

        # First call: INCR succeeds, EXPIRE raises -> fails open (no exception),
        # key is currently orphaned (count=1, no TTL).
        await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        assert key not in redis.ttls  # orphaned at this point

        # Next call: EXPIRE recovers and is re-asserted -> key now has a TTL.
        await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        assert redis.ttls.get(key) == window  # self-healed, no permanent lockout

    async def test_buckets_are_independent(self) -> None:
        redis = _FakeRedis()
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=2)

        # Spend the budget on the "token" bucket.
        await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        with pytest.raises(HTTPException):
            await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")

        # A different bucket for the same identifier still has its full budget.
        await check_rate_limit(redis, settings, bucket="refresh", identifier="1.2.3.4")

    async def test_identifiers_are_independent(self) -> None:
        redis = _FakeRedis()
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=1)

        await check_rate_limit(redis, settings, bucket="token", identifier="1.1.1.1")
        with pytest.raises(HTTPException):
            await check_rate_limit(redis, settings, bucket="token", identifier="1.1.1.1")

        # Different IP — unaffected.
        await check_rate_limit(redis, settings, bucket="token", identifier="2.2.2.2")

    async def test_fail_open_when_redis_none(self) -> None:
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=1)
        # Redis unavailable — never raises, regardless of how many calls.
        for _ in range(10):
            await check_rate_limit(None, settings, bucket="token", identifier="1.2.3.4")

    async def test_fail_open_on_redis_error(self) -> None:
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=1)
        broken = _BrokenRedis()
        for _ in range(10):
            await check_rate_limit(broken, settings, bucket="token", identifier="1.2.3.4")

    async def test_disabled_toggle_skips_limiting(self) -> None:
        redis = _FakeRedis()
        settings = _test_settings(AUTH_RATE_LIMIT_ENABLED=False, AUTH_MAX_LOGIN_ATTEMPTS=1)
        for _ in range(10):
            await check_rate_limit(redis, settings, bucket="token", identifier="1.2.3.4")
        # Limiter never touched Redis.
        assert redis.expire_calls == []

    async def test_enforce_ip_rate_limit_keys_by_client_ip(self) -> None:
        redis = _FakeRedis()
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=1)

        await enforce_ip_rate_limit(_request_with_ip("9.9.9.9"), redis, settings, bucket="validate")
        with pytest.raises(HTTPException) as exc_info:
            await enforce_ip_rate_limit(
                _request_with_ip("9.9.9.9"), redis, settings, bucket="validate"
            )
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # A request from a different IP is still allowed.
        await enforce_ip_rate_limit(_request_with_ip("8.8.8.8"), redis, settings, bucket="validate")


class TestRateLimitIntegration:
    """End-to-end: /auth/token/validate returns 429 once the IP budget is spent."""

    @pytest.fixture
    async def client(self) -> AsyncGenerator[tuple[AsyncClient, Settings], None]:
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=3)
        app = create_app()
        app.dependency_overrides[get_db_session] = lambda: AsyncMock()
        # Shared FakeRedis across requests so the counter accumulates.
        shared_redis = _FakeRedis()

        async def _rl_redis() -> AsyncGenerator[Any, None]:
            yield shared_redis

        app.dependency_overrides[get_redis_optional] = _rl_redis

        from src.app.config import get_settings

        app.dependency_overrides[get_settings] = lambda: settings

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac, settings

    async def test_validate_endpoint_429_after_budget(
        self, client: tuple[AsyncClient, Settings]
    ) -> None:
        ac, settings = client
        token, _ = create_access_token(settings, uuid.uuid4(), "rl@example.com", ["reader"], "free")
        headers = {"Authorization": f"Bearer {token}"}

        # First AUTH_MAX_LOGIN_ATTEMPTS requests succeed.
        for _ in range(settings.AUTH_MAX_LOGIN_ATTEMPTS):
            resp = await ac.get("/auth/token/validate", headers=headers)
            assert resp.status_code == 200

        # Next one is rate limited.
        resp = await ac.get("/auth/token/validate", headers=headers)
        assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "retry-after" in {k.lower() for k in resp.headers}

    async def test_validate_endpoint_fail_open_without_redis(self) -> None:
        """With Redis uninitialized (get_redis_optional yields None), no limiting."""
        settings = _test_settings(AUTH_MAX_LOGIN_ATTEMPTS=1)
        app = create_app()
        app.dependency_overrides[get_db_session] = lambda: AsyncMock()

        from src.app.config import get_settings

        app.dependency_overrides[get_settings] = lambda: settings
        # get_redis_optional is NOT overridden — yields None (Redis not initialized).

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        token, _ = create_access_token(settings, uuid.uuid4(), "rl@example.com", ["reader"], "free")
        headers = {"Authorization": f"Bearer {token}"}
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            for _ in range(5):
                resp = await ac.get("/auth/token/validate", headers=headers)
                assert resp.status_code == 200
