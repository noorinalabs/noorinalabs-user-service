"""Connection-URL construction from separate component env vars (#65).

The bug: a base64 ``USER_REDIS_PASSWORD`` containing ``/`` was string-interpolated
into ``redis://:<pw>@host:6379/0``; the first ``/`` terminated the URL authority
and ``urlparse`` crashed reading ``host:port`` at startup. The fix accepts separate
component env vars and builds the URL in-app with the password URL-encoded.
"""

from urllib.parse import urlparse

import pytest
from redis.asyncio import Redis
from sqlalchemy.engine import make_url

from src.app.config import Settings

# Every URL-reserved character that previously could corrupt a connection URL.
URL_UNSAFE_PASSWORDS = [
    "tW/Q37WBF/HilCx8Lls4o/J7UKrKsoA7jTI5o/Jd2tk=",  # the real #65 repro value
    "p/a/s/s",
    "pa+ss",
    "pass==",
    "p@ss",
    "pa:ss",
    "pa#ss",
    "pa?ss",
    "pa%ss",
    "a/b+c=d@e:f#g?h%i",  # all of them at once
]


class TestRedisUrlFromComponents:
    def test_falls_back_to_redis_url_when_host_unset(self) -> None:
        s = Settings(REDIS_URL="redis://localhost:6380/2")
        assert s.effective_redis_url == "redis://localhost:6380/2"

    def test_components_win_over_redis_url(self) -> None:
        s = Settings(
            REDIS_URL="redis://localhost:6380/0",
            REDIS_HOST="user-redis",
            REDIS_PORT=6379,
            REDIS_PASSWORD="simplepass",
            REDIS_DB=1,
        )
        parsed = urlparse(s.effective_redis_url)
        assert parsed.scheme == "redis"
        assert parsed.hostname == "user-redis"
        assert parsed.port == 6379
        assert parsed.path == "/1"

    def test_no_password_omits_authority(self) -> None:
        s = Settings(REDIS_HOST="user-redis", REDIS_PORT=6379, REDIS_DB=0)
        assert s.effective_redis_url == "redis://user-redis:6379/0"

    def test_tls_uses_rediss_scheme(self) -> None:
        s = Settings(REDIS_HOST="user-redis", REDIS_TLS=True)
        assert urlparse(s.effective_redis_url).scheme == "rediss"

    @pytest.mark.parametrize("password", URL_UNSAFE_PASSWORDS)
    def test_url_unsafe_password_parses_and_roundtrips(self, password: str) -> None:
        """Host/port must parse correctly and the redis client must recover the raw password."""
        s = Settings(
            REDIS_HOST="user-redis",
            REDIS_PORT=6379,
            REDIS_PASSWORD=password,
            REDIS_DB=0,
        )
        url = s.effective_redis_url
        # urlparse must not choke on host:port (the original #65 crash).
        parsed = urlparse(url)
        assert parsed.hostname == "user-redis"
        assert parsed.port == 6379
        # The redis client must decode the password back to the raw value.
        client = Redis.from_url(url, decode_responses=False)
        kwargs = client.connection_pool.connection_kwargs
        assert kwargs["host"] == "user-redis"
        assert kwargs["port"] == 6379
        assert kwargs["password"] == password


class TestDatabaseUrlFromComponents:
    def test_falls_back_to_database_url_when_host_unset(self) -> None:
        url = "postgresql+asyncpg://u:p@localhost:5433/db"
        s = Settings(DATABASE_URL=url)
        assert s.effective_database_url == url

    def test_components_win_over_database_url(self) -> None:
        s = Settings(
            DATABASE_URL="postgresql+asyncpg://u:p@localhost:5433/db",
            DATABASE_HOST="user-postgres",
            DATABASE_PORT=5432,
            DATABASE_USER="user_service",
            DATABASE_PASSWORD="simplepass",
            DATABASE_NAME="user_service",
        )
        parsed = make_url(s.effective_database_url)
        assert parsed.drivername == "postgresql+asyncpg"
        assert parsed.host == "user-postgres"
        assert parsed.port == 5432
        assert parsed.username == "user_service"
        assert parsed.database == "user_service"

    @pytest.mark.parametrize("password", URL_UNSAFE_PASSWORDS)
    def test_url_unsafe_password_parses_and_roundtrips(self, password: str) -> None:
        s = Settings(
            DATABASE_HOST="user-postgres",
            DATABASE_PORT=5432,
            DATABASE_USER="user_service",
            DATABASE_PASSWORD=password,
            DATABASE_NAME="user_service",
        )
        # SQLAlchemy must parse the URL back and recover the raw password.
        parsed = make_url(s.effective_database_url)
        assert parsed.host == "user-postgres"
        assert parsed.port == 5432
        assert parsed.username == "user_service"
        assert parsed.database == "user_service"
        assert parsed.password == password
