"""Server-side enforcement tests for the cross-method OAuth account-linking guard.

Issues #153 (cross-provider OAuth → OAuth collision) and #154 (password account
→ OAuth collision). Unlike ``test_oauth_callback.py`` (which mocks the DB
session), these tests run ``find_or_create_oauth_user`` against a REAL in-memory
SQLite database with the colliding account actually persisted. They prove the
rejection is enforced by the service's real SQL queries — not by a test mock —
which is the security-relevant property: silent, unconsented account-linking is
an account-takeover surface and must be blocked server-side.

After each rejection we re-query ``oauth_accounts`` to assert NO link row was
written, so a future regression that swallows the error but still links would
fail here.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.models.oauth_account import OAuthAccount
from src.app.models.user import Base, User
from src.app.services.user import (
    AccountExistsWithDifferentMethodError,
    find_or_create_oauth_user,
)


@pytest.fixture
async def db_engine():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:  # type: ignore[no-untyped-def, type-arg]
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


async def _seed_oauth_user(
    db: AsyncSession, *, email: str, provider: str, provider_account_id: str
) -> User:
    """Persist a user whose only auth method is the given OAuth provider."""
    user = User(id=uuid.uuid4(), email=email, email_verified=True, is_active=True)
    db.add(user)
    await db.flush()
    db.add(
        OAuthAccount(user_id=user.id, provider=provider, provider_account_id=provider_account_id)
    )
    await db.commit()
    return user


async def _seed_password_user(db: AsyncSession, *, email: str) -> User:
    """Persist a user whose only auth method is a password."""
    user = User(
        id=uuid.uuid4(),
        email=email,
        email_verified=True,
        password_hash="argon2:$fakehash",
        is_active=True,
    )
    db.add(user)
    await db.commit()
    return user


async def _count_links(db: AsyncSession, user_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.count()).select_from(OAuthAccount).where(OAuthAccount.user_id == user_id)
    )
    return int(result.scalar_one())


class TestCrossMethodLinkingGuardServerSide:
    @pytest.mark.asyncio
    async def test_google_then_github_same_email_rejected_no_link_written(
        self, db_session: AsyncSession
    ) -> None:
        """#153 — google account + github login, same email → reject, no link."""
        user = await _seed_oauth_user(
            db_session, email="alice@example.com", provider="google", provider_account_id="g-1"
        )

        with pytest.raises(AccountExistsWithDifferentMethodError) as excinfo:
            await find_or_create_oauth_user(
                db_session,
                provider="github",
                provider_account_id="gh-1",
                email="alice@example.com",
                display_name="Alice",
                avatar_url=None,
            )

        assert excinfo.value.primary_method == "google"
        assert excinfo.value.existing_methods == ["google"]
        # The real proof: the github link was NOT persisted — only the original
        # google link remains on the account.
        assert await _count_links(db_session, user.id) == 1

    @pytest.mark.asyncio
    async def test_github_then_google_same_email_rejected_no_link_written(
        self, db_session: AsyncSession
    ) -> None:
        """#153 — reversed providers, same outcome."""
        user = await _seed_oauth_user(
            db_session, email="carol@example.com", provider="github", provider_account_id="gh-2"
        )

        with pytest.raises(AccountExistsWithDifferentMethodError) as excinfo:
            await find_or_create_oauth_user(
                db_session,
                provider="google",
                provider_account_id="g-2",
                email="carol@example.com",
                display_name="Carol",
                avatar_url=None,
            )

        assert excinfo.value.primary_method == "github"
        assert await _count_links(db_session, user.id) == 1

    @pytest.mark.asyncio
    async def test_password_then_google_same_email_rejected_no_link_written(
        self, db_session: AsyncSession
    ) -> None:
        """#154 — password account + google login, same email → reject, no link."""
        user = await _seed_password_user(db_session, email="bob@example.com")

        with pytest.raises(AccountExistsWithDifferentMethodError) as excinfo:
            await find_or_create_oauth_user(
                db_session,
                provider="google",
                provider_account_id="g-3",
                email="bob@example.com",
                display_name="Bob",
                avatar_url=None,
            )

        assert excinfo.value.primary_method == "password"
        assert str(excinfo.value) == "bob@example.com is already registered as password"
        # No OAuth link was attached to the password account.
        assert await _count_links(db_session, user.id) == 0

    @pytest.mark.asyncio
    async def test_password_then_github_same_email_rejected(self, db_session: AsyncSession) -> None:
        """#154 — password account + github login, same email → reject."""
        user = await _seed_password_user(db_session, email="dave@example.com")

        with pytest.raises(AccountExistsWithDifferentMethodError):
            await find_or_create_oauth_user(
                db_session,
                provider="github",
                provider_account_id="gh-3",
                email="dave@example.com",
                display_name="Dave",
                avatar_url=None,
            )
        assert await _count_links(db_session, user.id) == 0

    @pytest.mark.asyncio
    async def test_same_provider_relogin_unchanged(self, db_session: AsyncSession) -> None:
        """Step 1 regression — re-login with the SAME provider account logs in,
        no new link, no rejection."""
        user = await _seed_oauth_user(
            db_session, email="eve@example.com", provider="google", provider_account_id="g-eve"
        )

        result = await find_or_create_oauth_user(
            db_session,
            provider="google",
            provider_account_id="g-eve",
            email="eve@example.com",
            display_name="Eve",
            avatar_url=None,
        )
        assert result.user.id == user.id
        assert result.is_new_user is False
        assert await _count_links(db_session, user.id) == 1

    @pytest.mark.asyncio
    async def test_brand_new_email_signup_unchanged(self, db_session: AsyncSession) -> None:
        """Step 3 regression — an unknown verified email creates a fresh user +
        link; no rejection."""
        result = await find_or_create_oauth_user(
            db_session,
            provider="github",
            provider_account_id="gh-new",
            email="frank@example.com",
            display_name="Frank",
            avatar_url=None,
        )
        assert result.is_new_user is True
        assert result.user.email == "frank@example.com"
        assert await _count_links(db_session, result.user.id) == 1
