"""User service — CRUD operations and OAuth account linking."""

from __future__ import annotations

import uuid
from base64 import b64decode, b64encode
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from src.app.models.oauth_account import OAuthAccount
from src.app.models.role import UserRole
from src.app.models.user import User
from src.app.schemas.user import UserUpdate

# --- User CRUD ---


async def get_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(
        select(User)
        .options(joinedload(User.user_roles).joinedload(UserRole.role))
        .where(User.id == user_id)
    )
    return result.unique().scalar_one_or_none()


async def update_profile(db: AsyncSession, user: User, data: UserUpdate) -> User:
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)
    await db.flush()
    await db.refresh(user)
    return user


async def list_users(
    db: AsyncSession,
    cursor: str | None = None,
    limit: int = 20,
) -> tuple[list[User], str | None]:
    query = (
        select(User)
        .options(joinedload(User.user_roles).joinedload(UserRole.role))
        .order_by(User.created_at, User.id)
        .limit(limit + 1)
    )

    if cursor:
        try:
            decoded = b64decode(cursor).decode()
            ts_str, uid_str = decoded.rsplit("|", 1)
            cursor_ts = datetime.fromisoformat(ts_str)
            cursor_id = uuid.UUID(uid_str)
        except (ValueError, UnicodeDecodeError):
            pass
        else:
            query = query.where(
                (User.created_at > cursor_ts)
                | ((User.created_at == cursor_ts) & (User.id > cursor_id))
            )

    result = await db.execute(query)
    users = list(result.unique().scalars().all())

    next_cursor: str | None = None
    if len(users) > limit:
        users = users[:limit]
        last = users[-1]
        raw = f"{last.created_at.isoformat()}|{last.id}"
        next_cursor = b64encode(raw.encode()).decode()

    return users, next_cursor


async def soft_delete(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    user = await get_by_id(db, user_id)
    if user is None:
        return None
    user.is_active = False
    await db.flush()
    await db.refresh(user)
    return user


# --- OAuth User Linking ---


class OAuthUserResult:
    """Result of find_or_create_oauth_user."""

    def __init__(self, user: User, is_new_user: bool) -> None:
        self.user = user
        self.is_new_user = is_new_user


class AccountExistsWithDifferentMethodError(Exception):
    """Raised when an OAuth login's verified email matches an existing account
    that authenticates via a *different* method (a password, or a different
    OAuth provider).

    The callback maps this to a user-facing "{email} is already registered as
    {method}" error rather than silently linking the new provider — silent
    cross-method linking is account-linking without consent and is an
    account-takeover surface (issues #153 / #154).

    `existing_methods` is the ordered, de-duplicated list of methods the
    account already authenticates with (e.g. ``["password", "google"]``).
    `primary_method` is the first of those, used for the single-method UX
    string.
    """

    def __init__(self, *, email: str, existing_methods: list[str]) -> None:
        self.email = email
        self.existing_methods = existing_methods
        self.primary_method = existing_methods[0] if existing_methods else "password"
        methods = ", ".join(existing_methods) if existing_methods else "password"
        super().__init__(f"{email} is already registered as {methods}")


async def _existing_auth_methods(db: AsyncSession, user: User) -> list[str]:
    """Enumerate the auth methods an existing account already uses.

    Returns an ordered, de-duplicated list: ``"password"`` first (if the user
    has a password set), followed by each linked OAuth provider in insertion
    order. Used to populate the "already registered as {method}" rejection.
    """
    methods: list[str] = []
    if user.password_hash:
        methods.append("password")

    link_stmt = (
        select(OAuthAccount.provider)
        .where(OAuthAccount.user_id == user.id)
        .order_by(OAuthAccount.created_at)
    )
    link_result = await db.execute(link_stmt)
    for provider in link_result.scalars().all():
        if provider not in methods:
            methods.append(provider)
    return methods


async def find_or_create_oauth_user(
    db: AsyncSession,
    *,
    provider: str,
    provider_account_id: str,
    email: str | None,
    display_name: str | None,
    avatar_url: str | None,
) -> OAuthUserResult:
    """Find an existing user by OAuth link, or create a new one.

    Lookup order:
    1. Match by (provider, provider_account_id) in oauth_accounts → log in.
    2. Match by verified email in users → REJECT with
       ``AccountExistsWithDifferentMethodError`` (the email already belongs to
       a different auth method; silent linking is unconsented account-linking,
       #153 / #154). No link is created.
    3. No match → create a new user and its oauth_accounts link.
    """
    # 1. Check for existing OAuth link
    stmt = select(OAuthAccount).where(
        OAuthAccount.provider == provider,
        OAuthAccount.provider_account_id == provider_account_id,
    )
    result = await db.execute(stmt)
    oauth_account = result.scalar_one_or_none()

    if oauth_account is not None:
        user_stmt = select(User).where(User.id == oauth_account.user_id)
        user_result = await db.execute(user_stmt)
        user = user_result.scalar_one()
        user.last_login_at = datetime.now(UTC)
        await db.commit()
        return OAuthUserResult(user=user, is_new_user=False)

    # 2. Existing user with this verified email — but NOT a same-provider
    #    re-login (that is handled by the (provider, provider_account_id) match
    #    in step 1). Reaching here means the incoming provider identity is new
    #    to an account that already authenticates via a different method
    #    (a password and/or another OAuth provider). Silently creating a link
    #    here is unconsented account-linking / an account-takeover surface, so
    #    we REJECT instead of linking (#153 / #154). An explicit, re-auth-gated
    #    linking flow is a separate, out-of-scope feature.
    if email:
        email_stmt = select(User).where(User.email == email, User.email_verified.is_(True))
        email_result = await db.execute(email_stmt)
        existing_user = email_result.scalar_one_or_none()

        if existing_user is not None:
            existing_methods = await _existing_auth_methods(db, existing_user)
            raise AccountExistsWithDifferentMethodError(
                email=email,
                existing_methods=existing_methods,
            )

    # 3. Create new user
    if not email:
        msg = "Cannot create user without an email address from the OAuth provider"
        raise ValueError(msg)

    new_user = User(
        id=uuid.uuid4(),
        email=email,
        email_verified=True,  # OAuth providers verify email
        display_name=display_name,
        avatar_url=avatar_url,
        is_active=True,
    )
    db.add(new_user)
    await db.flush()  # get user.id before creating the link

    oauth_link = OAuthAccount(
        user_id=new_user.id,
        provider=provider,
        provider_account_id=provider_account_id,
    )
    db.add(oauth_link)
    new_user.last_login_at = datetime.now(UTC)
    await db.commit()
    return OAuthUserResult(user=new_user, is_new_user=True)
