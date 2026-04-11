"""Migrate USER nodes from Neo4j (isnad-graph) to PostgreSQL (user-service).

Usage:
    python scripts/migrate_users.py \
        --neo4j-uri bolt://localhost:7687 \
        --neo4j-user neo4j \
        --neo4j-password secret \
        --database-url postgresql://user:pass@localhost:5432/userdb \
        [--dry-run] [--verbose] [--batch-size 50]
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import sqlalchemy as sa
from neo4j import GraphDatabase

log = logging.getLogger("migrate_users")

# ---------------------------------------------------------------------------
# Tier / status mapping: Neo4j enum values → PostgreSQL enum values
# ---------------------------------------------------------------------------
# Source (isnad-graph): trial, individual, team, enterprise
# Target (user-service): free, trial, researcher, institutional
TIER_MAP: dict[str | None, str] = {
    "trial": "trial",
    "individual": "researcher",
    "team": "institutional",
    "enterprise": "institutional",
    None: "free",
}

# Source: trial, active, expired, cancelled
# Target: active, expired, cancelled, suspended
STATUS_MAP: dict[str | None, str] = {
    "trial": "active",
    "active": "active",
    "expired": "expired",
    "cancelled": "cancelled",
    None: "active",
}

ROLE_DESCRIPTIONS: dict[str, str] = {
    "viewer": "Read-only access",
    "editor": "Can create and edit content",
    "moderator": "Can moderate content and users",
    "admin": "Full administrative access",
}


# ---------------------------------------------------------------------------
# Data container for a single migrated user
# ---------------------------------------------------------------------------
@dataclass
class MigratedUser:
    neo4j_id: str
    pg_user_id: uuid.UUID
    email: str
    display_name: str | None
    email_verified: bool
    avatar_url: str | None
    created_at: datetime
    provider: str | None
    provider_account_id: str | None
    role: str | None
    subscription_plan: str
    subscription_status: str
    subscription_starts_at: datetime
    subscription_expires_at: datetime | None


@dataclass
class MigrationResult:
    total: int = 0
    created: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Neo4j extraction
# ---------------------------------------------------------------------------
def fetch_neo4j_users(uri: str, user: str, password: str) -> list[dict]:
    """Return all USER nodes from Neo4j as plain dicts."""
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session() as session:
            result = session.run("MATCH (u:USER) RETURN u")
            users = []
            for record in result:
                node = record["u"]
                users.append(dict(node))
            return users
    finally:
        driver.close()


def count_neo4j_users(uri: str, user: str, password: str) -> int:
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session() as session:
            result = session.run("MATCH (u:USER) RETURN count(u) AS cnt")
            return result.single()["cnt"]
    finally:
        driver.close()


# ---------------------------------------------------------------------------
# Transform a Neo4j node dict into a MigratedUser
# ---------------------------------------------------------------------------
def _parse_neo4j_datetime(value: object) -> datetime:
    """Convert a Neo4j datetime (or ISO string) to a Python datetime."""
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    # neo4j driver returns neo4j.time.DateTime — convert via iso_format()
    try:
        iso = value.iso_format()  # type: ignore[union-attr]
    except AttributeError:
        iso = str(value)
    # Strip trailing [UTC] zone id that neo4j sometimes appends
    iso = iso.replace("[UTC]", "").replace("[Etc/UTC]", "").strip()
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def transform_user(node: dict) -> MigratedUser:
    """Map a Neo4j USER node dict to a MigratedUser."""
    neo4j_id: str = node["id"]

    # Parse provider and provider_account_id from the composite id
    # Format: "provider:provider_user_id"
    provider: str | None = None
    provider_account_id: str | None = None
    if ":" in neo4j_id:
        parts = neo4j_id.split(":", 1)
        provider = parts[0]
        provider_account_id = parts[1]

    # Fall back to the node's explicit provider property
    if provider is None:
        provider = node.get("provider")

    created_at = _parse_neo4j_datetime(node.get("created_at"))
    trial_start = node.get("trial_start")
    trial_expires = node.get("trial_expires")

    sub_tier = node.get("subscription_tier")
    sub_status = node.get("subscription_status")

    return MigratedUser(
        neo4j_id=neo4j_id,
        pg_user_id=uuid.uuid4(),
        email=node["email"],
        display_name=node.get("name"),
        email_verified=bool(node.get("email_verified", False)),
        avatar_url=node.get("avatar_url"),
        created_at=created_at,
        provider=provider,
        provider_account_id=provider_account_id,
        role=node.get("role"),
        subscription_plan=TIER_MAP.get(sub_tier, "free"),
        subscription_status=STATUS_MAP.get(sub_status, "active"),
        subscription_starts_at=_parse_neo4j_datetime(trial_start) if trial_start else created_at,
        subscription_expires_at=_parse_neo4j_datetime(trial_expires) if trial_expires else None,
    )


# ---------------------------------------------------------------------------
# PostgreSQL loading (sync via psycopg2 / sqlalchemy core)
# ---------------------------------------------------------------------------
def _ensure_roles(conn: sa.engine.Connection, roles_table: sa.Table) -> dict[str, uuid.UUID]:
    """Ensure all expected roles exist and return name→id mapping."""
    role_map: dict[str, uuid.UUID] = {}
    for name, description in ROLE_DESCRIPTIONS.items():
        row = conn.execute(sa.select(roles_table.c.id).where(roles_table.c.name == name)).fetchone()
        if row:
            role_map[name] = row[0]
        else:
            role_id = uuid.uuid4()
            conn.execute(
                roles_table.insert().values(id=role_id, name=name, description=description)
            )
            role_map[name] = role_id
            log.info("Created role: %s (%s)", name, role_id)
    return role_map


def load_user(
    conn: sa.engine.Connection,
    metadata: sa.MetaData,
    user: MigratedUser,
    role_map: dict[str, uuid.UUID],
) -> str:
    """Insert one user and related rows. Returns 'created' or 'skipped'."""
    users_t = metadata.tables["users"]
    oauth_t = metadata.tables["oauth_accounts"]
    user_roles_t = metadata.tables["user_roles"]
    subscriptions_t = metadata.tables["subscriptions"]

    # Idempotency: check if user with this email already exists
    existing = conn.execute(sa.select(users_t.c.id).where(users_t.c.email == user.email)).fetchone()
    if existing:
        log.debug("Skipping existing user: %s", user.email)
        return "skipped"

    # Insert user
    conn.execute(
        users_t.insert().values(
            id=user.pg_user_id,
            email=user.email,
            email_verified=user.email_verified,
            display_name=user.display_name,
            password_hash=None,
            avatar_url=user.avatar_url,
            locale=None,
            is_active=True,
            created_at=user.created_at,
            updated_at=user.created_at,
            last_login_at=None,
        )
    )

    # Insert OAuth account if provider info is available
    if user.provider and user.provider_account_id:
        conn.execute(
            oauth_t.insert().values(
                id=uuid.uuid4(),
                user_id=user.pg_user_id,
                provider=user.provider,
                provider_account_id=user.provider_account_id,
                created_at=user.created_at,
            )
        )

    # Insert role assignment
    if user.role and user.role in role_map:
        conn.execute(
            user_roles_t.insert().values(
                user_id=user.pg_user_id,
                role_id=role_map[user.role],
                granted_at=user.created_at,
                granted_by=None,
            )
        )

    # Insert subscription
    conn.execute(
        subscriptions_t.insert().values(
            id=uuid.uuid4(),
            user_id=user.pg_user_id,
            plan=user.subscription_plan,
            status=user.subscription_status,
            starts_at=user.subscription_starts_at,
            expires_at=user.subscription_expires_at,
            created_at=user.created_at,
            updated_at=user.created_at,
        )
    )

    return "created"


# ---------------------------------------------------------------------------
# Migration orchestrator
# ---------------------------------------------------------------------------
def migrate(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    database_url: str,
    dry_run: bool = False,
    batch_report: int = 50,
) -> MigrationResult:
    """Run the full migration."""
    result = MigrationResult()

    # --- Extract ---
    log.info("Fetching users from Neo4j (%s) ...", neo4j_uri)
    neo4j_nodes = fetch_neo4j_users(neo4j_uri, neo4j_user, neo4j_password)
    result.total = len(neo4j_nodes)
    log.info("Found %d USER nodes in Neo4j", result.total)

    if result.total == 0:
        log.info("Nothing to migrate.")
        return result

    # --- Transform ---
    migrated: list[MigratedUser] = []
    for node in neo4j_nodes:
        try:
            migrated.append(transform_user(node))
        except Exception as exc:
            neo_id = node.get("id", "<unknown>")
            msg = f"Transform error for {neo_id}: {exc}"
            log.warning(msg)
            result.errors.append(msg)

    if dry_run:
        log.info("[DRY RUN] Would migrate %d users:", len(migrated))
        for u in migrated:
            log.info(
                "  %s | %s | role=%s | plan=%s/%s",
                u.email,
                u.provider or "?",
                u.role or "viewer",
                u.subscription_plan,
                u.subscription_status,
            )
        result.created = len(migrated)
        return result

    # --- Load ---
    engine = sa.create_engine(database_url)
    metadata = sa.MetaData()
    metadata.reflect(bind=engine)

    with engine.begin() as conn:
        role_map = _ensure_roles(conn, metadata.tables["roles"])

        for i, user in enumerate(migrated, 1):
            try:
                status = load_user(conn, metadata, user, role_map)
                if status == "created":
                    result.created += 1
                else:
                    result.skipped += 1
            except Exception as exc:
                msg = f"Load error for {user.email}: {exc}"
                log.warning(msg)
                result.errors.append(msg)
                result.skipped += 1

            if i % batch_report == 0:
                log.info("Progress: %d / %d processed", i, result.total)

    log.info(
        "Migration complete: %d created, %d skipped, %d errors out of %d total",
        result.created,
        result.skipped,
        len(result.errors),
        result.total,
    )

    # --- Verification ---
    _verify(neo4j_uri, neo4j_user, neo4j_password, engine, result)

    return result


def _verify(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    engine: sa.engine.Engine,
    result: MigrationResult,
) -> None:
    """Compare Neo4j and PostgreSQL counts and spot-check a sample."""
    neo4j_count = count_neo4j_users(neo4j_uri, neo4j_user, neo4j_password)

    with engine.connect() as conn:
        pg_count_row = conn.execute(sa.text("SELECT count(*) FROM users")).fetchone()
        pg_count = pg_count_row[0] if pg_count_row else 0

    log.info("--- Verification ---")
    log.info("Neo4j USER count:      %d", neo4j_count)
    log.info("PostgreSQL user count:  %d", pg_count)

    if pg_count >= neo4j_count:
        log.info("Counts match (or PostgreSQL has additional users).")
    else:
        diff = neo4j_count - pg_count
        log.warning(
            "PostgreSQL has %d fewer users than Neo4j. Check errors above.",
            diff,
        )

    # Spot-check: pick up to 3 users from PostgreSQL and print them
    with engine.connect() as conn:
        sample = conn.execute(
            sa.text(
                "SELECT u.email, u.display_name, u.email_verified, u.created_at "
                "FROM users u ORDER BY u.created_at LIMIT 3"
            )
        ).fetchall()
    if sample:
        log.info("Sample migrated users:")
        for row in sample:
            log.info("  %s | %s | verified=%s | created=%s", row[0], row[1], row[2], row[3])
    else:
        log.warning("No users found in PostgreSQL after migration.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate USER nodes from Neo4j to PostgreSQL (user-service)"
    )
    parser.add_argument("--neo4j-uri", required=True, help="Neo4j bolt URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", required=True, help="Neo4j password")
    parser.add_argument("--database-url", required=True, help="PostgreSQL connection URL")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    parser.add_argument("--batch-size", type=int, default=50, help="Report progress every N users")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    result = migrate(
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        database_url=args.database_url,
        dry_run=args.dry_run,
        batch_report=args.batch_size,
    )

    if result.errors:
        log.error("Errors encountered:")
        for err in result.errors:
            log.error("  %s", err)
        sys.exit(1)


if __name__ == "__main__":
    main()
