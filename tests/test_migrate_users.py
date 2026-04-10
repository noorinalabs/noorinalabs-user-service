"""Tests for the Neo4j → PostgreSQL user migration script."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from scripts.migrate_users import (
    STATUS_MAP,
    TIER_MAP,
    MigrationResult,
    _parse_neo4j_datetime,
    parse_args,
    transform_user,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _make_neo4j_node(
    *,
    user_id: str = "google:abc123",
    email: str = "test@example.com",
    name: str = "Test User",
    provider: str = "google",
    role: str = "viewer",
    email_verified: bool = False,
    subscription_tier: str = "trial",
    subscription_status: str = "trial",
    created_at: datetime | None = None,
    trial_start: datetime | None = None,
    trial_expires: datetime | None = None,
    avatar_url: str | None = None,
) -> dict:
    node: dict = {
        "id": user_id,
        "email": email,
        "name": name,
        "provider": provider,
        "role": role,
        "email_verified": email_verified,
        "subscription_tier": subscription_tier,
        "subscription_status": subscription_status,
    }
    if created_at is not None:
        node["created_at"] = created_at
    if trial_start is not None:
        node["trial_start"] = trial_start
    if trial_expires is not None:
        node["trial_expires"] = trial_expires
    if avatar_url is not None:
        node["avatar_url"] = avatar_url
    return node


# ---------------------------------------------------------------------------
# transform_user
# ---------------------------------------------------------------------------
class TestTransformUser:
    def test_basic_transform(self) -> None:
        node = _make_neo4j_node(
            email="alice@example.com",
            name="Alice",
            user_id="google:g123",
            role="editor",
            subscription_tier="individual",
            subscription_status="active",
        )
        result = transform_user(node)

        assert result.email == "alice@example.com"
        assert result.display_name == "Alice"
        assert result.provider == "google"
        assert result.provider_account_id == "g123"
        assert result.role == "editor"
        assert result.subscription_plan == "researcher"  # individual → researcher
        assert result.subscription_status == "active"
        assert isinstance(result.pg_user_id, uuid.UUID)

    def test_composite_id_parsing(self) -> None:
        node = _make_neo4j_node(user_id="github:user456")
        result = transform_user(node)
        assert result.provider == "github"
        assert result.provider_account_id == "user456"

    def test_id_with_colon_in_provider_id(self) -> None:
        node = _make_neo4j_node(user_id="apple:user:with:colons")
        result = transform_user(node)
        assert result.provider == "apple"
        assert result.provider_account_id == "user:with:colons"

    def test_no_colon_in_id_falls_back_to_provider_property(self) -> None:
        node = _make_neo4j_node(user_id="plainid", provider="facebook")
        result = transform_user(node)
        assert result.provider == "facebook"
        assert result.provider_account_id is None

    def test_email_verified_true(self) -> None:
        node = _make_neo4j_node(email_verified=True)
        assert transform_user(node).email_verified is True

    def test_avatar_url(self) -> None:
        node = _make_neo4j_node(avatar_url="https://example.com/avatar.jpg")
        assert transform_user(node).avatar_url == "https://example.com/avatar.jpg"

    def test_missing_avatar_url(self) -> None:
        node = _make_neo4j_node()
        assert transform_user(node).avatar_url is None

    def test_created_at_with_timezone(self) -> None:
        dt = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        node = _make_neo4j_node(created_at=dt)
        result = transform_user(node)
        assert result.created_at == dt

    def test_created_at_naive_gets_utc(self) -> None:
        dt = datetime(2025, 6, 1, 12, 0, 0)
        node = _make_neo4j_node(created_at=dt)
        result = transform_user(node)
        assert result.created_at.tzinfo == UTC

    def test_subscription_starts_from_trial_start(self) -> None:
        trial_dt = datetime(2025, 3, 1, tzinfo=UTC)
        node = _make_neo4j_node(trial_start=trial_dt)
        result = transform_user(node)
        assert result.subscription_starts_at == trial_dt

    def test_subscription_expires_from_trial_expires(self) -> None:
        exp_dt = datetime(2025, 3, 8, tzinfo=UTC)
        node = _make_neo4j_node(trial_expires=exp_dt)
        result = transform_user(node)
        assert result.subscription_expires_at == exp_dt


# ---------------------------------------------------------------------------
# Tier and status mapping
# ---------------------------------------------------------------------------
class TestMappings:
    def test_tier_map_trial(self) -> None:
        assert TIER_MAP["trial"] == "trial"

    def test_tier_map_individual(self) -> None:
        assert TIER_MAP["individual"] == "researcher"

    def test_tier_map_team(self) -> None:
        assert TIER_MAP["team"] == "institutional"

    def test_tier_map_enterprise(self) -> None:
        assert TIER_MAP["enterprise"] == "institutional"

    def test_tier_map_none(self) -> None:
        assert TIER_MAP[None] == "free"

    def test_status_map_trial(self) -> None:
        assert STATUS_MAP["trial"] == "active"

    def test_status_map_active(self) -> None:
        assert STATUS_MAP["active"] == "active"

    def test_status_map_expired(self) -> None:
        assert STATUS_MAP["expired"] == "expired"

    def test_status_map_cancelled(self) -> None:
        assert STATUS_MAP["cancelled"] == "cancelled"

    def test_status_map_none(self) -> None:
        assert STATUS_MAP[None] == "active"


# ---------------------------------------------------------------------------
# _parse_neo4j_datetime
# ---------------------------------------------------------------------------
class TestParseNeo4jDatetime:
    def test_none_returns_utc_now(self) -> None:
        result = _parse_neo4j_datetime(None)
        assert result.tzinfo == UTC

    def test_python_datetime_with_tz(self) -> None:
        dt = datetime(2025, 1, 1, tzinfo=UTC)
        assert _parse_neo4j_datetime(dt) is dt

    def test_naive_datetime_gets_utc(self) -> None:
        dt = datetime(2025, 1, 1)
        result = _parse_neo4j_datetime(dt)
        assert result.tzinfo == UTC
        assert result.year == 2025

    def test_neo4j_datetime_object(self) -> None:
        """Simulate a neo4j.time.DateTime with iso_format()."""
        mock_dt = MagicMock()
        mock_dt.iso_format.return_value = "2025-06-15T10:30:00+00:00"
        result = _parse_neo4j_datetime(mock_dt)
        assert result.year == 2025
        assert result.month == 6

    def test_neo4j_datetime_with_utc_zone_id(self) -> None:
        mock_dt = MagicMock()
        mock_dt.iso_format.return_value = "2025-06-15T10:30:00+00:00[UTC]"
        result = _parse_neo4j_datetime(mock_dt)
        assert result.year == 2025


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
class TestParseArgs:
    def test_required_args(self) -> None:
        args = parse_args([
            "--neo4j-uri", "bolt://localhost:7687",
            "--neo4j-password", "secret",
            "--database-url", "postgresql://localhost/db",
        ])
        assert args.neo4j_uri == "bolt://localhost:7687"
        assert args.neo4j_user == "neo4j"  # default
        assert args.neo4j_password == "secret"
        assert args.database_url == "postgresql://localhost/db"
        assert args.dry_run is False
        assert args.verbose is False

    def test_dry_run_flag(self) -> None:
        args = parse_args([
            "--neo4j-uri", "bolt://localhost:7687",
            "--neo4j-password", "secret",
            "--database-url", "postgresql://localhost/db",
            "--dry-run",
        ])
        assert args.dry_run is True

    def test_verbose_flag(self) -> None:
        args = parse_args([
            "--neo4j-uri", "bolt://localhost:7687",
            "--neo4j-password", "secret",
            "--database-url", "postgresql://localhost/db",
            "--verbose",
        ])
        assert args.verbose is True

    def test_custom_batch_size(self) -> None:
        args = parse_args([
            "--neo4j-uri", "bolt://localhost:7687",
            "--neo4j-password", "secret",
            "--database-url", "postgresql://localhost/db",
            "--batch-size", "100",
        ])
        assert args.batch_size == 100


# ---------------------------------------------------------------------------
# Dry-run integration (mocked Neo4j)
# ---------------------------------------------------------------------------
class TestDryRun:
    @patch("scripts.migrate_users.fetch_neo4j_users")
    def test_dry_run_does_not_write(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = [
            _make_neo4j_node(email="a@test.com", user_id="google:1"),
            _make_neo4j_node(email="b@test.com", user_id="github:2"),
        ]
        result = migrate_dry_run(mock_fetch)
        assert result.total == 2
        assert result.created == 2
        assert result.skipped == 0
        assert len(result.errors) == 0

    @patch("scripts.migrate_users.fetch_neo4j_users")
    def test_dry_run_handles_transform_error(self, mock_fetch: MagicMock) -> None:
        """A node missing required 'email' should produce an error, not crash."""
        mock_fetch.return_value = [
            {"id": "google:bad"},  # missing email
            _make_neo4j_node(email="good@test.com"),
        ]
        result = migrate_dry_run(mock_fetch)
        assert result.total == 2
        assert result.created == 1
        assert len(result.errors) == 1


def migrate_dry_run(mock_fetch: MagicMock) -> MigrationResult:
    """Helper to run migration in dry-run mode with mocked Neo4j."""
    from scripts.migrate_users import migrate

    return migrate(
        neo4j_uri="bolt://fake:7687",
        neo4j_user="neo4j",
        neo4j_password="fake",
        database_url="postgresql://fake/db",
        dry_run=True,
    )
