"""Tests for RBAC role hierarchy and permission checks."""

import pytest

from src.app.services.rbac import get_role_level, user_has_minimum_role


class TestRoleHierarchy:
    def test_admin_has_highest_level(self) -> None:
        assert get_role_level("admin") > get_role_level("researcher")
        assert get_role_level("admin") > get_role_level("reader")
        assert get_role_level("admin") > get_role_level("trial")

    def test_researcher_above_reader(self) -> None:
        assert get_role_level("researcher") > get_role_level("reader")

    def test_reader_above_trial(self) -> None:
        assert get_role_level("reader") > get_role_level("trial")

    def test_unknown_role_is_zero(self) -> None:
        assert get_role_level("nonexistent") == 0


class TestUserHasMinimumRole:
    def test_admin_satisfies_all(self) -> None:
        roles = ["admin"]
        assert user_has_minimum_role(roles, "admin")
        assert user_has_minimum_role(roles, "researcher")
        assert user_has_minimum_role(roles, "reader")
        assert user_has_minimum_role(roles, "trial")

    def test_researcher_satisfies_reader(self) -> None:
        roles = ["researcher"]
        assert user_has_minimum_role(roles, "reader")
        assert user_has_minimum_role(roles, "trial")

    def test_researcher_does_not_satisfy_admin(self) -> None:
        roles = ["researcher"]
        assert not user_has_minimum_role(roles, "admin")

    def test_reader_does_not_satisfy_researcher(self) -> None:
        roles = ["reader"]
        assert not user_has_minimum_role(roles, "researcher")

    def test_trial_only_satisfies_trial(self) -> None:
        roles = ["trial"]
        assert user_has_minimum_role(roles, "trial")
        assert not user_has_minimum_role(roles, "reader")

    def test_no_roles_satisfies_nothing(self) -> None:
        assert not user_has_minimum_role([], "trial")

    @pytest.mark.parametrize(
        "roles",
        [["reader", "researcher"], ["trial", "admin"]],
    )
    def test_highest_role_wins(self, roles: list[str]) -> None:
        assert user_has_minimum_role(roles, "researcher")
