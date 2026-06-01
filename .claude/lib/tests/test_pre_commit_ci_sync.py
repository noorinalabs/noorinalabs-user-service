"""Tests for pre_commit_ci_sync — the pre-commit <-> CI drift gate (#327).

Verifies:
  1. Canonical kind extraction from both pre-commit configs and CI workflows.
  2. The drift direction that gates: CI-enforced-but-not-local is harmful;
     local-but-not-CI is stricter-local (informational, never a gate fail).
  3. ruff-format vs ruff-lint are not conflated.
  4. This repo's (noorinalabs-user-service) config mirrors its ci.yml kinds
     (no harmful drift) — the gate running against the very repo that ships it.
     The gate is scoped to ci.yml (the code-CI workflow); docs.yml is a separate
     artifact class (markdown/config/actionlint) pre-commit does not mirror.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Helper lives at .claude/lib/pre_commit_ci_sync.py; test is at
# .claude/lib/tests/test_*.py. parent.parent reaches the lib root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pre_commit_ci_sync import (
    check_repo,
    compute_drift,
    kinds_from_ci,
    kinds_from_precommit,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]


class PrecommitKindExtraction(unittest.TestCase):
    def test_ruff_format_and_lint_both_detected(self) -> None:
        cfg = """
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks:
      - id: ruff-format
      - id: ruff
"""
        kinds = kinds_from_precommit(cfg)
        self.assertIn("ruff-format", kinds)
        self.assertIn("ruff-lint", kinds)

    def test_mypy_and_pytest_local_hooks(self) -> None:
        cfg = """
repos:
  - repo: local
    hooks:
      - id: mypy
        entry: python3 -m mypy
      - id: pytest-unit
        entry: pytest
"""
        kinds = kinds_from_precommit(cfg)
        self.assertIn("mypy", kinds)
        self.assertIn("pytest", kinds)

    def test_frontend_kinds(self) -> None:
        cfg = """
repos:
  - repo: local
    hooks:
      - id: eslint
      - id: typecheck
        entry: tsc --noEmit
      - id: prettier
"""
        kinds = kinds_from_precommit(cfg)
        self.assertIn("eslint", kinds)
        self.assertIn("typescript", kinds)
        self.assertIn("prettier", kinds)

    def test_comments_ignored(self) -> None:
        cfg = "# id: mypy is just a comment\nrepos: []\n"
        self.assertNotIn("mypy", kinds_from_precommit(cfg))


class CiKindExtraction(unittest.TestCase):
    def test_run_steps_detected(self) -> None:
        wf = """
jobs:
  lint:
    steps:
      - run: ruff check .
      - run: ruff format --check .
      - run: mypy src/
      - run: pytest -q
"""
        kinds = kinds_from_ci(wf)
        self.assertEqual(
            kinds & {"ruff-lint", "ruff-format", "mypy", "pytest"},
            {"ruff-lint", "ruff-format", "mypy", "pytest"},
        )

    def test_uses_actions_detected(self) -> None:
        wf = """
jobs:
  scan:
    steps:
      - uses: gitleaks/gitleaks-action@v2
"""
        self.assertIn("gitleaks", kinds_from_ci(wf))

    def test_ruff_format_line_not_counted_as_lint(self) -> None:
        # A format-only line must NOT register ruff-lint.
        kinds = kinds_from_ci("      - run: ruff format --check .\n")
        self.assertIn("ruff-format", kinds)
        self.assertNotIn("ruff-lint", kinds)


class DriftDirection(unittest.TestCase):
    def test_ci_enforced_not_local_is_harmful(self) -> None:
        harmful, stricter = compute_drift(
            precommit_kinds={"ruff-lint"},
            ci_kinds={"ruff-lint", "mypy", "pytest"},
        )
        self.assertEqual(harmful, {"mypy", "pytest"})
        self.assertEqual(stricter, set())

    def test_local_not_ci_is_stricter_only(self) -> None:
        harmful, stricter = compute_drift(
            precommit_kinds={"ruff-lint", "gitleaks"},
            ci_kinds={"ruff-lint"},
        )
        self.assertEqual(harmful, set())
        self.assertEqual(stricter, {"gitleaks"})

    def test_perfect_mirror_no_drift(self) -> None:
        harmful, stricter = compute_drift(
            precommit_kinds={"ruff-lint", "ruff-format", "mypy"},
            ci_kinds={"ruff-lint", "ruff-format", "mypy"},
        )
        self.assertEqual(harmful, set())
        self.assertEqual(stricter, set())


class ThisRepoHasNoDrift(unittest.TestCase):
    """The user-service config must mirror its QUALITY-GATE CI kinds — this is the
    gate running against the very repo that ships it. Scoped to the two PR-gate
    workflows (ci.yml code + docs.yml markdown/config/actionlint); the actionlint
    pre-commit hook covers docs.yml's actionlint kind. ghcr-publish.yml is
    excluded — its `docker build` is a release-time publish, not a local
    fast-feedback check pre-commit should mirror."""

    def test_precommit_mirrors_quality_gate_ci(self) -> None:
        precommit = _REPO_ROOT / ".pre-commit-config.yaml"
        ci = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
        docs = _REPO_ROOT / ".github" / "workflows" / "docs.yml"
        self.assertTrue(precommit.is_file(), "repo must have a pre-commit config")
        self.assertTrue(ci.is_file(), "repo must have ci.yml")
        self.assertTrue(docs.is_file(), "repo must have docs.yml")
        harmful, _ = check_repo(precommit, [ci, docs])
        self.assertEqual(
            harmful,
            set(),
            f"pre-commit must mirror the quality-gate CI; missing locally: {sorted(harmful)}",
        )


if __name__ == "__main__":
    unittest.main()
