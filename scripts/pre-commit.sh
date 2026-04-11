#!/usr/bin/env bash
# Pre-commit hook replicating CI checks from .github/workflows/ci.yml
# CI checks: ruff check, ruff format --check, pytest
# Bonus: mypy (configured in pyproject.toml but not yet in CI)
#
# Install: ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit

set -euo pipefail

# Resolve repo root (works in worktrees too)
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

FAILED=0

echo "=== pre-commit: Running CI checks ==="

# 1. Ruff lint
echo ""
echo "--- ruff check ---"
if ! ruff check .; then
    echo "FAIL: ruff check found lint errors"
    FAILED=1
fi

# 2. Ruff format
echo ""
echo "--- ruff format --check ---"
if ! ruff format --check .; then
    echo "FAIL: ruff format found formatting issues (run: ruff format .)"
    FAILED=1
fi

# 3. Mypy type check (configured in pyproject.toml)
echo ""
echo "--- mypy ---"
if command -v mypy &>/dev/null; then
    if ! mypy src/; then
        echo "FAIL: mypy found type errors"
        FAILED=1
    fi
else
    echo "SKIP: mypy not installed"
fi

# 4. Pytest (optional — can be slow, skip with PRE_COMMIT_SKIP_TESTS=1)
echo ""
if [ "${PRE_COMMIT_SKIP_TESTS:-0}" = "1" ]; then
    echo "--- pytest (SKIPPED via PRE_COMMIT_SKIP_TESTS=1) ---"
else
    echo "--- pytest ---"
    if command -v pytest &>/dev/null; then
        if ! ENVIRONMENT=test pytest --tb=short -q; then
            echo "FAIL: pytest found test failures"
            FAILED=1
        fi
    else
        echo "SKIP: pytest not installed (run: uv sync --extra dev)"
    fi
fi

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "=== pre-commit: FAILED — fix errors before committing ==="
    exit 1
fi

echo "=== pre-commit: All checks passed ==="
exit 0
