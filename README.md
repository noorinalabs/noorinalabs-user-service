# noorinalabs-user-service

User/auth/RBAC service — JWT issuer, OAuth, sessions; FastAPI + Postgres.

This repo houses the FastAPI app (`src/`), its test suite (`tests/`), Alembic
migrations, and the OpenAPI snapshot under `docs/`.

## Git hooks (required)

This repo mirrors its CI checks locally via [pre-commit](https://pre-commit.com/).
After cloning, install BOTH hook stages once:

```bash
uvx pre-commit install                       # commit-stage checks
uvx pre-commit install --hook-type pre-push  # push-stage checks
```

- **Commit stage** runs: `ruff-format`, `ruff-lint` (`ruff --fix`), and
  `actionlint` over the workflow files.
- **Pre-push stage** runs: `mypy` (strict, over `src/`) and the `pytest` suite.

These mirror `.github/workflows/ci.yml` (and the docs/config gate in
`.github/workflows/docs.yml`) so failures surface locally before a PR — org-wide
local⇄CI parity, noorinalabs-main#684. Never bypass with `--no-verify`.

Notes:

- `actionlint` shells out to `shellcheck`; install `shellcheck` on your PATH or
  the embedded shellcheck integration is silently skipped (local "clean" then
  diverges from CI).
- If `pre-commit install` "cowardly refuses" because `core.hooksPath` is set,
  run `git config --unset core.hooksPath` first.
