# Parser-Fixture Coverage Audit — noorinalabs-user-service
<!-- audit_date: 2026-05-07 | wave: P3W7 | auditor: Mateo Salazar | parent: noorinalabs/noorinalabs-main#300 -->

## Hook Inventory

**Total hooks:** 5  
**Hook directory:** `.claude/hooks/`

| # | File | Role | Parser-Class? |
|---|------|------|--------------|
| 1 | `annunaki_log.py` | Utility (shared logging for block events) | No |
| 2 | `block_gh_pr_review.py` | PreToolUse — block `gh pr review` | **Yes** |
| 3 | `block_git_config.py` | PreToolUse — block `git config` writes | **Yes** |
| 4 | `block_no_verify.py` | PreToolUse — block `--no-verify` on git commit | **Yes** |
| 5 | `validate_commit_identity.py` | PreToolUse — validate per-commit `-c` identity flags | **Yes** |

**Parser-class hooks:** 4 of 5  
**Non-parser utility:** 1 (`annunaki_log.py` — called by hooks, no stdin parsing)

## Coverage Table

| Hook | Input Parsing | Test Fixture Exists | Fixture Path | Gap |
|------|--------------|--------------------|--------------|----|
| `annunaki_log.py` | None (utility only) | N/A | N/A | None (non-parser) |
| `block_gh_pr_review.py` | `json.load(sys.stdin)` + `re.split()` on command segments | **NO** | — | **MISSING** |
| `block_git_config.py` | `json.load(sys.stdin)` + `re.search()` | **NO** | — | **MISSING** |
| `block_no_verify.py` | `json.load(sys.stdin)` + `re.search()` | **NO** | — | **MISSING** |
| `validate_commit_identity.py` | `json.load(sys.stdin)` + `re.search()` + heredoc/quote stripping + cross-repo roster resolution | **NO** | — | **MISSING** |

**Summary:** 4 parser-class hooks, 0 fixture files. 100% fixture gap.

## Gap Analysis

### Gap 1 — No `check()` refactor on 3 simple hooks

`block_gh_pr_review.py`, `block_git_config.py`, and `block_no_verify.py` expose logic only inside `main()`. The parent repo's equivalent hooks have a `check(input_data: dict) -> dict | None` function extracted from `main()`, enabling direct unit testing without subprocess. All three user-service hooks lack this split.

**Impact:** Tests must either subprocess the hook (fragile, harder to assert) or the logic cannot be tested without refactor. The parent's pattern (used in `test_block_git_config.py`, `test_block_no_verify.py`) tests `check()` directly.

### Gap 2 — `validate_commit_identity.py` has `check()` but zero test coverage

`validate_commit_identity.py` already has the `check()` / `main()` split. The parent repo's `test_validate_commit_identity.py` covers: child-only roster, parent+child merge, cross-repo `cd` detection, heredoc stripping, quoted-string stripping, backslash line-continuation (#287 regression). None of these shapes are covered in this repo.

**High-risk areas specific to user-service:**
- OAuth callback routes contain `oauth/github/callback` — these do not interact with the hook but cross-repo deploy test shapes do.
- Alembic migration commits use `make migrate-new` then manual commit; any `heads`→`head` discipline commit (memory: W10 alembic migration #63) goes through this hook.
- No regression pinning for backslash-continuation (#287) or `deployments/*/wave-*` head shapes.

### Gap 3 — No `tests/` directory under `.claude/hooks/`

The parent repo has `.claude/hooks/tests/` with a full pytest suite. The user-service has no hook test directory at all.

## Pattern G Observations

**Pattern G** (per charter § 5 Parser-Fixture Coverage Requirements): new input shapes discovered in production require fixture-add backport before the bug-fix PR can merge. Four P3W6 bugs (#285, #287, #289, #294) all followed the same signature — parser bug discovered at runtime with no pre-existing fixture.

Observations for this repo:
1. All three simple hooks (`block_gh_pr_review`, `block_git_config`, `block_no_verify`) are structurally identical to their parent-repo counterparts at the time the parent's fixtures were written. The parent's fixture coverage arose *after* production bugs (#216 heredoc false-positive for `block_git_config`; #223 heredoc false-positive for `block_no_verify`). The child repo has not backported those fixture files despite the parser code being the same.
2. `validate_commit_identity.py` carries the most complex parser (heredoc stripping, quoted-string stripping, roster merge, cross-repo detection). It has the highest regression surface with zero coverage.
3. No negative-match fixture guards exist on any hook. Charter § 3 requires at least one "looks like a match but is intentionally excluded" case per hook.

## In-Wave Fixes

None landed in-wave (Pattern G in-wave fixes encouraged but require same-commit fixture + parser fix discipline; clean fix preferred over patch-without-fixture).

The `check()` refactor for the three simple hooks is a prerequisite Pattern G fix that can be done in-wave without risk, as it does not change logic — only extracts it. See backport issue filed below.

## Backport Issues Filed

| Issue | Title | Repo |
|-------|-------|------|
| [#98](https://github.com/noorinalabs/noorinalabs-user-service/issues/98) | backport(P3W7): add parser-fixture tests for block_gh_pr_review, block_git_config, block_no_verify hooks | noorinalabs/noorinalabs-user-service |
| [#99](https://github.com/noorinalabs/noorinalabs-user-service/issues/99) | backport(P3W7): add parser-fixture tests for validate_commit_identity hook — heredoc, backslash-continuation, wave-head shapes | noorinalabs/noorinalabs-user-service |

## References

- Charter: `noorinalabs-main/.claude/team/charter/hooks.md` § Parser-Fixture Coverage Requirements (§ 5)
- Meta-issue: noorinalabs/noorinalabs-main#300
- Parent fixture examples: `.claude/hooks/tests/test_validate_commit_identity.py`, `test_block_git_config.py`, `test_block_no_verify.py`
- Memory: `project_w10_user_service_alembic.md` — alembic `heads`→`head` discipline (commit identity hook relevance)
