# ADR-001: JWT Library — python-jose vs PyJWT vs joserfc

**Status:** Accepted
**Date:** 2026-04-11
**Issue:** noorinalabs/noorinalabs-user-service#19

## Context

The user-service uses `python-jose[cryptography]` for JWT encoding, decoding, and
validation. During PR #13 review, the question was raised whether to migrate to a
more actively maintained library before Phase 2 auth work deepens the dependency.

### Current usage surface (narrow)

| Call site | API used |
|-----------|----------|
| `services/token.py` | `jwt.encode`, `jwt.decode`, `JWTError` |
| `dependencies.py` | `jwt.decode` (via `JWTError`) |
| `routers/auth.py` | `JWTError` (catch block) |
| `services/oauth.py` | `jwt.encode`, `jwt.get_unverified_claims` |

Algorithm: RS256 with RSA key pair via `cryptography` backend.

## Options evaluated

### 1. python-jose (current)

- **Maintenance:** Active again as of 2025 (v3.5.0, May 2025). Was dormant 2022-2024 but the original maintainer resumed releases.
- **Typed stubs:** `types-python-jose` available and in use.
- **Backend:** Uses `cryptography` backend (the recommended one). The default `native` backend is weaker but we don't use it.
- **API:** Stable, well-known. Supports JWS, JWE, JWK.
- **Risk:** Had a period of no maintenance. Could go dormant again.

### 2. PyJWT

- **Maintenance:** Actively maintained, frequent releases.
- **Typed:** Ships inline types (`py.typed`). No need for separate stubs.
- **API:** `jwt.encode`, `jwt.decode`, `jwt.decode_complete`. No built-in `get_unverified_claims` — use `jwt.decode(token, options={"verify_signature": False})`.
- **Backend:** Uses `cryptography` for RSA/EC algorithms (installed via `PyJWT[crypto]`).
- **Risk:** No JWE support (we don't need it). More limited scope but that's a feature for our use case.

### 3. joserfc

- **Maintenance:** Actively maintained by the author of Authlib.
- **Typed:** Ships inline types.
- **API:** Different API shape — `jose.jwt.encode`, `jose.jwt.decode`. More verbose but more explicit.
- **Backend:** Built on `cryptography`.
- **Risk:** Smaller community, fewer Stack Overflow answers. API is less familiar.

## Decision

**Stay with python-jose for now. Revisit if maintenance lapses again.**

### Rationale

1. **python-jose is active again.** The v3.5.0 release (May 2025) includes security patches and the `cryptography` backend is solid. The maintenance concern that prompted this ADR has been resolved.

2. **Migration cost is non-trivial for marginal benefit.** We have 6 call sites, 5 test files importing `jose`, mypy overrides, and type stubs configured. Migration to PyJWT would require:
   - Replacing all `from jose import jwt` with `import jwt`
   - Replacing `jwt.get_unverified_claims()` with `jwt.decode(..., options={"verify_signature": False})`
   - Removing the mypy override for `jose.*`
   - Swapping `types-python-jose` for nothing (PyJWT is inline-typed)
   - Updating `uv.lock`

3. **No functional gap.** Our usage is encode/decode/validate with RS256. All three libraries handle this identically.

4. **If python-jose goes dormant again**, PyJWT is the recommended migration target. The migration is straightforward (< 1 hour of work) and can be done reactively.

### Migration trigger

Migrate to PyJWT if any of:
- python-jose has no release for 12+ months
- A CVE is filed against python-jose with no patch within 30 days
- We need features python-jose lacks (unlikely for JWT-only use)

## Consequences

- No code changes needed now
- `python-jose[cryptography]>=3.3.0` remains in `pyproject.toml`
- This ADR serves as the documented decision for future reference
