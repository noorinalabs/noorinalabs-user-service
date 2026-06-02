"""Redis-backed per-client rate limiting for auth endpoints — US #55.

The auth router endpoints (token issue, refresh, validate, OAuth callback) had
no rate limiting, leaving them open to brute-force / credential-stuffing. This
service implements a fixed-window counter keyed by client identifier (IP, and
optionally a secondary discriminator such as user_id).

Design notes:
  * Fixed-window counter: INCR a per-window key, then EXPIRE it to the window
    length on EVERY call. Cheap, atomic enough for this purpose (a burst
    straddling a window boundary can briefly allow up to 2x the limit —
    acceptable for a brute-force speed-bump; a sliding window would need a
    sorted set and is not worth the complexity here).
  * EXPIRE is re-asserted unconditionally, not just on the first hit. INCR and
    EXPIRE are two separate round-trips: if EXPIRE failed on the first hit (a
    transient Redis blip mid-call), a "set TTL only when counter == 1" approach
    would leave the key orphaned with NO expiry — once Redis recovers it INCRs
    forever and that identifier is permanently 429'd with no window reset.
    Re-asserting EXPIRE every call makes the limiter self-healing: any orphaned
    key gets its TTL back on the very next request. Resetting the TTL on each
    call is fine — the window is "time since the most recent attempt", which is
    the desired lockout semantics anyway.
  * Fail-open: if Redis is unavailable or errors, the limiter allows the request
    rather than hard-failing the whole auth surface. A rate limiter outage must
    not become an auth outage. Failures are logged so the degradation is visible.
  * Configurable: limits come from settings (AUTH_MAX_LOGIN_ATTEMPTS,
    AUTH_LOCKOUT_DURATION_MINUTES) and the whole feature can be disabled with
    AUTH_RATE_LIMIT_ENABLED.

Runtime backend: requires the same Redis instance the rest of the service uses
(REDIS_URL). No new infrastructure. See PR body for the runtime-acceptance note.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status
from redis.asyncio import Redis
from redis.exceptions import RedisError

from src.app.config import Settings

logger = logging.getLogger(__name__)

# Redis key namespace for auth rate-limit counters.
RATE_LIMIT_PREFIX = "auth_rl:"


def _client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limit keying.

    Uses the direct socket peer. We deliberately do NOT trust X-Forwarded-For
    here — honoring a client-supplied header would let an attacker rotate the
    rate-limit key at will. If/when the service runs behind a trusted proxy that
    sets a verified forwarded header, this is the single place to revisit.
    """
    if request.client is None:
        return "unknown"
    return request.client.host


async def check_rate_limit(
    redis: Redis | None,
    settings: Settings,
    *,
    bucket: str,
    identifier: str,
) -> None:
    """Enforce the auth rate limit for one (bucket, identifier) pair.

    `bucket` namespaces the limit (e.g. "token", "refresh", "oauth_callback") so
    a client's budget on one endpoint is independent of another. `identifier` is
    the client discriminator (typically an IP, optionally suffixed with a
    user_id).

    Raises HTTP 429 when the limit is exceeded. Returns None when the request is
    allowed. Fails open (allows the request) when Redis is unavailable
    (`redis is None`) or errors.
    """
    if not settings.AUTH_RATE_LIMIT_ENABLED:
        return

    if redis is None:
        # Redis not initialized — fail open. A limiter-backend outage must not
        # take down auth.
        logger.warning(
            "Rate limiter unavailable (Redis not initialized) — allowing request: bucket=%s",
            bucket,
        )
        return

    limit = settings.AUTH_MAX_LOGIN_ATTEMPTS
    window_seconds = settings.AUTH_LOCKOUT_DURATION_MINUTES * 60
    key = f"{RATE_LIMIT_PREFIX}{bucket}:{identifier}"

    try:
        current = await redis.incr(key)
        # Re-assert the TTL on every call, not just when current == 1. INCR and
        # EXPIRE are separate round-trips; if EXPIRE failed on the first hit the
        # key would otherwise be orphaned without a TTL and INCR forever, giving
        # that identifier a permanent 429. Unconditional re-assert is
        # self-healing — an orphaned key gets its expiry back on the next call.
        await redis.expire(key, window_seconds)
    except RedisError:
        # Fail open: a limiter-backend outage must not take down auth. Log so the
        # degraded state is observable.
        logger.warning(
            "Rate limiter unavailable (Redis error) — allowing request: bucket=%s",
            bucket,
        )
        return

    if current > limit:
        logger.info(
            "Auth rate limit exceeded: bucket=%s limit=%s window_s=%s",
            bucket,
            limit,
            window_seconds,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests — please try again later.",
            headers={"Retry-After": str(window_seconds)},
        )


async def enforce_ip_rate_limit(
    request: Request,
    redis: Redis | None,
    settings: Settings,
    *,
    bucket: str,
) -> None:
    """Convenience wrapper: rate-limit by client IP for the given bucket."""
    await check_rate_limit(
        redis,
        settings,
        bucket=bucket,
        identifier=_client_ip(request),
    )
