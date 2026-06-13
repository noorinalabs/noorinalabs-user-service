# syntax=docker/dockerfile:1

# Base image digest-pinned for reproducible builds + a trivy-stable OS-package
# baseline (issue us#129). The pinned digest is the multi-arch python:3.12-slim
# manifest-list index — it resolves linux/amd64 + linux/arm64, so the digest pin
# does NOT regress the multi-arch push build (ghcr-publish.yml builds amd64+arm64
# on push, amd64-only on PR for the Trivy scan).
#
# Re-pin cadence: monthly, OR whenever CI's Trivy gate surfaces OS-level CVE
# failures the current pin can't satisfy. Dependabot (.github/dependabot.yml)
# opens auto-PRs for fresher digests so re-pinning is an intentional, reviewed
# event rather than a CI-failure-triggered emergency.
#
# Base-image upgrade path: when python:3.12-slim-trixie (Debian 13 / Trixie)
# tags stabilize, evaluate switching — Trixie carries the +deb13u1 OS fixes that
# Bookworm only backports later, the structural source of the recurring libcap2 /
# libsystemd0 Trivy failures (us#127 round 2). Do NOT bump unilaterally: test
# dependency compatibility first (cf. PR #41 "3.14 breaks deps"), land the base
# switch in its own PR, and drop any then-redundant .trivyignore entries.
#
# Last pin: 2026-06-12 (digest resolved from Docker Hub at PR-open time) —
# re-pinned per the "Trivy gate surfaces an OS-level CVE" cadence: the prior pin
# carried openssl/libssl3t64 3.5.6-1~deb13u1, vulnerable to CVE-2026-45447 (HIGH),
# which began tripping ghcr-publish's Trivy gate on every PR once disclosed
# (us#157). This digest ships 3.5.6-1~deb13u2, the Debian backport that fixes it.
FROM python:3.12-slim@sha256:a39549e211a16149edf74e5fdc9ef03a6767e46cd987c5048b6659b6c9904c94 AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

FROM base AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv && uv sync --frozen --no-dev

FROM base AS runtime
WORKDIR /app
RUN adduser --system --no-create-home app
COPY --from=builder /app/.venv /app/.venv
COPY . .
USER app

ENV PATH="/app/.venv/bin:$PATH"

CMD ["uvicorn", "src.app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
