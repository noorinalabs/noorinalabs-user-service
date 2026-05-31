"""Tests for the Prometheus /metrics endpoint.

The endpoint is exposed by prometheus_fastapi_instrumentator and scraped by
Prometheus over the backend Docker network (deploy#64). It must respond 200
with the Prometheus text exposition format and emit the default
`http_requests_total` counter once at least one request has been handled.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_exposition(client: AsyncClient) -> None:
    # Drive one request through the instrumented middleware so the default
    # http_requests_total counter has at least one observed series to expose.
    health = await client.get("/health")
    assert health.status_code == 200

    response = await client.get("/metrics")
    assert response.status_code == 200

    content_type = response.headers["content-type"]
    assert content_type.startswith("text/plain"), content_type

    body = response.text
    assert "http_requests_total" in body


@pytest.mark.asyncio
async def test_metrics_endpoint_excluded_from_openapi_schema(client: AsyncClient) -> None:
    # include_in_schema=False — /metrics must not leak into the public OpenAPI spec.
    spec = await client.get("/openapi.json")
    assert spec.status_code == 200
    assert "/metrics" not in spec.json()["paths"]
