"""Tests for the Privacy Router — FastAPI local-only model routing proxy."""

import json
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from modules.router.privacy_router import (
    _is_loopback_host,
    _log_route_decision,
    app,
)


@pytest.fixture
def client():
    """TestClient as a context manager so FastAPI lifespan runs and the
    module-level AsyncClient (H8) is attached to ``app.state``.

    Individual tests replace ``app.state.http_client`` with a mock to
    avoid real network traffic; the lifespan client is closed on exit.

    ``base_url="http://127.0.0.1"`` makes Starlette populate
    ``scope["server"]`` with a real loopback address so the S9
    loopback-bind middleware (``_enforce_loopback_bind``) does not
    refuse the request. Non-loopback behaviour is exercised in
    ``TestLoopbackBoundary`` via a separate client built without the
    override.
    """
    with TestClient(app, base_url="http://127.0.0.1") as tc:
        yield tc


@pytest.fixture
def tmp_audit_log(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with patch("modules.router.privacy_router.AUDIT_LOG_PATH", str(log_path)):
        yield log_path


def _fake_http_client(
    *,
    post_return=None,
    get_return=None,
    post_side_effect=None,
    get_side_effect=None,
) -> AsyncMock:
    """Build an AsyncMock that mimics the subset of httpx.AsyncClient the
    router actually calls (``.post`` and ``.get``). Tests swap this into
    ``app.state.http_client`` for the duration of a request."""
    client = AsyncMock()
    if post_side_effect is not None:
        client.post = AsyncMock(side_effect=post_side_effect)
    else:
        client.post = AsyncMock(return_value=post_return)
    if get_side_effect is not None:
        client.get = AsyncMock(side_effect=get_side_effect)
    else:
        client.get = AsyncMock(return_value=get_return)
    return client


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        mock_resp = AsyncMock()
        mock_resp.status_code = 200
        app.state.http_client = _fake_http_client(get_return=mock_resp)

        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["router"] == "ok"
        assert data["model_status"] == "ok"

    def test_health_model_unreachable(self, client):
        app.state.http_client = _fake_http_client(
            get_side_effect=httpx.ConnectError("refused")
        )

        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["router"] == "ok"
        assert data["model_status"] == "unreachable"


class TestRouteEndpoint:
    def test_route_forwards_request(self, client):
        mock_body = json.dumps({
            "model": "nemotron-3-8b-instruct",
            "messages": [{"role": "user", "content": "Hello"}],
        })
        mock_response_body = json.dumps({
            "choices": [{"message": {"content": "Hi there"}}],
        })
        mock_resp = AsyncMock()
        mock_resp.content = mock_response_body.encode()
        mock_resp.status_code = 200
        app.state.http_client = _fake_http_client(post_return=mock_resp)

        resp = client.post(
            "/v1/chat/completions",
            content=mock_body,
            headers={"Content-Type": "application/json"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "choices" in data

    def test_route_logs_model_from_request_body(self, client, tmp_audit_log):
        """The audited model name comes from the request payload, not a
        hardcoded constant — a user targeting a different served model must
        still see that model in the audit chain."""
        mock_body = json.dumps({
            "model": "some-other-served-model:latest",
            "messages": [{"role": "user", "content": "Hello"}],
        })
        mock_response_body = json.dumps({"choices": [{"message": {"content": "ok"}}]})
        mock_resp = AsyncMock()
        mock_resp.content = mock_response_body.encode()
        mock_resp.status_code = 200
        app.state.http_client = _fake_http_client(post_return=mock_resp)

        client.post(
            "/v1/chat/completions",
            content=mock_body,
            headers={"Content-Type": "application/json"},
        )

        lines = tmp_audit_log.read_text().strip().split("\n")
        record = json.loads(lines[-1])
        assert record["event_type"] == "route_decision"
        assert record["model"] == "some-other-served-model:latest"

    def test_route_logs_unknown_model_for_malformed_body(self, client, tmp_audit_log):
        """A body that can't be parsed as JSON must still produce a
        route_decision event — logging is load-bearing for the audit chain."""
        mock_resp = AsyncMock()
        mock_resp.content = b'{"choices":[]}'
        mock_resp.status_code = 200
        app.state.http_client = _fake_http_client(post_return=mock_resp)

        client.post(
            "/v1/chat/completions",
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        )

        lines = tmp_audit_log.read_text().strip().split("\n")
        record = json.loads(lines[-1])
        assert record["event_type"] == "route_decision"
        assert record["model"] == "unknown"

    def test_route_returns_upstream_error(self, client):
        mock_resp = AsyncMock()
        mock_resp.content = b'{"error":"model overloaded"}'
        mock_resp.status_code = 503
        app.state.http_client = _fake_http_client(post_return=mock_resp)

        resp = client.post(
            "/v1/chat/completions",
            content=b'{"messages":[]}',
            headers={"Content-Type": "application/json"},
        )

        assert resp.status_code == 503

    def test_http_client_is_reused_across_requests(self, client):
        """H8: the lifespan-owned client must be the same instance across
        requests — a per-request client would defeat the connection pool
        that the whole refactor exists to enable."""
        mock_resp = AsyncMock()
        mock_resp.content = b'{"ok":true}'
        mock_resp.status_code = 200
        fake = _fake_http_client(post_return=mock_resp)
        app.state.http_client = fake

        for _ in range(3):
            client.post(
                "/v1/chat/completions",
                content=b'{"messages":[]}',
                headers={"Content-Type": "application/json"},
            )

        assert fake.post.await_count == 3


class TestRouteLogging:
    def test_log_route_decision_writes_jsonl(self, tmp_audit_log):
        _log_route_decision(target="local_nim", model="nemotron-3-8b-instruct", latency_ms=42.5)

        lines = tmp_audit_log.read_text().strip().split("\n")
        assert len(lines) == 1

        record = json.loads(lines[0])
        assert record["event_type"] == "route_decision"
        assert record["target"] == "local_nim"
        assert record["model"] == "nemotron-3-8b-instruct"
        assert record["latency_ms"] == 42.5
        assert "ts" in record

    def test_log_survives_missing_directory(self):
        """Logging to a nonexistent path should not crash the router."""
        # Should log a warning but not raise
        _log_route_decision(
            target="local_nim",
            model="nemotron-3-8b-instruct",
            latency_ms=10.0,
        )


class TestLoopbackBoundary:
    """S9 / RT-01: router refuses to serve when bound non-loopback unless
    the operator explicitly acknowledges with
    ``SAAF_ALLOW_NONLOOPBACK_ROUTER=1``. Trust model is documented in
    docs/SECURITY.md §10."""

    def test_is_loopback_host_accepts_ipv4_loopback(self):
        assert _is_loopback_host("127.0.0.1")
        assert _is_loopback_host("127.0.0.2")  # whole 127.0.0.0/8

    def test_is_loopback_host_accepts_ipv6_loopback(self):
        assert _is_loopback_host("::1")

    def test_is_loopback_host_accepts_localhost(self):
        assert _is_loopback_host("localhost")

    def test_is_loopback_host_rejects_wildcards_and_public(self):
        assert not _is_loopback_host("0.0.0.0")
        assert not _is_loopback_host("::")
        assert not _is_loopback_host("")
        assert not _is_loopback_host("10.0.0.1")
        assert not _is_loopback_host("192.168.1.50")
        assert not _is_loopback_host("8.8.8.8")

    def test_route_refused_when_bound_nonloopback(self, tmp_audit_log):
        """TestClient built without the loopback base_url override binds
        under 'testserver', which is not loopback — middleware must
        refuse and the refusal must land in the audit chain."""
        mock_resp = AsyncMock()
        mock_resp.content = b'{"ok":true}'
        mock_resp.status_code = 200

        with TestClient(app) as nonloopback_client:
            app.state.http_client = _fake_http_client(post_return=mock_resp)
            resp = nonloopback_client.post(
                "/v1/chat/completions",
                content=b'{"messages":[]}',
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 403
        assert resp.json()["detail"] == "router_bound_to_nonloopback"

        lines = tmp_audit_log.read_text().strip().split("\n")
        record = json.loads(lines[-1])
        assert record["event_type"] == "router_nonloopback_refused"
        assert record["bind_host"] == "testserver"

    def test_route_served_when_allow_env_set(self):
        """Operator-owned escape hatch: mirror of SAAF_ALLOW_IP_FORWARD.
        Setting ``SAAF_ALLOW_NONLOOPBACK_ROUTER=1`` allows a non-loopback
        bind to serve — still audited, operator owns the risk."""
        mock_resp = AsyncMock()
        mock_resp.content = b'{"ok":true}'
        mock_resp.status_code = 200

        with patch.dict(os.environ, {"SAAF_ALLOW_NONLOOPBACK_ROUTER": "1"}), TestClient(app) as nonloopback_client:
            app.state.http_client = _fake_http_client(post_return=mock_resp)
            resp = nonloopback_client.post(
                "/v1/chat/completions",
                content=b'{"messages":[]}',
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 200

    def test_health_refused_when_bound_nonloopback(self):
        """Refusal applies to every endpoint, not just /v1/chat/completions —
        /health would otherwise be a sentinel that a non-loopback bind
        was silently accepted."""
        with TestClient(app) as nonloopback_client:
            app.state.http_client = _fake_http_client()
            resp = nonloopback_client.get("/health")
        assert resp.status_code == 403
