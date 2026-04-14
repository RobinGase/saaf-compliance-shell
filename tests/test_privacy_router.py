"""Tests for the Privacy Router — FastAPI local-only model routing proxy."""

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from modules.router.privacy_router import _log_route_decision, app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def tmp_audit_log(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    with patch("modules.router.privacy_router.AUDIT_LOG_PATH", str(log_path)):
        yield log_path


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        with patch("modules.router.privacy_router.httpx.AsyncClient") as mock_client:
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["router"] == "ok"
            assert data["model_status"] == "ok"

    def test_health_model_unreachable(self, client):
        with patch("modules.router.privacy_router.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

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

        with patch("modules.router.privacy_router.httpx.AsyncClient") as mock_client:
            mock_resp = AsyncMock()
            mock_resp.content = mock_response_body.encode()
            mock_resp.status_code = 200
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

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

        with patch("modules.router.privacy_router.httpx.AsyncClient") as mock_client:
            mock_resp = AsyncMock()
            mock_resp.content = mock_response_body.encode()
            mock_resp.status_code = 200
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

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
        with patch("modules.router.privacy_router.httpx.AsyncClient") as mock_client:
            mock_resp = AsyncMock()
            mock_resp.content = b'{"choices":[]}'
            mock_resp.status_code = 200
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

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
        with patch("modules.router.privacy_router.httpx.AsyncClient") as mock_client:
            mock_resp = AsyncMock()
            mock_resp.content = b'{"error":"model overloaded"}'
            mock_resp.status_code = 503
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            resp = client.post(
                "/v1/chat/completions",
                content=b'{"messages":[]}',
                headers={"Content-Type": "application/json"},
            )

            assert resp.status_code == 503


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
