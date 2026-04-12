from pathlib import Path

from fastapi.testclient import TestClient

from modules.guardrails.service import create_app


def test_health_reports_config_id_and_path(tmp_path: Path) -> None:
    app = create_app(config_path=tmp_path / "guardrails")
    client = TestClient(app)

    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "config_id": "guardrails",
        "config_path": str((tmp_path / "guardrails").resolve()),
    }


def test_chat_completions_uses_single_config_rails(monkeypatch, tmp_path: Path) -> None:
    app = create_app(config_path=tmp_path / "guardrails")
    client = TestClient(app)

    class FakeRails:
        async def generate_async(self, *, messages):
            assert messages == [{"role": "user", "content": "Reply with only OK"}]
            return {"role": "assistant", "content": "OK"}

    monkeypatch.setattr("modules.guardrails.service.get_rails", lambda config_path, model_name=None: FakeRails())

    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "Randomblock1/nemotron-nano:8b",
            "messages": [{"role": "user", "content": "Reply with only OK"}],
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["choices"][0]["message"] == {"role": "assistant", "content": "OK"}
    assert body["model"] == "Randomblock1/nemotron-nano:8b"


def test_chat_completions_returns_500_on_generation_error(monkeypatch, tmp_path: Path) -> None:
    app = create_app(config_path=tmp_path / "guardrails")
    client = TestClient(app)

    class FakeRails:
        async def generate_async(self, *, messages):
            raise RuntimeError("generation failed")

    monkeypatch.setattr("modules.guardrails.service.get_rails", lambda config_path, model_name=None: FakeRails())

    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "Randomblock1/nemotron-nano:8b",
            "messages": [{"role": "user", "content": "Reply with only OK"}],
        },
    )

    assert resp.status_code == 500
    assert resp.json()["detail"] == "generation failed"


def test_chat_completions_recovers_quoted_value_from_invalid_llm_response(monkeypatch, tmp_path: Path) -> None:
    app = create_app(config_path=tmp_path / "guardrails")
    client = TestClient(app)

    class FakeRails:
        async def generate_async(self, *, messages):
            raise RuntimeError('Invalid LLM response: `"OK"  // comment`')

    monkeypatch.setattr("modules.guardrails.service.get_rails", lambda config_path, model_name=None: FakeRails())

    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "Randomblock1/nemotron-nano:8b",
            "messages": [{"role": "user", "content": "Reply with only OK"}],
        },
    )

    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"] == {"role": "assistant", "content": "OK"}


def test_chat_completions_strips_internal_guardrails_fields(monkeypatch, tmp_path: Path) -> None:
    app = create_app(config_path=tmp_path / "guardrails")
    client = TestClient(app)

    class FakeRails:
        async def generate_async(self, *, messages):
            return {
                "role": "assistant",
                "content": "OK",
                "tool_calls": [{"id": "timer-1"}],
                "events": [{"type": "StopTimerBotAction"}],
            }

    monkeypatch.setattr("modules.guardrails.service.get_rails", lambda config_path, model_name=None: FakeRails())

    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "Randomblock1/nemotron-nano:8b",
            "messages": [{"role": "user", "content": "Reply with only OK"}],
        },
    )

    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"] == {"role": "assistant", "content": "OK"}
