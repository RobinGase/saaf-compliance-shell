"""RT-05 regression tests: raw user/bot content must not reach the audit log.

Before S8, ``self_check_input_direct`` and ``self_check_output_direct``
emitted rail-fire events containing the verbatim ``user_input`` /
``bot_response`` fields. On a refusal that content is exactly what the
rail judged unsafe — typically PII, an injection payload, or both.
S8 replaces the raw field with a SHA-256 digest + character length so
operators retain a correlation handle without retaining the content.
"""

from __future__ import annotations

import asyncio
import hashlib

from guardrails_config.actions import self_check_direct as sut


def _expected_digest(text: str) -> dict[str, object]:
    return {
        "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "content_len": len(text),
    }


def test_digest_for_audit_hashes_and_sizes_text() -> None:
    assert sut._digest_for_audit("hello") == _expected_digest("hello")


def test_digest_for_audit_handles_none() -> None:
    # ``context.get(...)`` returns ``None`` when the key is absent. The
    # helper must not raise — a missing field is still auditable as a
    # zero-length message with a stable digest.
    assert sut._digest_for_audit(None) == _expected_digest("")


def test_digest_for_audit_is_stable_across_calls() -> None:
    payload = "BSN 123456782 email alice@example.com"
    first = sut._digest_for_audit(payload)
    second = sut._digest_for_audit(payload)
    assert first == second
    assert first["content_sha256"] != hashlib.sha256(b"").hexdigest()


def test_input_refusal_emits_digest_not_raw_text(monkeypatch) -> None:
    """A refused input must not land in the audit payload verbatim.

    Stub the LLM call to force ``is_safe=False`` and capture the
    rail-fire payload. The captured report must contain the digest
    fields and must not contain any field that equals the raw input.
    """
    raw_input = "my BSN is 123456782, please help"
    captured: dict[str, object] = {}

    async def fake_run_task(task, llm_task_manager, context, config):
        return False

    def fake_emit(rail_name, report):
        captured["rail_name"] = rail_name
        captured["report"] = report

    monkeypatch.setattr(sut, "_run_self_check_task", fake_run_task)
    monkeypatch.setattr(sut, "emit_rail_fire", fake_emit)

    asyncio.run(
        sut.self_check_input_direct(
            llm_task_manager=object(),
            context={"user_message": raw_input},
            config=object(),
        )
    )

    assert captured["rail_name"] == "self_check_input_refusal"
    report = captured["report"]
    assert isinstance(report, dict)
    assert report == _expected_digest(raw_input)
    assert "user_input" not in report
    assert raw_input not in report.values()


def test_output_refusal_emits_digest_not_raw_text(monkeypatch) -> None:
    """Mirror of the input test on the output-rail path."""
    raw_output = "Here is Alice's email: alice@example.com"
    captured: dict[str, object] = {}

    async def fake_run_task(task, llm_task_manager, context, config):
        return False

    def fake_emit(rail_name, report):
        captured["rail_name"] = rail_name
        captured["report"] = report

    monkeypatch.setattr(sut, "_run_self_check_task", fake_run_task)
    monkeypatch.setattr(sut, "emit_rail_fire", fake_emit)

    asyncio.run(
        sut.self_check_output_direct(
            llm_task_manager=object(),
            context={
                "user_message": "who is alice",
                "bot_message": raw_output,
                "bot_thinking": "alice is ...",
            },
            config=object(),
        )
    )

    assert captured["rail_name"] == "self_check_output_refusal"
    report = captured["report"]
    assert isinstance(report, dict)
    assert report == _expected_digest(raw_output)
    assert "bot_response" not in report
    assert raw_output not in report.values()


def test_safe_path_does_not_emit_rail_fire(monkeypatch) -> None:
    """On ``is_safe=True`` the code must not emit a refusal event."""
    calls: list[tuple[str, object]] = []

    async def fake_run_task(task, llm_task_manager, context, config):
        return True

    def fake_emit(rail_name, report):
        calls.append((rail_name, report))

    monkeypatch.setattr(sut, "_run_self_check_task", fake_run_task)
    monkeypatch.setattr(sut, "emit_rail_fire", fake_emit)

    asyncio.run(
        sut.self_check_input_direct(
            llm_task_manager=object(),
            context={"user_message": "hello"},
            config=object(),
        )
    )
    asyncio.run(
        sut.self_check_output_direct(
            llm_task_manager=object(),
            context={"user_message": "hi", "bot_message": "hello", "bot_thinking": ""},
            config=object(),
        )
    )

    assert calls == []
