from __future__ import annotations

import hashlib
from typing import Any

import httpx

from modules.guardrails.audit_emit import emit_rail_fire


def _digest_for_audit(value: Any) -> dict[str, Any]:
    """Return a PII-safe fingerprint of ``value`` for audit emission.

    The output-refusal path previously wrote ``bot_response`` verbatim
    into the audit log (RT-05). On a GDPR log that's a data leak:
    the refused output is exactly the text the rail judged unsafe and
    may contain the PII that tripped it. Emit a SHA-256 digest plus the
    character length instead so operators retain a stable correlation
    handle without retaining the content.
    """
    text = "" if value is None else str(value)
    return {
        "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "content_len": len(text),
    }

try:
    from nemoguardrails.actions import action
    from nemoguardrails.actions.actions import ActionResult
    from nemoguardrails.llm.types import Task
except ModuleNotFoundError:  # pragma: no cover
    def action(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

    class ActionResult:  # pragma: no cover
        def __init__(self, return_value=None):
            self.return_value = return_value

    class Task:  # pragma: no cover
        SELF_CHECK_INPUT = "self_check_input"
        SELF_CHECK_OUTPUT = "self_check_output"


def resolve_model_config(config, model_type: str) -> tuple[str, str]:
    for model in getattr(config, "models", []):
        if getattr(model, "type", None) == model_type:
            return model.model, model.parameters["base_url"]
    raise RuntimeError(f"No model configured with type '{model_type}'")


async def _run_self_check_task(task, llm_task_manager, context, config) -> bool:
    prompt = llm_task_manager.render_task_prompt(task=task, context=context)
    stop = llm_task_manager.get_stop_tokens(task=task)
    max_tokens = llm_task_manager.get_max_tokens(task=task) or 3
    model_name, base_url = resolve_model_config(config, "self_check")

    payload: dict[str, Any] = {
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": getattr(config, "lowest_temperature", 0),
        "max_tokens": max_tokens,
    }
    if stop:
        payload["stop"] = stop

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(f"{base_url}/chat/completions", json=payload)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]

    result = llm_task_manager.parse_task_output(task, output=content, forced_output_parser="is_content_safe")
    return result[0]


@action(name="SelfCheckInputDirectAction", execute_async=True)
async def self_check_input_direct(llm_task_manager, context=None, config=None, **kwargs):
    user_input = (context or {}).get("user_message")
    is_safe = await _run_self_check_task(
        Task.SELF_CHECK_INPUT,
        llm_task_manager,
        {"user_input": user_input},
        config,
    )
    if not is_safe:
        # Symmetric to the output-refusal path: a rail that just classified
        # this input as unsafe will often have classified it because it
        # contains PII or an attack payload. Never write the raw text into
        # the audit log — emit a digest + length for correlation only.
        emit_rail_fire(
            "self_check_input_refusal",
            _digest_for_audit(user_input),
        )
        return ActionResult(return_value=False)
    return is_safe


@action(name="SelfCheckOutputDirectAction", execute_async=True)
async def self_check_output_direct(llm_task_manager, context=None, config=None, **kwargs):
    context = context or {}
    is_safe = await _run_self_check_task(
        Task.SELF_CHECK_OUTPUT,
        llm_task_manager,
        {
            "user_input": context.get("user_message"),
            "bot_response": context.get("bot_message"),
            "bot_thinking": context.get("bot_thinking"),
        },
        config,
    )
    if not is_safe:
        emit_rail_fire(
            "self_check_output_refusal",
            _digest_for_audit(context.get("bot_message")),
        )
    return is_safe
