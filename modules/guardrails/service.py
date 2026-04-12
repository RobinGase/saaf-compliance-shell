"""Minimal FastAPI wrapper around a single Guardrails config."""

from __future__ import annotations

import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]


@lru_cache(maxsize=8)
def get_rails(config_path: str, model_name: str | None = None):
    os.environ.setdefault("OPENAI_API_KEY", "not-used")

    from nemoguardrails import LLMRails, RailsConfig

    cfg = RailsConfig.from_path(config_path)

    return LLMRails(cfg)


def create_app(config_path: str | Path) -> FastAPI:
    config_path = Path(config_path).resolve()
    app = FastAPI(title="saaf-guardrails-service", version="1.0.0")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {
            "status": "ok",
            "config_id": config_path.name,
            "config_path": str(config_path),
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(body: ChatCompletionRequest) -> dict[str, Any]:
        try:
            rails = get_rails(str(config_path), body.model)
            start = time.time()
            result = await rails.generate_async(messages=[message.model_dump() for message in body.messages])
            elapsed = int((time.time() - start) * 1000)
        except Exception as exc:
            salvaged = _recover_quoted_llm_value(str(exc))
            if salvaged is None:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            result = {"role": "assistant", "content": salvaged}
            elapsed = 0

        if isinstance(result, dict):
            bot_message = {
                "role": result.get("role", "assistant"),
                "content": result.get("content", ""),
            }
        else:
            bot_message = {"role": "assistant", "content": str(result)}

        return {
            "id": f"chatcmpl-saaf-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.model,
            "choices": [
                {
                    "index": 0,
                    "message": bot_message,
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
            "latency_ms": elapsed,
        }

    return app


def _recover_quoted_llm_value(error_text: str) -> str | None:
    if "Invalid LLM response:" not in error_text:
        return None
    match = re.search(r'`"([^"]+)"', error_text)
    if not match:
        return None
    return match.group(1)


def build_default_app() -> FastAPI:
    repo_root = Path(__file__).resolve().parents[2]
    return create_app(repo_root / "guardrails")


app = build_default_app()
