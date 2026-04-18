"""Privacy Router — local-only model routing for saaf-compliance-shell.

All inference traffic goes to a same-host model endpoint.
No cloud fallback in v1. PII masking is handled by NeMo Guardrails
before traffic reaches this router.
"""

import json
import logging
import os
import time

import httpx
from fastapi import FastAPI, Request, Response

from modules.audit.log import append_chained_event

LOCAL_NIM_URL = os.environ.get(
    "LOCAL_NIM_URL", "http://127.0.0.1:8000/v1/chat/completions"
)
AUDIT_LOG_PATH = os.environ.get(
    "AUDIT_LOG_PATH", "/var/log/openshell/audit.jsonl"
)
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "120.0"))

app = FastAPI(title="saaf-privacy-router", version="1.0.0")
logger = logging.getLogger("privacy_router")


def _log_route_decision(target: str, model: str, latency_ms: float) -> None:
    """Append a route_decision event to the hash-chained audit log.

    A caller-visible failure here would mask a successful downstream
    request as an error, but a silent swallow is worse: the audit
    trail is a compliance artefact, so any write failure must be
    loud in operator logs. We catch broadly (OSError *and* any
    corruption-surface error raised inside ``append_chained_event``
    such as JSON serialisation, hash-chain invariants, or the file
    lock layer) and ``logger.error`` with ``exc_info=True`` so the
    traceback reaches operator monitoring.
    """
    try:
        append_chained_event(
            AUDIT_LOG_PATH,
            "route_decision",
            target=target,
            model=model,
            latency_ms=round(latency_ms, 2),
        )
    except Exception:
        logger.error(
            "Failed to write route_decision audit event (target=%s model=%s)",
            target,
            model,
            exc_info=True,
        )


def _model_from_body(body: bytes) -> str:
    """Extract the ``model`` field from an OpenAI-style chat completion body.

    Returns ``"unknown"`` if the body is not JSON or has no ``model`` key —
    the audit event must still be logged in that case so the route decision
    is never silently dropped.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return "unknown"
    if not isinstance(payload, dict):
        return "unknown"
    model = payload.get("model")
    return model if isinstance(model, str) and model else "unknown"


@app.post("/v1/chat/completions")
async def route(request: Request) -> Response:
    """Forward inference request to local model endpoint.

    PII masking is already done by NeMo Guardrails input rails.
    This router only handles model routing and logging.
    """
    body = await request.body()
    start = time.monotonic()

    async with httpx.AsyncClient() as client:
        nim_response = await client.post(
            LOCAL_NIM_URL,
            content=body,
            headers={"Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )

    latency_ms = (time.monotonic() - start) * 1000

    _log_route_decision(
        target="local_nim",
        model=_model_from_body(body),
        latency_ms=latency_ms,
    )

    return Response(
        content=nim_response.content,
        status_code=nim_response.status_code,
        headers={"Content-Type": "application/json"},
    )


@app.get("/health")
async def health() -> dict:
    """Health check — also verifies model endpoint is reachable."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                LOCAL_NIM_URL.replace("/chat/completions", "/models"),
                timeout=5.0,
            )
            model_status = "ok" if resp.status_code == 200 else "unreachable"
    except httpx.ConnectError:
        model_status = "unreachable"

    return {
        "router": "ok",
        "model_endpoint": LOCAL_NIM_URL,
        "model_status": model_status,
    }
