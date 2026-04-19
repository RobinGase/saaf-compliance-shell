"""Privacy Router — local-only model routing for saaf-compliance-shell.

All inference traffic goes to a same-host model endpoint.
No cloud fallback in v1. PII masking is handled by NeMo Guardrails
before traffic reaches this router.
"""

import ipaddress
import json
import logging
import os
import time
from contextlib import asynccontextmanager

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

logger = logging.getLogger("privacy_router")


# H8: a module-level AsyncClient reused across requests. The previous
# per-request ``async with httpx.AsyncClient()`` opened a fresh TCP +
# (eventually) TLS handshake on every inference call — hundreds of ms
# per RTT on a cold pool, completely unnecessary for a same-host route
# that's going to ``127.0.0.1``. Lifespan hook owns the client so it
# closes cleanly on shutdown; tests can poke at the attribute directly.
@asynccontextmanager
async def _lifespan(_app: FastAPI):
    _app.state.http_client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
    try:
        yield
    finally:
        await _app.state.http_client.aclose()


app = FastAPI(title="saaf-privacy-router", version="1.0.0", lifespan=_lifespan)


def _is_loopback_host(host: str) -> bool:
    """True when ``host`` designates a loopback-only bind target.

    Accepts ``localhost`` and any address that ``ipaddress`` resolves as
    loopback (``127.0.0.0/8``, ``::1``). Wildcards (``0.0.0.0``, ``::``,
    empty string) return False — those are exactly the binds RT-01
    exists to refuse.
    """
    if host in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@app.middleware("http")
async def _enforce_loopback_bind(request: Request, call_next):
    """RT-01: refuse to serve when the router is bound non-loopback.

    The v0.9.0 trust model treats any caller able to reach the router's
    bind address as authorised to invoke the local model. That model
    only holds when the bind is loopback — a non-loopback bind silently
    exposes the model endpoint to the network. We inspect
    ``scope["server"]`` (uvicorn / hypercorn populate it with the actual
    bind host + port) and refuse with 403 ``router_bound_to_nonloopback``
    rather than serve. An operator who owns the network boundary by
    other means can opt out with ``SAAF_ALLOW_NONLOOPBACK_ROUTER=1`` —
    same escape-hatch pattern as ``SAAF_ALLOW_IP_FORWARD`` from the
    isolation setup. Every refusal emits a ``router_nonloopback_refused``
    audit event so the override surface is visible in the chain.
    """
    server = request.scope.get("server")
    if server is not None:
        host = server[0] or ""
        if not _is_loopback_host(host) and os.environ.get(
            "SAAF_ALLOW_NONLOOPBACK_ROUTER"
        ) != "1":
            try:
                append_chained_event(
                    AUDIT_LOG_PATH,
                    "router_nonloopback_refused",
                    bind_host=host,
                    bind_port=server[1] if len(server) > 1 else None,
                    client=request.client.host if request.client else None,
                )
            except Exception:
                logger.error(
                    "Failed to write router_nonloopback_refused audit event",
                    exc_info=True,
                )
            return Response(
                content=b'{"detail":"router_bound_to_nonloopback"}',
                status_code=403,
                headers={"Content-Type": "application/json"},
            )
    return await call_next(request)


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

    nim_response = await request.app.state.http_client.post(
        LOCAL_NIM_URL,
        content=body,
        headers={"Content-Type": "application/json"},
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
async def health(request: Request) -> dict:
    """Health check — also verifies model endpoint is reachable."""
    try:
        resp = await request.app.state.http_client.get(
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
