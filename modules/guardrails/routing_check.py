"""Helpers for validating Guardrails routing behavior."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml


def prepare_validation_config(
    *,
    source_dir: str | Path,
    target_dir: str | Path,
    router_url: str,
    direct_url: str,
) -> Path:
    source_dir = Path(source_dir)
    target_dir = Path(target_dir)
    if target_dir.exists():
        shutil.rmtree(target_dir)
    shutil.copytree(source_dir, target_dir)

    config_path = target_dir / "config.yml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    for model in config.get("models", []):
        if model.get("type") == "main":
            model.setdefault("parameters", {})["base_url"] = router_url
        elif model.get("type") == "self_check":
            model.setdefault("parameters", {})["base_url"] = direct_url
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return target_dir


class _RecorderHandler(BaseHTTPRequestHandler):
    router_hits: list[dict] = []
    direct_hits: list[dict] = []
    mode = "router"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if self.mode == "router":
            self.router_hits.append(payload)
            content = '"OK"'
        else:
            self.direct_hits.append(payload)
            content = "no"
        response = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 0,
            "model": payload.get("model", "test"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        }
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):  # noqa: A003
        return


def _serve(port: int, mode: str):
    handler = type(f"{mode.title()}Handler", (_RecorderHandler,), {"mode": mode})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


async def _run_validation(config_dir: Path) -> None:
    os.environ.setdefault("OPENAI_API_KEY", "not-used")
    from nemoguardrails import LLMRails, RailsConfig

    cfg = RailsConfig.from_path(str(config_dir))
    rails = LLMRails(cfg)
    await rails.generate_async(messages=[{"role": "user", "content": "Reply with only OK"}])


def run_guardrails_routing_validation(
    config_dir: str | Path,
    *,
    router_port: int = 18089,
    direct_port: int = 18000,
) -> dict[str, int | str]:
    _RecorderHandler.router_hits = []
    _RecorderHandler.direct_hits = []

    router_url = f"http://127.0.0.1:{router_port}/v1"
    direct_url = f"http://127.0.0.1:{direct_port}/v1"

    with TemporaryDirectory() as temp_dir:
        prepared = prepare_validation_config(
            source_dir=config_dir,
            target_dir=Path(temp_dir) / "routing_validation_config",
            router_url=router_url,
            direct_url=direct_url,
        )
        router_server = _serve(router_port, "router")
        direct_server = _serve(direct_port, "direct")
        try:
            asyncio.run(_run_validation(prepared))
        finally:
            router_server.shutdown()
            direct_server.shutdown()

    return {
        "router_hits": len(_RecorderHandler.router_hits),
        "direct_hits": len(_RecorderHandler.direct_hits),
        "main_url": router_url,
        "self_check_url": direct_url,
    }
