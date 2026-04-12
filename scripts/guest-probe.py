#!/usr/bin/python3.12
import json
import os
import time
import urllib.request
from pathlib import Path


def log_step(path: Path, message: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(message + "\n")
    os.sync()


def main() -> None:
    inference_url = os.environ["INFERENCE_URL"]
    output_path = os.environ.get("OUTPUT_PATH", "/audit_workspace/response.json")
    log_path = Path(os.environ.get("PROBE_LOG_PATH", "/audit_workspace/probe.log"))
    payload = {
        "model": "Randomblock1/nemotron-nano:8b",
        "messages": [{"role": "user", "content": "Reply with only OK"}],
    }
    log_step(log_path, "start")
    req = urllib.request.Request(
        inference_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    log_step(log_path, "request_built")
    body = urllib.request.urlopen(req, timeout=30).read().decode("utf-8")
    log_step(log_path, "response_received")
    Path(output_path).write_text(body, encoding="utf-8")
    os.sync()
    log_step(log_path, "response_written")
    time.sleep(1)


if __name__ == "__main__":
    main()
