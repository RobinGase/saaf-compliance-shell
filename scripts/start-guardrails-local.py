"""Start the repo-owned Guardrails HTTP service in local mode."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from modules.guardrails.service import create_app


def main() -> None:
    os.environ.setdefault("OPENAI_API_KEY", "not-used")
    repo_root = Path(__file__).resolve().parent.parent
    app = create_app(repo_root / "guardrails")

    # Single worker is intentional. ``_build_rails`` uses an
    # ``os.chdir``-based workaround for Colang 2.x's CWD-first import
    # resolver (see ``_neutral_cwd_for_colang_imports`` in
    # ``modules/guardrails/service.py``). A ``threading.Lock`` inside
    # the service makes the chdir safe across threads, but additional
    # OS-level workers would each hold their own CWD and any other
    # process sharing the working directory could observe the chdir
    # window. Until the config directory is renamed away from
    # ``guardrails/`` (tracked for v0.9), keep ``workers=1``.
    uvicorn.run(app, host="127.0.0.1", port=8088, log_level="info", workers=1)


if __name__ == "__main__":
    main()
