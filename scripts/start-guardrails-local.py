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

    uvicorn.run(app, host="127.0.0.1", port=8088, log_level="info")


if __name__ == "__main__":
    main()
