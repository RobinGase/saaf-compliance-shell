#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from modules.guardrails.routing_check import run_guardrails_routing_validation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", default="guardrails_config")
    parser.add_argument("--router-port", type=int, default=18089)
    parser.add_argument("--direct-port", type=int, default=18000)
    args = parser.parse_args()

    result = run_guardrails_routing_validation(
        Path(args.config_dir),
        router_port=args.router_port,
        direct_port=args.direct_port,
    )

    if not result["direct_hits"]:
        raise SystemExit("no direct self check hits recorded")

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
