#!/usr/bin/env python3
import asyncio
import json
from pathlib import Path

from nemoguardrails import LLMRails, RailsConfig


async def main() -> None:
    cfg = RailsConfig.from_path(str(Path("guardrails_config").resolve()))
    rails = LLMRails(cfg)
    result = await rails.generate_async(
        messages=[{"role": "user", "content": "Review this compliance note for GDPR issues."}]
    )
    print(json.dumps(result, default=str, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
