"""Branch-aware portability policy for modular and main branches."""

from __future__ import annotations

import argparse
from pathlib import Path

FORBIDDEN_STRINGS = (
    "maindev",
    "fedoraserver",
    "robindev",
    "100.87.245.60",
    "100.115.144.22",
    "setup-ollama-maindev",
    "build-rootfs-fedoraserver",
    # Sentinel — never used outside the portability test.
    "FORBIDDEN_PORTABILITY_SENTINEL",
)

TARGET_PATHS = (
    "README.md",
    "cli.py",
    "guardrails/config.yml",
    "docs/implementation_plan.md",
    "modules/isolation/agentfs.py",
    "modules/isolation/firecracker.py",
    "modules/isolation/network.py",
    "modules/isolation/runtime.py",
    "modules/router/privacy_router.py",
    "scripts/build-rootfs.sh",
    "scripts/setup-ollama-local.sh",
    "ops/systemd/saaf-guardrails.service",
    "ops/systemd/saaf-router.service",
    "ops/systemd/README.md",
)


def should_enforce_portability(branch_name: str) -> bool:
    return branch_name == "main" or branch_name.startswith("modular/")


def iter_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for relative in TARGET_PATHS:
        path = root / relative
        if path.exists():
            paths.append(path)
    return paths


def check_paths(paths: list[Path]) -> list[str]:
    violations: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for needle in FORBIDDEN_STRINGS:
            if needle in text:
                violations.append(f"{path}: found forbidden portability marker '{needle}'")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", required=True)
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)

    if not should_enforce_portability(args.branch):
        print(f"Skipping portability policy for branch '{args.branch}'")
        return 0

    violations = check_paths(iter_paths(Path(args.root).resolve()))
    if violations:
        for violation in violations:
            print(violation)
        return 1

    print(f"Portability policy passed for branch '{args.branch}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
