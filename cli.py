"""saaf-shell — CLI entry point for saaf-compliance-shell.

Usage:
    saaf-shell validate --manifest <path>
    saaf-shell verify-log --log <path>
    saaf-shell run --manifest <path>          (Phase 2+)
    saaf-shell diff --agent-id <id>           (Phase 2+)
    saaf-shell sessions                       (Phase 2+)
    saaf-shell test --manifest <path> --suite <name>  (Phase 3+)
"""

import argparse
import sys
from pathlib import Path

from modules.audit.log import verify_log
from modules.isolation.agentfs import AgentFSClient
from modules.isolation.runtime import run_manifest
from modules.manifest.validator import validate_manifest

DEFAULT_ROOTFS = Path("/opt/saaf/rootfs/ubuntu-24.04-python-base")
DEFAULT_OVERLAY_DIR = Path("/opt/saaf/.agentfs")


def _agentfs_client() -> AgentFSClient:
    return AgentFSClient(base_rootfs=DEFAULT_ROOTFS, overlay_dir=DEFAULT_OVERLAY_DIR)


def diff_session(agent_id: str) -> list[str]:
    return _agentfs_client().diff_session(agent_id)


def list_sessions() -> list[str]:
    return _agentfs_client().list_sessions()


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate a saaf-manifest.yaml file."""
    result = validate_manifest(args.manifest)

    if result.valid:
        print(f"OK — {args.manifest} is valid")
        if result.manifest:
            print(f"  name: {result.manifest.get('name', '?')}")
            print(f"  version: {result.manifest.get('version', '?')}")
        return 0

    print(f"INVALID — {len(result.errors)} error(s) in {args.manifest}:\n")
    for err in result.errors:
        print(f"  [{err.field}] {err.message}")
    return 1


def cmd_verify_log(args: argparse.Namespace) -> int:
    """Verify audit log hash chain integrity."""
    valid, message = verify_log(args.log)

    if valid:
        print(f"OK — {message}")
        return 0

    print(f"FAIL — {message}")
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    """Launch a target repo inside the compliance shell."""
    try:
        session_id = run_manifest(args.manifest)
    except Exception as exc:  # pragma: no cover - exercised via CLI tests with monkeypatch
        print(f"FAIL — {exc}")
        return 1

    print(f"OK — started session {session_id}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Inspect AgentFS filesystem changes."""
    try:
        changes = diff_session(args.agent_id)
    except Exception as exc:  # pragma: no cover - exercised via CLI tests with monkeypatch
        print(f"FAIL — {exc}")
        return 1

    if not changes:
        print(f"OK — no changes for {args.agent_id}")
        return 0

    for line in changes:
        print(line)
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    """List all agent sessions."""
    try:
        sessions = list_sessions()
    except Exception as exc:  # pragma: no cover - exercised via CLI tests with monkeypatch
        print(f"FAIL — {exc}")
        return 1

    if not sessions:
        print("OK — no sessions found")
        return 0

    for session_id in sessions:
        print(session_id)
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Run red team test suite (Phase 3+)."""
    print("ERROR: 'test' requires the red team suite (Phase 3). Not yet implemented.")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="saaf-shell",
        description="Compliance shell for AI agent workloads — GDPR/AVG, DORA, EU AI Act",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # validate
    p_val = sub.add_parser("validate", help="Validate a saaf-manifest.yaml")
    p_val.add_argument("--manifest", "-m", required=True, help="Path to saaf-manifest.yaml")
    p_val.set_defaults(func=cmd_validate)

    # verify-log
    p_ver = sub.add_parser("verify-log", help="Verify audit log hash chain")
    p_ver.add_argument("--log", "-l", required=True, help="Path to audit JSONL file")
    p_ver.set_defaults(func=cmd_verify_log)

    # run (Phase 2+)
    p_run = sub.add_parser("run", help="Launch agent in compliance shell (Phase 2+)")
    p_run.add_argument("--manifest", "-m", required=True, help="Path to saaf-manifest.yaml")
    p_run.set_defaults(func=cmd_run)

    # diff (Phase 2+)
    p_diff = sub.add_parser("diff", help="Inspect AgentFS changes (Phase 2+)")
    p_diff.add_argument("--agent-id", required=True, help="Agent session ID")
    p_diff.set_defaults(func=cmd_diff)

    # sessions (Phase 2+)
    p_sess = sub.add_parser("sessions", help="List agent sessions (Phase 2+)")
    p_sess.set_defaults(func=cmd_sessions)

    # test (Phase 3+)
    p_test = sub.add_parser("test", help="Run red team test suite (Phase 3+)")
    p_test.add_argument("--manifest", "-m", required=True, help="Path to saaf-manifest.yaml")
    p_test.add_argument("--suite", "-s", required=True, help="Test suite name")
    p_test.set_defaults(func=cmd_test)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
