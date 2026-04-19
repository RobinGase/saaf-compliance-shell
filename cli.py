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
import logging
import subprocess
import sys
from pathlib import Path

from modules.audit.log import verify_log
from modules.guardrails.red_team import run_red_team_suite
from modules.guardrails.routing_check import run_guardrails_routing_validation
from modules.isolation.agentfs import AgentFSClient, AgentFSError
from modules.isolation.network import IpForwardEnabledError, NetworkPolicyError
from modules.isolation.runtime import run_manifest
from modules.isolation.smoke import run_vm_probe
from modules.manifest.validator import validate_manifest

DEFAULT_ROOTFS = Path("/opt/saaf/rootfs/ubuntu-24.04-python-base")
DEFAULT_OVERLAY_DIR = Path("/opt/saaf/.agentfs")

# L1: CLI output goes through ``logging`` so systemd / operators can
# redirect + filter by level. The handler is attached at import time so
# command functions invoked directly (e.g. ``args.func(args)`` in tests)
# still produce output without routing through ``main()``. Handler resolves
# ``sys.stdout`` dynamically on each emit so pytest's ``capsys`` — which
# swaps ``sys.stdout`` after import — still captures everything under
# ``captured.out``. A plain ``StreamHandler(stream=sys.stdout)`` would pin
# the original stdout and silently bypass capsys.
class _DynamicStdoutHandler(logging.StreamHandler):
    @property
    def stream(self):
        return sys.stdout

    @stream.setter
    def stream(self, _value):
        # StreamHandler.__init__ tries to set self.stream; ignore so the
        # property lookup above stays authoritative.
        pass


logger = logging.getLogger("saaf_shell")
_stdout_handler = _DynamicStdoutHandler()
_stdout_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_stdout_handler)
logger.setLevel(logging.INFO)
logger.propagate = False

# L3: the narrow set of exceptions saaf-shell commands are expected to
# surface. Anything outside this tuple is a bug in the shell and should
# produce a traceback instead of a swallowed "FAIL — ...". Kept centrally
# so a new command can't silently broaden the catch.
_EXPECTED_ERRORS: tuple[type[BaseException], ...] = (
    ValueError,
    FileNotFoundError,
    NetworkPolicyError,
    IpForwardEnabledError,
    AgentFSError,
    subprocess.CalledProcessError,
)


def _configure_logging(verbose: bool) -> None:
    """Install a stdout handler at INFO (or DEBUG with ``--verbose``)."""
    if logger.handlers:
        # Already configured (e.g. repeated ``main()`` calls in tests).
        return
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False


def _agentfs_client() -> AgentFSClient:
    return AgentFSClient(base_rootfs=DEFAULT_ROOTFS, overlay_dir=DEFAULT_OVERLAY_DIR)


def diff_session(agent_id: str) -> list[str]:
    return _agentfs_client().diff_session(agent_id)


def list_sessions() -> list[str]:
    return _agentfs_client().list_sessions()


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate a saaf-manifest.yaml file.

    As of v0.8.7 ``validate_manifest`` folds in the v1 network-policy
    check that previously lived behind a separate
    ``validate_v1_network_rules`` call (M1). A single pass is now
    authoritative; the runtime path still re-checks as
    belt-and-suspenders.
    """
    result = validate_manifest(args.manifest)

    if not result.valid:
        logger.info("INVALID — %d error(s) in %s:\n", len(result.errors), args.manifest)
        for err in result.errors:
            logger.info("  [%s] %s", err.field, err.message)
        return 1

    logger.info("OK — %s is valid", args.manifest)
    if result.manifest:
        logger.info("  name: %s", result.manifest.get("name", "?"))
        logger.info("  version: %s", result.manifest.get("version", "?"))
    return 0


def cmd_verify_log(args: argparse.Namespace) -> int:
    """Verify audit log hash chain integrity."""
    valid, message = verify_log(args.log)

    if valid:
        logger.info("OK — %s", message)
        return 0

    logger.info("FAIL — %s", message)
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    """Launch a target repo inside the compliance shell."""
    try:
        session_id = run_manifest(args.manifest)
    except _EXPECTED_ERRORS as exc:
        logger.info("FAIL — %s", exc)
        return 1

    logger.info("OK — started session %s", session_id)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Inspect AgentFS filesystem changes."""
    try:
        changes = diff_session(args.agent_id)
    except _EXPECTED_ERRORS as exc:
        logger.info("FAIL — %s", exc)
        return 1

    if not changes:
        logger.info("OK — no changes for %s", args.agent_id)
        return 0

    for line in changes:
        logger.info("%s", line)
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    """List all agent sessions."""
    try:
        sessions = list_sessions()
    except _EXPECTED_ERRORS as exc:
        logger.info("FAIL — %s", exc)
        return 1

    if not sessions:
        logger.info("OK — no sessions found")
        return 0

    for session_id in sessions:
        logger.info("%s", session_id)
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Run repeatable integration and adversarial suites."""
    try:
        if args.suite == "vm-probe":
            result = run_vm_probe(
                manifest_path=args.manifest,
                overlay_dir=args.overlay_dir,
                audit_log_path=args.audit_log,
            )
        elif args.suite == "guardrails-routing":
            result = run_guardrails_routing_validation(args.config_dir)
        elif args.suite == "red-team":
            result = run_red_team_suite(cases_path=args.cases, endpoint=args.endpoint)
        else:
            logger.info("FAIL — unknown suite: %s", args.suite)
            return 1
    except _EXPECTED_ERRORS as exc:
        logger.info("FAIL — %s", exc)
        return 1

    logger.info("%s", result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="saaf-shell",
        description="Compliance shell for AI agent workloads — GDPR/AVG, DORA, EU AI Act",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging (default: INFO).",
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
    p_test.add_argument("--overlay-dir", default=str(DEFAULT_OVERLAY_DIR), help="AgentFS overlay directory for vm-probe")
    p_test.add_argument("--audit-log", default="/tmp/saaf-probe-audit.jsonl", help="Audit log path for vm-probe")
    p_test.add_argument("--config-dir", default="guardrails", help="Guardrails config directory for guardrails-routing")
    p_test.add_argument("--cases", default=str(Path("tests") / "fixtures" / "red_team_cases.json"), help="Path to red team case file")
    p_test.add_argument("--endpoint", default="http://127.0.0.1:8088/v1/chat/completions", help="Guardrails endpoint for red-team suite")
    p_test.set_defaults(func=cmd_test)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    _configure_logging(getattr(args, "verbose", False))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
