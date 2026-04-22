"""Runtime orchestration for Phase 2 Firecracker sessions."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
from pathlib import Path
from uuid import uuid4

from modules.audit.log import AuditLog
from modules.manifest.validator import validate_manifest

from .agentfs import AgentFSClient, start_nfs_server, stop_nfs_server
from .firecracker import build_vm_config, launch_firecracker
from .network import (
    GUEST_IP,
    HOST_GATEWAY,
    build_setup_commands,
    build_teardown_commands,
    ensure_ip_forward_disabled,
    tap_device_name,
    validate_v1_network_rules,
)
from .session_lock import DEFAULT_SESSION_LOCK_PATH, acquire_session_lock

DEFAULT_KERNEL_PATH = Path("/opt/saaf/kernels/vmlinux")
DEFAULT_ROOTFS_PATH = Path("/opt/saaf/rootfs/ubuntu-24.04-python-base")
DEFAULT_OVERLAY_DIR = Path("/opt/saaf/.agentfs")
DEFAULT_AUDIT_LOG = Path("/var/log/openshell/audit.jsonl")


def _pick_free_nfs_port() -> int:
    """Pick an ephemeral TCP port the kernel reports as free.

    H3: the previous implementation used a static ``DEFAULT_NFS_PORT =
    11111`` for every session. A crashed session leaving the port in
    ``TIME_WAIT`` (or any non-saaf process squatting on 11111) made the
    next session fail at ``start_nfs_server``. Picking a fresh port per
    session avoids that. Safe under S2 (host-wide session lock) —
    saaf-internal contention for the port is excluded by the lock, and
    the remaining micro-race against unrelated host processes between
    the pick-socket close and ``start_nfs_server`` bind is negligible
    on a dedicated VM host and would surface immediately as an NFS
    start failure (visible in the H2 log).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("", 0))
        return probe.getsockname()[1]


def run_manifest(
    manifest_path: str | Path,
    *,
    kernel_path: str | Path = DEFAULT_KERNEL_PATH,
    rootfs_path: str | Path = DEFAULT_ROOTFS_PATH,
    overlay_dir: str | Path = DEFAULT_OVERLAY_DIR,
    audit_log_path: str | Path = DEFAULT_AUDIT_LOG,
    nfs_port: int | None = None,
    session_lock_path: str | Path = DEFAULT_SESSION_LOCK_PATH,
) -> str:
    result = validate_manifest(manifest_path)
    if not result.valid or not result.manifest:
        errors = "; ".join(f"[{err.field}] {err.message}" for err in result.errors)
        raise ValueError(errors or "Manifest is invalid")

    manifest = result.manifest
    validate_v1_network_rules(manifest)
    ensure_ip_forward_disabled(allow_env=os.environ.get("SAAF_ALLOW_IP_FORWARD"))

    manifest_path = Path(manifest_path)
    session_id = f"{manifest.get('name', 'saaf')}-{uuid4().hex[:8]}"
    agentfs = AgentFSClient(base_rootfs=rootfs_path, overlay_dir=overlay_dir)
    db_path = agentfs.create_session(session_id)

    manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    audit = AuditLog(audit_log_path)

    # S2: host-wide session lock. Firecracker shares host NFS port,
    # iptables tables, and the ip_forward gate across sessions; two
    # concurrent ``run_manifest`` calls on the same host would race on
    # those. The lock is released on normal exit and on crash (flock
    # lives on the FD, not the inode).
    with acquire_session_lock(session_lock_path, audit=audit, session_id=session_id):
        # H3: pick NFS port inside the lock so the policy_hash,
        # iptables ACCEPT rule, VM boot args, and NFS server bind all
        # see the same value. Port is callable-overridable for tests
        # and the debug scripts; when not supplied the kernel assigns a
        # fresh ephemeral port.
        chosen_nfs_port = nfs_port if nfs_port is not None else _pick_free_nfs_port()
        setup_commands = build_setup_commands(session_id, chosen_nfs_port)
        teardown_commands = build_teardown_commands(session_id, chosen_nfs_port)
        tap_device = tap_device_name(session_id)
        config = build_vm_config(
            manifest=manifest,
            kernel_path=kernel_path,
            tap_device=tap_device,
            host_gateway=HOST_GATEWAY,
            guest_ip=GUEST_IP,
            nfs_port=chosen_nfs_port,
        )
        policy_hash = hashlib.sha256(
            json.dumps(config, sort_keys=True).encode("utf-8")
        ).hexdigest()
        audit.start_session(
            session_id=session_id,
            policy_hash=policy_hash,
            manifest_hash=manifest_hash,
            vm_config=config,
        )
        audit.record(
            "nfs_port_selected",
            session_id=session_id,
            nfs_port=chosen_nfs_port,
            selection="static" if nfs_port is not None else "ephemeral",
        )
        nfs_process = None

        try:
            _run_commands(setup_commands, audit=audit, phase="setup", session_id=session_id)
            nfs_log_path = Path(overlay_dir).parent / f"{session_id}.nfs.log"
            nfs_process = start_nfs_server(
                session_id,
                HOST_GATEWAY,
                chosen_nfs_port,
                db_path=db_path,
                workdir=Path(overlay_dir).parent,
                log_path=nfs_log_path,
            )
            console_log_path = Path(overlay_dir).parent / f"{session_id}.console.log"
            launch_firecracker(config, console_log_path=console_log_path)
            audit.record("vm_exit", session_id=session_id, status="ok")
        except Exception as exc:
            # C2: an abnormal exit (setup failure, NFS launch failure,
            # Firecracker crash) used to leave only a session_start +
            # session_end pair in the audit log, with no record of why the
            # VM never ran. Emit an explicit ``vm_exit`` with status=failed
            # before re-raising so operators reading the log see the
            # failure reason without cross-referencing stderr or container
            # logs. Teardown in ``finally`` still runs.
            try:
                audit.record(
                    "vm_exit",
                    session_id=session_id,
                    status="failed",
                    reason=str(exc),
                    exception_class=type(exc).__name__,
                )
            except Exception:
                # B2: audit-chain tamper detection can itself raise here
                # (AuditTamperDetected). Don't let it swallow the original
                # failure and, more importantly, don't let it skip the
                # finally-block teardown — that's the path that deletes
                # the tap. Re-raise ``exc`` below so the original cause
                # surfaces to the operator.
                pass
            raise
        finally:
            stop_nfs_server(nfs_process)
            try:
                _run_commands(
                    teardown_commands,
                    check=False,
                    audit=audit,
                    phase="teardown",
                    session_id=session_id,
                )
            except Exception:
                # B2: teardown must never abort the tap-cleanup sweep.
                # ``_run_commands`` with ``check=False`` only raises if
                # ``audit.record`` itself raises (e.g. AuditTamperDetected
                # mid-teardown). Swallow so the force-delete below runs;
                # the original exception, if any, propagates from the
                # outer try/except above.
                pass
            _force_delete_tap(tap_device, audit=audit, session_id=session_id)
            try:
                audit.end_session()
            except Exception:
                pass

    return session_id


def _force_delete_tap(
    tap: str,
    *,
    audit: AuditLog | None = None,
    session_id: str = "",
) -> None:
    """Guarantee the session's tap interface is gone after teardown.

    B2: the ordered teardown command list can be aborted mid-iteration when
    ``audit.record`` itself raises (AuditTamperDetected, disk-full, etc.),
    and a number of failure paths upstream of the final ``ip link del`` can
    leave the tap behind. Host-side evidence: a session interrupted during
    audit writing leaves ``fc-<prefix>-<hash>`` in ``ip link show``, which
    accumulates between runs and eventually causes
    ``RTNETLINK answers: File exists`` on the next session's ``ip tuntap
    add``. This helper runs after the ordered teardown as a last resort:
    check the interface, force-delete if present, and emit a best-effort
    audit event naming the outcome so operators see the sweep in the chain.

    All subprocess calls are isolated in ``try/except`` — the function
    never raises. Audit failures are swallowed; by this point the session
    is already unwinding and the priority is host-state cleanup, not log
    fidelity.
    """
    try:
        show = subprocess.run(
            ["ip", "link", "show", tap],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        return
    if show.returncode != 0:
        # Interface already gone — teardown path succeeded or the tap was
        # never created. Nothing to do.
        return

    try:
        delete = subprocess.run(
            ["ip", "link", "del", tap],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        if audit is not None:
            try:
                audit.record(
                    "tap_force_delete_failed",
                    session_id=session_id,
                    tap=tap,
                    exception_class=type(exc).__name__,
                    reason=str(exc),
                )
            except Exception:
                pass
        return

    if audit is not None:
        try:
            audit.record(
                "tap_force_deleted",
                session_id=session_id,
                tap=tap,
                returncode=delete.returncode,
                stderr=delete.stderr.strip()[:500],
            )
        except Exception:
            pass


def _run_commands(
    commands: list[list[str]],
    check: bool = True,
    *,
    audit: AuditLog | None = None,
    phase: str = "unknown",
    session_id: str = "",
) -> None:
    """Run network setup/teardown commands and emit audit context on failure.

    C3: the previous implementation called ``subprocess.run(check=True)``
    and let ``CalledProcessError`` propagate. Operators saw the
    exception's ``__str__`` — return code plus the bare command —
    never the captured ``stderr``. Here we inspect ``returncode``
    explicitly so the audit log carries ``stderr`` and the command
    that failed, then raise with the same context attached to the
    exception message.

    With ``check=False`` (teardown path) failures are still audited —
    they just don't raise, so cleanup continues.
    """
    for cmd in commands:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if proc.returncode == 0:
            continue
        if audit is not None:
            audit.record(
                "command_failed",
                session_id=session_id,
                phase=phase,
                command=cmd,
                returncode=proc.returncode,
                stderr=proc.stderr.strip(),
                stdout_tail=proc.stdout[-500:] if proc.stdout else "",
            )
        if check:
            raise subprocess.CalledProcessError(
                proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr
            )
