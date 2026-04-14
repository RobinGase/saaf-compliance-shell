"""Runtime orchestration for Phase 2 Firecracker sessions."""

from __future__ import annotations

import hashlib
import json
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
    tap_device_name,
    validate_v1_network_rules,
)

DEFAULT_KERNEL_PATH = Path("/opt/saaf/kernels/vmlinux")
DEFAULT_ROOTFS_PATH = Path("/opt/saaf/rootfs/ubuntu-24.04-python-base")
DEFAULT_OVERLAY_DIR = Path("/opt/saaf/.agentfs")
DEFAULT_AUDIT_LOG = Path("/var/log/openshell/audit.jsonl")
DEFAULT_NFS_PORT = 11111


def run_manifest(
    manifest_path: str | Path,
    *,
    kernel_path: str | Path = DEFAULT_KERNEL_PATH,
    rootfs_path: str | Path = DEFAULT_ROOTFS_PATH,
    overlay_dir: str | Path = DEFAULT_OVERLAY_DIR,
    audit_log_path: str | Path = DEFAULT_AUDIT_LOG,
    nfs_port: int = DEFAULT_NFS_PORT,
) -> str:
    result = validate_manifest(manifest_path)
    if not result.valid or not result.manifest:
        errors = "; ".join(f"[{err.field}] {err.message}" for err in result.errors)
        raise ValueError(errors or "Manifest is invalid")

    manifest = result.manifest
    validate_v1_network_rules(manifest)

    manifest_path = Path(manifest_path)
    session_id = f"{manifest.get('name', 'saaf')}-{uuid4().hex[:8]}"
    agentfs = AgentFSClient(base_rootfs=rootfs_path, overlay_dir=overlay_dir)
    db_path = agentfs.create_session(session_id)

    setup_commands = build_setup_commands(session_id)
    teardown_commands = build_teardown_commands(session_id)
    tap_device = tap_device_name(session_id)
    config = build_vm_config(
        manifest=manifest,
        kernel_path=kernel_path,
        tap_device=tap_device,
        host_gateway=HOST_GATEWAY,
        guest_ip=GUEST_IP,
        nfs_port=nfs_port,
    )
    manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    policy_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode("utf-8")).hexdigest()
    audit = AuditLog(audit_log_path)
    audit.start_session(
        session_id=session_id,
        policy_hash=policy_hash,
        manifest_hash=manifest_hash,
        vm_config=config,
    )
    nfs_process = None

    try:
        _run_commands(setup_commands)
        nfs_process = start_nfs_server(session_id, HOST_GATEWAY, nfs_port, db_path=db_path, workdir=Path(overlay_dir).parent)
        console_log_path = Path(overlay_dir).parent / f"{session_id}.console.log"
        launch_firecracker(config, console_log_path=console_log_path)
        audit.record("vm_exit", session_id=session_id, status="ok")
    finally:
        stop_nfs_server(nfs_process)
        _run_commands(teardown_commands, check=False)
        audit.end_session()

    return session_id


def _run_commands(commands: list[list[str]], check: bool = True) -> None:
    for cmd in commands:
        subprocess.run(cmd, check=check, capture_output=True, text=True)
