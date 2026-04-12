"""Repeatable VM smoke helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .runtime import run_manifest


def collect_diff(overlay_dir: str | Path, session_id: str, binary: str = "/usr/local/bin/agentfs") -> list[str]:
    overlay_dir = Path(overlay_dir)
    db_path = overlay_dir / f"{session_id}.db"
    completed = subprocess.run(
        [binary, "diff", str(db_path)],
        check=True,
        capture_output=True,
        text=True,
        cwd=overlay_dir.parent,
    )
    return [line for line in completed.stdout.splitlines() if line.strip()]


def run_vm_probe(
    *,
    manifest_path: str | Path,
    overlay_dir: str | Path,
    audit_log_path: str | Path,
    kernel_path: str | Path = "/opt/saaf/kernels/vmlinux",
    rootfs_path: str | Path = "/opt/saaf/rootfs/ubuntu-24.04-python-base",
    nfs_port: int = 11111,
) -> dict[str, Any]:
    session_id = run_manifest(
        manifest_path,
        kernel_path=kernel_path,
        rootfs_path=rootfs_path,
        overlay_dir=overlay_dir,
        audit_log_path=audit_log_path,
        nfs_port=nfs_port,
    )
    diff = collect_diff(overlay_dir, session_id)

    required = {
        "/audit_workspace/init.log",
        "/audit_workspace/probe.log",
        "/audit_workspace/response.json",
    }
    seen = {line.split(" ", 2)[-1] for line in diff}
    missing = sorted(required - seen)
    if missing:
        raise RuntimeError(f"VM probe missing expected artifacts: {', '.join(missing)}")

    return {"session_id": session_id, "diff": diff}
