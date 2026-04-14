#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import tempfile
from pathlib import Path

from modules.isolation.agentfs import AgentFSClient, start_nfs_server, stop_nfs_server
from modules.isolation.firecracker import build_vm_config
from modules.isolation.network import (
    GUEST_IP,
    HOST_GATEWAY,
    build_setup_commands,
    build_teardown_commands,
    tap_device_name,
)
from modules.manifest.validator import validate_manifest


def append(log_path: Path, message: str) -> None:
    print(message, flush=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(message + "\n")


def to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--overlay-dir", default="/tmp/.agentfs")
    parser.add_argument("--kernel", default="/opt/saaf/kernels/vmlinux")
    parser.add_argument("--nfs-port", type=int, default=11111)
    parser.add_argument("--session-id", default="debug-session")
    parser.add_argument("--log", default="/tmp/saaf-debug-vm.log")
    args = parser.parse_args()

    manifest = validate_manifest(Path(args.manifest)).manifest
    log_path = Path(args.log)
    overlay_dir = Path(args.overlay_dir)

    append(log_path, "START")
    agentfs = AgentFSClient(base_rootfs=args.rootfs, overlay_dir=overlay_dir)
    append(log_path, str(agentfs.create_session(args.session_id)))
    nfs = start_nfs_server(args.session_id, HOST_GATEWAY, args.nfs_port, workdir=overlay_dir.parent)
    setup = build_setup_commands(args.session_id)
    teardown = build_teardown_commands(args.session_id)

    for cmd in setup:
        subprocess.run(cmd, check=True)

    config = build_vm_config(
        manifest=manifest,
        kernel_path=args.kernel,
        tap_device=tap_device_name(args.session_id),
        host_gateway=HOST_GATEWAY,
        guest_ip=GUEST_IP,
        nfs_port=args.nfs_port,
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as temp:
        json.dump(config, temp)
        config_path = temp.name

    append(log_path, pathlib.Path(config_path).read_text())

    try:
        completed = subprocess.run(
            ["firecracker", "--no-api", "--config-file", config_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        append(log_path, f"RETURN {completed.returncode}")
        append(log_path, "STDOUT\n" + completed.stdout)
        append(log_path, "STDERR\n" + completed.stderr)
    except Exception as exc:
        append(log_path, f"EXC {exc!r}")
        stdout = getattr(exc, "stdout", None)
        stderr = getattr(exc, "stderr", None)
        if stdout:
            append(log_path, "PARTIAL_STDOUT\n" + to_text(stdout))
        if stderr:
            append(log_path, "PARTIAL_STDERR\n" + to_text(stderr))
    finally:
        for cmd in teardown:
            subprocess.run(cmd, check=False)
        stop_nfs_server(nfs)
        pathlib.Path(config_path).unlink(missing_ok=True)
        append(log_path, "DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
