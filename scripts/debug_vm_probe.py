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


def main() -> None:
    manifest = validate_manifest(Path("tests/fixtures/manifest_probe.yaml")).manifest
    session_id = "guest-debug4"
    log_path = Path("/tmp/saaf-debug-vm.log")

    append(log_path, "START")
    agentfs = AgentFSClient(base_rootfs="/opt/saaf/rootfs/ubuntu-24.04-python-base", overlay_dir="/tmp/.agentfs")
    append(log_path, str(agentfs.create_session(session_id)))
    nfs = start_nfs_server(session_id, HOST_GATEWAY, 11111)
    setup = build_setup_commands(session_id)
    teardown = build_teardown_commands(session_id)

    for cmd in setup:
        subprocess.run(cmd, check=True)

    config = build_vm_config(
        manifest=manifest,
        kernel_path="/opt/saaf/kernels/vmlinux",
        tap_device=tap_device_name(session_id),
        host_gateway=HOST_GATEWAY,
        guest_ip=GUEST_IP,
        nfs_port=11111,
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
            timeout=90,
        )
        append(log_path, f"RETURN {completed.returncode}")
        append(log_path, "STDOUT\n" + completed.stdout)
        append(log_path, "STDERR\n" + completed.stderr)
    except Exception as exc:  # pragma: no cover - debug helper only
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


if __name__ == "__main__":
    main()
