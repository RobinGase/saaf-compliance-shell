"""Firecracker configuration helpers."""

from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from pathlib import Path


def build_vm_config(
    manifest: dict,
    kernel_path: str | Path,
    tap_device: str,
    host_gateway: str,
    guest_ip: str,
    nfs_port: int,
) -> dict:
    vm_name = manifest.get("name", "saaf-vm")
    resources = manifest["resources"]
    agent = manifest.get("agent", {})
    boot_params = [
        f"saaf.entrypoint={_encode_boot_value(agent.get('entrypoint', ''))}",
        f"saaf.workdir={_encode_boot_value(agent.get('working_directory', '/'))}",
    ]
    for key, value in sorted(agent.get("env", {}).items()):
        boot_params.append(f"saaf.env.{key}={_encode_boot_value(str(value))}")
    boot_args = (
        "console=ttyS0 reboot=k panic=1 pci=off "
        f"ip={guest_ip}::{host_gateway}:255.255.255.0:{vm_name}:eth0:off "
        f"root=/dev/nfs nfsroot={host_gateway}:/,nfsvers=3,tcp,nolock,port={nfs_port},mountport={nfs_port} rw init=/init {' '.join(boot_params)}"
    )
    return {
        "boot-source": {
            "kernel_image_path": Path(kernel_path).as_posix(),
            "boot_args": boot_args,
        },
        "drives": [],
        "network-interfaces": [
            {
                "iface_id": "eth0",
                "guest_mac": "AA:FC:00:00:00:01",
                "host_dev_name": tap_device,
            }
        ],
        "machine-config": {
            "vcpu_count": resources["vcpu_count"],
            "mem_size_mib": resources["mem_size_mib"],
        },
    }


def launch_firecracker(config: dict, binary: str = "firecracker", console_log_path: str | Path | None = None) -> int:
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tmp:
        json.dump(config, tmp)
        config_path = tmp.name

    try:
        completed = subprocess.run(
            [binary, "--no-api", "--config-file", config_path],
            check=True,
            capture_output=True,
            text=True,
        )
        if console_log_path is not None:
            Path(console_log_path).write_text(
                f"STDOUT\n{completed.stdout}\nSTDERR\n{completed.stderr}\n",
                encoding="utf-8",
            )
        return completed.returncode
    finally:
        Path(config_path).unlink(missing_ok=True)


def _encode_boot_value(value: str) -> str:
    encoded = []
    for char in value:
        if char == " ":
            encoded.append("\\x20")
        else:
            encoded.append(char)
    return "".join(encoded)
