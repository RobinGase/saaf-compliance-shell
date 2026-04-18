"""Firecracker configuration helpers."""

from __future__ import annotations

import json
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
    nfsroot = f"{host_gateway}:/,nfsvers=3,tcp,nolock,port={nfs_port},mountport={nfs_port}"
    boot_args = (
        "console=ttyS0 reboot=k panic=1 pci=off "
        f"ip={guest_ip}::{host_gateway}:255.255.255.0:{vm_name}:eth0:off "
        f"root=/dev/nfs nfsroot={nfsroot} rw init=/init {' '.join(boot_params)}"
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
    """Run the Firecracker binary and stream its console to disk.

    C4: the previous implementation used ``subprocess.run(capture_output=True)``
    which buffers the guest's entire ``stdout``/``stderr`` in memory.
    A chatty VM (a failing boot loop, a noisy agent, or anything that
    dumps a kernel oops) grows that buffer without bound and can OOM
    the host. Stream directly to ``console_log_path`` instead, one
    file for stdout and one for stderr — operators still get the full
    console for post-mortem, and memory stays flat.

    If ``console_log_path`` is ``None`` both streams go to
    ``DEVNULL``. A non-zero exit raises ``CalledProcessError`` with
    the captured stderr tail so callers see the failure reason
    without having to grep the log file.
    """
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tmp:
        json.dump(config, tmp)
        config_path = tmp.name

    cmd = [binary, "--no-api", "--config-file", config_path]

    try:
        if console_log_path is None:
            returncode = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            ).returncode
            if returncode != 0:
                raise subprocess.CalledProcessError(returncode, cmd)
            return returncode

        console_path = Path(console_log_path)
        console_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = console_path.with_suffix(console_path.suffix + ".stderr")
        with open(console_path, "wb") as stdout_fh, open(stderr_path, "wb") as stderr_fh:
            returncode = subprocess.run(
                cmd, stdout=stdout_fh, stderr=stderr_fh, check=False
            ).returncode
        if returncode != 0:
            stderr_tail = _tail_bytes(stderr_path, 2000)
            raise subprocess.CalledProcessError(returncode, cmd, stderr=stderr_tail)
        return returncode
    finally:
        Path(config_path).unlink(missing_ok=True)


def _tail_bytes(path: Path, n: int) -> str:
    """Return up to the last ``n`` bytes of ``path`` decoded as UTF-8 with replacement."""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    with open(path, "rb") as fh:
        if size > n:
            fh.seek(-n, 2)
        return fh.read().decode("utf-8", errors="replace")


def _encode_boot_value(value: str) -> str:
    encoded = []
    for char in value:
        if char == " ":
            encoded.append("\\x20")
        else:
            encoded.append(char)
    return "".join(encoded)
