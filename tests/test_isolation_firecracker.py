from pathlib import Path

from modules.isolation.firecracker import build_vm_config, launch_firecracker


def test_build_vm_config_uses_manifest_resources(tmp_path: Path) -> None:
    manifest = {
        "name": "vendor-guard",
        "agent": {
            "entrypoint": "python3 -m vendor_guard.agent",
            "working_directory": "/audit_workspace",
            "env": {"INFERENCE_URL": "http://172.16.0.1:8088/v1/chat/completions"},
        },
        "resources": {"vcpu_count": 2, "mem_size_mib": 2048},
    }

    config = build_vm_config(
        manifest=manifest,
        kernel_path=Path("/opt/saaf/kernels/vmlinux"),
        tap_device="fc-session-001",
        host_gateway="172.16.0.1",
        guest_ip="172.16.0.2",
        nfs_port=11111,
    )

    assert config["boot-source"]["kernel_image_path"] == "/opt/saaf/kernels/vmlinux"
    assert "ip=172.16.0.2::172.16.0.1:255.255.255.0:vendor-guard:eth0:off" in config["boot-source"]["boot_args"]
    assert "nfsroot=172.16.0.1:/,nfsvers=3,tcp,nolock,port=11111,mountport=11111 rw init=/init" in config["boot-source"]["boot_args"]
    assert "saaf.entrypoint=python3\\x20-m\\x20vendor_guard.agent" in config["boot-source"]["boot_args"]
    assert "saaf.workdir=/audit_workspace" in config["boot-source"]["boot_args"]
    assert "saaf.env.INFERENCE_URL=http://172.16.0.1:8088/v1/chat/completions" in config["boot-source"]["boot_args"]
    assert config["network-interfaces"][0]["host_dev_name"] == "fc-session-001"
    assert config["machine-config"] == {"vcpu_count": 2, "mem_size_mib": 2048}


def test_launch_firecracker_streams_console_to_disk(tmp_path: Path, monkeypatch) -> None:
    """C4: Firecracker console is streamed directly to two files (stdout + stderr)
    to keep host memory flat regardless of guest verbosity."""
    console_log = tmp_path / "guest.console.log"

    class FakeCompleted:
        returncode = 0

    def fake_run(cmd, *, stdout=None, stderr=None, check=False):
        # Write through the real file handles the launcher opened,
        # so the on-disk artefact reflects what a real guest would produce.
        if hasattr(stdout, "write"):
            stdout.write(b"guest stdout bytes")
        if hasattr(stderr, "write"):
            stderr.write(b"guest stderr bytes")
        return FakeCompleted()

    monkeypatch.setattr("modules.isolation.firecracker.subprocess.run", fake_run)

    rc = launch_firecracker({"boot-source": {}}, console_log_path=console_log)

    assert rc == 0
    assert console_log.read_bytes() == b"guest stdout bytes"
    stderr_log = console_log.with_suffix(console_log.suffix + ".stderr")
    assert stderr_log.read_bytes() == b"guest stderr bytes"


def test_launch_firecracker_raises_on_nonzero_with_stderr_tail(
    tmp_path: Path, monkeypatch
) -> None:
    import subprocess as _sp

    console_log = tmp_path / "guest.console.log"

    class FakeCompleted:
        returncode = 7

    def fake_run(cmd, *, stdout=None, stderr=None, check=False):
        if hasattr(stderr, "write"):
            stderr.write(b"boot panic: no root device")
        return FakeCompleted()

    monkeypatch.setattr("modules.isolation.firecracker.subprocess.run", fake_run)

    try:
        launch_firecracker({"boot-source": {}}, console_log_path=console_log)
    except _sp.CalledProcessError as exc:
        assert exc.returncode == 7
        assert "boot panic" in exc.stderr
    else:
        raise AssertionError("Expected CalledProcessError on non-zero return")
