from pathlib import Path

from modules.isolation.firecracker import build_vm_config


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
