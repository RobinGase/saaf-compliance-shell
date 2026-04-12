from pathlib import Path


def test_rootfs_builder_init_consumes_manifest_kernel_args() -> None:
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    builder = (scripts_dir / "build-rootfs.sh").read_text()
    init_template = (scripts_dir / "rootfs-init.sh").read_text()

    assert 'cp "${SCRIPT_DIR}/rootfs-init.sh" "${ROOTFS_DIR}/init"' in builder
    assert "cat /proc/cmdline" in init_template
    assert "saaf.entrypoint=" in init_template
    assert "saaf.workdir=" in init_template
    assert "saaf.env." in init_template
    assert "/audit_workspace/init.log" in init_template
    assert "exec /bin/sh -lc \"$SAAF_ENTRYPOINT\"" in init_template


def test_rootfs_builder_copies_guest_probe_script() -> None:
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    builder = (scripts_dir / "build-rootfs.sh").read_text()
    probe_script = (scripts_dir / "guest-probe.py").read_text()

    assert 'cp "${SCRIPT_DIR}/guest-probe.py" "${ROOTFS_DIR}/usr/local/bin/guest-probe.py"' in builder
    assert 'Path(output_path).write_text(body, encoding="utf-8")' in probe_script
    assert 'urllib.request.urlopen(req, timeout=30)' in probe_script
    assert 'probe.log' in probe_script
