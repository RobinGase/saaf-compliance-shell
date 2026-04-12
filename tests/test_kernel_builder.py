from pathlib import Path


def test_kernel_builder_enables_nfs_root_and_disables_desktop_drivers() -> None:
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "build-kernel.sh"
    content = script_path.read_text()

    assert "./scripts/config --enable ROOT_NFS" in content
    assert "./scripts/config --enable NFS_FS" in content
    assert "./scripts/config --disable DRM" in content
    assert "./scripts/config --disable DRM_I915" in content
    assert "./scripts/config --disable WIRELESS" in content
    assert "make -j\"${BUILD_JOBS}\" vmlinux" in content
