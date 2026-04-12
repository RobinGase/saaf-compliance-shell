#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="${KERNEL_DIR:-${SCRIPT_DIR}/linux-amazon}"
KERNEL_TAG="${KERNEL_TAG:-microvm-kernel-6.1.167-27.319.amzn2023}"
BUILD_JOBS="${BUILD_JOBS:-2}"

log() {
    printf '==> %s\n' "$*"
}

prepare_sources() {
    if [ ! -d "${KERNEL_DIR}/.git" ]; then
        log "Cloning Amazon Linux kernel ${KERNEL_TAG}"
        git clone --depth 1 --branch "${KERNEL_TAG}" https://github.com/amazonlinux/linux.git "${KERNEL_DIR}"
    fi
}

configure_kernel() {
    log "Configuring kernel for Firecracker + AgentFS NFS root"
    make x86_64_defconfig

    ./scripts/config --disable SYSTEM_TRUSTED_KEYRING
    ./scripts/config --disable SECONDARY_TRUSTED_KEYRING
    ./scripts/config --disable SYSTEM_REVOCATION_KEYS
    ./scripts/config --disable MODULE_SIG
    ./scripts/config --disable INTEGRITY
    ./scripts/config --disable IMA
    ./scripts/config --disable EVM
    ./scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
    ./scripts/config --set-str SYSTEM_REVOCATION_KEYS ""

    ./scripts/config --enable VIRTIO_MMIO_CMDLINE_DEVICES
    ./scripts/config --enable VIRTIO
    ./scripts/config --enable VIRTIO_MMIO
    ./scripts/config --enable VIRTIO_NET
    ./scripts/config --disable BLK_DEV_INTEGRITY
    ./scripts/config --enable DEVTMPFS
    ./scripts/config --enable DEVTMPFS_MOUNT
    ./scripts/config --enable TMPFS

    ./scripts/config --enable IP_PNP
    ./scripts/config --enable IP_PNP_DHCP
    ./scripts/config --enable IP_PNP_BOOTP
    ./scripts/config --enable IP_PNP_RARP
    ./scripts/config --enable NFS_FS
    ./scripts/config --enable ROOT_NFS
    ./scripts/config --enable NFS_V3
    ./scripts/config --enable NFS_V3_ACL
    ./scripts/config --enable LOCKD
    ./scripts/config --enable LOCKD_V4

    # Trim unrelated desktop/network stacks so the microVM kernel is smaller
    # and avoids host-specific desktop driver build failures.
    ./scripts/config --disable DRM
    ./scripts/config --disable DRM_I915
    ./scripts/config --disable WIRELESS
    ./scripts/config --disable CFG80211
    ./scripts/config --disable MAC80211
    ./scripts/config --disable WLAN

    ./scripts/config --enable BINFMT_MISC
    ./scripts/config --enable USER_NS
    ./scripts/config --enable PID_NS
    ./scripts/config --enable NET_NS
    ./scripts/config --enable IPC_NS
    ./scripts/config --enable UTS_NS
    ./scripts/config --enable CGROUPS
    ./scripts/config --enable CGROUP_PIDS
    ./scripts/config --enable CGROUP_FREEZER
    ./scripts/config --enable CPUSETS
    ./scripts/config --enable BPF_SYSCALL
    ./scripts/config --enable FANOTIFY
    ./scripts/config --enable INOTIFY_USER
    ./scripts/config --enable FUSE_FS
    ./scripts/config --enable OVERLAY_FS
    ./scripts/config --enable SECCOMP
    ./scripts/config --disable DEBUG_STACK_USAGE

    make olddefconfig
}

build_kernel() {
    log "Building vmlinux with ${BUILD_JOBS} jobs"
    make -j"${BUILD_JOBS}" vmlinux CC="gcc -std=gnu11"
}

prepare_sources
cd "${KERNEL_DIR}"
configure_kernel
build_kernel

log "Kernel available at ${KERNEL_DIR}/vmlinux"
