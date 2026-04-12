#!/usr/bin/env bash
# Build the hardened base Firecracker rootfs on the Linux host that runs Firecracker.
# Run on the target Linux host as a sudo-capable user:
#   bash scripts/build-rootfs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ROOTFS_DIR="${ROOTFS_DIR:-/opt/saaf/rootfs/ubuntu-24.04-python-base}"
ROOTFS_RELEASE="${ROOTFS_RELEASE:-noble}"
ROOTFS_MIRROR="${ROOTFS_MIRROR:-http://archive.ubuntu.com/ubuntu}"
ROOTFS_ARCH="${ROOTFS_ARCH:-amd64}"

log() {
    printf '==> %s\n' "$*"
}

sudo_run() {
    sudo "$@"
}

chroot_run() {
    sudo chroot "${ROOTFS_DIR}" /usr/bin/env DEBIAN_FRONTEND=noninteractive bash -lc "$1"
}

mount_chroot() {
    sudo_run mkdir -p "${ROOTFS_DIR}/dev" "${ROOTFS_DIR}/dev/pts" "${ROOTFS_DIR}/proc" "${ROOTFS_DIR}/sys"
    mountpoint -q "${ROOTFS_DIR}/dev" || sudo_run mount --bind /dev "${ROOTFS_DIR}/dev"
    mountpoint -q "${ROOTFS_DIR}/dev/pts" || sudo_run mount --bind /dev/pts "${ROOTFS_DIR}/dev/pts"
    mountpoint -q "${ROOTFS_DIR}/proc" || sudo_run mount -t proc proc "${ROOTFS_DIR}/proc"
    mountpoint -q "${ROOTFS_DIR}/sys" || sudo_run mount -t sysfs sysfs "${ROOTFS_DIR}/sys"
    sudo_run cp /etc/resolv.conf "${ROOTFS_DIR}/etc/resolv.conf"
}

umount_chroot() {
    sudo_run umount -lf "${ROOTFS_DIR}/sys" 2>/dev/null || true
    sudo_run umount -lf "${ROOTFS_DIR}/proc" 2>/dev/null || true
    sudo_run umount -lf "${ROOTFS_DIR}/dev/pts" 2>/dev/null || true
    sudo_run umount -lf "${ROOTFS_DIR}/dev" 2>/dev/null || true
}

cleanup() {
    umount_chroot
}
trap cleanup EXIT

log "Preparing ${ROOTFS_DIR}"
sudo_run mkdir -p /opt/saaf/rootfs
umount_chroot
sudo_run rm -rf "${ROOTFS_DIR}"
sudo_run mkdir -p "${ROOTFS_DIR}"

log "Bootstrapping Ubuntu ${ROOTFS_RELEASE}"
sudo_run debootstrap \
    --arch="${ROOTFS_ARCH}" \
    --variant=minbase \
    --components=main,universe \
    "${ROOTFS_RELEASE}" \
    "${ROOTFS_DIR}" \
    "${ROOTFS_MIRROR}"

mount_chroot

log "Installing Python runtime and guest networking tools"
chroot_run "apt-get update && apt-get install -y --no-install-recommends bash ca-certificates iproute2 iputils-ping netbase procps python3 python3-pip python3-setuptools python3-venv python3-wheel"

log "Removing tools we do not want in the guest"
chroot_run "apt-get purge -y --allow-remove-essential false curl wget gcc g++ make build-essential 2>/dev/null || true"
chroot_run "rm -rf /usr/share/doc/* /usr/share/man/* /var/cache/* /var/lib/apt/lists/*"

log "Writing base guest metadata"
sudo_run mkdir -p "${ROOTFS_DIR}/audit_workspace" "${ROOTFS_DIR}/etc/profile.d"
PYTHON_VERSION="$(sudo chroot "${ROOTFS_DIR}" python3 --version 2>/dev/null | tr -d '\r')"
sudo_run tee "${ROOTFS_DIR}/etc/hostname" > /dev/null <<'EOF'
saaf-vm
EOF

sudo_run tee "${ROOTFS_DIR}/etc/profile.d/saaf.sh" > /dev/null <<'EOF'
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export PATH="/usr/local/bin:/usr/bin:/bin"
cd /audit_workspace 2>/dev/null || true
EOF

sudo_run tee "${ROOTFS_DIR}/etc/motd" > /dev/null <<'EOF'
saaf-compliance-shell base guest

Included:
  - python3 / pip / venv
  - iproute2 / iputils-ping
  - minimal Ubuntu 24.04 userspace

Excluded intentionally:
  - curl / wget
  - compiler toolchain
  - SSH server
EOF

sudo_run tee "${ROOTFS_DIR}/etc/agentvm-release" > /dev/null <<EOF
base_os=ubuntu:${ROOTFS_RELEASE}
rootfs_path=${ROOTFS_DIR}
python=${PYTHON_VERSION}
built_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

sudo_run cp "${SCRIPT_DIR}/rootfs-init.sh" "${ROOTFS_DIR}/init"
sudo_run chmod +x "${ROOTFS_DIR}/init"
sudo_run mkdir -p "${ROOTFS_DIR}/usr/local/bin"
sudo_run cp "${SCRIPT_DIR}/guest-probe.py" "${ROOTFS_DIR}/usr/local/bin/guest-probe.py"
sudo_run chmod +x "${ROOTFS_DIR}/usr/local/bin/guest-probe.py"

log "Rootfs ready at ${ROOTFS_DIR}"
sudo_run du -sh "${ROOTFS_DIR}"
