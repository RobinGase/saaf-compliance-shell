#!/usr/bin/env bash
# setup-linux-host.sh — Install Firecracker + AgentFS on the target Linux host.
# Run as: sudo bash setup-linux-host.sh
# The invoking user (SUDO_USER) is added to the kvm group so they can run
# Firecracker without root after this script finishes.
set -euo pipefail

# --- Pinned versions and checksums -------------------------------------------
# Update these together. Expected SHA256 must match exactly or install aborts.
FIRECRACKER_VERSION="v1.15.0"
FIRECRACKER_SHA256="00cadf7f21e709e939dc0c8d16e2d2ce7b975a62bec6c50f74b421cc8ab3cab4"

# AgentFS upstream (mitkox/firecracker-agentfs) publishes no tags or release
# binaries; we pin to a specific commit on master and build from source.
AGENTFS_COMMIT="0e0e89abdd6e2340586f1ef3a4d204ea7e5949cc"

# Firecracker CI kernel. vmlinux-6.1.102 was rotated out of S3; 6.1.155 is the
# current 6.1.x kernel. Upstream does not publish a checksum manifest so this
# value was computed locally against the downloaded file.
KERNEL_VERSION="6.1.155"
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-${KERNEL_VERSION}"
KERNEL_SHA256="e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2"

INSTALL_DIR="/usr/local/bin"

verify_sha256() {
    local path="$1" expected="$2"
    local actual
    actual=$(sha256sum "${path}" | awk '{print $1}')
    if [ "${actual}" != "${expected}" ]; then
        echo "FATAL: sha256 mismatch for ${path}" >&2
        echo "  expected: ${expected}" >&2
        echo "  actual:   ${actual}" >&2
        exit 1
    fi
    echo "sha256 ok: ${path}"
}

echo "=== Phase 1.1: Verify KVM ==="
if [ ! -e /dev/kvm ]; then
    echo "FATAL: /dev/kvm not found. KVM is required for Firecracker."
    exit 1
fi
echo "OK — /dev/kvm present"

echo ""
echo "=== Phase 1.2a: Install Firecracker ${FIRECRACKER_VERSION} ==="
if command -v firecracker &>/dev/null; then
    echo "Firecracker already installed: $(firecracker --version)"
else
    ARCH=$(uname -m)
    if [ "${ARCH}" != "x86_64" ]; then
        echo "FATAL: pinned checksum is for x86_64; got ${ARCH}." >&2
        exit 1
    fi
    RELEASE_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz"
    echo "Downloading from ${RELEASE_URL}..."

    TMPDIR=$(mktemp -d)
    curl -fSL "${RELEASE_URL}" -o "${TMPDIR}/firecracker.tgz"
    verify_sha256 "${TMPDIR}/firecracker.tgz" "${FIRECRACKER_SHA256}"
    tar -xzf "${TMPDIR}/firecracker.tgz" -C "${TMPDIR}"

    RELEASE_DIR=$(find "${TMPDIR}" -maxdepth 1 -type d -name "release-*" | head -1)

    cp "${RELEASE_DIR}/firecracker-${FIRECRACKER_VERSION}-${ARCH}" "${INSTALL_DIR}/firecracker"
    cp "${RELEASE_DIR}/jailer-${FIRECRACKER_VERSION}-${ARCH}" "${INSTALL_DIR}/jailer"
    chmod +x "${INSTALL_DIR}/firecracker" "${INSTALL_DIR}/jailer"

    rm -rf "${TMPDIR}"
    echo "Installed: $(firecracker --version)"
fi

echo ""
echo "=== Phase 1.2b: Install AgentFS (commit ${AGENTFS_COMMIT:0:12}) ==="
if command -v agentfs &>/dev/null; then
    echo "AgentFS already installed: $(agentfs --version 2>&1 || echo 'version unknown')"
else
    # AgentFS has no published binaries; build from source. Rust toolchain must
    # be pre-installed (rustup curl|sh was removed as a supply-chain concern).
    if ! command -v cargo &>/dev/null; then
        echo "FATAL: cargo not found. Install Rust first:" >&2
        echo "  dnf install -y rust cargo" >&2
        echo "  # or the distro-packaged rustup + 'rustup default stable'" >&2
        exit 1
    fi

    dnf install -y sqlite-devel fuse3-devel pkg-config gcc git

    TMPDIR=$(mktemp -d)
    git clone https://github.com/mitkox/firecracker-agentfs.git "${TMPDIR}/agentfs"
    git -C "${TMPDIR}/agentfs" checkout "${AGENTFS_COMMIT}"
    actual_commit=$(git -C "${TMPDIR}/agentfs" rev-parse HEAD)
    if [ "${actual_commit}" != "${AGENTFS_COMMIT}" ]; then
        echo "FATAL: AgentFS commit mismatch" >&2
        echo "  expected: ${AGENTFS_COMMIT}" >&2
        echo "  actual:   ${actual_commit}" >&2
        exit 1
    fi

    (cd "${TMPDIR}/agentfs" && cargo build --release)
    cp "${TMPDIR}/agentfs/target/release/agentfs" "${INSTALL_DIR}/agentfs"
    chmod +x "${INSTALL_DIR}/agentfs"
    rm -rf "${TMPDIR}"
    echo "Built and installed AgentFS from source"
fi

echo ""
echo "=== Phase 1.3: Install debootstrap for rootfs building ==="
if command -v debootstrap &>/dev/null; then
    echo "debootstrap already installed"
else
    dnf install -y debootstrap
    echo "Installed debootstrap"
fi

echo ""
echo "=== Phase 1.4: Download pre-built microVM kernel (${KERNEL_VERSION}) ==="
KERNEL_DIR="/opt/saaf/kernels"
mkdir -p "${KERNEL_DIR}"
if [ -f "${KERNEL_DIR}/vmlinux" ]; then
    echo "Kernel already exists at ${KERNEL_DIR}/vmlinux — verifying checksum"
    # On systems provisioned before pinning landed, the existing kernel may be
    # an older version. Verify, warn if mismatch, do not auto-replace.
    existing_sha=$(sha256sum "${KERNEL_DIR}/vmlinux" | awk '{print $1}')
    if [ "${existing_sha}" = "${KERNEL_SHA256}" ]; then
        echo "sha256 ok: ${KERNEL_DIR}/vmlinux (matches pinned ${KERNEL_VERSION})"
    else
        echo "WARN: ${KERNEL_DIR}/vmlinux does not match pinned ${KERNEL_VERSION}." >&2
        echo "  existing: ${existing_sha}" >&2
        echo "  pinned:   ${KERNEL_SHA256}" >&2
        echo "  Leaving as-is. Remove the file and rerun to install the pinned version." >&2
    fi
else
    echo "Downloading from ${KERNEL_URL}..."
    curl -fSL "${KERNEL_URL}" -o "${KERNEL_DIR}/vmlinux"
    verify_sha256 "${KERNEL_DIR}/vmlinux" "${KERNEL_SHA256}"
    echo "Downloaded kernel to ${KERNEL_DIR}/vmlinux"
fi

echo ""
echo "=== Ensure invoking user has KVM access ==="
TARGET_USER="${SUDO_USER:-}"
if [ -n "${TARGET_USER}" ]; then
    usermod -aG kvm "${TARGET_USER}" 2>/dev/null || true
    echo "Added ${TARGET_USER} to kvm group (log out and back in for it to take effect)"
else
    echo "SUDO_USER not set — skipping kvm group add. Run: sudo usermod -aG kvm <username>"
fi

echo ""
echo "=== Summary ==="
echo "Firecracker: $(firecracker --version 2>&1 | head -1)"
echo "Jailer:      $(jailer --version 2>&1 | head -1)"
echo "AgentFS:     $(agentfs --version 2>&1 || echo 'installed')"
echo "Kernel:      ${KERNEL_DIR}/vmlinux (pinned ${KERNEL_VERSION})"
echo "debootstrap: $(which debootstrap)"
echo ""
echo "Done. Items 1.1–1.4 complete."
