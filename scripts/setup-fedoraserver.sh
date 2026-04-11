#!/usr/bin/env bash
# setup-fedoraserver.sh — Install Firecracker + AgentFS on fedoraserver
# Run as: sudo bash setup-fedoraserver.sh
set -euo pipefail

FIRECRACKER_VERSION="v1.15.0"
AGENTFS_VERSION="v0.6.0"
INSTALL_DIR="/usr/local/bin"

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
    RELEASE_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz"
    echo "Downloading from ${RELEASE_URL}..."

    TMPDIR=$(mktemp -d)
    curl -fSL "${RELEASE_URL}" -o "${TMPDIR}/firecracker.tgz"
    tar -xzf "${TMPDIR}/firecracker.tgz" -C "${TMPDIR}"

    # The tarball extracts to a directory like release-v1.15.0-x86_64/
    RELEASE_DIR=$(find "${TMPDIR}" -maxdepth 1 -type d -name "release-*" | head -1)

    cp "${RELEASE_DIR}/firecracker-${FIRECRACKER_VERSION}-${ARCH}" "${INSTALL_DIR}/firecracker"
    cp "${RELEASE_DIR}/jailer-${FIRECRACKER_VERSION}-${ARCH}" "${INSTALL_DIR}/jailer"
    chmod +x "${INSTALL_DIR}/firecracker" "${INSTALL_DIR}/jailer"

    rm -rf "${TMPDIR}"
    echo "Installed: $(firecracker --version)"
fi

echo ""
echo "=== Phase 1.2b: Install AgentFS ==="
if command -v agentfs &>/dev/null; then
    echo "AgentFS already installed: $(agentfs --version 2>&1 || echo 'version unknown')"
else
    # AgentFS is a Rust binary from mitkox/firecracker-agentfs
    AGENTFS_URL="https://github.com/mitkox/firecracker-agentfs/releases/download/${AGENTFS_VERSION}/agentfs-${AGENTFS_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
    echo "Attempting download from ${AGENTFS_URL}..."

    TMPDIR=$(mktemp -d)
    if curl -fSL "${AGENTFS_URL}" -o "${TMPDIR}/agentfs.tar.gz" 2>/dev/null; then
        tar -xzf "${TMPDIR}/agentfs.tar.gz" -C "${TMPDIR}"
        cp "${TMPDIR}/agentfs" "${INSTALL_DIR}/agentfs" 2>/dev/null || \
            find "${TMPDIR}" -name "agentfs" -type f -exec cp {} "${INSTALL_DIR}/agentfs" \;
        chmod +x "${INSTALL_DIR}/agentfs"
        rm -rf "${TMPDIR}"
        echo "Installed AgentFS from release"
    else
        echo "No pre-built release found. Building from source..."
        rm -rf "${TMPDIR}"

        # Install Rust if needed
        if ! command -v cargo &>/dev/null; then
            echo "Installing Rust toolchain..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
        fi

        # Install build deps
        dnf install -y sqlite-devel fuse3-devel pkg-config gcc 2>/dev/null || true

        TMPDIR=$(mktemp -d)
        git clone --depth 1 --branch "${AGENTFS_VERSION}" https://github.com/mitkox/firecracker-agentfs.git "${TMPDIR}/agentfs" 2>/dev/null || \
            git clone --depth 1 https://github.com/mitkox/firecracker-agentfs.git "${TMPDIR}/agentfs"

        cd "${TMPDIR}/agentfs"
        cargo build --release
        cp target/release/agentfs "${INSTALL_DIR}/agentfs"
        chmod +x "${INSTALL_DIR}/agentfs"
        cd /
        rm -rf "${TMPDIR}"
        echo "Built and installed AgentFS from source"
    fi
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
echo "=== Phase 1.4: Download pre-built microVM kernel ==="
KERNEL_DIR="/opt/saaf/kernels"
mkdir -p "${KERNEL_DIR}"
if [ -f "${KERNEL_DIR}/vmlinux" ]; then
    echo "Kernel already exists at ${KERNEL_DIR}/vmlinux"
else
    # Use Firecracker's CI-tested kernel
    KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.102"
    echo "Downloading pre-built kernel..."
    curl -fSL "${KERNEL_URL}" -o "${KERNEL_DIR}/vmlinux"
    echo "Downloaded kernel to ${KERNEL_DIR}/vmlinux"
fi

echo ""
echo "=== Ensure robindev has KVM access ==="
usermod -aG kvm robindev 2>/dev/null || true

echo ""
echo "=== Summary ==="
echo "Firecracker: $(firecracker --version 2>&1 | head -1)"
echo "Jailer:      $(jailer --version 2>&1 | head -1)"
echo "AgentFS:     $(agentfs --version 2>&1 || echo 'installed')"
echo "Kernel:      ${KERNEL_DIR}/vmlinux"
echo "debootstrap: $(which debootstrap)"
echo ""
echo "Done. Items 1.1–1.4 complete."
