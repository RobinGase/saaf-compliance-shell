#!/usr/bin/env bash
# Check if the host supports KVM — run this on fedoraserver first.
# Usage: ssh fedoraserver 'bash -s' < scripts/check-kvm.sh

set -euo pipefail

echo "=== saaf-compliance-shell: KVM support check ==="
echo ""

# 1. CPU virtualization support
echo "--- CPU virtualization ---"
if grep -qE '(vmx|svm)' /proc/cpuinfo; then
    VIRT_TYPE=$(grep -oE '(vmx|svm)' /proc/cpuinfo | head -1)
    if [ "$VIRT_TYPE" = "vmx" ]; then
        echo "OK: Intel VT-x detected"
    else
        echo "OK: AMD-V detected"
    fi
else
    echo "FAIL: No hardware virtualization support found in /proc/cpuinfo"
    echo "      If this is a VM, enable nested virtualization on the hypervisor."
    exit 1
fi

# 2. /dev/kvm exists
echo ""
echo "--- /dev/kvm ---"
if [ -e /dev/kvm ]; then
    echo "OK: /dev/kvm exists"
    # Check permissions
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        echo "OK: Current user has read/write access to /dev/kvm"
    else
        echo "WARN: /dev/kvm exists but current user lacks permissions"
        echo "      Fix: sudo usermod -aG kvm $(whoami)"
        ls -la /dev/kvm
    fi
else
    echo "FAIL: /dev/kvm does not exist"
    echo "      Ensure KVM kernel modules are loaded: sudo modprobe kvm kvm_intel (or kvm_amd)"
    exit 1
fi

# 3. Kernel version
echo ""
echo "--- Kernel ---"
KERNEL=$(uname -r)
echo "Kernel: $KERNEL"

# 4. Check if Firecracker is installed
echo ""
echo "--- Firecracker ---"
if command -v firecracker &>/dev/null; then
    echo "OK: Firecracker found at $(which firecracker)"
    firecracker --version 2>/dev/null || true
else
    echo "INFO: Firecracker not installed yet"
    echo "      Install: https://github.com/firecracker-microvm/firecracker/releases"
fi

# 5. Check if AgentFS is installed
echo ""
echo "--- AgentFS ---"
if command -v agentfs &>/dev/null; then
    echo "OK: AgentFS found at $(which agentfs)"
    agentfs --version 2>/dev/null || true
else
    echo "INFO: AgentFS not installed yet"
    echo "      Install: https://github.com/mitkox/firecracker-agentfs"
fi

# 6. Check networking tools
echo ""
echo "--- Networking tools ---"
for tool in ip iptables; do
    if command -v $tool &>/dev/null; then
        echo "OK: $tool found"
    else
        echo "WARN: $tool not found — required for TAP networking"
    fi
done

# 7. Check NFS support (for AgentFS overlay export)
echo ""
echo "--- NFS ---"
if command -v exportfs &>/dev/null || [ -f /etc/exports ]; then
    echo "OK: NFS tools available"
else
    echo "INFO: NFS tools not found — needed for AgentFS overlay export to guest"
    echo "      Install: sudo dnf install nfs-utils (Fedora)"
fi

# 8. Tailscale connectivity to maindev
echo ""
echo "--- Tailscale (maindev connectivity) ---"
if command -v tailscale &>/dev/null; then
    echo "OK: Tailscale installed"
    if ping -c 1 -W 2 100.87.245.60 &>/dev/null; then
        echo "OK: maindev (100.87.245.60) reachable"
    else
        echo "WARN: maindev (100.87.245.60) not reachable — is it online?"
    fi
else
    echo "WARN: Tailscale not installed"
fi

echo ""
echo "=== Check complete ==="
