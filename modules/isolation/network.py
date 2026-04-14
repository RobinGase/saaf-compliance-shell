"""TAP device naming and v1 host-side network policy generation.

The v1 policy is default-deny: a guest may only reach the host-local
guardrails endpoint (via DNAT on the tap), nothing else. That requires
rules on **both** the INPUT and FORWARD chains, because INPUT only
matches packets destined for the host. On a server with
``net.ipv4.ip_forward=1`` (common when Tailscale/Docker/k8s is running),
packets from the guest to any non-host destination skip INPUT entirely
and traverse FORWARD — without a FORWARD DROP we would silently
let the guest route through the host. ``ensure_ip_forward_disabled``
surfaces that misconfiguration at startup instead of leaving it to
deployment-time discovery.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

HOST_GATEWAY = "172.16.0.1"
GUEST_IP = "172.16.0.2"
GUARDRAILS_PORT = 8088
NFS_PORT = 11111


IP_FORWARD_PROC_PATH = Path("/proc/sys/net/ipv4/ip_forward")


class NetworkPolicyError(ValueError):
    """Raised when a manifest requests a network policy not supported in v1."""


class IpForwardEnabledError(RuntimeError):
    """Raised at startup when the host has IP forwarding enabled.

    With ``net.ipv4.ip_forward=1`` the kernel will route guest packets
    out of the tap through any other interface, which the INPUT+FORWARD
    default-deny rules cover — but only if FORWARD is actually consulted.
    Rather than trust that silently, refuse to start so the operator
    disables forwarding (``sysctl -w net.ipv4.ip_forward=0``) or
    explicitly acknowledges it with ``SAAF_ALLOW_IP_FORWARD=1``.
    """


def ensure_ip_forward_disabled(
    *, proc_path: Path | str = IP_FORWARD_PROC_PATH, allow_env: str | None = None
) -> None:
    """Refuse to run when the host kernel has IPv4 forwarding enabled.

    ``allow_env`` is the value of ``SAAF_ALLOW_IP_FORWARD`` read by the
    caller; a truthy value turns the hard error into a no-op so operators
    who share the host with Tailscale/Docker can opt in after confirming
    the FORWARD DROP rules are in place.
    """
    path = Path(proc_path)
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return
    except OSError:
        return

    if value != "1":
        return

    if allow_env and allow_env.strip() not in ("", "0", "false", "False"):
        return

    raise IpForwardEnabledError(
        "net.ipv4.ip_forward=1 on this host. The v1 guest network policy "
        "relies on FORWARD DROP rules; disable forwarding "
        "(`sysctl -w net.ipv4.ip_forward=0`) or set "
        "SAAF_ALLOW_IP_FORWARD=1 to acknowledge the shared-host risk."
    )


def tap_device_name(session_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", session_id.lower()).strip("-")
    if not slug:
        slug = "session"
    digest = hashlib.sha1(session_id.encode("utf-8")).hexdigest()[:4]
    prefix = slug[:8]
    return f"fc-{prefix}-{digest}"[:15]


def validate_v1_network_rules(manifest: dict) -> dict:
    allow = manifest.get("network", {}).get("allow", [])
    if len(allow) != 1:
        raise NetworkPolicyError("v1 network policy must only permit gateway:8088")

    rule = allow[0]
    if rule.get("host") != "gateway" or rule.get("port") != GUARDRAILS_PORT:
        raise NetworkPolicyError("v1 network policy must only permit gateway:8088")

    return rule


def build_setup_commands(session_id: str) -> list[list[str]]:
    tap = tap_device_name(session_id)
    return [
        ["ip", "tuntap", "add", "dev", tap, "mode", "tap"],
        ["ip", "addr", "add", f"{HOST_GATEWAY}/24", "dev", tap],
        ["ip", "link", "set", tap, "up"],
        ["sysctl", "-w", f"net.ipv4.conf.{tap}.route_localnet=1"],
        [
            "iptables",
            "-A",
            "INPUT",
            "-i",
            tap,
            "-p",
            "tcp",
            "-d",
            HOST_GATEWAY,
            "--dport",
            str(NFS_PORT),
            "-j",
            "ACCEPT",
        ],
        [
            "iptables",
            "-A",
            "INPUT",
            "-i",
            tap,
            "-p",
            "tcp",
            "-d",
            "127.0.0.1",
            "--dport",
            str(GUARDRAILS_PORT),
            "-j",
            "ACCEPT",
        ],
        ["iptables", "-A", "INPUT", "-i", tap, "-j", "DROP"],
        ["iptables", "-A", "FORWARD", "-i", tap, "-j", "DROP"],
        ["iptables", "-A", "FORWARD", "-o", tap, "-j", "DROP"],
        [
            "iptables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            tap,
            "-p",
            "tcp",
            "--dport",
            str(GUARDRAILS_PORT),
            "-j",
            "DNAT",
            "--to-destination",
            f"127.0.0.1:{GUARDRAILS_PORT}",
        ],
    ]


def build_teardown_commands(session_id: str) -> list[list[str]]:
    tap = tap_device_name(session_id)
    return [
        [
            "iptables",
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            tap,
            "-p",
            "tcp",
            "--dport",
            str(GUARDRAILS_PORT),
            "-j",
            "DNAT",
            "--to-destination",
            f"127.0.0.1:{GUARDRAILS_PORT}",
        ],
        ["iptables", "-D", "FORWARD", "-o", tap, "-j", "DROP"],
        ["iptables", "-D", "FORWARD", "-i", tap, "-j", "DROP"],
        ["iptables", "-D", "INPUT", "-i", tap, "-j", "DROP"],
        [
            "iptables",
            "-D",
            "INPUT",
            "-i",
            tap,
            "-p",
            "tcp",
            "-d",
            HOST_GATEWAY,
            "--dport",
            str(NFS_PORT),
            "-j",
            "ACCEPT",
        ],
        [
            "iptables",
            "-D",
            "INPUT",
            "-i",
            tap,
            "-p",
            "tcp",
            "-d",
            "127.0.0.1",
            "--dport",
            str(GUARDRAILS_PORT),
            "-j",
            "ACCEPT",
        ],
        ["sysctl", "-w", f"net.ipv4.conf.{tap}.route_localnet=0"],
        ["ip", "link", "del", tap],
    ]
