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

The same reasoning applies to IPv6. Linux auto-assigns a link-local
address to every new interface unless forbidden, and iptables rules
do not cover IPv6 — they're the IPv4 table. The policy therefore also
disables IPv6 on the tap outright and installs mirror DROP rules in
ip6tables for defence in depth, and the forwarding check reads both
``/proc/sys/net/ipv4/ip_forward`` and ``/proc/sys/net/ipv6/conf/all/forwarding``.
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
IPV6_FORWARD_PROC_PATH = Path("/proc/sys/net/ipv6/conf/all/forwarding")


class NetworkPolicyError(ValueError):
    """Raised when a manifest requests a network policy not supported in v1."""


class IpForwardEnabledError(RuntimeError):
    """Raised at startup when the host has IP forwarding enabled.

    With ``net.ipv4.ip_forward=1`` or ``net.ipv6.conf.all.forwarding=1``
    the kernel will route guest packets out of the tap through another
    interface. The INPUT+FORWARD DROP rules cover that — but only if
    FORWARD is consulted and only for the matching address family.
    Rather than trust that silently, refuse to start so the operator
    disables forwarding or explicitly acknowledges it with
    ``SAAF_ALLOW_IP_FORWARD=1``.
    """


def _allow_env_is_truthy(allow_env: str | None) -> bool:
    if allow_env is None:
        return False
    return allow_env.strip() not in ("", "0", "false", "False")


def _read_forward_flag(proc_path: Path) -> str | None:
    try:
        return proc_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError:
        return None


def ensure_ip_forward_disabled(
    *,
    proc_path: Path | str = IP_FORWARD_PROC_PATH,
    ipv6_proc_path: Path | str = IPV6_FORWARD_PROC_PATH,
    allow_env: str | None = None,
) -> None:
    """Refuse to run when the host kernel has IPv4 or IPv6 forwarding enabled.

    ``allow_env`` is the value of ``SAAF_ALLOW_IP_FORWARD`` read by the
    caller; a truthy value turns the hard error into a no-op so operators
    who share the host with Tailscale/Docker can opt in after confirming
    the FORWARD DROP rules are in place.
    """
    if _allow_env_is_truthy(allow_env):
        return

    enabled: list[str] = []
    if _read_forward_flag(Path(proc_path)) == "1":
        enabled.append("net.ipv4.ip_forward=1")
    if _read_forward_flag(Path(ipv6_proc_path)) == "1":
        enabled.append("net.ipv6.conf.all.forwarding=1")

    if not enabled:
        return

    raise IpForwardEnabledError(
        f"{' and '.join(enabled)} on this host. The v1 guest network policy "
        "relies on FORWARD DROP rules; disable forwarding "
        "(`sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0`) or set "
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
        ["sysctl", "-w", f"net.ipv6.conf.{tap}.disable_ipv6=1"],
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
        ["ip6tables", "-A", "INPUT", "-i", tap, "-j", "DROP"],
        ["ip6tables", "-A", "FORWARD", "-i", tap, "-j", "DROP"],
        ["ip6tables", "-A", "FORWARD", "-o", tap, "-j", "DROP"],
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
        ["ip6tables", "-D", "FORWARD", "-o", tap, "-j", "DROP"],
        ["ip6tables", "-D", "FORWARD", "-i", tap, "-j", "DROP"],
        ["ip6tables", "-D", "INPUT", "-i", tap, "-j", "DROP"],
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
        ["sysctl", "-w", f"net.ipv6.conf.{tap}.disable_ipv6=0"],
        ["sysctl", "-w", f"net.ipv4.conf.{tap}.route_localnet=0"],
        ["ip", "link", "del", tap],
    ]
