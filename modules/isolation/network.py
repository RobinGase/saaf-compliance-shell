"""TAP device naming and v1 host-side network policy generation."""

from __future__ import annotations

import hashlib
import re

HOST_GATEWAY = "172.16.0.1"
GUEST_IP = "172.16.0.2"
GUARDRAILS_PORT = 8088
NFS_PORT = 11111


class NetworkPolicyError(ValueError):
    """Raised when a manifest requests a network policy not supported in v1."""


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
