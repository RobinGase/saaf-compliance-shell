import pytest

from modules.isolation.network import (
    NetworkPolicyError,
    build_setup_commands,
    build_teardown_commands,
    tap_device_name,
    validate_v1_network_rules,
)


def test_tap_device_name_is_stable_and_trimmed() -> None:
    tap = tap_device_name("Vendor Guard Session 001")
    assert tap.startswith("fc-vendor-g-")
    assert len(tap) <= 15


def test_tap_device_name_keeps_session_entropy() -> None:
    assert tap_device_name("vendor-guard-aaaa1111") != tap_device_name("vendor-guard-bbbb2222")


def test_validate_v1_network_rules_accepts_gateway_guardrails_only() -> None:
    manifest = {
        "network": {
            "allow": [
                {"host": "gateway", "port": 8088, "purpose": "nemo_guardrails"},
            ]
        }
    }

    rule = validate_v1_network_rules(manifest)

    assert rule == {"host": "gateway", "port": 8088, "purpose": "nemo_guardrails"}


def test_validate_v1_network_rules_rejects_any_other_endpoint() -> None:
    manifest = {
        "network": {
            "allow": [
                {"host": "100.87.245.60", "port": 8000, "purpose": "ollama"},
            ]
        }
    }

    with pytest.raises(NetworkPolicyError, match="only permit gateway:8088"):
        validate_v1_network_rules(manifest)


def test_build_setup_commands_locks_guest_to_guardrails() -> None:
    tap = tap_device_name("session-001")
    commands = build_setup_commands(session_id="session-001")

    assert commands == [
        ["ip", "tuntap", "add", "dev", tap, "mode", "tap"],
        ["ip", "addr", "add", "172.16.0.1/24", "dev", tap],
        ["ip", "link", "set", tap, "up"],
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
            "8088",
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
            "8088",
            "-j",
            "DNAT",
            "--to-destination",
            "127.0.0.1:8088",
        ],
    ]


def test_build_teardown_commands_reverse_setup_order() -> None:
    tap = tap_device_name("session-001")
    assert build_teardown_commands(session_id="session-001") == [
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
            "8088",
            "-j",
            "DNAT",
            "--to-destination",
            "127.0.0.1:8088",
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
            "127.0.0.1",
            "--dport",
            "8088",
            "-j",
            "ACCEPT",
        ],
        ["ip", "link", "del", tap],
    ]
