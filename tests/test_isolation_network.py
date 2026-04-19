import pytest

from modules.isolation.network import (
    IpForwardEnabledError,
    NetworkPolicyError,
    build_setup_commands,
    build_teardown_commands,
    ensure_ip_forward_disabled,
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
                {"host": "192.0.2.1", "port": 8000, "purpose": "ollama"},
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
        ["sysctl", "-w", f"net.ipv4.conf.{tap}.route_localnet=1"],
        ["sysctl", "-w", f"net.ipv6.conf.{tap}.disable_ipv6=1"],
        [
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-i",
            tap,
            "-p",
            "tcp",
            "-d",
            "172.16.0.1",
            "--dport",
            "11111",
            "-j",
            "ACCEPT",
        ],
        [
            "iptables",
            "-I",
            "INPUT",
            "2",
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
        ["iptables", "-I", "INPUT", "3", "-i", tap, "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "1", "-i", tap, "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "2", "-o", tap, "-j", "DROP"],
        ["ip6tables", "-I", "INPUT", "1", "-i", tap, "-j", "DROP"],
        ["ip6tables", "-I", "FORWARD", "1", "-i", tap, "-j", "DROP"],
        ["ip6tables", "-I", "FORWARD", "2", "-o", tap, "-j", "DROP"],
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


def test_build_setup_commands_prepends_filter_rules_for_shared_host_safety() -> None:
    """RT-06 regression: filter-table rules must use ``-I <chain> N``,
    not ``-A``. On a shared host with Tailscale/Docker/libvirt, those
    tools append their own ACCEPT rules to FORWARD (and occasionally
    INPUT). Under ``SAAF_ALLOW_IP_FORWARD=1``, any earlier-appended
    ACCEPT would match and return before SAAF's DROP is evaluated.
    Inserting at explicit positions keeps the SAAF block at the top of
    each filter chain.

    The NAT PREROUTING rule is scoped by ``-i <tap>`` and stays ``-A`` —
    no Docker/libvirt rule on another interface can shadow it.
    """
    commands = build_setup_commands(session_id="session-rt06")

    filter_insert_ops = [
        (cmd[0], cmd[1], cmd[2], cmd[3])
        for cmd in commands
        if cmd[0] in ("iptables", "ip6tables") and cmd[1] == "-I"
    ]
    # Each filter insert must carry an explicit position; positions within
    # a chain are contiguous from 1 so SAAF rules land as an adjacent
    # block at the top.
    assert filter_insert_ops == [
        ("iptables", "-I", "INPUT", "1"),
        ("iptables", "-I", "INPUT", "2"),
        ("iptables", "-I", "INPUT", "3"),
        ("iptables", "-I", "FORWARD", "1"),
        ("iptables", "-I", "FORWARD", "2"),
        ("ip6tables", "-I", "INPUT", "1"),
        ("ip6tables", "-I", "FORWARD", "1"),
        ("ip6tables", "-I", "FORWARD", "2"),
    ]

    # No filter-table command should still be using ``-A``. NAT PREROUTING
    # is the only ``-A`` left, intentionally.
    leftover_appends = [
        cmd for cmd in commands
        if cmd[0] in ("iptables", "ip6tables") and "-A" in cmd and "-t" not in cmd
    ]
    assert leftover_appends == []

    # Guard the NAT-table exception explicitly so a future refactor
    # doesn't silently switch the DNAT to an insert without thinking
    # through chain-placement for Docker coexistence.
    nat_commands = [cmd for cmd in commands if "-t" in cmd and "nat" in cmd]
    assert len(nat_commands) == 1
    assert "-A" in nat_commands[0]
    assert "PREROUTING" in nat_commands[0]


def test_setup_input_insert_order_preserves_accept_before_drop() -> None:
    """Walk the three INPUT inserts and simulate their effect on a chain
    that already contains a hostile ACCEPT rule (e.g. Tailscale's
    ``-A INPUT -j ACCEPT``). After SAAF setup the chain must start with
    [ACCEPT nfs, ACCEPT gateway, DROP, <existing>] — otherwise either
    the gateway traffic gets blocked or the guest can reach host
    services other than the guardrails port.
    """
    commands = build_setup_commands(session_id="s-order")
    input_inserts = [cmd for cmd in commands if cmd[:3] == ["iptables", "-I", "INPUT"]]
    assert len(input_inserts) == 3

    chain: list[str] = ["EXISTING_ACCEPT_FROM_TAILSCALE"]
    for cmd in input_inserts:
        pos = int(cmd[3])
        # ``-j X`` is the last two tokens.
        verdict = cmd[-1]
        chain.insert(pos - 1, verdict)

    assert chain == ["ACCEPT", "ACCEPT", "DROP", "EXISTING_ACCEPT_FROM_TAILSCALE"]


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
            "172.16.0.1",
            "--dport",
            "11111",
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
            "8088",
            "-j",
            "ACCEPT",
        ],
        ["sysctl", "-w", f"net.ipv6.conf.{tap}.disable_ipv6=0"],
        ["sysctl", "-w", f"net.ipv4.conf.{tap}.route_localnet=0"],
        ["ip", "link", "del", tap],
    ]


def _forward_proc_paths(tmp_path, v4: str = "0", v6: str = "0") -> dict:
    ipv4 = tmp_path / "ipv4_forward"
    ipv6 = tmp_path / "ipv6_forwarding"
    ipv4.write_text(v4 + "\n", encoding="utf-8")
    ipv6.write_text(v6 + "\n", encoding="utf-8")
    return {"proc_path": ipv4, "ipv6_proc_path": ipv6}


def test_ensure_ip_forward_disabled_passes_when_both_zero(tmp_path) -> None:
    ensure_ip_forward_disabled(**_forward_proc_paths(tmp_path), allow_env=None)


def test_ensure_ip_forward_disabled_raises_when_ipv4_enabled(tmp_path) -> None:
    with pytest.raises(IpForwardEnabledError, match="net.ipv4.ip_forward=1"):
        ensure_ip_forward_disabled(**_forward_proc_paths(tmp_path, v4="1"), allow_env=None)


def test_ensure_ip_forward_disabled_raises_when_ipv6_enabled(tmp_path) -> None:
    with pytest.raises(IpForwardEnabledError, match="net.ipv6.conf.all.forwarding=1"):
        ensure_ip_forward_disabled(**_forward_proc_paths(tmp_path, v6="1"), allow_env=None)


def test_ensure_ip_forward_disabled_reports_both_when_both_enabled(tmp_path) -> None:
    with pytest.raises(IpForwardEnabledError) as excinfo:
        ensure_ip_forward_disabled(**_forward_proc_paths(tmp_path, v4="1", v6="1"), allow_env=None)
    assert "net.ipv4.ip_forward=1" in str(excinfo.value)
    assert "net.ipv6.conf.all.forwarding=1" in str(excinfo.value)


def test_ensure_ip_forward_disabled_allows_opt_in_when_env_truthy(tmp_path) -> None:
    ensure_ip_forward_disabled(**_forward_proc_paths(tmp_path, v4="1", v6="1"), allow_env="1")


@pytest.mark.parametrize("falsy", ["", "0", "false", "False"])
def test_ensure_ip_forward_disabled_ignores_falsy_env(tmp_path, falsy: str) -> None:
    with pytest.raises(IpForwardEnabledError):
        ensure_ip_forward_disabled(**_forward_proc_paths(tmp_path, v4="1"), allow_env=falsy)


def test_ensure_ip_forward_disabled_noops_when_proc_missing(tmp_path) -> None:
    ensure_ip_forward_disabled(
        proc_path=tmp_path / "missing_v4",
        ipv6_proc_path=tmp_path / "missing_v6",
        allow_env=None,
    )
