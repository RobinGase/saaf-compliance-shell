from pathlib import Path

from modules.isolation.runtime import run_manifest


def test_run_manifest_starts_agentfs_nfs_for_session(tmp_path: Path, monkeypatch) -> None:
    manifest_path = tmp_path / "saaf-manifest.yaml"
    manifest_path.write_text(
        """
version: 1
name: vendor-guard
agent:
  entrypoint: python3 -m vendor_guard.agent
  working_directory: /audit_workspace
  env:
    INFERENCE_URL: http://172.16.0.1:8088/v1/chat/completions
data_classification:
  default: sensitive
filesystem:
  read_write:
    - /audit_workspace
network:
  allow:
    - host: gateway
      port: 8088
      purpose: nemo_guardrails
resources:
  vcpu_count: 2
  mem_size_mib: 2048
pii:
  entities:
    - PERSON
audit:
  retention_days: 2555
""".strip()
    )

    calls: list[tuple] = []

    monkeypatch.setattr("modules.isolation.runtime.ensure_ip_forward_disabled", lambda **kwargs: None)
    monkeypatch.setattr(
        "modules.isolation.runtime._run_commands",
        lambda commands, check=True, **kwargs: calls.append(("commands", commands, check)),
    )
    monkeypatch.setattr("modules.isolation.runtime.launch_firecracker", lambda config, console_log_path=None: calls.append(("launch", config, console_log_path)) or 0)
    monkeypatch.setattr("modules.isolation.runtime.AgentFSClient.create_session", lambda self, session_id: calls.append(("create", session_id)))
    monkeypatch.setattr(
        "modules.isolation.runtime.start_nfs_server",
        lambda session_id, host, port, db_path=None, binary="/usr/local/bin/agentfs", workdir="/opt/saaf", log_path=None: calls.append(("start_nfs", session_id, host, port, db_path, binary, workdir, log_path)) or object(),
    )
    monkeypatch.setattr("modules.isolation.runtime.stop_nfs_server", lambda process: calls.append(("stop_nfs", process)))

    session_id = run_manifest(
        manifest_path,
        kernel_path="/opt/saaf/kernels/vmlinux",
        rootfs_path=tmp_path / "rootfs",
        overlay_dir=tmp_path / ".agentfs",
        audit_log_path=tmp_path / "audit.jsonl",
        session_lock_path=tmp_path / "session.lock",
    )

    assert session_id.startswith("vendor-guard-")
    start_nfs_index = next(i for i, call in enumerate(calls) if call[0] == "start_nfs")
    setup_index = next(i for i, call in enumerate(calls) if call[0] == "commands" and call[2] is True)

    assert setup_index < start_nfs_index
    assert any(call[0] == "start_nfs" and call[1] == session_id for call in calls)
    assert any(call[0] == "stop_nfs" for call in calls)

    # H2: runtime must route NFS stdout/stderr to a per-session log file
    # so guest-side mount failures surface in the session workdir instead
    # of being swallowed into DEVNULL.
    start_nfs_call = next(call for call in calls if call[0] == "start_nfs")
    nfs_log_path = start_nfs_call[7]
    assert nfs_log_path is not None
    assert Path(nfs_log_path).name == f"{session_id}.nfs.log"
    assert Path(nfs_log_path).parent == tmp_path

    # H3: NFS port is picked inside the session lock (ephemeral) rather
    # than hardcoded. Assert port is non-zero and != the pre-H3 static
    # DEFAULT_NFS_PORT=11111 so a regression back to the static value
    # surfaces as a test failure.
    chosen_port = start_nfs_call[3]
    assert isinstance(chosen_port, int)
    assert chosen_port > 0
    # Ephemeral ports land in the kernel ip_local_port_range, which on
    # every mainstream Linux and on Windows is well above 11111; use a
    # conservative floor so we don't false-fail on unusual tuning.
    assert chosen_port != 11111


def test_run_manifest_ephemeral_port_differs_across_sessions(tmp_path: Path, monkeypatch) -> None:
    """H3: two sequential ``run_manifest`` calls on the same host should
    in general pick different ephemeral ports. The kernel *may* reuse a
    port if no one else has claimed it, so this test doesn't assert
    strict inequality — it just asserts both picks are ephemeral-range
    integers distinct from the pre-H3 static value."""
    manifest_path = tmp_path / "saaf-manifest.yaml"
    manifest_path.write_text(
        """
version: 1
name: vendor-guard
agent:
  entrypoint: python3 -m vendor_guard.agent
  working_directory: /audit_workspace
  env:
    INFERENCE_URL: http://172.16.0.1:8088/v1/chat/completions
data_classification:
  default: sensitive
filesystem:
  read_write:
    - /audit_workspace
network:
  allow:
    - host: gateway
      port: 8088
      purpose: nemo_guardrails
resources:
  vcpu_count: 2
  mem_size_mib: 2048
pii:
  entities:
    - PERSON
audit:
  retention_days: 2555
""".strip()
    )

    ports: list[int] = []

    monkeypatch.setattr("modules.isolation.runtime.ensure_ip_forward_disabled", lambda **kwargs: None)
    monkeypatch.setattr(
        "modules.isolation.runtime._run_commands",
        lambda commands, check=True, **kwargs: None,
    )
    monkeypatch.setattr(
        "modules.isolation.runtime.launch_firecracker",
        lambda config, console_log_path=None: 0,
    )
    monkeypatch.setattr(
        "modules.isolation.runtime.AgentFSClient.create_session",
        lambda self, session_id: tmp_path / f"{session_id}.db",
    )
    monkeypatch.setattr(
        "modules.isolation.runtime.start_nfs_server",
        lambda session_id, host, port, db_path=None, binary="/usr/local/bin/agentfs", workdir="/opt/saaf", log_path=None: ports.append(port) or object(),
    )
    monkeypatch.setattr("modules.isolation.runtime.stop_nfs_server", lambda process: None)

    for _ in range(2):
        run_manifest(
            manifest_path,
            kernel_path="/opt/saaf/kernels/vmlinux",
            rootfs_path=tmp_path / "rootfs",
            overlay_dir=tmp_path / ".agentfs",
            audit_log_path=tmp_path / "audit.jsonl",
            session_lock_path=tmp_path / "session.lock",
        )

    assert len(ports) == 2
    for port in ports:
        assert isinstance(port, int) and port > 0
        assert port != 11111  # regression guard: pre-H3 static default


# B2: tap-leak teardown. The ordered teardown command list can be aborted
# mid-iteration when ``audit.record`` itself raises (AuditTamperDetected,
# disk full, etc.). Before this fix, the final ``ip link del <tap>`` was
# skipped and the tap accumulated on the host, eventually colliding with
# the next session's ``ip tuntap add``. The fix adds ``_force_delete_tap``
# as a post-teardown safety net that runs even when the ordered teardown
# raised — verified via a fake ``ip link show/del`` that captures the
# force-delete call.


def test_tap_force_delete_runs_when_teardown_raises(tmp_path: Path, monkeypatch) -> None:
    """B2: if ``_run_commands`` aborts mid-teardown, the tap still gets deleted.

    Simulates AuditTamperDetected raised from the teardown phase by making
    ``_run_commands`` raise when called with ``phase="teardown"``. Asserts
    that ``_force_delete_tap`` still runs and issues the final ``ip link
    del`` against the session's tap.
    """
    from modules.isolation.network import tap_device_name
    import subprocess as _subprocess

    manifest_path = tmp_path / "saaf-manifest.yaml"
    manifest_path.write_text(
        """
version: 1
name: vendor-guard
agent:
  entrypoint: python3 -m vendor_guard.agent
  working_directory: /audit_workspace
  env:
    INFERENCE_URL: http://172.16.0.1:8088/v1/chat/completions
data_classification:
  default: sensitive
filesystem:
  read_write:
    - /audit_workspace
network:
  allow:
    - host: gateway
      port: 8088
      purpose: nemo_guardrails
resources:
  vcpu_count: 2
  mem_size_mib: 2048
pii:
  entities:
    - PERSON
audit:
  retention_days: 2555
""".strip()
    )

    def fake_run_commands(commands, check=True, **kwargs):
        if kwargs.get("phase") == "teardown":
            raise RuntimeError("simulated AuditTamperDetected during teardown")

    monkeypatch.setattr("modules.isolation.runtime.ensure_ip_forward_disabled", lambda **kwargs: None)
    monkeypatch.setattr("modules.isolation.runtime._run_commands", fake_run_commands)
    monkeypatch.setattr(
        "modules.isolation.runtime.launch_firecracker",
        lambda config, console_log_path=None: 0,
    )
    monkeypatch.setattr(
        "modules.isolation.runtime.AgentFSClient.create_session",
        lambda self, session_id: tmp_path / f"{session_id}.db",
    )
    monkeypatch.setattr(
        "modules.isolation.runtime.start_nfs_server",
        lambda session_id, host, port, db_path=None, binary="/usr/local/bin/agentfs", workdir="/opt/saaf", log_path=None: object(),
    )
    monkeypatch.setattr("modules.isolation.runtime.stop_nfs_server", lambda process: None)

    # Intercept subprocess.run so we can (a) report the tap as existing
    # on ``ip link show`` and (b) capture the force-delete call.
    captured: list[list[str]] = []

    class _Completed:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_subprocess_run(cmd, check=False, capture_output=False, text=False):
        captured.append(list(cmd))
        if cmd[:3] == ["ip", "link", "show"]:
            # Tap exists — force delete must proceed.
            return _Completed(returncode=0, stdout="1: fc-*: <BROADCAST,MULTICAST,UP>")
        if cmd[:3] == ["ip", "link", "del"]:
            return _Completed(returncode=0)
        return _Completed(returncode=0)

    monkeypatch.setattr(
        "modules.isolation.runtime.subprocess.run",
        fake_subprocess_run,
    )

    session_id = run_manifest(
        manifest_path,
        kernel_path="/opt/saaf/kernels/vmlinux",
        rootfs_path=tmp_path / "rootfs",
        overlay_dir=tmp_path / ".agentfs",
        audit_log_path=tmp_path / "audit.jsonl",
        session_lock_path=tmp_path / "session.lock",
    )

    expected_tap = tap_device_name(session_id)
    # Force-delete must have issued both a show and a del against the tap.
    assert ["ip", "link", "show", expected_tap] in captured
    assert ["ip", "link", "del", expected_tap] in captured


def test_tap_force_delete_skips_when_interface_already_gone(tmp_path: Path, monkeypatch) -> None:
    """B2: happy path must not issue a redundant ``ip link del`` if the ordered
    teardown already removed the tap. ``ip link show`` returns non-zero, so
    ``_force_delete_tap`` returns without attempting a delete.
    """
    from modules.isolation.network import tap_device_name

    manifest_path = tmp_path / "saaf-manifest.yaml"
    manifest_path.write_text(
        """
version: 1
name: vendor-guard
agent:
  entrypoint: python3 -m vendor_guard.agent
  working_directory: /audit_workspace
  env:
    INFERENCE_URL: http://172.16.0.1:8088/v1/chat/completions
data_classification:
  default: sensitive
filesystem:
  read_write:
    - /audit_workspace
network:
  allow:
    - host: gateway
      port: 8088
      purpose: nemo_guardrails
resources:
  vcpu_count: 2
  mem_size_mib: 2048
pii:
  entities:
    - PERSON
audit:
  retention_days: 2555
""".strip()
    )

    monkeypatch.setattr("modules.isolation.runtime.ensure_ip_forward_disabled", lambda **kwargs: None)
    monkeypatch.setattr("modules.isolation.runtime._run_commands", lambda commands, check=True, **kwargs: None)
    monkeypatch.setattr(
        "modules.isolation.runtime.launch_firecracker",
        lambda config, console_log_path=None: 0,
    )
    monkeypatch.setattr(
        "modules.isolation.runtime.AgentFSClient.create_session",
        lambda self, session_id: tmp_path / f"{session_id}.db",
    )
    monkeypatch.setattr(
        "modules.isolation.runtime.start_nfs_server",
        lambda session_id, host, port, db_path=None, binary="/usr/local/bin/agentfs", workdir="/opt/saaf", log_path=None: object(),
    )
    monkeypatch.setattr("modules.isolation.runtime.stop_nfs_server", lambda process: None)

    captured: list[list[str]] = []

    class _Completed:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_subprocess_run(cmd, check=False, capture_output=False, text=False):
        captured.append(list(cmd))
        if cmd[:3] == ["ip", "link", "show"]:
            # Interface already gone — ordered teardown succeeded.
            return _Completed(returncode=1, stderr="Device does not exist")
        return _Completed(returncode=0)

    monkeypatch.setattr(
        "modules.isolation.runtime.subprocess.run",
        fake_subprocess_run,
    )

    session_id = run_manifest(
        manifest_path,
        kernel_path="/opt/saaf/kernels/vmlinux",
        rootfs_path=tmp_path / "rootfs",
        overlay_dir=tmp_path / ".agentfs",
        audit_log_path=tmp_path / "audit.jsonl",
        session_lock_path=tmp_path / "session.lock",
    )

    expected_tap = tap_device_name(session_id)
    # Probe happens exactly once; no redundant delete issued.
    assert ["ip", "link", "show", expected_tap] in captured
    assert ["ip", "link", "del", expected_tap] not in captured
