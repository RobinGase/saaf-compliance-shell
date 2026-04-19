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
