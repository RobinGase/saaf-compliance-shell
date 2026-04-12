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

    monkeypatch.setattr("modules.isolation.runtime._run_commands", lambda commands, check=True: calls.append(("commands", commands, check)))
    monkeypatch.setattr("modules.isolation.runtime.launch_firecracker", lambda config: calls.append(("launch", config)) or 0)
    monkeypatch.setattr("modules.isolation.runtime.AgentFSClient.create_session", lambda self, session_id: calls.append(("create", session_id)))
    monkeypatch.setattr(
        "modules.isolation.runtime.start_nfs_server",
        lambda session_id, host, port, db_path=None, binary="/usr/local/bin/agentfs", workdir="/opt/saaf": calls.append(("start_nfs", session_id, host, port, db_path, binary, workdir)) or object(),
    )
    monkeypatch.setattr("modules.isolation.runtime.stop_nfs_server", lambda process: calls.append(("stop_nfs", process)))

    session_id = run_manifest(
        manifest_path,
        kernel_path="/opt/saaf/kernels/vmlinux",
        rootfs_path=tmp_path / "rootfs",
        overlay_dir=tmp_path / ".agentfs",
        audit_log_path=tmp_path / "audit.jsonl",
    )

    assert session_id.startswith("vendor-guard-")
    start_nfs_index = next(i for i, call in enumerate(calls) if call[0] == "start_nfs")
    setup_index = next(i for i, call in enumerate(calls) if call[0] == "commands" and call[2] is True)

    assert setup_index < start_nfs_index
    assert any(call[0] == "start_nfs" and call[1] == session_id for call in calls)
    assert any(call[0] == "stop_nfs" for call in calls)
