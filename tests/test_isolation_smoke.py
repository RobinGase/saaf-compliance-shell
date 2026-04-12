from pathlib import Path

import pytest

from modules.isolation.smoke import run_vm_probe


def test_run_vm_probe_returns_session_and_diff(monkeypatch, tmp_path: Path) -> None:
    overlay_dir = tmp_path / ".agentfs"
    overlay_dir.mkdir()

    monkeypatch.setattr("modules.isolation.smoke.run_manifest", lambda *args, **kwargs: "guest-probe-abc12345")
    monkeypatch.setattr(
        "modules.isolation.smoke.collect_diff",
        lambda overlay_dir, session_id, binary="/usr/local/bin/agentfs": [
            "A f /audit_workspace/init.log",
            "A f /audit_workspace/probe.log",
            "A f /audit_workspace/response.json",
        ],
    )

    result = run_vm_probe(
        manifest_path=tmp_path / "manifest.yaml",
        overlay_dir=overlay_dir,
        audit_log_path=tmp_path / "audit.jsonl",
    )

    assert result["session_id"] == "guest-probe-abc12345"
    assert result["diff"] == [
        "A f /audit_workspace/init.log",
        "A f /audit_workspace/probe.log",
        "A f /audit_workspace/response.json",
    ]


def test_run_vm_probe_fails_when_expected_artifacts_missing(monkeypatch, tmp_path: Path) -> None:
    overlay_dir = tmp_path / ".agentfs"
    overlay_dir.mkdir()

    monkeypatch.setattr("modules.isolation.smoke.run_manifest", lambda *args, **kwargs: "guest-probe-abc12345")
    monkeypatch.setattr(
        "modules.isolation.smoke.collect_diff",
        lambda overlay_dir, session_id, binary="/usr/local/bin/agentfs": [
            "A f /audit_workspace/init.log",
        ],
    )

    with pytest.raises(RuntimeError, match="response.json"):
        run_vm_probe(
            manifest_path=tmp_path / "manifest.yaml",
            overlay_dir=overlay_dir,
            audit_log_path=tmp_path / "audit.jsonl",
        )
