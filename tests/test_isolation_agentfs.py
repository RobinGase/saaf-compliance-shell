from pathlib import Path

import pytest

from modules.isolation.agentfs import AgentFSClient, AgentFSError


def test_create_session_runs_agentfs_init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    overlay_dir = tmp_path / ".agentfs"
    base_rootfs = tmp_path / "rootfs"
    overlay_dir.mkdir()
    base_rootfs.mkdir()

    calls: list[tuple[list[str], Path]] = []

    def fake_run(cmd: list[str], check: bool, capture_output: bool, text: bool, cwd: Path):
        calls.append((cmd, cwd))
        return None

    monkeypatch.setattr("modules.isolation.agentfs.subprocess.run", fake_run)

    client = AgentFSClient(base_rootfs=base_rootfs, overlay_dir=overlay_dir, binary="/usr/local/bin/agentfs")
    db_path = client.create_session("session-001")

    assert db_path == overlay_dir / "session-001.db"
    assert calls == [
        (
            [
                "/usr/local/bin/agentfs",
                "init",
                "--force",
                "--base",
                str(base_rootfs),
                "session-001",
            ],
            tmp_path,
        )
    ]


def test_diff_session_returns_stdout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    overlay_dir = tmp_path / ".agentfs"
    base_rootfs = tmp_path / "rootfs"
    overlay_dir.mkdir()
    base_rootfs.mkdir()

    class Result:
        stdout = "M /audit_workspace/report.txt\nA /audit_workspace/notes.md\n"

    def fake_run(cmd: list[str], check: bool, capture_output: bool, text: bool, cwd: Path):
        assert cmd == ["/usr/local/bin/agentfs", "diff", "session-001"]
        assert cwd == tmp_path
        return Result()

    monkeypatch.setattr("modules.isolation.agentfs.subprocess.run", fake_run)

    client = AgentFSClient(base_rootfs=base_rootfs, overlay_dir=overlay_dir, binary="/usr/local/bin/agentfs")
    assert client.diff_session("session-001") == [
        "M /audit_workspace/report.txt",
        "A /audit_workspace/notes.md",
    ]


def test_list_sessions_reads_overlay_directory(tmp_path: Path) -> None:
    overlay_dir = tmp_path / ".agentfs"
    base_rootfs = tmp_path / "rootfs"
    overlay_dir.mkdir()
    base_rootfs.mkdir()
    (overlay_dir / "b-session.db").write_text("")
    (overlay_dir / "a-session.db").write_text("")
    (overlay_dir / "ignore.txt").write_text("")

    client = AgentFSClient(base_rootfs=base_rootfs, overlay_dir=overlay_dir)

    assert client.list_sessions() == ["a-session", "b-session"]


def test_create_session_wraps_subprocess_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    overlay_dir = tmp_path / ".agentfs"
    base_rootfs = tmp_path / "rootfs"
    overlay_dir.mkdir()
    base_rootfs.mkdir()

    def fake_run(cmd: list[str], check: bool, capture_output: bool, text: bool, cwd: Path):
        raise OSError("agentfs missing")

    monkeypatch.setattr("modules.isolation.agentfs.subprocess.run", fake_run)

    client = AgentFSClient(base_rootfs=base_rootfs, overlay_dir=overlay_dir)

    with pytest.raises(AgentFSError, match="agentfs missing"):
        client.create_session("session-001")
