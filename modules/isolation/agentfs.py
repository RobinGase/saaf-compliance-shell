"""Thin wrapper around the AgentFS CLI."""

from __future__ import annotations

import subprocess
from pathlib import Path


class AgentFSError(RuntimeError):
    """Raised when an AgentFS command fails."""


class AgentFSClient:
    def __init__(
        self,
        base_rootfs: str | Path,
        overlay_dir: str | Path,
        binary: str = "/usr/local/bin/agentfs",
    ):
        self.base_rootfs = Path(base_rootfs)
        self.overlay_dir = Path(overlay_dir)
        self.binary = binary
        if self.overlay_dir.name != ".agentfs":
            raise ValueError("AgentFS overlay_dir must be named .agentfs")

    @property
    def _workdir(self) -> Path:
        return self.overlay_dir.parent

    def create_session(self, session_id: str) -> Path:
        self.overlay_dir.mkdir(parents=True, exist_ok=True)
        self._run([self.binary, "init", "--force", "--base", str(self.base_rootfs), session_id])
        return self.overlay_dir / f"{session_id}.db"

    def diff_session(self, session_id: str) -> list[str]:
        result = self._run([self.binary, "diff", session_id])
        return [line for line in result.stdout.splitlines() if line.strip()]

    def list_sessions(self) -> list[str]:
        if not self.overlay_dir.exists():
            return []
        return sorted(path.stem for path in self.overlay_dir.glob("*.db"))

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                cwd=self._workdir,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise AgentFSError(str(exc)) from exc


def start_nfs_server(
    session_id: str,
    host: str,
    port: int,
    *,
    binary: str = "/usr/local/bin/agentfs",
    workdir: str | Path = "/opt/saaf",
) -> subprocess.Popen[str]:
    try:
        return subprocess.Popen(
            [binary, "serve", "nfs", "--bind", host, "--port", str(port), session_id],
            cwd=Path(workdir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError as exc:
        raise AgentFSError(str(exc)) from exc


def stop_nfs_server(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
