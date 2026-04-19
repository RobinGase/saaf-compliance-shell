"""Thin wrapper around the AgentFS CLI."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


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
    db_path: str | Path | None = None,
    binary: str = "/usr/local/bin/agentfs",
    workdir: str | Path = "/opt/saaf",
    log_path: str | Path | None = None,
) -> subprocess.Popen[str]:
    """Start the per-session NFS server.

    H2: when ``log_path`` is supplied, the NFS server's stdout and stderr
    are appended to that file (with stderr merged into stdout). Before
    this, NFS chatter and setup errors were routed to ``DEVNULL`` — a
    guest-side mount failure surfaced only as a Firecracker boot error
    with no visibility into the NFS side. Leaving ``log_path`` at
    ``None`` preserves the old DEVNULL behaviour for callers that don't
    opt in.
    """
    stdout: int | Any = subprocess.DEVNULL
    stderr: int | Any = subprocess.DEVNULL
    log_fh: Any = None
    if log_path is not None:
        # Binary append: NFS server may emit non-UTF-8 bytes, and append
        # preserves prior-session context when operators reuse log paths
        # during debugging.
        # ruff: SIM115 suppressed — Popen dupes the fd into the child, and
        # we close our parent-side handle in the finally block below once
        # Popen has returned. A ``with`` block would close before Popen
        # sees the fd.
        log_fh = open(log_path, "ab", buffering=0)  # noqa: SIM115
        stdout = log_fh
        stderr = subprocess.STDOUT
    try:
        return subprocess.Popen(
            [binary, "serve", "nfs", "--bind", host, "--port", str(port), session_id],
            cwd=Path(workdir),
            stdout=stdout,
            stderr=stderr,
            text=True,
        )
    except OSError as exc:
        if log_fh is not None:
            log_fh.close()
        raise AgentFSError(str(exc)) from exc
    finally:
        # Popen duplicates the fd into the child; the parent handle is
        # safe to close once Popen returns. Closing releases our own fd
        # so the log file isn't held by the parent for the session's
        # lifetime (the child keeps its copy open).
        if log_fh is not None:
            log_fh.close()


def stop_nfs_server(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
