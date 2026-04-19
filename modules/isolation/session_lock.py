"""Host-wide single-session lock (S2 / v0.9.0-s2).

Firecracker requires cross-session host resources that do not serialize
themselves: a single NFS port (``DEFAULT_NFS_PORT``) bound by the
AgentFS server, iptables INPUT/FORWARD rules against the host gateway,
and the ip_forward gate. Two concurrent ``run_manifest`` invocations on
the same host would race on those, and the second session would either
fail halfway through setup (port already bound) or silently share the
first session's firewall posture.

The cure is a host-wide advisory lock held for the entire lifetime of a
session. We use ``fcntl.flock(LOCK_EX | LOCK_NB)`` on
``/var/run/saaf-shell/session.lock`` (path configurable). Two properties
matter:

1. **Crash-safe recovery is free.** ``flock`` is held by the file
   descriptor, not the on-disk inode, so the kernel drops the lock when
   the owning process exits — including on SIGKILL, OOM, or a crash
   inside Firecracker. No cleanup script, no stale-lock heuristic. A
   lockfile left over on disk after a crash is harmless; the next
   ``flock`` call will acquire it.

2. **We audit contention, not just acquisition.** Every denied request
   lands as ``session_lock_contended`` in the hash-chained audit log
   with the holder's PID, so operators can see when an automated
   scheduler or a second operator tried to start a session behind a
   live one. Acquisition and release also emit events so the lock's
   lifetime bounds the session in the log.

POSIX-only: on Windows ``fcntl`` is not importable and this module
degrades to a no-op so test collection works. The Firecracker runtime
is Linux-only anyway — Windows support is test-harness scope only.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

if sys.platform != "win32":
    import fcntl

if TYPE_CHECKING:
    from modules.audit.log import AuditLog


DEFAULT_SESSION_LOCK_PATH = Path("/var/run/saaf-shell/session.lock")


class SessionLockHeld(RuntimeError):
    """Raised when another process already holds the host-wide session lock."""

    def __init__(self, lock_path: Path, holder_pid: int | None):
        self.lock_path = lock_path
        self.holder_pid = holder_pid
        holder = f"pid={holder_pid}" if holder_pid is not None else "pid=unknown"
        super().__init__(
            f"another saaf-shell session holds {lock_path} ({holder})"
        )


def _read_holder_pid(lock_path: Path) -> int | None:
    """Best-effort read of the PID recorded by the current lock holder.

    Only called after ``LOCK_EX | LOCK_NB`` returns ``EWOULDBLOCK``, so
    the holder's process is alive and has already written its PID
    (we write + fsync before yielding). A race where the holder has
    acquired the lock but not yet written the PID returns ``None``;
    diagnostic-only, so ``None`` is acceptable.
    """
    try:
        text = lock_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        return int(text)
    except ValueError:
        return None


@contextmanager
def acquire_session_lock(
    lock_path: Path | str = DEFAULT_SESSION_LOCK_PATH,
    *,
    audit: AuditLog | None = None,
    session_id: str = "",
) -> Iterator[None]:
    """Take the host-wide session lock, or raise ``SessionLockHeld``.

    Non-blocking: the second caller fails fast with the live holder's
    PID rather than queueing. Queueing would let a scheduler starve the
    host with silent waiters; fail-fast forces explicit retry policy.

    On POSIX the lock is released when the file descriptor closes
    (context-manager exit, process death, SIGKILL). The on-disk file is
    not removed — leaving it in place avoids a TOCTOU where another
    process recreates it between our unlink and close. It is a tiny
    fixed-size file and its contents are overwritten on every acquire.
    """
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform != "win32":
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                holder_pid = _read_holder_pid(lock_path)
                if audit is not None:
                    audit.record(
                        "session_lock_contended",
                        session_id=session_id,
                        lock_path=str(lock_path),
                        holder_pid=holder_pid,
                    )
                raise SessionLockHeld(lock_path, holder_pid) from None

            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
            os.fsync(fd)

            if audit is not None:
                audit.record(
                    "session_lock_acquired",
                    session_id=session_id,
                    lock_path=str(lock_path),
                    pid=os.getpid(),
                )

            try:
                yield
            finally:
                if audit is not None:
                    audit.record(
                        "session_lock_released",
                        session_id=session_id,
                        lock_path=str(lock_path),
                        pid=os.getpid(),
                    )
        finally:
            os.close(fd)
    else:
        # Firecracker runtime is POSIX-only; on Windows we degrade to a
        # no-op so pytest collection and cross-platform dev work.
        yield
