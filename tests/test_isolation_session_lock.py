"""Tests for the host-wide session lock (S2)."""

from __future__ import annotations

import json
import os
import sys
from multiprocessing import Process, Queue
from pathlib import Path

import pytest

from modules.audit.log import AuditLog
from modules.isolation.session_lock import (
    SessionLockHeld,
    acquire_session_lock,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="fcntl-based lock is POSIX-only; Windows path is a no-op",
)


def _read_events(audit_log: Path) -> list[dict]:
    if not audit_log.exists():
        return []
    return [json.loads(line) for line in audit_log.read_text().splitlines() if line]


def test_session_lock_acquire_release_happy(tmp_path: Path) -> None:
    lock_path = tmp_path / "session.lock"
    with acquire_session_lock(lock_path):
        assert lock_path.exists()
        assert lock_path.read_text().strip() == str(os.getpid())
    # Released: we can re-acquire immediately.
    with acquire_session_lock(lock_path):
        pass


def _hold_lock(lock_path: str, ready: Queue, done: Queue) -> None:
    with acquire_session_lock(Path(lock_path)):
        ready.put(os.getpid())
        done.get()


def test_session_lock_contention_raises_with_holder_pid(tmp_path: Path) -> None:
    lock_path = tmp_path / "session.lock"
    ready: Queue = Queue()
    done: Queue = Queue()
    holder = Process(target=_hold_lock, args=(str(lock_path), ready, done))
    holder.start()
    try:
        holder_pid = ready.get(timeout=10)
        with pytest.raises(SessionLockHeld) as exc, acquire_session_lock(lock_path):
            pass
        assert exc.value.holder_pid == holder_pid
        assert exc.value.lock_path == lock_path
    finally:
        done.put(True)
        holder.join(timeout=10)


def test_session_lock_emits_acquire_and_release_events(tmp_path: Path) -> None:
    lock_path = tmp_path / "session.lock"
    audit_log = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_log)

    with acquire_session_lock(lock_path, audit=audit, session_id="sess-abc"):
        pass

    events = _read_events(audit_log)
    types = [e["event_type"] for e in events]
    assert "session_lock_acquired" in types
    assert "session_lock_released" in types

    acquired = next(e for e in events if e["event_type"] == "session_lock_acquired")
    assert acquired["session_id"] == "sess-abc"
    assert acquired["pid"] == os.getpid()
    assert acquired["lock_path"] == str(lock_path)


def test_session_lock_contention_emits_audit_event(tmp_path: Path) -> None:
    lock_path = tmp_path / "session.lock"
    audit_log = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_log)

    ready: Queue = Queue()
    done: Queue = Queue()
    holder = Process(target=_hold_lock, args=(str(lock_path), ready, done))
    holder.start()
    try:
        holder_pid = ready.get(timeout=10)
        with pytest.raises(SessionLockHeld), acquire_session_lock(
            lock_path, audit=audit, session_id="sess-second"
        ):
            pass
    finally:
        done.put(True)
        holder.join(timeout=10)

    events = _read_events(audit_log)
    contended = [e for e in events if e["event_type"] == "session_lock_contended"]
    assert len(contended) == 1
    assert contended[0]["session_id"] == "sess-second"
    assert contended[0]["holder_pid"] == holder_pid
    assert contended[0]["lock_path"] == str(lock_path)
    # The failed acquirer must not have emitted acquired/released events.
    assert all(
        e["event_type"] not in {"session_lock_acquired", "session_lock_released"}
        or e.get("session_id") != "sess-second"
        for e in events
    )


def test_session_lock_released_on_exception(tmp_path: Path) -> None:
    lock_path = tmp_path / "session.lock"

    class Boom(RuntimeError):
        pass

    with pytest.raises(Boom), acquire_session_lock(lock_path):
        raise Boom("body failure should still release the lock")

    # Lock re-acquirable after an exception inside the context.
    with acquire_session_lock(lock_path):
        pass
