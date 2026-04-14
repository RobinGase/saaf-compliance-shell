"""Tamper-evident audit log with SHA-256 hash chaining.

Produces JSONL records where each event is chained to the previous via
prev_hash / event_hash. A single-writer model with a monotonic sequence
counter ensures no parallel hash chain ambiguity.

Usage:
    log = AuditLog("/var/log/openshell/audit.jsonl")
    log.start_session(session_id="abc", policy_hash="sha256:...", manifest_hash="sha256:...")
    log.record("file_create", path="/audit_workspace/report.txt", sha256="sha256:...")
    log.end_session()
"""

import hashlib
import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

if sys.platform != "win32":
    import fcntl


GENESIS_PREV_HASH = "0" * 64


def _canonical_json(obj: dict) -> bytes:
    """Deterministic JSON serialization for hashing.

    Keys sorted alphabetically, no whitespace, UTF-8.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL audit log.

    Every append re-reads the tail of the log under a process-wide file lock
    so out-of-process writers (the privacy router) can interleave without
    breaking the chain. The threading lock still serializes callers inside
    one process before the file lock is taken.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._session_id: str | None = None

    def start_session(
        self,
        session_id: str,
        policy_hash: str,
        manifest_hash: str,
        vm_config: dict | None = None,
    ) -> dict:
        """Write a genesis record for a new session."""
        self._session_id = session_id
        return self._write_event(
            event_type="session_start",
            session_id=session_id,
            policy_hash=policy_hash,
            manifest_hash=manifest_hash,
            vm_config=vm_config or {},
        )

    def record(self, event_type: str, **fields) -> dict:
        """Write an audit event to the log."""
        return self._write_event(event_type=event_type, **fields)

    def end_session(self) -> dict:
        """Write a session_end record.

        ``event_count`` is the number of events whose ``session_id`` matches
        this session, read from the full log at close. That means it includes
        records written by out-of-process writers (the privacy router and the
        guardrails service), not just records from this ``AuditLog`` instance.
        The end record itself is included in the count.
        """
        session_id = self._session_id
        event_count = self._count_session_events(session_id) + 1
        event = self._write_event(
            event_type="session_end",
            session_id=session_id,
            event_count=event_count,
        )
        self._session_id = None
        return event

    def _count_session_events(self, session_id: str | None) -> int:
        """Return the number of events written since this session's genesis.

        Scans the log for the ``session_start`` record matching ``session_id``
        and counts every record from that point onward, inclusive. Individual
        event records (``file_create``, ``pii_redaction``, ``guardrails_*``)
        don't carry ``session_id``, so counting by start-position is the only
        way to include out-of-process writers (the privacy router and the
        guardrails service) in the total. Ignores lines that don't parse —
        those are crash-truncated tails that ``append_chained_event`` heals
        on the next write.
        """
        if session_id is None or not self._path.exists():
            return 0
        count = 0
        found_start = False
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not found_start:
                    if (
                        record.get("event_type") == "session_start"
                        and record.get("session_id") == session_id
                    ):
                        found_start = True
                        count = 1
                    continue
                count += 1
        return count

    def _write_event(self, **fields) -> dict:
        """Build, hash, and append a single event via the cross-process writer."""
        with self._lock:
            return append_chained_event(self._path, **fields)


def _read_chain_tail(log_path: Path) -> tuple[str | None, int, str, int | None]:
    """Scan the log forward and return (session_id, next_seq, last_hash, truncate_at).

    Used by out-of-process writers (the privacy router) to append records
    that link into the existing hash chain. If the log is absent or empty,
    returns (None, 0, GENESIS_PREV_HASH, None).

    ``truncate_at`` is the byte offset at which a crash-truncated tail
    begins — either a line that failed to parse or a line without a
    terminating newline. The caller should truncate the file to that
    offset before appending, otherwise the new event would be concatenated
    onto the partial record and permanently poison the chain.
    """
    if not log_path.exists():
        return None, 0, GENESIS_PREV_HASH, None

    session_id: str | None = None
    next_seq = 0
    last_hash = GENESIS_PREV_HASH
    truncate_at: int | None = None

    with open(log_path, "rb") as f:
        offset = 0
        for raw in f:
            line_start = offset
            offset += len(raw)

            if not raw.endswith(b"\n"):
                truncate_at = line_start
                break

            stripped = raw.strip()
            if not stripped:
                continue

            try:
                rec = json.loads(stripped.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                truncate_at = line_start
                break

            if rec.get("event_type") == "session_start":
                session_id = rec.get("session_id")
            seq = rec.get("seq")
            if isinstance(seq, int):
                next_seq = seq + 1
            event_hash = rec.get("event_hash")
            if isinstance(event_hash, str):
                last_hash = event_hash

    return session_id, next_seq, last_hash, truncate_at


def append_chained_event(log_path: str | Path, event_type: str, **fields) -> dict:
    """Append a hash-chained event from a process that does not own the AuditLog.

    Takes an exclusive file lock (fcntl on POSIX), re-reads the tail to
    determine the current chain state, then writes one record. Used by
    the privacy router so its route_decision events join the chain
    instead of sitting outside it.
    """
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(log_path, "a+", encoding="utf-8") as f:
        if sys.platform != "win32":
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            session_id, next_seq, prev_hash, truncate_at = _read_chain_tail(log_path)

            # Drop a crash-truncated tail so the new event lands on a clean
            # boundary. Without this, the next verify_log would still trip
            # on the partial line even though this append itself was clean.
            if truncate_at is not None:
                f.truncate(truncate_at)
                f.flush()

            # A new session resets the chain — matches verify_log behavior
            if event_type == "session_start":
                next_seq = 0
                prev_hash = GENESIS_PREV_HASH

            record: dict = {
                "seq": next_seq,
                "ts": datetime.now(UTC).isoformat(),
                "event_type": event_type,
            }
            if session_id is not None and "session_id" not in fields:
                record["session_id"] = session_id
            record.update(fields)
            record["prev_hash"] = prev_hash

            event_hash = _sha256(_canonical_json(record))
            record["event_hash"] = event_hash

            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
            f.write(line + "\n")
            f.flush()
            return record
        finally:
            if sys.platform != "win32":
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def verify_log(path: str | Path) -> tuple[bool, str]:
    """Verify the hash chain integrity of an audit log.

    Returns (valid, message). On failure, reports the first broken link.
    Handles multi-session logs (multiple genesis records).
    """
    path = Path(path)
    if not path.exists():
        return False, f"Log file not found: {path}"

    prev_hash = GENESIS_PREV_HASH
    count = 0

    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Partial write from crash — report as truncated, not tampered
                return False, f"Truncated record at line {line_num} (possible crash during write)"

            # New session resets the chain
            if record.get("event_type") == "session_start":
                prev_hash = GENESIS_PREV_HASH

            # Verify prev_hash links to previous event
            if record.get("prev_hash") != prev_hash:
                return (
                    False,
                    f"CHAIN BROKEN at seq {record.get('seq', '?')} (line {line_num}). "
                    f"Expected prev_hash {prev_hash[:16]}..., found {record.get('prev_hash', 'missing')[:16]}...",
                )

            # Recompute event_hash from record contents
            stored_hash = record.pop("event_hash", None)
            expected_hash = _sha256(_canonical_json(record))
            record["event_hash"] = stored_hash  # restore

            if stored_hash != expected_hash:
                return (
                    False,
                    f"HASH MISMATCH at seq {record.get('seq', '?')} (line {line_num}). "
                    f"Expected {expected_hash[:16]}..., found {(stored_hash or 'missing')[:16]}...",
                )

            prev_hash = stored_hash
            count += 1

    if count == 0:
        return False, "Log file is empty"

    return True, f"Verified {count} events. Chain intact."
