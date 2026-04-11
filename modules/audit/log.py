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
import threading
from datetime import datetime, timezone
from pathlib import Path


GENESIS_PREV_HASH = "0" * 64


def _canonical_json(obj: dict) -> bytes:
    """Deterministic JSON serialization for hashing.

    Keys sorted alphabetically, no whitespace, UTF-8.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_PREV_HASH
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
        self._seq = 0
        self._prev_hash = GENESIS_PREV_HASH

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
        """Write a session_end record with final chain state."""
        event = self._write_event(
            event_type="session_end",
            session_id=self._session_id,
            event_count=self._seq + 1,  # include the end event itself
        )
        self._session_id = None
        return event

    def _write_event(self, **fields) -> dict:
        """Build, hash, and append a single event."""
        with self._lock:
            record = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                **fields,
                "prev_hash": self._prev_hash,
            }

            # Hash the record without event_hash (it's computed from the rest)
            event_hash = _sha256(_canonical_json(record))
            record["event_hash"] = event_hash

            # Append to file
            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

            # Advance chain
            self._prev_hash = event_hash
            self._seq += 1

            return record


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

    with open(path, "r", encoding="utf-8") as f:
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
