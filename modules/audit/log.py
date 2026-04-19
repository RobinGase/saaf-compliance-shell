"""Tamper-evident audit log with SHA-256 hash chaining.

Produces JSONL records where each event is chained to the previous via
prev_hash / event_hash. A single-writer model with a monotonic sequence
counter ensures no parallel hash chain ambiguity.

Concurrency model:
- ``AuditLog._lock`` (threading.Lock) serializes callers inside one
  process before they reach the file lock.
- ``fcntl.LOCK_EX`` inside ``append_chained_event`` serializes
  out-of-process writers (the privacy router and the guardrails
  service) against each other AND against any same-process thread
  that bypasses ``AuditLog`` and calls ``append_chained_event``
  directly. Do not remove the file lock on the assumption that the
  threading lock covers intra-process races — the standalone
  ``append_chained_event`` does not hold ``AuditLog._lock``.

Usage:
    log = AuditLog("/var/log/openshell/audit.jsonl")
    log.start_session(session_id="abc", policy_hash="sha256:...", manifest_hash="sha256:...")
    log.record("file_create", path="/audit_workspace/report.txt", sha256="sha256:...")
    log.end_session()
"""

import hashlib
import json
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

if sys.platform != "win32":
    import fcntl


GENESIS_PREV_HASH = "0" * 64

# S7: out-of-band anchor that ``verify_log`` cross-checks against the
# log's tail. Updated atomically alongside every successful append under
# the same file lock. Sidecar's value is NOT cryptographic — an attacker
# with write to the log usually has write here too — but it (a) catches
# accidental truncation, (b) raises attack cost (attacker must know to
# update it), and (c) gives operators a single small file to mirror
# externally (journald, remote log, WORM) for a real anchor.
HEAD_POINTER_SUFFIX = ".head"
HEAL_ACK_ENV = "SAAF_ACK_AUDIT_HEAL"


class AuditTamperDetected(RuntimeError):
    """Raised when the log tail disagrees with the head-pointer sidecar.

    Intentionally a ``RuntimeError`` subclass, not a silent log-and-heal:
    the only reason this fires in normal operation is that the log or the
    sidecar was edited out-of-band. Operators who know why (e.g. a
    manual log-rotation or a restored backup) set ``SAAF_ACK_AUDIT_HEAL=1``
    to proceed; that path still emits ``audit_tail_heal_acknowledged``
    into the chain so the override itself is audited.
    """


def _canonical_json(obj: dict) -> bytes:
    """Deterministic JSON serialization for hashing.

    Keys sorted alphabetically, no whitespace, UTF-8.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _iter_lines_reverse(path: Path, chunk_size: int = 8192):
    """Yield lines from ``path`` in reverse order without loading the whole file.

    The audit log is append-only JSONL, so reading backward lets
    ``_count_session_events`` stop as soon as it finds its
    ``session_start`` — cost proportional to the session, not the
    whole retention window. Yields text lines stripped of trailing
    newline; does not yield an empty trailing line if the file ends
    with a newline (the common case).

    Reads in fixed-size chunks from EOF toward BOF, carrying a
    ``leftover`` buffer for the line that straddles a chunk
    boundary. Binary-mode reads + UTF-8 decode with ``replace``
    keeps a corrupted tail from blowing up the whole scan.
    """
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        pos = fh.tell()
        leftover = b""
        while pos > 0:
            read_size = min(chunk_size, pos)
            pos -= read_size
            fh.seek(pos)
            chunk = fh.read(read_size) + leftover
            lines = chunk.split(b"\n")
            # The first element may be an incomplete line whose start
            # lies in the next (earlier) chunk — hold it as leftover.
            leftover = lines[0]
            # Yield the rest in reverse; the last element is the
            # trailing line (or empty if the chunk ended on \n).
            for line in reversed(lines[1:]):
                if line:
                    yield line.decode("utf-8", errors="replace")
        if leftover:
            yield leftover.decode("utf-8", errors="replace")


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
        """Return the number of events whose ``session_id`` matches this session.

        H6: scans the log *backward* from EOF, stopping at the
        ``session_start`` record for this session. That keeps the
        per-close cost proportional to the number of records *in
        this session*, not the whole retention window. A forward
        scan was fine at v0 retention but becomes a real hotspot at
        the 7-year retention the audit section targets.

        Every record written via ``append_chained_event`` carries
        the active session_id (propagated from the tail in
        ``_read_chain_tail``), so filtering by ``session_id``
        correctly counts events from every writer — the
        ``AuditLog`` instance itself, the privacy router, and the
        guardrails service — without double-counting when a second
        session interleaves on the same log. Lines that don't parse
        (crash-truncated tails that ``append_chained_event`` heals
        on the next write) are skipped.
        """
        if session_id is None or not self._path.exists():
            return 0
        count = 0
        for line in _iter_lines_reverse(self._path):
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("session_id") != session_id:
                # A different session's record (or an unattributed
                # preamble) interleaved in the log — skip, keep scanning
                # backward. We only stop at *this* session's start.
                continue
            count += 1
            if record.get("event_type") == "session_start":
                break
        return count

    def _write_event(self, **fields) -> dict:
        """Build, hash, and append a single event via the cross-process writer."""
        with self._lock:
            return append_chained_event(self._path, **fields)


def _read_chain_tail(
    log_path: Path,
) -> tuple[str | None, int, str, int | None, int]:
    """Scan the log forward and return tail state.

    Returns ``(session_id, next_seq, last_hash, truncate_at, record_count)``.
    ``record_count`` is the number of intact records seen before
    ``truncate_at`` (or total record count when the whole file parses).
    If the log is absent or empty, returns ``(None, 0, GENESIS_PREV_HASH,
    None, 0)``.

    ``truncate_at`` is the byte offset at which a crash-truncated tail
    begins — either a line that failed to parse or a line without a
    terminating newline. Whether the tail is healed or refused is the
    caller's decision; this function only reports the state.
    """
    if not log_path.exists():
        return None, 0, GENESIS_PREV_HASH, None, 0

    session_id: str | None = None
    next_seq = 0
    last_hash = GENESIS_PREV_HASH
    truncate_at: int | None = None
    record_count = 0

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
            elif rec.get("event_type") == "session_end":
                # RT-09: without this clear, a later writer that omits
                # ``session_id`` (e.g. a ``route_decision`` emitted by
                # the privacy router after the session closed) would
                # inherit the closed session's id via the propagation
                # block below and appear to belong to it.
                session_id = None
            seq = rec.get("seq")
            if isinstance(seq, int):
                next_seq = seq + 1
            event_hash = rec.get("event_hash")
            if isinstance(event_hash, str):
                last_hash = event_hash
            record_count += 1

    return session_id, next_seq, last_hash, truncate_at, record_count


def _head_pointer_path(log_path: Path) -> Path:
    """Return the sidecar path for ``log_path``.

    Alongside the log (same dir, same base name + ``.head``). Keeping it
    adjacent means operators who mirror ``/var/log/openshell/`` get both
    files with no extra configuration.
    """
    return log_path.with_name(log_path.name + HEAD_POINTER_SUFFIX)


def _read_head_pointer(log_path: Path) -> dict | None:
    """Load the head-pointer sidecar, or return ``None`` if absent/corrupt.

    A corrupt sidecar is treated as absent — the tamper check above will
    then fire against the log itself, surfacing the inconsistency. We do
    not raise here because a crash mid-``os.replace`` is recoverable and
    must not wedge the audit writer.
    """
    hp = _head_pointer_path(log_path)
    if not hp.exists():
        return None
    try:
        text = hp.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _write_head_pointer(
    log_path: Path,
    *,
    last_seq: int,
    last_event_hash: str,
    event_count: int,
) -> None:
    """Atomically replace the head-pointer sidecar.

    Write to a sibling ``.tmp`` and ``os.replace`` so a reader never sees
    a half-written pointer. ``os.replace`` is atomic on both POSIX and
    Windows; a crash between the log append and this replace leaves a
    stale-but-consistent pointer — the next successful append restores
    the invariant.
    """
    hp = _head_pointer_path(log_path)
    tmp = hp.with_name(hp.name + ".tmp")
    payload = {
        "last_seq": last_seq,
        "last_event_hash": last_event_hash,
        "event_count": event_count,
        "ts": datetime.now(UTC).isoformat(),
    }
    tmp.write_text(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(tmp, hp)


def _heal_ack_env() -> bool:
    """Return True when ``SAAF_ACK_AUDIT_HEAL`` is set to a truthy value.

    Same truth semantics as ``SAAF_ALLOW_IP_FORWARD`` — empty / "0" /
    "false" are false, anything else is true.
    """
    val = os.environ.get(HEAL_ACK_ENV)
    if val is None:
        return False
    return val.strip() not in ("", "0", "false", "False")


def _classify_tail(
    head: dict | None,
    next_seq: int,
    last_hash: str,
    truncate_at: int | None,
    record_count: int,
) -> tuple[str, str | None]:
    """Classify the tail relative to the head pointer.

    Returns ``(status, reason)`` where ``status`` is:

    - ``"clean"`` — tail is intact and matches head (or both absent).
      Normal append path, no heal needed.
    - ``"heal_legit"`` — truncate_at is set and the last intact record
      above it matches the head pointer. The malformed tail was an
      uncommitted write; safe to truncate and emit an audited heal event.
    - ``"tamper"`` — either the head says a newer/different record is
      the tip than the log shows, or the file was rolled back, or the
      malformed tail could not be matched to head. Refuse to append
      without ``SAAF_ACK_AUDIT_HEAL=1``.
    - ``"first_write"`` — no head pointer AND no log records. Legitimate
      first-ever append; initialise the sidecar.
    - ``"legacy"`` — no head pointer but log has records. Pre-S7 log;
      trust-on-first-write, initialise sidecar from current tail.
    """
    if head is None:
        if record_count == 0 and truncate_at is None:
            return "first_write", None
        if truncate_at is not None:
            # Pre-S7 log with a crash-truncated tail. We can't distinguish
            # legit crash from tamper without an anchor; conservative path
            # is to refuse unless the operator acks.
            return (
                "tamper",
                "legacy log with unhealed tail and no head pointer — set "
                f"{HEAL_ACK_ENV}=1 to heal after confirming the truncation "
                "is from a crash and not from tampering",
            )
        return "legacy", None

    expected_last_hash = head.get("last_event_hash")
    expected_last_seq = head.get("last_seq")
    expected_count = head.get("event_count")

    if truncate_at is None:
        # No partial tail. The last committed record must match head.
        if last_hash != expected_last_hash:
            return (
                "tamper",
                f"head says last_event_hash={str(expected_last_hash)[:16]}... "
                f"but log tail shows {last_hash[:16]}... (rollback or edit)",
            )
        if isinstance(expected_last_seq, int) and next_seq - 1 != expected_last_seq:
            return (
                "tamper",
                f"head says last_seq={expected_last_seq} but log tail "
                f"shows last_seq={next_seq - 1}",
            )
        if isinstance(expected_count, int) and record_count != expected_count:
            return (
                "tamper",
                f"head says event_count={expected_count} but log has "
                f"{record_count} intact records",
            )
        return "clean", None

    # truncate_at is not None: the last bytes of the file are a partial
    # or malformed record. Determine whether the intact prefix ends at
    # the head's last committed record.
    if last_hash == expected_last_hash:
        # The committed tail matches head; the malformed trailer is an
        # uncommitted write (writer died between flush and sidecar update,
        # OR this IS a tamper-append of garbage bytes — in both cases the
        # committed record is intact and the trailer is unrecoverable).
        return "heal_legit", None

    return (
        "tamper",
        f"crash-truncated tail above offset {truncate_at}: last intact "
        f"record_hash={last_hash[:16]}... does not match head "
        f"last_event_hash={str(expected_last_hash)[:16]}... (rollback-plus-"
        "corrupt-tail pattern)",
    )


def _build_and_write_record(
    f,
    *,
    event_type: str,
    session_id: str | None,
    next_seq: int,
    prev_hash: str,
    fields: dict,
) -> dict:
    """Shared record-construction + write path.

    Used for both the primary event and — when a heal is classified as
    legitimate — for the chained ``audit_tail_healed`` /
    ``audit_tail_heal_acknowledged`` marker event. Keeping the record
    shape identical (same hashing, same session-id propagation, same
    session_start chain-reset) means the heal event is indistinguishable
    from any other event to a downstream verifier.
    """
    if event_type == "session_start":
        # A new session resets the chain — matches verify_log behaviour.
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


def append_chained_event(log_path: str | Path, event_type: str, **fields) -> dict:
    """Append a hash-chained event from a process that does not own the AuditLog.

    Takes an exclusive file lock (fcntl on POSIX), re-reads the tail to
    determine the current chain state, then writes one record. Used by
    the privacy router so its route_decision events join the chain
    instead of sitting outside it.

    S7: also cross-checks the log's tail against the head-pointer sidecar
    and, depending on the classification, either proceeds cleanly, heals
    a legitimately-crash-truncated tail (emitting an audited
    ``audit_tail_healed`` record in the chain), or raises
    ``AuditTamperDetected`` to refuse the append. Operators who know why
    the divergence exists (backup restore, log rotation) set
    ``SAAF_ACK_AUDIT_HEAL=1``; that path emits
    ``audit_tail_heal_acknowledged`` into the chain so the override is
    itself audited.
    """
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(log_path, "a+", encoding="utf-8") as f:
        if sys.platform != "win32":
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            session_id, next_seq, prev_hash, truncate_at, record_count = (
                _read_chain_tail(log_path)
            )
            head = _read_head_pointer(log_path)
            status, reason = _classify_tail(
                head, next_seq, prev_hash, truncate_at, record_count
            )

            if status == "tamper":
                if not _heal_ack_env():
                    raise AuditTamperDetected(
                        f"audit log tail disagrees with head pointer: "
                        f"{reason}. Set {HEAL_ACK_ENV}=1 to override after "
                        "confirming the divergence is legitimate."
                    )
                # Acked override: truncate any malformed trailer, emit a
                # ``audit_tail_heal_acknowledged`` record so the override
                # itself is chained evidence, then fall through to the
                # primary event write.
                if truncate_at is not None:
                    f.truncate(truncate_at)
                    f.flush()
                ack_record = _build_and_write_record(
                    f,
                    event_type="audit_tail_heal_acknowledged",
                    session_id=session_id,
                    next_seq=next_seq,
                    prev_hash=prev_hash,
                    fields={"reason": reason or "", "truncate_at": truncate_at},
                )
                next_seq = ack_record["seq"] + 1
                prev_hash = ack_record["event_hash"]
                record_count += 1

            elif status == "heal_legit":
                # Truncate the unrecoverable trailer, emit a chained
                # ``audit_tail_healed`` record so the heal is itself
                # audited, then fall through to the primary write.
                assert truncate_at is not None  # narrow for type-checkers
                f.truncate(truncate_at)
                f.flush()
                heal_record = _build_and_write_record(
                    f,
                    event_type="audit_tail_healed",
                    session_id=session_id,
                    next_seq=next_seq,
                    prev_hash=prev_hash,
                    fields={"truncate_at": truncate_at},
                )
                next_seq = heal_record["seq"] + 1
                prev_hash = heal_record["event_hash"]
                record_count += 1

            # status == "clean" / "first_write" / "legacy" all proceed
            # straight to the primary append. "legacy" will initialise the
            # sidecar at the bottom of this call.

            record = _build_and_write_record(
                f,
                event_type=event_type,
                session_id=session_id,
                next_seq=next_seq,
                prev_hash=prev_hash,
                fields=fields,
            )
            _write_head_pointer(
                log_path,
                last_seq=record["seq"],
                last_event_hash=record["event_hash"],
                event_count=record_count + 1,
            )
            return record
        finally:
            if sys.platform != "win32":
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def verify_log(path: str | Path) -> tuple[bool, str]:
    """Verify the hash chain integrity of an audit log.

    Returns (valid, message). On failure, reports the first broken link.
    Handles multi-session logs (multiple genesis records).

    S7: when a head-pointer sidecar is present, cross-check that the
    log's final record matches the sidecar's ``last_event_hash`` and
    ``last_seq``, and that ``event_count`` agrees. This closes the
    rollback / suffix-deletion hole where a pruned tail still validates
    as an intact prefix. When the sidecar is absent (pre-S7 log, or
    removed), verification succeeds if the chain is intact but the
    result message flags the missing anchor.
    """
    path = Path(path)
    if not path.exists():
        return False, f"Log file not found: {path}"

    prev_hash = GENESIS_PREV_HASH
    count = 0
    last_seq: int | None = None
    last_hash: str | None = None

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

            # Recompute event_hash from record contents. Build a
            # throwaway dict without event_hash rather than pop-then-restore:
            # an exception in _canonical_json between pop and restore would
            # leave the record un-restored, and downstream code would then
            # see a record without its stored hash.
            stored_hash = record.get("event_hash")
            to_hash = {k: v for k, v in record.items() if k != "event_hash"}
            expected_hash = _sha256(_canonical_json(to_hash))

            if stored_hash != expected_hash:
                return (
                    False,
                    f"HASH MISMATCH at seq {record.get('seq', '?')} (line {line_num}). "
                    f"Expected {expected_hash[:16]}..., found {(stored_hash or 'missing')[:16]}...",
                )

            prev_hash = stored_hash
            raw_seq = record.get("seq")
            if isinstance(raw_seq, int):
                last_seq = raw_seq
            last_hash = stored_hash
            count += 1

    if count == 0:
        return False, "Log file is empty"

    head = _read_head_pointer(path)
    if head is None:
        return (
            True,
            f"Verified {count} events. Chain intact. "
            "WARNING: no head-pointer sidecar present — rollback of trailing "
            f"records cannot be detected. Expected at {_head_pointer_path(path)}.",
        )

    expected_last_hash = head.get("last_event_hash")
    expected_last_seq = head.get("last_seq")
    expected_count = head.get("event_count")

    if last_hash != expected_last_hash:
        return (
            False,
            f"TAMPER DETECTED: head pointer last_event_hash="
            f"{str(expected_last_hash)[:16]}... but log tail shows "
            f"{(last_hash or 'missing')[:16]}... (rollback of trailing events).",
        )
    if isinstance(expected_last_seq, int) and last_seq != expected_last_seq:
        return (
            False,
            f"TAMPER DETECTED: head pointer last_seq={expected_last_seq} but "
            f"log tail shows last_seq={last_seq}.",
        )
    if isinstance(expected_count, int) and count != expected_count:
        return (
            False,
            f"TAMPER DETECTED: head pointer event_count={expected_count} but "
            f"log contains {count} intact records.",
        )

    return True, f"Verified {count} events. Chain intact. Head pointer matches."
