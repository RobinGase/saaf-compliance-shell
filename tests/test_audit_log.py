"""Tests for the tamper-evident audit log with hash chain verification."""

import json
from pathlib import Path

import pytest

from modules.audit.log import (
    GENESIS_PREV_HASH,
    HEAL_ACK_ENV,
    AuditLog,
    AuditTamperDetected,
    _head_pointer_path,
    append_chained_event,
    verify_log,
)


@pytest.fixture
def tmp_log(tmp_path) -> Path:
    return tmp_path / "audit.jsonl"


class TestAuditLog:
    def test_session_start_creates_genesis(self, tmp_log):
        log = AuditLog(tmp_log)
        event = log.start_session(
            session_id="test-001",
            policy_hash="sha256:abc",
            manifest_hash="sha256:def",
        )
        assert event["seq"] == 0
        assert event["event_type"] == "session_start"
        assert event["prev_hash"] == GENESIS_PREV_HASH
        assert "event_hash" in event

    def test_sequential_events(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="test-001", policy_hash="a", manifest_hash="b")
        e1 = log.record("file_create", path="/audit_workspace/test.txt")
        e2 = log.record("file_create", path="/audit_workspace/test2.txt")

        assert e1["seq"] == 1
        assert e2["seq"] == 2
        assert e2["prev_hash"] == e1["event_hash"]

    def test_session_end(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="test-001", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/test.txt")
        end = log.end_session()

        assert end["event_type"] == "session_end"
        assert end["event_count"] == 3  # genesis + 1 record + end itself

    def test_session_end_count_isolates_concurrent_sessions(self, tmp_log):
        """Two sessions interleaving on the same log must each report only
        their own events in ``event_count`` — the position-based counter this
        replaces double-counted cross-session writers.
        """
        a = AuditLog(tmp_log)
        a.start_session(session_id="sess-a", policy_hash="x", manifest_hash="y")
        a.record("vm_exit", exit_code=0)

        b = AuditLog(tmp_log)
        b.start_session(session_id="sess-b", policy_hash="x", manifest_hash="y")
        b.record("vm_exit", exit_code=0)

        end_a = a.end_session()
        end_b = b.end_session()

        assert end_a["event_count"] == 3  # start + vm_exit + end for sess-a
        assert end_b["event_count"] == 3  # start + vm_exit + end for sess-b

    def test_session_end_count_with_large_prior_history(self, tmp_log):
        """H6: session_end must count only this session's events, even when
        the audit log already carries a large volume of records from earlier
        sessions. This is the scaling regression — prior implementation was
        O(whole log) on every close."""
        # Seed ~500 events across prior sessions.
        for i in range(5):
            prior = AuditLog(tmp_log)
            prior.start_session(session_id=f"prior-{i}", policy_hash="x", manifest_hash="y")
            for _ in range(98):
                prior.record("noise", kind="filler")
            prior.end_session()

        # This session is tiny.
        current = AuditLog(tmp_log)
        current.start_session(session_id="current", policy_hash="x", manifest_hash="y")
        current.record("vm_exit", exit_code=0)
        end = current.end_session()

        # start + vm_exit + end = 3
        assert end["event_count"] == 3

    def test_file_written_as_jsonl(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="test-001", policy_hash="a", manifest_hash="b")
        log.record("network_connect", host="172.16.0.1", port=8088, decision="allow")
        log.end_session()

        lines = tmp_log.read_text().strip().split("\n")
        assert len(lines) == 3

        for line in lines:
            record = json.loads(line)
            assert "seq" in record
            assert "ts" in record
            assert "event_hash" in record
            assert "prev_hash" in record


class TestVerifyLog:
    def test_valid_chain(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="test-001", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/report.pdf", sha256="sha256:123")
        log.record("pii_redaction", entity_count=2, entities_found=["PERSON", "BSN_NL"])
        log.record("route_decision", target="local_nim", model="nemotron-3-8b-instruct")
        log.end_session()

        valid, message = verify_log(tmp_log)
        assert valid is True
        assert "5 events" in message
        assert "Chain intact" in message

    def test_tampered_record_detected(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="test-001", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/test.txt")
        log.end_session()

        # Tamper with the second line
        lines = tmp_log.read_text().strip().split("\n")
        record = json.loads(lines[1])
        record["path"] = "/audit_workspace/TAMPERED.txt"
        lines[1] = json.dumps(record, separators=(",", ":"))
        tmp_log.write_text("\n".join(lines) + "\n")

        valid, message = verify_log(tmp_log)
        assert valid is False
        assert "HASH MISMATCH" in message

    def test_broken_chain_detected(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="test-001", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/test.txt")
        log.end_session()

        # Break the chain by modifying prev_hash
        lines = tmp_log.read_text().strip().split("\n")
        record = json.loads(lines[2])
        record["prev_hash"] = "0" * 64  # wrong prev_hash
        lines[2] = json.dumps(record, separators=(",", ":"))
        tmp_log.write_text("\n".join(lines) + "\n")

        valid, message = verify_log(tmp_log)
        assert valid is False
        assert "CHAIN BROKEN" in message

    def test_multi_session_log(self, tmp_log):
        log = AuditLog(tmp_log)

        # Session 1
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/s1.txt")
        log.end_session()

        # Session 2 — chain resets at genesis
        log.start_session(session_id="s2", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/s2.txt")
        log.end_session()

        valid, message = verify_log(tmp_log)
        assert valid is True
        assert "6 events" in message

    def test_truncated_record_detected(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="test-001", policy_hash="a", manifest_hash="b")

        # Simulate crash: append a partial JSON line
        with open(tmp_log, "a") as f:
            f.write('{"seq":1,"ts":"2026-04-11T10:00:00","event_type":"file_cr\n')

        valid, message = verify_log(tmp_log)
        assert valid is False
        assert "Truncated" in message

    def test_empty_log(self, tmp_log):
        tmp_log.write_text("")
        valid, message = verify_log(tmp_log)
        assert valid is False
        assert "empty" in message

    def test_nonexistent_log(self):
        valid, message = verify_log("/nonexistent/audit.jsonl")
        assert valid is False
        assert "not found" in message


class TestAppendChainedEvent:
    """append_chained_event lets a second process join the hash chain."""

    def test_router_event_extends_chain(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/x.txt")

        # Simulate the router writing from its own process
        appended = append_chained_event(
            tmp_log,
            "route_decision",
            target="local_nim",
            model="nemotron-nano:8b",
            latency_ms=12.3,
        )

        log.record("file_create", path="/audit_workspace/y.txt")
        log.end_session()

        # Verify the whole chain — including the router's event
        valid, message = verify_log(tmp_log)
        assert valid is True, message

        # Router event carries the session context and correct seq
        assert appended["event_type"] == "route_decision"
        assert appended["session_id"] == "s1"
        assert appended["seq"] == 2

    def test_appends_to_empty_log_with_genesis_prev(self, tmp_log):
        # No session in progress — still produces a well-formed record
        rec = append_chained_event(tmp_log, "route_decision", target="x", model="m")
        assert rec["seq"] == 0
        assert rec["prev_hash"] == GENESIS_PREV_HASH
        assert "event_hash" in rec

    def test_heals_partial_json_tail_from_crash(self, tmp_log):
        """S7: a crash-truncated trailing line is discarded and the heal
        is itself chained into the log as ``audit_tail_healed``.

        Pre-S7 behaviour was to silently truncate. That path let an
        attacker who corrupted the last record erase it by triggering
        any subsequent append (RT-03). The S7 path only classifies the
        heal as legitimate when the last intact record matches the head
        pointer, and emits an audited heal record so the event is never
        lost silently.
        """
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        last_good = log.record("file_create", path="/audit_workspace/x.txt")

        with open(tmp_log, "a", encoding="utf-8") as f:
            f.write('{"seq":99,"event_type":"file_cre\n')

        appended = append_chained_event(
            tmp_log, "route_decision", target="local_nim", model="m"
        )

        # Chain: last_good → audit_tail_healed → route_decision.
        # The appended event's prev_hash is NOT last_good's event_hash
        # any more; it is the heal record's event_hash, keeping the
        # heal itself auditable.
        assert appended["seq"] == last_good["seq"] + 2
        assert appended["prev_hash"] != last_good["event_hash"]

        with open(tmp_log, encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        heal = next(r for r in records if r["event_type"] == "audit_tail_healed")
        assert heal["prev_hash"] == last_good["event_hash"]
        assert heal["seq"] == last_good["seq"] + 1
        assert appended["prev_hash"] == heal["event_hash"]

        valid, message = verify_log(tmp_log)
        assert valid is True, message

    def test_heals_missing_trailing_newline(self, tmp_log):
        """S7: a record without a terminating newline triggers the same
        audited heal path as a malformed JSON tail.
        """
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        last_good = log.record("file_create", path="/audit_workspace/x.txt")

        with open(tmp_log, "a", encoding="utf-8") as f:
            f.write('{"seq":50,"event_type":"noop"}')

        appended = append_chained_event(
            tmp_log, "route_decision", target="local_nim", model="m"
        )

        assert appended["seq"] == last_good["seq"] + 2

        with open(tmp_log, encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        heal = next(r for r in records if r["event_type"] == "audit_tail_healed")
        assert heal["prev_hash"] == last_good["event_hash"]
        assert appended["prev_hash"] == heal["event_hash"]

        valid, message = verify_log(tmp_log)
        assert valid is True, message

    def test_post_session_event_does_not_inherit_closed_session_id(self, tmp_log):
        """RT-09: after ``session_end`` the tail scanner must forget the
        session id. A ``route_decision`` written later (by the privacy
        router, for instance) that omits ``session_id`` must not appear
        to belong to the just-closed session.
        """
        log = AuditLog(tmp_log)
        log.start_session(session_id="s-closed", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/x.txt")
        log.end_session()

        # Router emits an event without explicit session_id after close.
        appended = append_chained_event(
            tmp_log, "route_decision", target="local_nim", model="m"
        )
        assert "session_id" not in appended

        valid, message = verify_log(tmp_log)
        assert valid is True, message

    def test_new_session_event_ids_do_not_bleed_into_next_session(self, tmp_log):
        """RT-09 companion: a second session's events must carry the new
        session_id, not the prior one. Guards the normal multi-session case
        where the tail-scanner previously would have kept propagating the
        first session's id through the entire file.
        """
        log_a = AuditLog(tmp_log)
        log_a.start_session(session_id="s-a", policy_hash="a", manifest_hash="b")
        log_a.record("file_create", path="/audit_workspace/x.txt")
        log_a.end_session()

        # Between sessions: a router event with no explicit session_id
        between = append_chained_event(tmp_log, "route_decision", target="t", model="m")
        assert "session_id" not in between

        log_b = AuditLog(tmp_log)
        log_b.start_session(session_id="s-b", policy_hash="a", manifest_hash="b")
        in_b = append_chained_event(tmp_log, "route_decision", target="t", model="m")
        assert in_b["session_id"] == "s-b"

        log_b.end_session()
        valid, message = verify_log(tmp_log)
        assert valid is True, message

    def test_interleaved_writers_keep_chain(self, tmp_log):
        """AuditLog and append_chained_event must interleave without breaking the chain.

        Models the production topology: the saaf-shell runtime owns an AuditLog
        instance, while the privacy router is a separate systemd service that
        calls append_chained_event for its route_decision events.
        """
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/a.txt")
        append_chained_event(tmp_log, "route_decision", target="t", model="m")
        log.record("file_create", path="/audit_workspace/b.txt")
        append_chained_event(tmp_log, "route_decision", target="t", model="m")
        log.end_session()

        valid, message = verify_log(tmp_log)
        assert valid is True, message


class TestHeadPointerAndTamper:
    """S7 — head-pointer sidecar + discriminating heal.

    RT-02 closure: detect rollback of trailing records even though the
    remaining prefix still hash-validates.
    RT-03 closure: distinguish legit crash-heal from tamper-erasure, and
    make the heal itself chained evidence instead of a silent truncate.
    """

    def test_head_pointer_written_on_every_append(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/x.txt")
        end = log.end_session()

        hp_path = _head_pointer_path(tmp_log)
        assert hp_path.exists()
        head = json.loads(hp_path.read_text(encoding="utf-8"))
        assert head["last_event_hash"] == end["event_hash"]
        assert head["last_seq"] == end["seq"]
        assert head["event_count"] == 3  # start + record + end

    def test_verify_with_matching_head_reports_strong(self, tmp_log):
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/x.txt")
        log.end_session()

        valid, message = verify_log(tmp_log)
        assert valid is True
        assert "Head pointer matches" in message

    def test_verify_detects_trailing_record_rollback(self, tmp_log):
        """RT-02: truncate the last two records — chain still valid on
        the prefix, but the head pointer disagrees with the new tail."""
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/a.txt")
        log.record("file_create", path="/audit_workspace/b.txt")
        end = log.end_session()

        # Snapshot head pointer (attacker doesn't know to edit it).
        hp_path = _head_pointer_path(tmp_log)
        head_before = json.loads(hp_path.read_text(encoding="utf-8"))
        assert head_before["last_event_hash"] == end["event_hash"]

        # Attacker deletes the last two records: the file_create at seq=2
        # and the session_end at seq=3. The remaining chain (genesis +
        # seq=1) is still internally consistent.
        with open(tmp_log, encoding="utf-8") as f:
            lines = [line for line in f if line.strip()]
        with open(tmp_log, "w", encoding="utf-8") as f:
            f.writelines(lines[:2])

        valid, message = verify_log(tmp_log)
        assert valid is False
        assert "TAMPER DETECTED" in message

    def test_verify_detects_last_record_rollback(self, tmp_log):
        """Deleting only the final record must also be caught."""
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/a.txt")
        log.end_session()

        with open(tmp_log, encoding="utf-8") as f:
            lines = [line for line in f if line.strip()]
        with open(tmp_log, "w", encoding="utf-8") as f:
            f.writelines(lines[:-1])

        valid, message = verify_log(tmp_log)
        assert valid is False
        assert "TAMPER DETECTED" in message

    def test_verify_without_head_pointer_warns_but_passes(self, tmp_log):
        """A log without a sidecar (pre-S7 or deleted) verifies but flags
        the missing anchor — operators can still manually cross-check."""
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/x.txt")
        log.end_session()

        _head_pointer_path(tmp_log).unlink()

        valid, message = verify_log(tmp_log)
        assert valid is True
        assert "WARNING" in message
        assert "no head-pointer sidecar" in message

    def test_append_refuses_on_tampered_tail(self, tmp_log, monkeypatch):
        """RT-03: an attacker corrupts the last record (a valid-looking
        record gets its final byte garbled) and then a legit writer
        fires. Without the head pointer the old code would have
        truncated the tampered record silently. With S7 the head
        pointer's last_event_hash doesn't match the intact prefix's
        last hash, so the append refuses."""
        monkeypatch.delenv(HEAL_ACK_ENV, raising=False)

        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/a.txt")
        log.record("file_create", path="/audit_workspace/b.txt")

        # Corrupt the final record's trailing newline → now
        # _read_chain_tail sees truncate_at pointing at it, with the
        # last intact record being the *second-to-last* line. Head
        # still says the last record is the final one.
        raw = tmp_log.read_bytes()
        # Strip the last newline so the final line is "unterminated".
        assert raw.endswith(b"\n")
        tmp_log.write_bytes(raw[:-1] + b"X")

        with pytest.raises(AuditTamperDetected) as exc:
            append_chained_event(
                tmp_log, "route_decision", target="t", model="m"
            )
        assert "head pointer" in str(exc.value).lower()

    def test_heal_ack_env_allows_override_and_audits_override(
        self, tmp_log, monkeypatch
    ):
        """Operator explicitly acks a divergence (e.g. restored from
        backup). The override path emits an
        ``audit_tail_heal_acknowledged`` record into the chain so the
        override itself is auditable."""
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/a.txt")
        log.record("file_create", path="/audit_workspace/b.txt")

        raw = tmp_log.read_bytes()
        tmp_log.write_bytes(raw[:-1] + b"X")

        monkeypatch.setenv(HEAL_ACK_ENV, "1")
        appended = append_chained_event(
            tmp_log, "route_decision", target="t", model="m"
        )

        with open(tmp_log, encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        event_types = [r["event_type"] for r in records]
        assert "audit_tail_heal_acknowledged" in event_types
        # The route_decision is the last event and verification passes.
        assert records[-1] == appended
        valid, message = verify_log(tmp_log)
        assert valid is True, message

    def test_legacy_log_without_head_pointer_initialises_on_next_append(
        self, tmp_log
    ):
        """A log written by a pre-S7 build has no sidecar. The first S7
        append must not refuse; it initialises the sidecar and emits
        normally."""
        # Simulate a pre-S7 log by writing records, then deleting the
        # sidecar.
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/x.txt")
        _head_pointer_path(tmp_log).unlink()

        appended = append_chained_event(
            tmp_log, "route_decision", target="t", model="m"
        )
        assert appended["event_type"] == "route_decision"

        hp_path = _head_pointer_path(tmp_log)
        assert hp_path.exists()
        head = json.loads(hp_path.read_text(encoding="utf-8"))
        assert head["last_event_hash"] == appended["event_hash"]

        valid, message = verify_log(tmp_log)
        assert valid is True, message

    def test_legacy_log_with_partial_tail_refuses_without_ack(
        self, tmp_log, monkeypatch
    ):
        """A pre-S7 log that also has a partial tail is ambiguous — we
        can't tell crash from tamper without an anchor. Refuse unless
        ack. This is the conservative migration path."""
        monkeypatch.delenv(HEAL_ACK_ENV, raising=False)

        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        log.record("file_create", path="/audit_workspace/x.txt")
        _head_pointer_path(tmp_log).unlink()

        # Inject a partial tail.
        with open(tmp_log, "a", encoding="utf-8") as f:
            f.write('{"seq":99,"event_type":"partial')

        with pytest.raises(AuditTamperDetected):
            append_chained_event(
                tmp_log, "route_decision", target="t", model="m"
            )
