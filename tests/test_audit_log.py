"""Tests for the tamper-evident audit log with hash chain verification."""

import json
from pathlib import Path

import pytest

from modules.audit.log import (
    GENESIS_PREV_HASH,
    AuditLog,
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
        """A crash-truncated trailing line must be discarded before the next append.

        Otherwise the new event is concatenated onto the partial record and
        every subsequent verify_log stays broken. The fix keeps the chain
        linked from the last intact event.
        """
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        last_good = log.record("file_create", path="/audit_workspace/x.txt")

        with open(tmp_log, "a", encoding="utf-8") as f:
            f.write('{"seq":99,"event_type":"file_cre\n')

        appended = append_chained_event(
            tmp_log, "route_decision", target="local_nim", model="m"
        )

        assert appended["prev_hash"] == last_good["event_hash"]
        assert appended["seq"] == last_good["seq"] + 1

        valid, message = verify_log(tmp_log)
        assert valid is True, message

    def test_heals_missing_trailing_newline(self, tmp_log):
        """A record without a terminating newline is treated as partial.

        Parseable JSON on its own line but without `\\n` still signals
        "write may not have been flushed." Safer to discard it than to
        let the next append concatenate onto it and break the chain.
        """
        log = AuditLog(tmp_log)
        log.start_session(session_id="s1", policy_hash="a", manifest_hash="b")
        last_good = log.record("file_create", path="/audit_workspace/x.txt")

        with open(tmp_log, "a", encoding="utf-8") as f:
            f.write('{"seq":50,"event_type":"noop"}')

        appended = append_chained_event(
            tmp_log, "route_decision", target="local_nim", model="m"
        )

        assert appended["prev_hash"] == last_good["event_hash"]
        assert appended["seq"] == last_good["seq"] + 1

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
