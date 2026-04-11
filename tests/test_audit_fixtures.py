"""Tests that verify audit log fixtures with verify_log."""

from pathlib import Path

from modules.audit.log import verify_log

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestAuditFixtures:
    def test_valid_fixture_passes(self):
        valid, message = verify_log(FIXTURES_DIR / "audit_log_valid.jsonl")
        assert valid is True
        assert "4 events" in message

    def test_tampered_fixture_detected(self):
        valid, message = verify_log(FIXTURES_DIR / "audit_log_tampered.jsonl")
        assert valid is False
        assert "HASH MISMATCH" in message
        assert "seq 1" in message

    def test_chain_broken_fixture_detected(self):
        valid, message = verify_log(FIXTURES_DIR / "audit_log_chain_broken.jsonl")
        assert valid is False
        assert "CHAIN BROKEN" in message
        assert "seq 2" in message
