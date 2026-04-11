"""Tests for the saaf-shell CLI entry point."""

from pathlib import Path

import pytest

from cli import build_parser, cmd_validate, cmd_verify_log

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestValidateCommand:
    def test_valid_manifest(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["validate", "--manifest", str(FIXTURES_DIR / "manifest_valid.yaml")])
        rc = args.func(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "OK" in out
        assert "vendor-guard" in out

    def test_invalid_manifest(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["validate", "--manifest", str(FIXTURES_DIR / "manifest_invalid.yaml")])
        rc = args.func(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "INVALID" in out
        assert "error" in out

    def test_nonexistent_manifest(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["validate", "--manifest", "/nonexistent/manifest.yaml"])
        rc = args.func(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "INVALID" in out


class TestVerifyLogCommand:
    def test_valid_log(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["verify-log", "--log", str(FIXTURES_DIR / "audit_log_valid.jsonl")])
        rc = args.func(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "OK" in out
        assert "4 events" in out

    def test_tampered_log(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["verify-log", "--log", str(FIXTURES_DIR / "audit_log_tampered.jsonl")])
        rc = args.func(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "FAIL" in out
        assert "HASH MISMATCH" in out

    def test_nonexistent_log(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["verify-log", "--log", "/nonexistent/audit.jsonl"])
        rc = args.func(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "FAIL" in out


class TestPhase2Stubs:
    def test_run_not_implemented(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["run", "--manifest", "dummy.yaml"])
        rc = args.func(args)
        assert rc == 2
        assert "Phase 2" in capsys.readouterr().out

    def test_diff_not_implemented(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["diff", "--agent-id", "test-001"])
        rc = args.func(args)
        assert rc == 2

    def test_sessions_not_implemented(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["sessions"])
        rc = args.func(args)
        assert rc == 2

    def test_test_not_implemented(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["test", "--manifest", "dummy.yaml", "--suite", "red-team"])
        rc = args.func(args)
        assert rc == 2
