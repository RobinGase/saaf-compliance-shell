"""Tests for the saaf-shell CLI entry point."""

from pathlib import Path

from cli import build_parser

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


class TestPhase2Commands:
    def test_run_executes_manifest(self, monkeypatch, capsys):
        parser = build_parser()
        args = parser.parse_args(["run", "--manifest", "dummy.yaml"])

        def fake_run_manifest(path: str):
            assert path == "dummy.yaml"
            return "session-001"

        monkeypatch.setattr("cli.run_manifest", fake_run_manifest)

        rc = args.func(args)

        assert rc == 0
        assert "session-001" in capsys.readouterr().out

    def test_diff_prints_agentfs_changes(self, monkeypatch, capsys):
        parser = build_parser()
        args = parser.parse_args(["diff", "--agent-id", "test-001"])

        monkeypatch.setattr(
            "cli.diff_session",
            lambda agent_id: ["M /audit_workspace/report.txt", "A /audit_workspace/notes.md"],
        )

        rc = args.func(args)

        assert rc == 0
        out = capsys.readouterr().out
        assert "report.txt" in out
        assert "notes.md" in out

    def test_sessions_lists_known_agentfs_sessions(self, monkeypatch, capsys):
        parser = build_parser()
        args = parser.parse_args(["sessions"])

        monkeypatch.setattr("cli.list_sessions", lambda: ["session-001", "session-002"])

        rc = args.func(args)

        assert rc == 0
        out = capsys.readouterr().out
        assert "session-001" in out
        assert "session-002" in out

    def test_test_runs_vm_probe_suite(self, monkeypatch, capsys):
        parser = build_parser()
        args = parser.parse_args(["test", "--manifest", "dummy.yaml", "--suite", "vm-probe"])

        monkeypatch.setattr(
            "cli.run_vm_probe",
            lambda manifest_path, overlay_dir, audit_log_path: {
                "session_id": "guest-probe-abc123",
                "diff": ["A f /audit_workspace/response.json"],
            },
        )

        rc = args.func(args)

        assert rc == 0
        assert "guest-probe-abc123" in capsys.readouterr().out

    def test_test_runs_guardrails_routing_suite(self, monkeypatch, capsys):
        parser = build_parser()
        args = parser.parse_args(["test", "--manifest", "dummy.yaml", "--suite", "guardrails-routing"])

        monkeypatch.setattr("cli.run_guardrails_routing_validation", lambda config_dir: {"router_hits": 1, "direct_hits": 1})

        rc = args.func(args)

        assert rc == 0
        out = capsys.readouterr().out
        assert "router_hits" in out
        assert "direct_hits" in out

    def test_test_runs_red_team_suite(self, monkeypatch, capsys):
        parser = build_parser()
        args = parser.parse_args(["test", "--manifest", "dummy.yaml", "--suite", "red-team"])

        monkeypatch.setattr("cli.run_red_team_suite", lambda cases_path, endpoint: {"total": 4, "passed": 4, "failed": 0})

        rc = args.func(args)

        assert rc == 0
        out = capsys.readouterr().out
        assert "'total': 4" in out or '"total": 4' in out

    def test_test_rejects_unknown_suite(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["test", "--manifest", "dummy.yaml", "--suite", "unknown-suite"])
        rc = args.func(args)
        assert rc == 1
