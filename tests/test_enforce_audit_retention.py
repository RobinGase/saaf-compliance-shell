"""Tests for scripts/enforce_audit_retention.py."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import enforce_audit_retention as retention  # noqa: E402


def _touch(path: Path, age_days: float) -> None:
    path.write_text("old archive\n", encoding="utf-8")
    mtime = time.time() - age_days * 86400
    os.utime(path, (mtime, mtime))


def test_prune_disabled_when_retention_zero(tmp_path: Path) -> None:
    archive = tmp_path / "audit.jsonl.2026-01-01"
    _touch(archive, age_days=365)

    pruned, errors = retention.prune(tmp_path, retention_seconds=0)

    assert (pruned, errors) == (0, 0)
    assert archive.exists()


def test_prune_removes_old_archives_only(tmp_path: Path) -> None:
    live = tmp_path / "audit.jsonl"
    live.write_text("live chain\n", encoding="utf-8")

    old_archive = tmp_path / "audit.jsonl.2026-01-01"
    fresh_archive = tmp_path / "audit.jsonl.2026-04-10"
    _touch(old_archive, age_days=120)
    _touch(fresh_archive, age_days=2)

    pruned, errors = retention.prune(tmp_path, retention_seconds=30 * 86400)

    assert (pruned, errors) == (1, 0)
    assert not old_archive.exists()
    assert fresh_archive.exists()
    assert live.exists(), "live audit.jsonl must never be pruned"


def test_prune_ignores_missing_log_dir(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    pruned, errors = retention.prune(missing, retention_seconds=86400)

    assert (pruned, errors) == (0, 0)


def test_retention_seconds_rejects_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAAF_AUDIT_RETENTION_DAYS", "-1")
    assert retention._retention_seconds() == -1


def test_retention_seconds_rejects_non_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAAF_AUDIT_RETENTION_DAYS", "not-a-number")
    assert retention._retention_seconds() == -1


def test_retention_seconds_defaults_to_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SAAF_AUDIT_RETENTION_DAYS", raising=False)
    assert retention._retention_seconds() == 0


def test_retention_seconds_converts_days(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAAF_AUDIT_RETENTION_DAYS", "7")
    assert retention._retention_seconds() == 7 * 86400
