"""Adversarial-paraphrase harness (S3 / v0.9.0-s3).

Per-rail unit tests (``tests/test_*_check.py``) exercise each rail's
regex logic exhaustively. This harness is different: it is a flat,
cross-rail drift detector. One JSON file
(``tests/harness/rail_paraphrases_baseline.json``) fixes the expected
flag state of every rail against a small set of adversarial
paraphrases. A refactor that silently changes rail behavior makes the
harness fail even if the rail's own tests still pass — e.g. a regex
tweak that accidentally narrows deadline-rail coverage, or a citation
rail edit that starts firing on legitimate article numbers.

How to extend: add a paraphrase under the matching rail with
``should_flag`` set to the **current** behavior (run the suite and
record what happens), then commit. The baseline is the record of
"today's behavior"; diverging from it deliberately means updating the
baseline in the same commit that changes the rail.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules.guardrails.output_scan import _RAILS

_BASELINE_PATH = Path(__file__).parent / "harness" / "rail_paraphrases_baseline.json"
_RAIL_BY_NAME = {name: (report_fn, flag_key) for name, report_fn, flag_key in _RAILS}


def _load_cases() -> list[tuple[str, str, bool, str]]:
    data = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    cases: list[tuple[str, str, bool, str]] = []
    for rail_name, entries in data.items():
        if rail_name.startswith("_"):
            continue
        assert rail_name in _RAIL_BY_NAME, (
            f"Baseline references unknown rail {rail_name!r}; "
            f"known rails: {sorted(_RAIL_BY_NAME)}"
        )
        for entry in entries:
            cases.append(
                (
                    rail_name,
                    entry["text"],
                    bool(entry["should_flag"]),
                    entry.get("note", ""),
                )
            )
    return cases


_CASES = _load_cases()


def test_harness_covers_every_rail() -> None:
    """Every rail in the registry must have at least one baseline entry.

    Adding a rail to ``_RAILS`` without adding a paraphrase would let
    the new rail drift unchecked through this harness.
    """
    covered = {case[0] for case in _CASES}
    missing = sorted(set(_RAIL_BY_NAME) - covered)
    assert not missing, f"rails without paraphrase coverage: {missing}"


@pytest.mark.parametrize(
    ("rail_name", "text", "should_flag", "note"),
    _CASES,
    ids=[f"{case[0]}::{case[3] or case[1][:40]}" for case in _CASES],
)
def test_rail_paraphrase_matches_baseline(
    rail_name: str, text: str, should_flag: bool, note: str
) -> None:
    report_fn, flag_key = _RAIL_BY_NAME[rail_name]
    report = report_fn(text)
    actual = bool(report.get(flag_key))
    assert actual is should_flag, (
        f"{rail_name} drift: expected should_flag={should_flag} "
        f"for paraphrase {text!r} ({note or 'no note'}), got {actual}. "
        f"If the new behavior is intentional, update "
        f"{_BASELINE_PATH.name} in the same commit."
    )
