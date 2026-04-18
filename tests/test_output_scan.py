"""Tests for the shared bypass-path output-rail runner.

``scan_output`` runs every pure-Python rail module against assistant
text. It is invoked on the three bypass paths in
``modules/guardrails/service.py`` (oversized payload, salvage-from-
error, empty rails) where the Colang pipeline would otherwise not
touch the rails at all.

The review for v0.8.2 found that the newly-added deadline rail had
been wired into the Colang flow but NOT into this bypass runner —
so a fabricated-deadline response that reached a bypass path would
skip the rail entirely. This suite exists to keep that class of
regression from happening again as new rails land.
"""

from __future__ import annotations

from modules.guardrails.output_scan import _RAILS, scan_output


def test_rails_tuple_covers_every_rule_module() -> None:
    """Every ``*_report`` rail module must be listed in ``_RAILS``."""
    # Hard-coded against the expected set. Adding a new rail requires
    # (a) a new *_rule.py under modules/guardrails/, (b) wiring its
    # @action into guardrails/rails.co, and (c) extending _RAILS below
    # so the same rail fires on the three bypass paths.
    expected = {
        "unfounded_verdict",
        "cot_leakage",
        "fabricated_citation",
        "absolutist_claim",
        "stale_attestation",
        "jurisdiction_mismatch",
        "currency_mismatch",
        "fabricated_standards_version",
        "fabricated_cve",
        "fabricated_regulator",
        "fabricated_deadline",
        "fabricated_case_law",
    }
    actual = {name for name, _fn, _flag in _RAILS}
    assert actual == expected, (
        f"rail registry drift: missing={expected - actual!r}, "
        f"extra={actual - expected!r}"
    )


def test_deadline_rail_fires_on_bypass_path() -> None:
    """A fabricated-deadline payload must not pass the bypass scanner.

    Regression guard for the v0.8.2 review finding: the deadline
    rail was wired into Colang but not into ``scan_output``, so any
    bypass path (oversized, salvage, empty) would have returned the
    response unmodified.
    """
    text = "Under GDPR, the controller must notify within 24 hours of a breach."
    firings = scan_output(text)
    names = {f.name for f in firings}
    assert "fabricated_deadline" in names, (
        f"deadline rail did not fire on bypass scan: {firings!r}"
    )


def test_clean_text_produces_no_firings() -> None:
    """Ordinary audit text with no rail-triggering content returns []."""
    text = "The vendor provided an ISAE 3402 report dated 2025-Q3."
    firings = scan_output(text)
    assert firings == [], f"unexpected firings on clean text: {firings!r}"
