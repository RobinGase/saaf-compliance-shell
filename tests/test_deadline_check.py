"""Tests for the fabricated-incident-deadline compliance rail.

Real windows per framework:

    GDPR Art. 33        — 72h to supervisory authority
    NIS2 Art. 23        — 24h early warning, 72h incident,
                          1 month final report
    DORA Art. 19 + RTS  — 4h initial, 72h intermediate,
                          1 month final

The rail must catch obvious wrong-number claims ("NIS2 within 48
hours") while letting every statutory window pass, including
month-length paraphrases.
"""

from __future__ import annotations

import pytest

from modules.guardrails.deadline_rule import (
    deadline_report,
    find_deadline_citations,
)

# ---- Cases that MUST be flagged (wrong deadline) ---------------------------

FABRICATED_CASES = [
    # GDPR is 72h, not 24h.
    "GDPR requires notification within 24 hours of a personal data breach.",
    # GDPR Art. 33 alias, wrong number.
    "Under GDPR Article 33, the controller must notify within 96 hours.",
    # NIS2 doesn't have a 48h window.
    "NIS2 requires an early warning within 48 hours of awareness.",
    # DORA initial is 4h, not 12h.
    "DORA requires initial notification within 12 hours of classification.",
    # Dutch phrasing — AVG is the Dutch name for GDPR, binnen = within.
    "Op grond van AVG moet de verwerker binnen 24 uur melden.",
    # Paraphrased connective.
    "Under NIS2, covered entities must report no later than 36 hours.",
    # Days unit, wrong for GDPR (72h = 3 days, 4 days is not a window).
    "The GDPR notification obligation must be met within 4 days.",
    # "in N hours" variant.
    "DORA expects the initial report in 2 hours.",
]


@pytest.mark.parametrize("text", FABRICATED_CASES)
def test_fabricated_deadlines_are_flagged(text: str) -> None:
    findings = find_deadline_citations(text)
    assert findings, f"no deadline detected in: {text!r}"
    assert any(f.is_fabricated for f in findings), (
        f"no fabricated finding in: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (statutory windows) ------------------------------

VALID_CASES = [
    # GDPR canonical.
    "GDPR Article 33 requires notification within 72 hours of awareness.",
    # NIS2 early warning.
    "NIS2 requires an early warning within 24 hours of becoming aware.",
    # NIS2 incident notification.
    "Under NIS2, a full incident notification is required within 72 hours.",
    # NIS2 final report — month literal.
    "The NIS2 final report must be submitted within 1 month.",
    # NIS2 final report — 30 days phrased out.
    "NIS2 permits the final report within 30 days of the early warning.",
    # DORA initial.
    "DORA requires the initial notification within 4 hours of classification.",
    # DORA intermediate.
    "The intermediate DORA report is due within 72 hours.",
    # DORA final report — month tolerance (28 days).
    "The DORA final report is expected within 28 days of the incident.",
    # Dutch valid — AVG + 72 uur.
    "AVG vereist een melding binnen 72 uur na bewustwording.",
]


@pytest.mark.parametrize("text", VALID_CASES)
def test_valid_deadlines_pass(text: str) -> None:
    findings = find_deadline_citations(text)
    assert findings, f"no deadline detected in: {text!r}"
    assert all(not f.is_fabricated for f in findings), (
        f"false positive in: {text!r} → {findings!r}"
    )


# ---- Cases that MUST NOT trigger (no framework-linked deadline) ------------

NON_CITATION_CASES = [
    # Plain duration, no framework anchor nearby.
    "The meeting ran for 4 hours and then adjourned.",
    # Framework mention without a deadline clause.
    "The vendor is subject to GDPR, DORA, and NIS2.",
    # Duration far from any framework — outside the 200-char window.
    (
        "The vendor has been operating for 24 hours a day since 2019. "
        + ("x " * 120)
        + "GDPR is the relevant regulation."
    ),
    # Non-notification "within" usage.
    "Reviews are conducted within a 30-day period by the internal team.",
    # Unrelated compliance term without a framework.
    "The report is due within 72 hours per internal SLA.",
]


@pytest.mark.parametrize("text", NON_CITATION_CASES)
def test_non_citations_are_not_detected(text: str) -> None:
    findings = find_deadline_citations(text)
    assert all(not f.is_fabricated for f in findings), (
        f"spurious fabrication in: {text!r} → {findings!r}"
    )


# ---- Framework association -------------------------------------------------


def test_framework_is_identified_per_deadline() -> None:
    text = (
        "GDPR requires notification within 72 hours; NIS2 requires an early "
        "warning within 24 hours; DORA requires the initial report within 4 hours."
    )
    findings = find_deadline_citations(text)
    frameworks = {f.framework for f in findings}
    assert {"GDPR", "NIS2", "DORA"} <= frameworks
    assert all(not f.is_fabricated for f in findings)


def test_mixed_valid_and_fabricated() -> None:
    text = (
        "GDPR requires notification within 72 hours. DORA, by contrast, "
        "requires an initial report within 12 hours of classification."
    )
    findings = find_deadline_citations(text)
    assert len(findings) == 2
    good = [f for f in findings if not f.is_fabricated]
    bad = [f for f in findings if f.is_fabricated]
    assert len(good) == 1 and good[0].framework == "GDPR"
    assert len(bad) == 1 and bad[0].framework == "DORA"


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_fabrication() -> None:
    result = deadline_report(
        "GDPR requires notification within 24 hours of a breach."
    )
    assert result["has_fabricated_deadline"] is True
    assert result["fabricated_count"] == 1
    assert result["deadline_count"] == 1
    assert any("GDPR" in s for s in result["samples"])


def test_report_shape_for_clean() -> None:
    result = deadline_report(
        "GDPR Art. 33 requires notification within 72 hours."
    )
    assert result == {
        "has_fabricated_deadline": False,
        "deadline_count": 1,
        "fabricated_count": 0,
        "samples": [],
    }
