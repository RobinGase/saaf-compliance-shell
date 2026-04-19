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


# ---- Trigger-term guard (P2-2) ---------------------------------------------
# A deadline clause without a notification trigger word is not a
# notification deadline. GDPR Art. 12 DSAR response windows,
# retention periods, SLAs, and generic durations must not fire the
# rail even when a framework is named in the same sentence.


NON_NOTIFICATION_CONTEXT_CASES = [
    # GDPR Art. 12 — data-subject access request response: 1 month.
    # Framework + duration in the same sentence, but "response to a
    # request" is not a breach/incident notification.
    "Under GDPR, the controller must respond to a data-subject access "
    "request within 1 month of receipt.",
    # Retention period — same pattern, different clock.
    "Per GDPR, personal data may be retained within 6 months of "
    "collection for the stated purpose.",
    # DORA contractual clock that is not an incident report.
    "DORA registers must be updated within 30 days of a contractual change.",
    # Paraphrased form without a trigger.
    "The GDPR-covered entity has 2 days to review its records.",
]


@pytest.mark.parametrize("text", NON_NOTIFICATION_CONTEXT_CASES)
def test_non_notification_contexts_not_flagged(text: str) -> None:
    findings = find_deadline_citations(text)
    assert all(not f.is_fabricated for f in findings), (
        f"spurious notification-deadline fabrication in: {text!r} → {findings!r}"
    )


# ---- AVG case-sensitivity (P2-5) -------------------------------------------
# "AVG" is the Dutch name for GDPR and must match. English "avg"
# (shorthand for "average") must NOT match. The alias is compiled
# with an inline case-sensitivity override.


def test_avg_dutch_matches_when_capitalised() -> None:
    text = "AVG vereist een melding binnen 24 uur na bewustwording."
    findings = find_deadline_citations(text)
    assert findings and findings[0].framework == "GDPR"
    assert findings[0].is_fabricated  # 24h is not a GDPR window


def test_avg_english_lowercase_does_not_match() -> None:
    text = (
        "The avg data-subject request completed within 24 hours "
        "per our SLA and operational metrics."
    )
    findings = find_deadline_citations(text)
    assert findings == [], (
        f"lowercase 'avg' (English) should not anchor the rail: {findings!r}"
    )


# ---- Multi-framework attribution (P2-3) ------------------------------------
# A deadline clause that follows a conjunction-joined alias list
# ("GDPR and NIS2", "NIS2/DORA") should be evaluated against *every*
# attributed framework — the sentence asserts the window applies to
# both, so the rail must catch the one where it doesn't.


def test_multi_framework_and_flags_fabrication_regardless_of_order() -> None:
    forward = "Under GDPR and NIS2, the controller must notify within 24 hours."
    reverse = "Under NIS2 and GDPR, the controller must notify within 24 hours."
    for text in (forward, reverse):
        findings = find_deadline_citations(text)
        frameworks = {f.framework for f in findings}
        assert "GDPR" in frameworks, f"GDPR missing in: {text!r} → {findings!r}"
        assert any(
            f.framework == "GDPR" and f.is_fabricated for f in findings
        ), f"GDPR not flagged in: {text!r} → {findings!r}"


def test_multi_framework_slash_join() -> None:
    text = "NIS2/DORA both require notification within 12 hours."
    findings = find_deadline_citations(text)
    frameworks = {f.framework for f in findings}
    assert {"NIS2", "DORA"} <= frameworks
    assert all(f.is_fabricated for f in findings)


def test_independent_framework_mentions_do_not_chain() -> None:
    """A prior-sentence framework name is not a conjunct partner."""
    text = (
        "GDPR is referenced throughout. NIS2 requires an early warning "
        "within 24 hours of awareness."
    )
    findings = find_deadline_citations(text)
    assert findings
    assert all(f.framework == "NIS2" for f in findings)
    assert all(not f.is_fabricated for f in findings)


# ---- Paraphrase coverage (P2-4) --------------------------------------------
# Three high-frequency LLM paraphrases beyond "within N unit":
#   (1) N-hour notification window / deadline / clock / mark / period
#   (2) has N hours to notify / report
#   (5) N hours after becoming aware / classification / detection


PARAPHRASE_FABRICATED_CASES = [
    # (1) Hour-window framing — wrong number for GDPR (it's 72h).
    "GDPR's 24-hour notification window is often misquoted.",
    # (1) Deadline framing — wrong number for DORA (4h initial).
    "Under DORA, the 12-hour reporting deadline has passed.",
    # (2) "has N hours to" — wrong for GDPR.
    "The controller has 24 hours to notify under GDPR.",
    # (2) "is given N days to" — wrong for GDPR (3 days ≠ 72h? 3*24=72, wait)
    # Actually 3 days = 72 hours = valid for GDPR.
    # Use a wrong number instead.
    "The controller is given 4 days to notify under GDPR.",
    # (5) "N hours after becoming aware" — wrong for GDPR.
    "48 hours after becoming aware of a breach, GDPR notification is due.",
    # (5) "N hours after classification" — wrong for DORA (4h initial).
    "8 hours after classification, DORA requires the initial incident report.",
]


@pytest.mark.parametrize("text", PARAPHRASE_FABRICATED_CASES)
def test_paraphrase_fabricated_are_flagged(text: str) -> None:
    findings = find_deadline_citations(text)
    assert findings, f"no deadline detected in: {text!r}"
    assert any(f.is_fabricated for f in findings), (
        f"paraphrase not flagged as fabricated: {text!r} → {findings!r}"
    )


PARAPHRASE_VALID_CASES = [
    # (1) Correct GDPR window in hour-window framing.
    "GDPR's 72-hour notification window applies to personal data breaches.",
    # (2) "has N hours to" — correct for DORA initial.
    "The financial entity has 4 hours to notify under DORA.",
    # (5) "N hours after classification" — correct for DORA.
    "72 hours after classification, DORA requires the intermediate report.",
]


@pytest.mark.parametrize("text", PARAPHRASE_VALID_CASES)
def test_paraphrase_valid_pass(text: str) -> None:
    findings = find_deadline_citations(text)
    assert findings, f"no deadline detected in: {text!r}"
    assert all(not f.is_fabricated for f in findings), (
        f"valid paraphrase false-positive: {text!r} → {findings!r}"
    )


# ---- Num-absent guard (P3-1) -----------------------------------------------
# "within hours" / "within days" with no number and no word-number
# prefix (a/an/one/1) is a colloquial duration, not a statutory
# window. The rail must not fabricate num=1 from nothing.


NUM_ABSENT_CASES = [
    "Under DORA, the incident response team acted within hours of detection.",
    "NIS2-covered operators often respond within days of a reported breach.",
    "GDPR-scope entities are expected to respond within minutes for severe "
    "incidents, per internal policy.",
]


@pytest.mark.parametrize("text", NUM_ABSENT_CASES)
def test_num_absent_does_not_flag(text: str) -> None:
    findings = find_deadline_citations(text)
    assert all(not f.is_fabricated for f in findings), (
        f"num-absent phrase should not fire: {text!r} → {findings!r}"
    )


# ---- Article 33 alias removal (P3-3) ---------------------------------------
# Bare "Article 33" without a regulation name is a citation-rail
# concern, not a deadline-rail anchor. The deadline rail must not
# fabricate GDPR attribution from "Article 33" alone.


def test_article_33_alone_does_not_anchor_gdpr() -> None:
    text = "Article 33 notifications must be submitted within 12 hours."
    findings = find_deadline_citations(text)
    # Without "GDPR" / "AVG" / etc. in the sentence, the rail has no
    # framework to evaluate against and emits nothing.
    assert findings == [], (
        f"Article-33-only text should not anchor a framework: {findings!r}"
    )


# ---- S5 regression: DORA 24h-from-awareness claim is fabricated ------------
#
# Deferred finding P2-1 (v0.8.3 review) claimed that Commission Delegated
# Regulation (EU) 2024/1772 Art. 5 sets both a 4-hour-from-classification
# AND a 24-hour-from-awareness initial-notification deadline for DORA.
# Verified against the OJ text on 2026-04-19 as part of hardening wave S5:
# the claim is wrong about location. 2024/1772 Art. 5 is titled "Data
# losses" and defines a classification criterion (availability,
# authenticity, integrity, confidentiality), not a notification
# deadline. The only 24h reference in the entire regulation is Art.
# 9(3)(a) — a duration-materiality threshold for classifying an
# incident as major (how long the incident ran), not a reporting
# window. DORA's actual reporting timeframes come from Article 19 of
# the parent Regulation (EU) 2022/2554 plus the separate RTS on
# reporting timeframes under DORA Art. 20.
#
# _VALID_WINDOWS_HOURS["DORA"] = {4, 72, 720} stays as-is. Any LLM
# output claiming "DORA requires 24-hour initial notification" is
# fabrication and must fire the rail. Lock that behaviour below.


def test_dora_24h_initial_notification_claim_is_flagged_as_fabricated() -> None:
    """Regression for hardening wave S5 — deferred P2-1 closed as
    reviewer-wrong-about-location. A DORA 24h-initial-notification
    claim cites a timeframe that does not exist in the statute; the
    rail must fire.
    """
    text = "DORA requires initial notification within 24 hours of becoming aware of the incident."
    findings = find_deadline_citations(text)
    assert len(findings) == 1, (
        f"expected exactly one DORA deadline finding; got {findings!r}"
    )
    finding = findings[0]
    assert finding.framework == "DORA"
    assert finding.hours == 24
    assert finding.is_fabricated, (
        "DORA 24h initial-notification claim must be flagged as "
        "fabricated — 2024/1772 contains no such deadline (see "
        "deadline_rule.py module docstring)."
    )


def test_dora_24h_from_awareness_variant_is_flagged_as_fabricated() -> None:
    """Same fabrication in the 'N hours after awareness' paraphrase —
    the specific shape the reviewer's P2-1 claim predicted."""
    text = "Under DORA, the initial notification must be filed 24 hours after becoming aware of the breach."
    report = deadline_report(text)
    assert report["has_fabricated_deadline"] is True
    assert report["fabricated_count"] == 1


def test_dora_4h_initial_notification_passes() -> None:
    """Positive control: the statutory 4h DORA initial-notification
    window does not fire the rail."""
    text = "DORA requires initial notification within 4 hours of classification."
    report = deadline_report(text)
    assert report["has_fabricated_deadline"] is False


def test_dora_incident_duration_24h_is_not_a_notification_claim() -> None:
    """Negative control covering the exact confusion the reviewer hit.
    Art. 9(3)(a) of 2024/1772 says an incident lasting longer than 24h
    meets the duration-materiality threshold. Describing that threshold
    in an audit note is not a notification-deadline claim and must not
    fire the rail — no trigger term in the enclosing sentence.
    """
    text = "Under DORA, the incident duration exceeded 24 hours, meeting the materiality threshold."
    report = deadline_report(text)
    assert report["has_fabricated_deadline"] is False, (
        "duration-threshold language must not trigger the notification "
        "rail — there is no 'notification' / 'report' trigger in the "
        "sentence"
    )
