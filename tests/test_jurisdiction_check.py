"""Tests for the jurisdiction-mismatch compliance rail.

The rail targets an audit-specific failure mode: a model applying a
regulation to an entity outside that regulation's jurisdictional
scope — "the German vendor must comply with HIPAA", "the US
subsidiary falls under DORA". Detection is sentence-scoped, narrow
(only strict-scope regulations), and suppressed by
negation/comparison/hypothetical phrasing.
"""

from __future__ import annotations

import pytest

from modules.guardrails.jurisdiction_rule import (
    find_jurisdiction_mismatches,
    jurisdiction_report,
)

# ---- Cases that MUST be flagged (regulation from wrong zone) ---------------

MISMATCH_CASES = [
    # EU entity + US regulation.
    "The German vendor must comply with HIPAA.",
    "Per SOX, the Dutch bank is required to rotate keys annually.",
    "Our French subsidiary is subject to CCPA.",
    "The Italian processor falls under GLBA.",
    "European operations remain governed by FISMA.",
    "Gramm-Leach-Bliley applies to the Belgian branch.",
    # UK entity + US regulation.
    "The UK processor must comply with HIPAA.",
    "British fintech firms fall under Sarbanes-Oxley.",
    # US entity + EU-only regulation.
    "The US vendor falls under DORA.",
    "American banks must comply with NIS2.",
    "Our United States subsidiary is governed by eIDAS.",
    # UK entity + EU-only regulation (post-Brexit).
    "The British subsidiary is subject to DORA.",
    # EU entity + UK-only regulation.
    "The German vendor must comply with UK GDPR.",
]


@pytest.mark.parametrize("text", MISMATCH_CASES)
def test_jurisdiction_mismatches_are_flagged(text: str) -> None:
    findings = find_jurisdiction_mismatches(text)
    assert findings, f"no finding in: {text!r}"


# ---- Cases that MUST pass (matching zone) ----------------------------------

MATCHING_ZONE_CASES = [
    "The US vendor must comply with HIPAA.",
    "Per SOX, the American bank is required to rotate keys annually.",
    "The EU vendor falls under DORA.",
    "German banks must comply with NIS2.",
    "Our European subsidiary is governed by eIDAS.",
    "The UK processor must comply with UK GDPR.",
    "British financial firms fall under the Data Protection Act 2018.",
]


@pytest.mark.parametrize("text", MATCHING_ZONE_CASES)
def test_matching_jurisdictions_pass(text: str) -> None:
    findings = find_jurisdiction_mismatches(text)
    assert findings == [], (
        f"false positive on matching jurisdiction: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (negation / comparison / hypothetical) -----------

NEGATED_OR_COMPARATIVE_CASES = [
    "HIPAA does not apply to our EU operations.",
    "DORA is not applicable to the US parent.",
    "The German subsidiary is not subject to HIPAA.",
    "Unlike HIPAA, GDPR governs all personal data processing.",
    "Whereas SOX applies in the US, DORA governs EU financial entities.",
    "Compared to HIPAA, the Dutch framework is stricter.",
    "If the German vendor were US-based, HIPAA would apply.",
    "The UK equivalent of HIPAA is the Data Protection Act 2018.",
    "HIPAA's extraterritorial reach could extend to the German vendor.",
    "DORA differs from SOX in scope and enforcement mechanism.",
    "NIS2 mirrors FISMA in some of its incident-reporting expectations.",
]


@pytest.mark.parametrize("text", NEGATED_OR_COMPARATIVE_CASES)
def test_negated_or_comparative_phrases_are_skipped(text: str) -> None:
    findings = find_jurisdiction_mismatches(text)
    assert findings == [], (
        f"spurious match in negated/comparative: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (no jurisdiction marker / no regulation) ---------

OUT_OF_SCOPE_CASES = [
    # Regulation without jurisdiction marker.
    "HIPAA covers health data handling.",
    "SOX imposes financial reporting controls.",
    "DORA came into force in January 2025.",
    # Jurisdiction marker without regulation.
    "The German vendor processes customer data.",
    "American banks report quarterly.",
    # GDPR is deliberately excluded — its Article 3 reach means a US
    # entity can genuinely be subject to it, so the rail must not flag.
    "The US vendor must comply with GDPR.",
    "American companies are subject to GDPR when processing EU data.",
    # AI Act is also deliberately excluded.
    "The US vendor falls under the EU AI Act for high-risk systems.",
]


@pytest.mark.parametrize("text", OUT_OF_SCOPE_CASES)
def test_out_of_scope_cases_are_not_flagged(text: str) -> None:
    findings = find_jurisdiction_mismatches(text)
    assert findings == [], (
        f"spurious match in out-of-scope case: {text!r} → {findings!r}"
    )


# ---- Sentence scoping ------------------------------------------------------


def test_mismatch_detection_is_sentence_scoped() -> None:
    # Regulation in one sentence, wrong-zone jurisdiction in another —
    # should NOT be flagged, since the rail reasons per sentence.
    text = (
        "HIPAA imposes strict rules on health data. "
        "Our German vendor has a robust security posture."
    )
    assert find_jurisdiction_mismatches(text) == []


def test_semicolon_separated_clauses_are_scoped_independently() -> None:
    # The semicolon marks a clause break — the SOX citation and the
    # German jurisdiction are in separate clauses, so no flag.
    text = (
        "SOX governs US public companies; our German subsidiary "
        "reports under different regimes."
    )
    assert find_jurisdiction_mismatches(text) == []


def test_uk_gdpr_is_recognised_as_uk_scope() -> None:
    # "UK GDPR" as a multi-word regulation is UK-scope; a sentence
    # containing only "UK GDPR" and UK markers must not misfire on
    # the embedded "UK" token.
    findings = find_jurisdiction_mismatches(
        "UK vendors must comply with UK GDPR."
    )
    assert findings == []


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_mismatch() -> None:
    result = jurisdiction_report(
        "The German vendor must comply with HIPAA."
    )
    assert result["has_jurisdiction_mismatch"] is True
    assert result["mismatch_count"] == 1
    assert len(result["samples"]) == 1
    assert "HIPAA" in result["samples"][0]
    assert "US" in result["samples"][0]
    assert "German" in result["samples"][0]
    assert "EU" in result["samples"][0]


def test_report_shape_for_clean() -> None:
    result = jurisdiction_report(
        "The US vendor must comply with HIPAA."
    )
    assert result == {
        "has_jurisdiction_mismatch": False,
        "mismatch_count": 0,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "The German vendor must comply with HIPAA. "
        "Our French subsidiary is subject to CCPA. "
        "The Dutch processor falls under GLBA. "
        "Italian banks are governed by SOX."
    )
    result = jurisdiction_report(text)
    assert result["mismatch_count"] == 4
    assert len(result["samples"]) == 3
