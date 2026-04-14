"""Tests for the unfounded-verdict compliance rail.

Each test case is a fixture string that represents the kind of output a
general-purpose LLM would produce for a vendor audit question. The rail
must block the absolutist-without-evidence cases and let the evidence-
anchored cases through.
"""

from __future__ import annotations

import pytest

from modules.guardrails.verdict_rule import (
    ANCHOR_WINDOW_CHARS,
    find_unfounded_verdicts,
    verdict_report,
)

# ---- Cases that MUST be blocked (verdict without evidence) ------------------

BLOCK_CASES = [
    # The canonical failure mode: confident verdict, no source.
    "Vendor Acme is fully compliant with ISO 27001.",
    # Vague claim with no supporting detail.
    "The vendor meets all requirements for DORA operational resilience.",
    # Passive / cert framing.
    "Acme is certified for ISO 27001 and NIS2.",
    # Different verb, same failure shape.
    "The vendor satisfies all the requirements in the audit scope.",
    # Verdict at the end after a long preamble with irrelevant content.
    (
        "The vendor provided a staff handbook and a policy document. "
        "After reviewing the material, I conclude that Acme is compliant."
    ),
]


@pytest.mark.parametrize("text", BLOCK_CASES)
def test_unfounded_verdicts_are_flagged(text: str) -> None:
    findings = find_unfounded_verdicts(text)
    assert findings, f"no verdict detected in: {text!r}"
    assert all(not f.has_evidence for f in findings), (
        f"evidence false-positive in: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (verdict with adjacent evidence) ------------------

PASS_CASES = [
    # Explicit section citation.
    "Acme is compliant with ISO 27001 per Section 5 of their attestation report.",
    # SOC 2 reference as the evidence anchor.
    "As shown in the SOC 2 report, the vendor meets all requirements for access control.",
    # "According to" followed by a concrete source.
    "According to the DORA self-assessment dated 2025-11, the vendor conforms to Article 5.",
    # Structured citation marker.
    "The vendor is compliant with NIS2 [ref: attestation_2026_Q1.pdf, p. 12].",
    # Evidence anchor precedes the verdict.
    "As shown in the ISAE 3402 report, the processing controls are compliant.",
]


@pytest.mark.parametrize("text", PASS_CASES)
def test_founded_verdicts_pass(text: str) -> None:
    findings = find_unfounded_verdicts(text)
    assert findings, f"no verdict detected in: {text!r}"
    assert all(f.has_evidence for f in findings), (
        f"evidence not detected in: {text!r} → {findings!r}"
    )


# ---- Cases that MUST NOT trigger the rail (no verdict at all) ---------------

NON_VERDICT_CASES = [
    # A finding, not a verdict — this is what the agent should produce.
    "Control A.5.1 is implemented; evidence was provided in the questionnaire.",
    # Discussion of compliance without asserting it.
    "The vendor discusses their compliance programme in section 3 of the RFP.",
    # Neutral risk language.
    "Residual risk is medium; further evidence would be required to confirm.",
    # RAG scoring language — what the Vendor_Guard scorecard produces.
    "Status: AMBER. Partial evidence supports the control; gap noted.",
]


@pytest.mark.parametrize("text", NON_VERDICT_CASES)
def test_non_verdicts_are_not_detected(text: str) -> None:
    findings = find_unfounded_verdicts(text)
    assert findings == [], (
        f"spurious verdict match in non-verdict text: {text!r} → {findings!r}"
    )


# ---- Window boundary tests --------------------------------------------------


def test_evidence_outside_window_does_not_count() -> None:
    """An evidence anchor far from the verdict must not satisfy it."""
    padding = "x" * (ANCHOR_WINDOW_CHARS + 50)
    text = f"The vendor is compliant. {padding} Per Section 3 of the SOC 2 report."
    findings = find_unfounded_verdicts(text)
    assert findings
    assert findings[0].has_evidence is False


def test_evidence_inside_window_is_accepted() -> None:
    """An evidence anchor just inside the window must satisfy the verdict."""
    padding = "x" * (ANCHOR_WINDOW_CHARS - 50)
    text = f"The vendor is compliant. {padding} per Section 3."
    findings = find_unfounded_verdicts(text)
    assert findings
    assert findings[0].has_evidence is True


# ---- Report shape (what the Guardrails action returns) ----------------------


def test_report_shape_for_unfounded() -> None:
    result = verdict_report("Acme is compliant.")
    assert result == {
        "has_unfounded_verdict": True,
        "verdict_count": 1,
        "unfounded_count": 1,
        "samples": [result["samples"][0]],
    }
    assert "compliant" in result["samples"][0].lower()


def test_report_shape_for_founded() -> None:
    result = verdict_report(
        "Acme is compliant with ISO 27001 per Section 5 of the SOC 2 report."
    )
    assert result["has_unfounded_verdict"] is False
    assert result["verdict_count"] == 1
    assert result["unfounded_count"] == 0
    assert result["samples"] == []
