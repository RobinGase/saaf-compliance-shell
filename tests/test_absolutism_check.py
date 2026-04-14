"""Tests for the absolutist-language compliance rail.

This rail flags phrases like "100% secure" or "zero risk" — claims
that are effectively never valid in an audit deliverable because
audit conclusions are probabilistic and point-in-time. Sibling to
the verdict rail; deliberately narrower than the verdict rail's
evidence-anchor semantic.
"""

from __future__ import annotations

import pytest

from modules.guardrails.absolutism_rule import (
    find_absolutist_claims,
    absolutism_report,
)


# ---- Cases that MUST be flagged -------------------------------------------

ABSOLUTIST_CASES = [
    "The platform is 100% secure against modern threats.",
    "This architecture is 100 % compliant with ISO 27001.",
    "The vendor guarantees zero risk of data loss.",
    "No vulnerabilities remain after the latest patch cycle.",
    "The solution is risk-free for regulated workloads.",
    "Our encryption stack is completely secure.",
    "The system is absolutely compliant with GDPR.",
    "The database is perfectly secure against SQL injection.",
    "This control cannot be breached by external actors.",
    "The network can not be compromised under any circumstances.",
    "Their infrastructure will never be exploited.",
    "The HSM is impossible to breach.",
    "Access tokens are guaranteed secure in transit.",
    "The service is guaranteed to pass the next audit.",
    "With this in place the vendor is always compliant.",
    "The architecture provides perfect security end to end.",
    "Their appliance is unhackable per the marketing material.",
    "This encryption scheme is unbreakable.",
    "The monitoring stack never fails to detect lateral movement.",
    # SLA absolutist claims — uptime/availability/downtime framings
    # that are effectively never truthful in a vendor deliverable.
    "The platform delivers 100% uptime across all regions.",
    "The service guarantees 100 % availability to enterprise tenants.",
    "The architecture provides zero downtime during maintenance windows.",
    "The vendor promises no downtime for tier-1 workloads.",
    "No outages have occurred and none will occur.",
]


@pytest.mark.parametrize("text", ABSOLUTIST_CASES)
def test_absolutist_claims_are_flagged(text: str) -> None:
    findings = find_absolutist_claims(text)
    assert findings, f"no absolutist claim detected in: {text!r}"


# ---- Cases that MUST NOT be flagged ---------------------------------------

HEDGED_CASES = [
    # Properly hedged audit language.
    "The control is designed to be resilient against credential theft.",
    "The vendor is expected to meet the availability SLA during Q2.",
    "Encryption in transit is implemented via TLS 1.3 (per SOC 2 §CC6.7).",
    "Based on the 2025 attestation, the vendor appears aligned with ISO 27001.",
    "Risk was assessed as low given the compensating controls in place.",
    # Talking about the concept of risk, not claiming zero risk.
    "The risk register enumerates residual risks after mitigations.",
    # "secure" appears but not as an absolutist claim.
    "The vendor uses a secure software development lifecycle.",
    # Discussing limits honestly.
    "No audit can guarantee that a future breach is impossible.",
    # Discussion of a guarantee that explicitly acknowledges limits.
    "The contract provides a best-effort guarantee, not an absolute one.",
    # Negated absolutist phrases — legitimate hedged audit language.
    "The system is not 100% secure against targeted adversaries.",
    "The platform is never completely secure; residual risk remains.",
    "No control is unbreakable in the face of insider misuse.",
    "The appliance isn't unhackable — the SOC 2 report flags gaps.",
    "The service does not guarantee zero downtime during failover.",
]


@pytest.mark.parametrize("text", HEDGED_CASES)
def test_hedged_language_is_not_flagged(text: str) -> None:
    findings = find_absolutist_claims(text)
    assert findings == [], (
        f"false positive in: {text!r} → {findings!r}"
    )


# ---- Report shape ----------------------------------------------------------


def test_report_shape_with_claim() -> None:
    result = absolutism_report("The platform is 100% secure and risk-free.")
    assert result["has_absolutist_claim"] is True
    assert result["claim_count"] == 2
    assert len(result["samples"]) == 2


def test_report_shape_clean() -> None:
    result = absolutism_report(
        "The vendor is designed to meet ISO 27001 controls, per SOC 2 §CC6."
    )
    assert result == {
        "has_absolutist_claim": False,
        "claim_count": 0,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "The platform is 100% secure. It has zero risk. The stack is "
        "unhackable. The design is unbreakable. It never fails."
    )
    result = absolutism_report(text)
    assert result["claim_count"] == 5
    assert len(result["samples"]) == 3
