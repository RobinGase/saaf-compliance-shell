"""Tests for the stale-attestation compliance rail.

Fixtures pass an explicit reference date so the matrix does not
rot over calendar time. The default threshold is 2 years — an
attestation older than that is considered no longer current
evidence for audit purposes.
"""

from __future__ import annotations

from datetime import date

import pytest

from modules.guardrails.stale_date_rule import (
    find_stale_attestations,
    stale_date_report,
)


TODAY = date(2026, 4, 14)


# ---- Cases that MUST be flagged (attestation >2 years old) -----------------

STALE_CASES = [
    "The vendor provided a SOC 2 report from 2019.",
    "Per the 2018 SOC 2 Type II attestation, encryption is in place.",
    "ISAE 3402 report dated 2020 was reviewed.",
    "ISO 27001 certificate issued in 2019.",
    "ISO/IEC 27001:2013 certificate from 2020.",
    "Per the 2022 PCI DSS assessment, card data is scoped correctly.",
    "We reviewed the 2021 SOC 2 report last week.",
]


@pytest.mark.parametrize("text", STALE_CASES)
def test_stale_attestations_are_flagged(text: str) -> None:
    findings = find_stale_attestations(text, today=TODAY)
    assert findings, f"no stale finding in: {text!r}"


# ---- Cases that MUST pass (recent attestation or not a reference) ----------

FRESH_CASES = [
    # Within the 2-year window.
    "The vendor provided a SOC 2 report from 2025.",
    "ISO 27001 certificate issued in 2024.",
    "Per the 2024 SOC 2 Type II attestation, encryption is in place.",
    # Current year is trivially fresh.
    "ISAE 3402 report dated 2026.",
]


@pytest.mark.parametrize("text", FRESH_CASES)
def test_fresh_attestations_pass(text: str) -> None:
    findings = find_stale_attestations(text, today=TODAY)
    assert findings == [], (
        f"false positive on fresh attestation: {text!r} → {findings!r}"
    )


# ---- Cases that MUST NOT be detected (not an attestation reference) --------

NON_REFERENCE_CASES = [
    # Year appears but not next to an attestation word.
    "The 2019 incident response plan was updated.",
    "The contract was signed in 2019.",
    # Framework reference without any year.
    "SOC 2 covers security, availability, and confidentiality.",
    # Discussing a regulation, not an attestation date.
    "GDPR Regulation (EU) 2016/679 came into force in 2018.",
    # Narrative about a year, not a citation.
    "In 2018 the vendor rewrote its cloud stack.",
]


@pytest.mark.parametrize("text", NON_REFERENCE_CASES)
def test_non_references_are_not_detected(text: str) -> None:
    findings = find_stale_attestations(text, today=TODAY)
    assert findings == [], (
        f"spurious match in: {text!r} → {findings!r}"
    )


# ---- Threshold behaviour ---------------------------------------------------


def test_threshold_is_inclusive_of_2_years() -> None:
    # 2024 is exactly 2 years before 2026 — should NOT be flagged with
    # the default `>= max_age_years + 1` rule (stale = older than 2y).
    text = "The SOC 2 report from 2024 is current."
    assert find_stale_attestations(text, today=TODAY) == []


def test_threshold_can_be_tuned() -> None:
    text = "Per the 2024 SOC 2 report."
    # With max_age_years=1, 2024 (2y old) is stale.
    findings = find_stale_attestations(text, today=TODAY, max_age_years=1)
    assert len(findings) == 1
    assert findings[0].year == 2024
    assert findings[0].age_years == 2


def test_future_year_is_ignored() -> None:
    # Typos or model confabulations producing a future year are
    # ignored rather than treated as fresh (cannot be "current
    # evidence" if the date hasn't happened).
    text = "SOC 2 report from 2099."
    assert find_stale_attestations(text, today=TODAY) == []


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_stale() -> None:
    result = stale_date_report(
        "Per the 2019 SOC 2 attestation, controls are in place.",
        today=TODAY,
    )
    assert result["has_stale_attestation"] is True
    assert result["stale_count"] == 1
    assert result["max_age_years"] == 2
    assert any("2019" in s and "7y" in s for s in result["samples"])


def test_report_shape_for_clean() -> None:
    result = stale_date_report(
        "Per the 2025 SOC 2 attestation, controls are in place.",
        today=TODAY,
    )
    assert result == {
        "has_stale_attestation": False,
        "stale_count": 0,
        "max_age_years": 2,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "Per the 2018 SOC 2 report, controls are A. "
        "Per the 2019 ISAE 3402 report, controls are B. "
        "Per the 2020 ISO 27001 certificate, controls are C. "
        "Per the 2017 PCI DSS assessment, controls are D."
    )
    result = stale_date_report(text, today=TODAY)
    assert result["stale_count"] == 4
    assert len(result["samples"]) == 3
