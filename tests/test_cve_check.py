"""Tests for the fabricated-CVE compliance rail.

CVE identifiers have a strict shape (CVE-YYYY-NNNN with 4+ digit
sequence, year >= 1999) so out-of-range years and malformed shapes
are clean fabrication signals. Reference date 2026-04-14 anchors
future-year checks so the matrix does not rot.
"""

from __future__ import annotations

from datetime import date

import pytest

from modules.guardrails.cve_rule import (
    cve_report,
    find_fabricated_cves,
)

REFERENCE_DATE = date(2026, 4, 14)


# ---- Cases that MUST be flagged (fabricated) -------------------------------

FABRICATED_CASES = [
    # Far-future year.
    "The vendor is affected by CVE-2099-12345.",
    "The advisory references CVE-2040-0001 as remediated.",
    # Year before CVE program existed.
    "The legacy advisory cites CVE-1995-0001.",
    "CVE-1980-0042 is mentioned in the historical audit.",
    # Short sequence (< 4 digits) — malformed shape.
    "See CVE-2024-1 in the security notes.",
    "The advisory lists CVE-2024-42 as open.",
    "CVE-2023-123 has been remediated.",
    # Spaces instead of dashes.
    "The write-up cites CVE 2024 12345.",
    "CVE 2023 0001 was patched in Q4.",
]


@pytest.mark.parametrize("text", FABRICATED_CASES)
def test_fabricated_cves_are_flagged(text: str) -> None:
    findings = find_fabricated_cves(text, today=REFERENCE_DATE)
    assert findings, f"no fabrication detected in: {text!r}"


# ---- Cases that MUST pass (real shape, in-range) ---------------------------

VALID_CASES = [
    # Classic 4-digit sequence.
    "The vendor is affected by CVE-2014-0160 (Heartbleed).",
    # Wider sequence (format expanded in 2014).
    "The supply-chain flaw is tracked as CVE-2021-44228.",
    "Patched against CVE-2023-12345.",
    # Very long sequence — valid by format.
    "See CVE-2022-0123456 in the advisory.",
    # First year of the CVE program.
    "CVE-1999-0001 is the first recorded identifier.",
    # Reserved for next year (within tolerance window).
    "The reserved identifier CVE-2027-0001 has not yet been published.",
    # Current year.
    "The vendor has disclosed CVE-2026-12345.",
]


@pytest.mark.parametrize("text", VALID_CASES)
def test_valid_cves_pass(text: str) -> None:
    findings = find_fabricated_cves(text, today=REFERENCE_DATE)
    assert findings == [], (
        f"false positive on real CVE: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (no CVE present) ---------------------------------

NO_CVE_CASES = [
    "The vendor patches weekly and discloses via its PSIRT.",
    "The audit found no unremediated vulnerabilities.",
    # Non-CVE numeric identifier — shouldn't trigger the rail.
    "Reference 2024-0001 in the internal tracker.",
    # Bare "CVE" without an ID.
    "The organisation subscribes to the CVE program.",
]


@pytest.mark.parametrize("text", NO_CVE_CASES)
def test_no_cve_cases_are_not_flagged(text: str) -> None:
    findings = find_fabricated_cves(text, today=REFERENCE_DATE)
    assert findings == [], (
        f"spurious match where no CVE given: {text!r} → {findings!r}"
    )


# ---- Boundary behaviour ----------------------------------------------------


def test_first_cve_year_boundary() -> None:
    # 1999 is the first CVE year; 1998 is flagged.
    assert find_fabricated_cves(
        "CVE-1999-0001 is the earliest entry.", today=REFERENCE_DATE
    ) == []
    assert find_fabricated_cves(
        "CVE-1998-0001 is cited in the report.", today=REFERENCE_DATE
    )


def test_future_year_tolerance_is_one_year() -> None:
    # Reference 2026-04-14 → 2027 allowed, 2028 flagged.
    assert find_fabricated_cves(
        "CVE-2027-0001 has been reserved.", today=REFERENCE_DATE
    ) == []
    assert find_fabricated_cves(
        "CVE-2028-0001 appears in the advisory.", today=REFERENCE_DATE
    )


def test_mixed_valid_and_fabricated() -> None:
    text = (
        "The advisory covers CVE-2021-44228 (Log4Shell) and "
        "the new CVE-2099-0001 the vendor disclosed."
    )
    findings = find_fabricated_cves(text, today=REFERENCE_DATE)
    assert len(findings) == 1
    assert findings[0].year == 2099


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_fabrication() -> None:
    result = cve_report(
        "The vendor cited CVE-2099-12345 in the notes.",
        today=REFERENCE_DATE,
    )
    assert result["has_fabricated_cve"] is True
    assert result["fabrication_count"] == 1
    assert any("2099" in s for s in result["samples"])


def test_report_shape_for_clean() -> None:
    result = cve_report(
        "The advisory covers CVE-2021-44228.",
        today=REFERENCE_DATE,
    )
    assert result == {
        "has_fabricated_cve": False,
        "fabrication_count": 0,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "The report lists CVE-2099-0001, CVE-2098-0002, "
        "CVE-2097-0003, and CVE-2096-0004."
    )
    result = cve_report(text, today=REFERENCE_DATE)
    assert result["fabrication_count"] == 4
    assert len(result["samples"]) == 3
