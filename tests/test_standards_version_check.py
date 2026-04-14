"""Tests for the fabricated-standards-version compliance rail.

The rail flags version/year stamps on standards whose prefix is real
but whose revision is hallucinated — "ISO 27001:3000", "PCI DSS v9.0",
"NIST SP 800-53 Rev 12". The explicit reference date (2026-04-14)
anchors future-year checks so the matrix does not rot over time.
"""

from __future__ import annotations

from datetime import date

import pytest

from modules.guardrails.standards_version_rule import (
    find_fabricated_standards_versions,
    standards_version_report,
)

REFERENCE_DATE = date(2026, 4, 14)


# ---- Cases that MUST be flagged (fabricated versions) ----------------------

FABRICATED_CASES = [
    # ISO: far-future year.
    "The vendor is certified against ISO 27001:3000.",
    "The platform is ISO/IEC 27001:2030-compliant.",
    "ISO 9001:2099 is in place at the manufacturing site.",
    # ISO: year predates first publication.
    "ISO 27001:1999 is the long-standing baseline.",
    "The management system follows ISO 22301:2001.",
    # PCI DSS: version outside the published set.
    "The environment is PCI DSS v9.0-compliant.",
    "The cardholder zone meets PCI DSS 5.2.",
    "PCI DSS version 7.0 has been adopted.",
    # NIST 800-53: revision outside the published range.
    "Controls map to NIST SP 800-53 Rev. 12.",
    "The baseline is NIST 800-53 Revision 8.",
    "Controls align with 800-53r9.",
    # NIST CSF: version outside the published set.
    "The program aligns with NIST CSF v5.0.",
    "The organisation adopted Cybersecurity Framework 3.5.",
]


@pytest.mark.parametrize("text", FABRICATED_CASES)
def test_fabricated_versions_are_flagged(text: str) -> None:
    findings = find_fabricated_standards_versions(text, today=REFERENCE_DATE)
    assert findings, f"no fabrication detected in: {text!r}"


# ---- Cases that MUST pass (real versions) ----------------------------------

VALID_CASES = [
    # ISO: real published years.
    "The vendor is certified against ISO 27001:2022.",
    "ISO 27001:2013 remains in use during the transition.",
    "ISO/IEC 27001:2022 is the current baseline.",
    "The site is certified to ISO 9001:2015.",
    "Business continuity follows ISO 22301:2019.",
    # ISO: year inside the near-future tolerance (<= current_year + 1).
    # Reference date is 2026-04-14 so 2027 is acceptable.
    "ISO 27002:2027 has been pre-announced.",
    # PCI DSS: real versions.
    "The environment is PCI DSS v4.0-compliant.",
    "The acquirer accepts PCI DSS 3.2.1 reports during the transition.",
    "PCI DSS version 4.0.1 is the current release.",
    # NIST 800-53: real revisions.
    "Controls map to NIST SP 800-53 Rev. 5.",
    "The baseline is NIST 800-53 Revision 4.",
    "Controls align with 800-53r5.",
    # NIST CSF: real versions.
    "The program aligns with NIST CSF v2.0.",
    "The organisation adopted Cybersecurity Framework 1.1.",
]


@pytest.mark.parametrize("text", VALID_CASES)
def test_valid_versions_pass(text: str) -> None:
    findings = find_fabricated_standards_versions(text, today=REFERENCE_DATE)
    assert findings == [], (
        f"false positive on real version: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (no version token) -------------------------------

NO_VERSION_CASES = [
    # Bare standard citation — not this rail's scope.
    "The vendor is ISO 27001-certified.",
    "The environment is PCI DSS-compliant.",
    "Controls map to NIST 800-53.",
    "The program aligns with the NIST Cybersecurity Framework.",
    # Narrative with the standard name but no version token.
    "ISO 27001 covers information-security management systems.",
]


@pytest.mark.parametrize("text", NO_VERSION_CASES)
def test_no_version_cases_are_not_flagged(text: str) -> None:
    findings = find_fabricated_standards_versions(text, today=REFERENCE_DATE)
    assert findings == [], (
        f"spurious match where no version given: {text!r} → {findings!r}"
    )


# ---- Boundary behaviour ----------------------------------------------------


def test_future_year_tolerance_is_one_year() -> None:
    # Reference 2026-04-14 → 2027 allowed, 2028 flagged.
    assert find_fabricated_standards_versions(
        "ISO 27001:2027 is pre-announced.", today=REFERENCE_DATE
    ) == []
    assert find_fabricated_standards_versions(
        "ISO 27001:2028 is pre-announced.", today=REFERENCE_DATE
    )


def test_first_publication_boundary() -> None:
    # ISO 27001 first published 2005; 2004 flagged, 2005 ok.
    assert find_fabricated_standards_versions(
        "ISO 27001:2005 is the baseline.", today=REFERENCE_DATE
    ) == []
    assert find_fabricated_standards_versions(
        "ISO 27001:2004 is the baseline.", today=REFERENCE_DATE
    )


def test_pci_dss_v4_0_1_is_real() -> None:
    findings = find_fabricated_standards_versions(
        "PCI DSS v4.0.1 is the current release.", today=REFERENCE_DATE
    )
    assert findings == []


def test_mixed_valid_and_fabricated() -> None:
    text = (
        "The vendor is certified against ISO 27001:2022 "
        "and the environment meets PCI DSS v9.0."
    )
    findings = find_fabricated_standards_versions(text, today=REFERENCE_DATE)
    assert len(findings) == 1
    assert findings[0].standard == "PCI DSS"
    assert findings[0].version == "9.0"


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_fabrication() -> None:
    result = standards_version_report(
        "The vendor claims ISO 27001:3000 certification.",
        today=REFERENCE_DATE,
    )
    assert result["has_fabricated_version"] is True
    assert result["fabrication_count"] == 1
    assert any("3000" in s for s in result["samples"])


def test_report_shape_for_clean() -> None:
    result = standards_version_report(
        "The vendor is certified against ISO 27001:2022.",
        today=REFERENCE_DATE,
    )
    assert result == {
        "has_fabricated_version": False,
        "fabrication_count": 0,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "Certifications include ISO 27001:3000, ISO 9001:2099, "
        "PCI DSS v9.0, and NIST SP 800-53 Rev. 12."
    )
    result = standards_version_report(text, today=REFERENCE_DATE)
    assert result["fabrication_count"] == 4
    assert len(result["samples"]) == 3
