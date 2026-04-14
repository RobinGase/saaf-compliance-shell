"""Tests for the fabricated-regulator-name compliance rail.

Generalist models routinely confabulate plausible-sounding supervisory
bodies — "European Privacy Authority", "EU Cybersecurity Commission",
"Federal Data Protection Agency". These patterns are narrow and
definitive: the body does not exist. The rail flags the phrase and
carries a canonical suggestion into the refusal so reviewers know
which real body was probably meant.
"""

from __future__ import annotations

import pytest

from modules.guardrails.regulator_rule import (
    find_fabricated_regulators,
    regulator_report,
)


# ---- Cases that MUST be flagged (fabricated) -------------------------------

FABRICATED_CASES = [
    # EU — data protection.
    "The vendor is under investigation by the European Privacy Authority.",
    "The EU Privacy Authority issued new guidance last quarter.",
    "The European Data Authority published a consultation on profiling.",
    "The EU Privacy Commission will review the transfer mechanism.",
    "A European Privacy Commission ruling is expected in Q4.",
    "The European Data Protection Agency has issued a €20m fine.",
    # EU — cybersecurity.
    "The EU Cybersecurity Commission released an advisory last week.",
    "Per the European Cybersecurity Commission, the incident is severe.",
    "The European Cybersecurity Authority classifies this as high risk.",
    # EU — AI.
    "The EU AI Commission requires a conformity assessment.",
    "The European AI Authority enforces the AI Act.",
    "The European AI Agency maintains the high-risk registry.",
    # US — data protection.
    "The Federal Data Protection Agency is investigating the breach.",
    "The US Data Protection Agency announced a settlement.",
    "The US Privacy Commission reviews complaints under federal privacy law.",
    "The Federal Privacy Commission has jurisdiction over this matter.",
    # UK — data protection.
    "The UK Privacy Authority opened an enforcement action.",
    "The UK Data Protection Agency issued a monetary penalty.",
    "The British Data Protection Agency received the complaint.",
    "The British Privacy Authority coordinates with EU bodies.",
]


@pytest.mark.parametrize("text", FABRICATED_CASES)
def test_fabricated_regulators_are_flagged(text: str) -> None:
    findings = find_fabricated_regulators(text)
    assert findings, f"no fabrication detected in: {text!r}"


# ---- Cases that MUST pass (real bodies) -----------------------------------

VALID_CASES = [
    # Real EU data-protection bodies.
    "The European Data Protection Board (EDPB) issued guidance.",
    "The EDPB adopted a binding decision on cross-border transfers.",
    "The European Data Protection Supervisor (EDPS) reviewed the programme.",
    # Real EU cybersecurity / AI bodies.
    "ENISA published the threat landscape report for 2026.",
    "The European Union Agency for Cybersecurity coordinates incident response.",
    "The European AI Office oversees general-purpose AI model obligations.",
    # Real national DPAs.
    "The Dutch Autoriteit Persoonsgegevens opened an investigation.",
    "The Irish Data Protection Commission is the lead supervisory authority.",
    "The CNIL issued a fine under French data-protection law.",
    # Real UK body.
    "The Information Commissioner's Office (ICO) published guidance.",
    "The ICO is the UK supervisory authority for data protection.",
    # Real US bodies (no federal DPA exists — sector regulators).
    "The FTC announced an enforcement action under Section 5.",
    "HHS OCR enforces HIPAA at the federal level.",
    "The SEC issued rules on cybersecurity disclosure.",
]


@pytest.mark.parametrize("text", VALID_CASES)
def test_valid_regulators_pass(text: str) -> None:
    findings = find_fabricated_regulators(text)
    assert findings == [], (
        f"false positive on real regulator: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (no regulator named) -----------------------------

NO_REGULATOR_CASES = [
    "The vendor maintains an internal privacy programme.",
    "The audit did not identify any unresolved findings.",
    "Controls are tested annually by an independent assessor.",
]


@pytest.mark.parametrize("text", NO_REGULATOR_CASES)
def test_no_regulator_cases_are_not_flagged(text: str) -> None:
    findings = find_fabricated_regulators(text)
    assert findings == [], (
        f"spurious match where no regulator given: {text!r} → {findings!r}"
    )


# ---- Suggestion payload ----------------------------------------------------


def test_eu_privacy_authority_suggests_edpb() -> None:
    findings = find_fabricated_regulators(
        "The European Privacy Authority has ruled."
    )
    assert len(findings) == 1
    assert "EDPB" in findings[0].suggested


def test_eu_cybersecurity_commission_suggests_enisa() -> None:
    findings = find_fabricated_regulators(
        "The EU Cybersecurity Commission issued the advisory."
    )
    assert len(findings) == 1
    assert "ENISA" in findings[0].suggested


def test_uk_privacy_authority_suggests_ico() -> None:
    findings = find_fabricated_regulators(
        "The UK Privacy Authority accepted the undertaking."
    )
    assert len(findings) == 1
    assert "ICO" in findings[0].suggested


def test_federal_data_protection_agency_names_real_us_regulators() -> None:
    findings = find_fabricated_regulators(
        "The Federal Data Protection Agency is reviewing the matter."
    )
    assert len(findings) == 1
    # Suggestion should name FTC (and likely HHS OCR / SEC) since no
    # federal DPA exists.
    assert "FTC" in findings[0].suggested


def test_mixed_real_and_fabricated() -> None:
    text = (
        "The EDPB issued guidance, and separately the European Privacy "
        "Authority opened its own investigation."
    )
    findings = find_fabricated_regulators(text)
    assert len(findings) == 1
    assert findings[0].phrase == "European Privacy Authority"


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_fabrication() -> None:
    result = regulator_report(
        "The European Privacy Authority has ruled on the matter."
    )
    assert result["has_fabricated_regulator"] is True
    assert result["fabrication_count"] == 1
    assert len(result["samples"]) == 1
    assert "European Privacy Authority" in result["samples"][0]
    assert "EDPB" in result["samples"][0]


def test_report_shape_for_clean() -> None:
    result = regulator_report(
        "The EDPB and ENISA both published guidance this year."
    )
    assert result == {
        "has_fabricated_regulator": False,
        "fabrication_count": 0,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "The European Privacy Authority, the EU Cybersecurity Commission, "
        "the European AI Authority, and the Federal Data Protection Agency "
        "all issued statements."
    )
    result = regulator_report(text)
    assert result["fabrication_count"] == 4
    assert len(result["samples"]) == 3
