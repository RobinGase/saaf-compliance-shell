"""Tests for the fabricated-case-law compliance rail.

CJEU case identifiers use the canonical ``[CTF]-NNN/YY`` scheme
introduced in 1989; CNIL SAN enforcement IDs use ``SAN-YYYY-NNN``.
Year outside the court's issuing window is a clean fabrication
signal. Reference date 2026-04-18 anchors future-year checks so the
matrix does not rot as time passes.
"""

from __future__ import annotations

from datetime import date

import pytest

from modules.guardrails.case_law_rule import (
    case_law_report,
    find_fabricated_case_law,
)

REFERENCE_DATE = date(2026, 4, 18)


# ---- Cases that MUST be flagged (fabricated) -------------------------------

FABRICATED_CASES = [
    # CJEU canonical shape — far-future year.
    "In Case C-521/29, the Court of Justice held that the controller was liable.",
    "The CJEU judgment in T-442/30 is instructive here.",
    "Per Case C-100/2099 the controller must notify.",
    # CJEU canonical — year before 1989 [CTF] numbering scheme.
    "See Case C-26/62 (Van Gend en Loos) for the classical position.",
    "The Court's reasoning in C-237/88 predates the current scheme.",
    # Four-digit pre-1989 year.
    "The CJEU held in C-237/1985 that direct effect applied.",
    # CJEU malformed separators with explicit CJEU context.
    "The CJEU judgment in C.237/23 set the precedent.",
    "Per the Court of Justice, Case C_442/22 established the test.",
    "The General Court ruled in T-442-22 against the applicant.",
    # CNIL SAN — far-future year.
    "CNIL Délibération SAN-2099-047 imposed a record fine.",
    "The sanction SAN-2040-012 was the largest that year.",
    # CNIL SAN — pre-1999 (well before the SAN scheme).
    "The historical reference SAN-1975-001 is often misquoted.",
]


@pytest.mark.parametrize("text", FABRICATED_CASES)
def test_fabricated_case_law_is_flagged(text: str) -> None:
    findings = find_fabricated_case_law(text, today=REFERENCE_DATE)
    assert findings, f"no fabrication detected in: {text!r}"


# ---- Cases that MUST pass (real shape, in-range) ---------------------------

VALID_CASES = [
    # CJEU canonical, two-digit year, post-1989.
    "In Case C-311/18 (Schrems II), the CJEU invalidated the Privacy Shield.",
    "The General Court's judgment in T-612/17 is cited in the memo.",
    # CJEU canonical, four-digit year, post-1989.
    "Per Case C-131/2012, the right to be forgotten was articulated.",
    # Current year.
    "The recent Case C-100/26 reached the Court this term.",
    # Next year (pre-allocation tolerance).
    "The reserved number C-001/27 has not yet been argued.",
    # CNIL SAN in valid range.
    "CNIL Délibération SAN-2023-024 fined the controller EUR 40 million.",
    "Per SAN-2019-010 the CNIL imposed its largest sanction at the time.",
    # Current-year SAN.
    "The most recent sanction SAN-2026-003 is on appeal.",
]


@pytest.mark.parametrize("text", VALID_CASES)
def test_valid_case_law_passes(text: str) -> None:
    findings = find_fabricated_case_law(text, today=REFERENCE_DATE)
    assert findings == [], (
        f"false positive on real citation: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (no case citation present) -----------------------

NO_CITATION_CASES = [
    "The vendor produces quarterly audit reports.",
    "Section 12.3 of the agreement governs data handling.",
    # Date ranges, not case IDs.
    "Cases from 1952-1960 established the Court's jurisprudence.",
    # Non-citation alphanumeric — the malformed matcher should NOT fire
    # without CJEU context.
    "The part number C.237/23 appears on the invoice.",
    "Serial F-100-22 was stamped on the housing.",
    "Version T-442-22 of the internal tool was deprecated.",
    # "SAN" without the SAN-YYYY-NNN shape.
    "The SAN storage fabric is documented in appendix C.",
    # Bare "Case" mention without an identifier.
    "This case was decided in the claimant's favour.",
]


@pytest.mark.parametrize("text", NO_CITATION_CASES)
def test_no_citation_cases_are_not_flagged(text: str) -> None:
    findings = find_fabricated_case_law(text, today=REFERENCE_DATE)
    assert findings == [], (
        f"spurious match where no citation given: {text!r} → {findings!r}"
    )


# ---- Boundary behaviour ----------------------------------------------------


def test_cjeu_first_year_boundary() -> None:
    # 1989 is the first year of the [CTF]-NNN/YY scheme; 1988 flagged.
    assert find_fabricated_case_law(
        "Case C-001/89 is among the earliest under the new scheme.",
        today=REFERENCE_DATE,
    ) == []
    assert find_fabricated_case_law(
        "Case C-001/88 cannot use the [CTF]- scheme.",
        today=REFERENCE_DATE,
    )


def test_cjeu_future_year_tolerance_is_one_year() -> None:
    # Reference 2026 → 2027 allowed, 2028 flagged.
    assert find_fabricated_case_law(
        "Case C-001/27 has been reserved.", today=REFERENCE_DATE
    ) == []
    assert find_fabricated_case_law(
        "Case C-001/28 is cited in the brief.", today=REFERENCE_DATE
    )


def test_cnil_san_first_year_boundary() -> None:
    # SAN-2000 allowed (conservative lower bound), SAN-1999 flagged.
    assert find_fabricated_case_law(
        "SAN-2000-001 was issued under the early scheme.",
        today=REFERENCE_DATE,
    ) == []
    assert find_fabricated_case_law(
        "SAN-1999-001 predates the current numbering.",
        today=REFERENCE_DATE,
    )


def test_two_digit_year_windowing() -> None:
    # YY in [89, 99] → 19YY; otherwise → 20YY.
    # 1995 (C-001/95) is valid; 2095 is absurdly future.
    assert find_fabricated_case_law(
        "Case C-001/95 is cited in the note.", today=REFERENCE_DATE
    ) == []
    findings = find_fabricated_case_law(
        "Case C-001/95 and Case C-001/2095 are discussed.",
        today=REFERENCE_DATE,
    )
    assert len(findings) == 1
    assert findings[0].year == 2095


def test_malformed_requires_cjeu_context() -> None:
    """Malformed shapes only fire with explicit CJEU/Court-of-Justice nearby."""
    # No context — should NOT fire.
    assert find_fabricated_case_law(
        "The part code C.237/23 was shipped yesterday.",
        today=REFERENCE_DATE,
    ) == []
    # With context — should fire.
    findings = find_fabricated_case_law(
        "The CJEU ruled in C.237/23 against the defendant.",
        today=REFERENCE_DATE,
    )
    assert findings
    assert "non-canonical separators" in findings[0].reason


def test_mixed_valid_and_fabricated() -> None:
    text = (
        "In Case C-311/18 (Schrems II), the CJEU invalidated the Privacy "
        "Shield, while the later Case C-100/2099 is purely speculative."
    )
    findings = find_fabricated_case_law(text, today=REFERENCE_DATE)
    assert len(findings) == 1
    assert findings[0].year == 2099


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_fabrication() -> None:
    result = case_law_report(
        "Case C-100/2099 was cited in the opinion.",
        today=REFERENCE_DATE,
    )
    assert result["has_fabricated_case_law"] is True
    assert result["fabrication_count"] == 1
    assert any("2099" in s for s in result["samples"])


def test_report_shape_for_clean() -> None:
    result = case_law_report(
        "Case C-311/18 (Schrems II) is the leading authority.",
        today=REFERENCE_DATE,
    )
    assert result == {
        "has_fabricated_case_law": False,
        "fabrication_count": 0,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "The memo cites C-001/2099, C-002/2098, C-003/2097, "
        "and C-004/2096 as speculative."
    )
    result = case_law_report(text, today=REFERENCE_DATE)
    assert result["fabrication_count"] == 4
    assert len(result["samples"]) == 3
