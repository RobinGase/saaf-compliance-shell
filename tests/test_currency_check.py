"""Tests for the currency/regulation-zone mismatch compliance rail.

Each regulation denominates its fines in a specific currency:
GDPR and the AI Act in euros (Art. 83 / Art. 99), SOX and HIPAA in
dollars, UK GDPR and the Data Protection Act 2018 in pounds. A model
citing a fine amount in the wrong currency is almost always
hallucinating the amount itself; this rail refuses output where a
regulation co-occurs with a wrong-zone currency in the same sentence.
"""

from __future__ import annotations

import pytest

from modules.guardrails.currency_rule import (
    currency_report,
    find_currency_mismatches,
)


# ---- Cases that MUST be flagged (wrong-currency citation) ------------------

MISMATCH_CASES = [
    # EU regulation + USD.
    "The GDPR allows fines up to $20 million.",
    "GDPR penalties can reach USD 20 million.",
    "DORA contemplates fines of $5 million per violation.",
    "NIS2 imposes penalties of up to 10 million dollars.",
    "The EU AI Act allows fines of $35 million for prohibited practices.",
    "Under the AI Act, penalties of US$10 million are contemplated.",
    "AVG-boetes kunnen oplopen tot $20 million.",  # Dutch + wrong currency
    # US regulation + EUR.
    "SOX penalties can reach €25 million for corporate violations.",
    "HIPAA fines are capped at €1.5 million per violation category.",
    "The CCPA allows for €7,500 per intentional violation.",
    "GLBA contemplates penalties of EUR 100,000 per violation.",
    # UK regulation + non-GBP.
    "UK GDPR fines are capped at €17.5 million or 4% of turnover.",
    "The Data Protection Act 2018 allows fines of $20 million.",
    # US regulation + GBP.
    "SOX imposes penalties of £5 million on corporate officers.",
    # EU regulation + GBP.
    "GDPR allows fines of up to £20 million.",
]


@pytest.mark.parametrize("text", MISMATCH_CASES)
def test_currency_mismatches_are_flagged(text: str) -> None:
    findings = find_currency_mismatches(text)
    assert findings, f"no finding in: {text!r}"


# ---- Cases that MUST pass (matching currency) ------------------------------

MATCHING_CURRENCY_CASES = [
    # EU regulations with euros.
    "The GDPR allows fines up to €20 million or 4% of annual turnover.",
    "GDPR penalties can reach EUR 20 million.",
    "DORA contemplates fines of €5 million per infringement.",
    "NIS2 imposes penalties of up to 10 million euros.",
    "The EU AI Act allows fines of €35 million for prohibited practices.",
    # US regulations with dollars.
    "SOX penalties can reach $25 million for corporate violations.",
    "HIPAA fines are capped at $1.5 million per violation category.",
    "GLBA contemplates penalties of USD 100,000 per violation.",
    # UK regulations with pounds.
    "UK GDPR fines are capped at £17.5 million or 4% of turnover.",
    "The Data Protection Act 2018 allows fines of GBP 17.5 million.",
]


@pytest.mark.parametrize("text", MATCHING_CURRENCY_CASES)
def test_matching_currency_passes(text: str) -> None:
    findings = find_currency_mismatches(text)
    assert findings == [], (
        f"false positive on matching currency: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (conversion / comparison / negation) -------------

CONVERSION_OR_COMPARISON_CASES = [
    "The €20M GDPR fine is equivalent to approximately $22M at current rates.",
    "GDPR fines of €20M can be converted to $22M USD at prevailing rates.",
    "Expressed in USD terms, the maximum GDPR fine is approximately $22M.",
    "Unlike SOX fines in dollars, DORA denominates penalties in euros.",
    "Whereas SOX uses dollars, GDPR fines are denominated in euros.",
    "Compared to HIPAA's $1.5M cap, GDPR's €20M ceiling is broader.",
    "If the GDPR fine were expressed in dollars, it would be approximately $22M.",
    "The GDPR fine of €20M is roughly $22M in today's dollars.",
    "HIPAA penalties are not denominated in euros.",
]


@pytest.mark.parametrize("text", CONVERSION_OR_COMPARISON_CASES)
def test_conversions_and_comparisons_are_skipped(text: str) -> None:
    findings = find_currency_mismatches(text)
    assert findings == [], (
        f"spurious match in conversion/comparison: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (no currency / no regulation) --------------------

OUT_OF_SCOPE_CASES = [
    # Regulation without currency.
    "GDPR requires a lawful basis for processing.",
    "SOX mandates internal-control attestations.",
    "DORA came into force in January 2025.",
    # Currency without regulation.
    "The vendor reported $100 million in annual revenue.",
    "Our European subsidiary generated €50 million last year.",
    # Bare "pound" as a weight isn't likely paired with a regulation;
    # this case just confirms no regulation = no flag.
    "The shipment weighed 500 pounds.",
]


@pytest.mark.parametrize("text", OUT_OF_SCOPE_CASES)
def test_out_of_scope_cases_are_not_flagged(text: str) -> None:
    findings = find_currency_mismatches(text)
    assert findings == [], (
        f"spurious match in out-of-scope case: {text!r} → {findings!r}"
    )


# ---- Sentence scoping ------------------------------------------------------


def test_currency_detection_is_sentence_scoped() -> None:
    # GDPR in one sentence, $ in another — must not flag.
    text = (
        "GDPR requires a lawful basis for processing. "
        "Our US subsidiary had $20 million in revenue last year."
    )
    assert find_currency_mismatches(text) == []


def test_semicolon_separated_clauses_are_scoped_independently() -> None:
    text = (
        "GDPR requires a lawful basis; our US subsidiary "
        "reported $20 million in revenue."
    )
    assert find_currency_mismatches(text) == []


def test_uk_gdpr_is_recognised_as_gbp_scope() -> None:
    # "UK GDPR" with pounds should NOT be flagged — GBP matches the
    # UK GDPR zone even though bare "GDPR" maps to EUR.
    assert find_currency_mismatches(
        "UK GDPR fines reach £17.5 million."
    ) == []


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_mismatch() -> None:
    result = currency_report("The GDPR allows fines up to $20 million.")
    assert result["has_currency_mismatch"] is True
    assert result["mismatch_count"] == 1
    assert len(result["samples"]) == 1
    assert "GDPR" in result["samples"][0]
    assert "EUR" in result["samples"][0]
    assert "USD" in result["samples"][0]


def test_report_shape_for_clean() -> None:
    result = currency_report("GDPR allows fines up to €20 million.")
    assert result == {
        "has_currency_mismatch": False,
        "mismatch_count": 0,
        "samples": [],
    }


def test_samples_cap_at_three() -> None:
    text = (
        "GDPR allows fines up to $20 million. "
        "DORA imposes penalties of $5 million. "
        "NIS2 allows $10 million in fines. "
        "The AI Act contemplates $35 million penalties."
    )
    result = currency_report(text)
    assert result["mismatch_count"] == 4
    assert len(result["samples"]) == 3
