"""Tests for the fabricated-article-citation compliance rail.

Article-number maxima per regulation (as of the rule's written-in
comment):

    GDPR     99 articles
    DORA     64 articles
    NIS2     46 articles
    AI Act  113 articles
"""

from __future__ import annotations

import pytest

from modules.guardrails.citation_rule import (
    citation_report,
    find_article_citations,
)

# ---- Cases that MUST be flagged (out-of-range article numbers) -------------

FABRICATED_CASES = [
    # GDPR has 99 articles; 237 does not exist.
    "The vendor's processing aligns with GDPR Article 237.",
    # DORA has 64 articles.
    "Per DORA Article 89, the vendor must maintain an ICT register.",
    # NIS2 has 46 articles.
    "NIS2 Art. 120 requires incident notification within 24 hours.",
    # AI Act has 113 articles.
    "The system is prohibited under AI Act Article 250.",
    # Reverse phrasing: "Article X of FRAMEWORK".
    "See Article 900 of GDPR for the full text.",
    # Dutch: AVG is the Dutch name for GDPR; "Artikel" is the Dutch
    # word for Article. Same 99-article ceiling applies.
    "Op grond van AVG Artikel 500 moet de verwerker de gegevens verwijderen.",
    # Dutch reverse phrasing: "artikel N van de AVG".
    "Zie artikel 500 van de AVG voor de volledige tekst.",
    # Dutch reverse phrasing without definite article.
    "Per artikel 200 van AVG moet de gegevensverwerker een register bijhouden.",
    # Dutch reverse phrasing with "van het" (used with neuter nouns).
    "Op basis van artikel 800 van het EU AI Act is het systeem verboden.",
    # Dutch reverse phrasing against DORA.
    "Volgens artikel 100 van DORA moet de entiteit een ICT-register bijhouden.",
    # Bare juxtaposition, no connective — common LLM phrasing.
    "The obligation derives from Article 237 GDPR.",
    # Bare juxtaposition against the AI Act.
    "See Article 250 AI Act for the ban on prohibited practices.",
]


@pytest.mark.parametrize("text", FABRICATED_CASES)
def test_fabricated_citations_are_flagged(text: str) -> None:
    findings = find_article_citations(text)
    assert findings, f"no citation detected in: {text!r}"
    assert any(f.is_fabricated for f in findings), (
        f"no fabricated finding in: {text!r} → {findings!r}"
    )


# ---- Cases that MUST pass (in-range citations) -----------------------------

VALID_CASES = [
    # GDPR Art. 5 — real.
    "GDPR Article 5 lays out the lawfulness-of-processing principles.",
    # GDPR Art. 99 — the last article, boundary case.
    "GDPR Art. 99 covers entry into force.",
    # DORA Art. 5 — real.
    "The vendor referenced DORA Art. 5 in the ICT risk framework.",
    # Reverse phrasing, in-range.
    "Per Article 30 of GDPR, records of processing must be maintained.",
    # NIS2, in-range.
    "NIS2 Article 21 governs cybersecurity risk-management measures.",
    # AI Act Art. 6 — real.
    "AI Act Article 6 defines high-risk systems.",
    # Sub-paragraph numbers — the rule extracts the main article number only.
    "GDPR Art. 6(1)(a) permits processing based on consent.",
    # Dutch in-range citation — AVG + Artikel maps to GDPR's 99-article ceiling.
    "AVG Artikel 5 stelt de beginselen van rechtmatige verwerking.",
    # Dutch reverse phrasing, in-range.
    "Zie artikel 30 van de AVG voor de registerplicht.",
    # Dutch reverse phrasing against DORA, in-range.
    "Artikel 5 van DORA beschrijft het ICT-risicokader.",
]


@pytest.mark.parametrize("text", VALID_CASES)
def test_valid_citations_pass(text: str) -> None:
    findings = find_article_citations(text)
    assert findings, f"no citation detected in: {text!r}"
    assert all(not f.is_fabricated for f in findings), (
        f"false positive in: {text!r} → {findings!r}"
    )


# ---- Cases that MUST NOT be detected (not an article citation) -------------

NON_CITATION_CASES = [
    # Recital, not article — GDPR has ~173 recitals and we deliberately
    # don't validate them.
    "GDPR Recital 47 explains the legitimate-interests balancing test.",
    # Plain framework mention, no article.
    "The vendor is subject to GDPR, DORA, and NIS2.",
    # Section-numbered citation, not article.
    "Per Section 3 of the SOC 2 report, encryption is in place.",
    # ISO control number — not this rail's job.
    "Control A.5.1 is implemented as described in Annex A.",
    # Year number next to "Article" but not as an article reference.
    "The Article was published in 2016 in the Official Journal.",
    # Sentence where a number follows "Article" and some later clause
    # mentions a framework — the bare-juxtaposition branch should not
    # span across intervening words.
    "Article 5 describes principles; subsequently the GDPR text follows.",
]


@pytest.mark.parametrize("text", NON_CITATION_CASES)
def test_non_citations_are_not_detected(text: str) -> None:
    findings = find_article_citations(text)
    assert findings == [], (
        f"spurious citation match in: {text!r} → {findings!r}"
    )


# ---- Framework identification ----------------------------------------------


def test_framework_is_identified_per_citation() -> None:
    text = "Compare GDPR Art. 5 with DORA Art. 5 and AI Act Article 6."
    findings = find_article_citations(text)
    frameworks = {f.framework for f in findings}
    assert {"GDPR", "DORA", "AI_ACT"} <= frameworks


def test_mixed_valid_and_fabricated() -> None:
    text = "GDPR Art. 5 is about principles; GDPR Art. 237 does not exist."
    findings = find_article_citations(text)
    assert len(findings) == 2
    valid, fabricated = sorted(findings, key=lambda f: f.article_number)
    assert valid.article_number == 5 and not valid.is_fabricated
    assert fabricated.article_number == 237 and fabricated.is_fabricated


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_fabrication() -> None:
    result = citation_report("Per GDPR Article 500, the vendor must comply.")
    assert result["has_fabricated_citation"] is True
    assert result["fabricated_count"] == 1
    assert result["citation_count"] == 1
    assert any("500" in s for s in result["samples"])


def test_report_shape_for_clean() -> None:
    result = citation_report("GDPR Art. 5 and DORA Art. 5 are both foundational.")
    assert result == {
        "has_fabricated_citation": False,
        "citation_count": 2,
        "fabricated_count": 0,
        "samples": [],
    }
