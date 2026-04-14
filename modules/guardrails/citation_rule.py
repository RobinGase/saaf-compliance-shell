"""Pure-Python detection of fabricated EU-regulation article numbers.

General-purpose LLMs hallucinate article numbers routinely — "GDPR
Article 237" and "DORA Article 89" are common failure modes because
the model knows the regulation name and is confident about the
citation shape, but the article number is drawn from the prior text
rather than the regulation's actual contents. This rule catches
obvious range-violation fabrications; it does not — and cannot —
validate that an in-range article number says what the agent claims
it says. Semantic accuracy is outside this rail's scope.

Approach:
- Known regulations are listed with their highest real article number.
- Citations are extracted in either order ("GDPR Art. 5" and
  "Article 5 of GDPR") and normalised to (framework, article_number).
- Any article number above the known max is flagged as fabricated.
- Recitals, annexes, and ISO-style control numbers (A.5.1) are
  deliberately ignored — they use different numbering and need
  different validation approaches.

Separated from the @action wrapper so CI can run these tests without
a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Highest real article number per regulation. Sources:
#   GDPR    — Regulation (EU) 2016/679: 99 articles.
#   DORA    — Regulation (EU) 2022/2554: 64 articles.
#   NIS2    — Directive (EU) 2022/2555: 46 articles.
#   AI Act  — Regulation (EU) 2024/1689: 113 articles.
#
# Only the maximum is stored — we're rejecting obvious out-of-range
# fabrications, not claiming every in-range citation is accurate.
_FRAMEWORKS: dict[str, int] = {
    "GDPR": 99,
    "DORA": 64,
    "NIS2": 46,
    "AI_ACT": 113,
}


# Aliases the model may use for each framework. Matched case-insensitively.
# Keys here map to the _FRAMEWORKS keys above. Order matters inside each
# list only for regex alternation efficiency.
_ALIASES: dict[str, list[str]] = {
    "GDPR": [
        r"GDPR",
        r"AVG",  # Dutch abbreviation
        r"General Data Protection Regulation",
        r"Regulation\s*\(EU\)\s*2016/679",
    ],
    "DORA": [
        r"DORA",
        r"Digital Operational Resilience Act",
        r"Regulation\s*\(EU\)\s*2022/2554",
    ],
    "NIS2": [
        r"NIS\s*2",
        r"NIS2",
        r"Directive\s*\(EU\)\s*2022/2555",
    ],
    "AI_ACT": [
        r"EU\s+AI\s+Act",
        r"AI\s+Act",
        r"Artificial\s+Intelligence\s+Act",
        r"Regulation\s*\(EU\)\s*2024/1689",
    ],
}


def _alias_group(framework: str) -> str:
    """Return a non-capturing regex group that matches any alias."""
    return "(?:" + "|".join(_ALIASES[framework]) + ")"


# One pattern per framework, matching both "FRAMEWORK Art. N" and
# "Article N <connective>? FRAMEWORK". The article number is captured
# as group "num". `Artikel` is included alongside `Art.`/`Article` so
# Dutch-language citations against AVG/GDPR are matched by the same rule.
# The reverse-phrasing connective accepts multiple English prepositions
# (of, under, in, within, from, as part of) and their Dutch equivalents
# (van) so paraphrased citations like "Article 237 under GDPR" and
# "Article 237 as part of GDPR" are caught alongside the canonical
# "Article 237 of the GDPR" / "artikel 237 van de AVG".
def _framework_pattern(framework: str) -> re.Pattern[str]:
    alias = _alias_group(framework)
    # Reverse-phrasing connective between "Article N" and the framework
    # alias. Covers four shapes:
    #   1. Canonical prepositions: "of", "van", "under", "in", "within",
    #      "from", "as part of", each with an optional definite article
    #      ("the", "de", "het"). An optional generic noun ("regulation",
    #      "directive", "act") may sit between the article and a
    #      parenthesised framework name — "Article 237 of the regulation
    #      (GDPR)".
    #   2. Em-dash or en-dash clusters with optional "see"/"per"/"under":
    #      "Article 237 — see GDPR —".
    #   3. Comma-delimited qualifier: "Article 237, per GDPR, ...".
    #   4. Bare juxtaposition: "Article 100 GDPR" (whitespace only).
    connective = (
        r"(?:"
        r"\s+(?:of|van|under|in|within|from|as\s+part\s+of)\s+"
        r"(?:the\s+|de\s+|het\s+)?"
        r"(?:(?:regulation|directive|act|law|rules?)\s*\(\s*)?"
        r"|"
        r"\s*[—–]+\s*(?:see\s+|per\s+|under\s+)?"
        r"|"
        r"\s*,\s*(?:per\s+|see\s+|under\s+)"
        r"|"
        r"\s+"
        r")"
    )
    # Branch A also accepts a possessive suffix on the alias ("GDPR's
    # Article 237") and both ASCII and typographic apostrophes.
    pattern = (
        rf"(?:{alias}(?:['\u2019]s)?\s*(?:Art\.?|Article|Artikel)\s*(?P<num_a>\d+)"
        rf"|(?:Art\.?|Article|Artikel)\s+(?P<num_b>\d+){connective}{alias}\s*\)?)"
    )
    return re.compile(pattern, re.IGNORECASE)


_PATTERNS: dict[str, re.Pattern[str]] = {
    framework: _framework_pattern(framework) for framework in _FRAMEWORKS
}


# Context tokens that mean the number is NOT an article — used to
# filter false positives like "recital 47" being mistaken for an
# article because the word "Article" happens to appear nearby.
# (Currently the regex already anchors on "Art."/"Article" so these
# aren't strictly needed, but the list is kept as documentation of
# what is intentionally out of scope.)
# _OUT_OF_SCOPE = {"recital", "annex", "chapter", "section"}


@dataclass
class CitationFinding:
    """A regulation-article citation located in text."""

    framework: str
    article_number: int
    max_valid: int
    phrase: str
    start: int
    end: int

    @property
    def is_fabricated(self) -> bool:
        return self.article_number > self.max_valid


def find_article_citations(text: str) -> list[CitationFinding]:
    """Return every regulation-article citation detected in `text`."""
    findings: list[CitationFinding] = []
    for framework, pattern in _PATTERNS.items():
        max_valid = _FRAMEWORKS[framework]
        for match in pattern.finditer(text):
            num_str = match.group("num_a") or match.group("num_b")
            num = int(num_str)
            findings.append(
                CitationFinding(
                    framework=framework,
                    article_number=num,
                    max_valid=max_valid,
                    phrase=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
    # Sort by position so the order of findings matches reading order,
    # regardless of which framework's regex matched first.
    findings.sort(key=lambda f: f.start)
    return findings


def citation_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_article_citations(text)
    fabricated = [f for f in findings if f.is_fabricated]
    return {
        "has_fabricated_citation": bool(fabricated),
        "citation_count": len(findings),
        "fabricated_count": len(fabricated),
        "samples": [
            f"{f.framework} Art. {f.article_number} (max {f.max_valid})"
            for f in fabricated[:3]
        ],
    }
