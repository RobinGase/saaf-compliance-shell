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
# "Article N of (the) FRAMEWORK". The article number is captured as
# group "num". The framework label is carried outside the regex —
# one compiled pattern per framework, assembled below. `Artikel` is
# included alongside `Art.`/`Article` so Dutch-language citations
# against AVG/GDPR are matched by the same rule. The reverse-phrasing
# connective accepts both English `of (the)` and Dutch `van (de|het)`
# so "artikel 500 van de AVG" is caught alongside "Article 500 of GDPR".
def _framework_pattern(framework: str) -> re.Pattern[str]:
    alias = _alias_group(framework)
    connective = r"(?:of|van)\s+(?:the\s+|de\s+|het\s+)?"
    pattern = (
        rf"(?:{alias}\s*(?:Art\.?|Article|Artikel)\s*(?P<num_a>\d+)"
        rf"|(?:Art\.?|Article|Artikel)\s*(?P<num_b>\d+)\s*{connective}{alias})"
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
