"""Pure-Python detection of jurisdiction-mismatch citations.

Generalist models frequently apply a regulation to an entity outside
that regulation's jurisdictional scope — "the German vendor must
comply with HIPAA", "our US subsidiary falls under DORA". These
mismatches are category errors, not hedgeable opinions, and they
travel into audit deliverables with an air of authority.

Approach:
- A narrow list of "strict-scope" regulations — ones whose
  applicability is tightly bound to a single jurisdiction and which
  do NOT have broad extraterritorial reach. GDPR and the AI Act are
  deliberately excluded because their Article 3 / Article 2 reach
  means a US or UK entity can genuinely be subject to them.
- A jurisdiction-marker list — US / EU / UK tokens, plus the major
  EU member-state adjectives an audit report tends to use.
- For each sentence-level window, if a strict-scope regulation
  co-occurs with a jurisdiction marker from a different zone, and
  the sentence does not contain a negation/comparison/hypothetical
  phrase, the sentence is flagged.

The goal is not semantic precision — it is to refuse obvious
cross-jurisdiction confabulations before they land in a report.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Regulations whose scope is jurisdiction-bound with no material
# extraterritorial reach. GDPR, UK GDPR, and the AI Act are
# intentionally omitted — each has Article 3 / Article 2
# extraterritorial provisions that make cross-zone citations
# legitimate in common audit scenarios.
_STRICT_SCOPE_REGULATIONS: list[tuple[re.Pattern[str], str]] = [
    # US
    (re.compile(r"\bHIPAA\b", re.IGNORECASE), "US"),
    (re.compile(r"\bCCPA\b"), "US"),
    (re.compile(r"\bCPRA\b"), "US"),
    (re.compile(r"\bSarbanes[-\s]?Oxley\b", re.IGNORECASE), "US"),
    (re.compile(r"\bSOX\b"), "US"),
    (re.compile(r"\bGLBA\b"), "US"),
    (re.compile(r"\bGramm[-\s]?Leach[-\s]?Bliley\b", re.IGNORECASE), "US"),
    (re.compile(r"\bHITECH\b"), "US"),
    (re.compile(r"\bFERPA\b"), "US"),
    (re.compile(r"\bFISMA\b"), "US"),
    # EU
    (re.compile(r"\bDORA\b"), "EU"),
    (re.compile(r"\bNIS\s?2\b"), "EU"),
    (re.compile(r"\beIDAS\b", re.IGNORECASE), "EU"),
    # UK — must match before bare "GDPR" (GDPR isn't in this list,
    # but "UK GDPR" needs to be recognised as the UK-scope regulation
    # so the bare-GDPR jurisdiction marker doesn't misfire).
    (re.compile(r"\bUK\s+GDPR\b", re.IGNORECASE), "UK"),
    (re.compile(r"\bData Protection Act 2018\b", re.IGNORECASE), "UK"),
    (re.compile(r"\bDPA\s?2018\b", re.IGNORECASE), "UK"),
]


# Jurisdiction markers grouped into zones. Order matters only for
# readability — longest alternatives should come first inside each
# alternation so "United States" beats "US" on overlapping spans.
_JURISDICTION_MARKERS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:United States|U\.S\.A\.|U\.S\.|USA|US|American(?:s)?)\b",
        ),
        "US",
    ),
    (
        re.compile(
            r"\b(?:European Union|E\.U\.|EU|European|EEA|"
            r"Germany|German|France|French|Netherlands|Dutch|"
            r"Italy|Italian|Spain|Spanish|Ireland|Irish|"
            r"Belgium|Belgian|Austria|Austrian|Poland|Polish|"
            r"Sweden|Swedish|Denmark|Danish|Finland|Finnish)\b",
        ),
        "EU",
    ),
    (
        re.compile(
            r"\b(?:United Kingdom|U\.K\.|UK|British|Britain)\b",
        ),
        "UK",
    ),
]


# Phrases that neutralise an apparent mismatch: explicit negation,
# comparison, analogy, or hypothetical framing. If any of these
# appear in the sentence, skip mismatch detection for that sentence.
_NEGATION_OR_COMPARISON = re.compile(
    r"\b(?:"
    r"does not apply|do not apply|doesn'?t apply|don'?t apply|"
    r"not subject to|not governed by|not applicable|"
    r"outside the scope|"
    r"unlike|whereas|compared to|compared with|in contrast to|"
    r"rather than|instead of|differs from|"
    r"similar to|mirrors?|corresponds to|"
    r"versus|vs\.?|"
    r"equivalent|analog(?:ue|ous)|extraterritorial|"
    r"\bif\b[^.;]{0,80}?\b(?:were|was)\b|"
    r"would (?:be|have been|also be) subject to|"
    r"would (?:apply|fall under|be governed|cover)|"
    r"hypothetically"
    r")\b",
    re.IGNORECASE,
)


# Sentence-boundary split. Keep light — a full-grammar splitter is
# not worth the dependency. Semicolons are treated as sentence-like
# clause breaks because audit prose often runs long.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|;\s+")


@dataclass
class JurisdictionFinding:
    """A jurisdiction-mismatch citation located in text."""

    sentence: str
    regulation: str
    regulation_zone: str
    jurisdiction: str
    jurisdiction_zone: str


def find_jurisdiction_mismatches(text: str) -> list[JurisdictionFinding]:
    """Return every jurisdiction-mismatch citation in `text`."""
    findings: list[JurisdictionFinding] = []
    for sentence in _SENTENCE_SPLIT.split(text):
        sentence = sentence.strip()
        if not sentence:
            continue
        if _NEGATION_OR_COMPARISON.search(sentence):
            continue

        # Find regulation matches first, consuming their spans so a
        # marker embedded in the regulation phrase (e.g. "UK" inside
        # "UK GDPR") is not double-counted as a jurisdiction marker.
        reg_matches: list[tuple[str, str, tuple[int, int]]] = []
        for pattern, zone in _STRICT_SCOPE_REGULATIONS:
            for match in pattern.finditer(sentence):
                reg_matches.append(
                    (match.group(0), zone, (match.start(), match.end()))
                )
        if not reg_matches:
            continue

        def _inside_regulation_span(span: tuple[int, int], _regs=reg_matches) -> bool:
            return any(
                rs <= span[0] and span[1] <= re_
                for _, _, (rs, re_) in _regs
            )

        jurisdiction_matches: list[tuple[str, str]] = []
        for pattern, zone in _JURISDICTION_MARKERS:
            for match in pattern.finditer(sentence):
                if _inside_regulation_span((match.start(), match.end())):
                    continue
                jurisdiction_matches.append((match.group(0), zone))
        if not jurisdiction_matches:
            continue

        for reg_text, reg_zone, _ in reg_matches:
            for juris_text, juris_zone in jurisdiction_matches:
                if juris_zone != reg_zone:
                    findings.append(
                        JurisdictionFinding(
                            sentence=sentence,
                            regulation=reg_text,
                            regulation_zone=reg_zone,
                            jurisdiction=juris_text,
                            jurisdiction_zone=juris_zone,
                        )
                    )

    return findings


def jurisdiction_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_jurisdiction_mismatches(text)
    return {
        "has_jurisdiction_mismatch": bool(findings),
        "mismatch_count": len(findings),
        "samples": [
            f"{f.regulation} ({f.regulation_zone}) applied to "
            f"{f.jurisdiction} ({f.jurisdiction_zone})"
            for f in findings[:3]
        ],
    }
