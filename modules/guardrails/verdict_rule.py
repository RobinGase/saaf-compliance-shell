"""Pure-Python detection of unfounded compliance verdicts.

Separated from `guardrails/actions/verdict_check.py` (which wraps this
logic as a NeMo Guardrails action) so the detection can be unit-tested
without a nemoguardrails install.

See tests/test_verdict_check.py for the blocked/pass/non-verdict matrix
that documents the rail's intended behaviour.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Verdict phrases that claim compliance in absolutes. Case-insensitive.
# Kept intentionally narrow for high precision. A true positive is
# "vendor X is compliant with ISO 27001"; a false positive would block
# too much normal discussion.
_VERDICT_PATTERNS = [
    r"\b(?:is|are)\s+(?:fully\s+|wholly\s+|entirely\s+)?compliant\b",
    r"\b(?:fully\s+|wholly\s+)?meets\s+all\s+(?:the\s+)?requirements\b",
    r"\bpasses\s+all\s+(?:the\s+)?requirements\b",
    r"\bis\s+certified\s+(?:for|to|with|under|against)\b",
    r"\bconforms\s+(?:fully\s+)?to\b",
    r"\bsatisfies\s+(?:all|each|every)(?:\s+and\s+(?:all|each|every))?(?:\s+\S+){0,3}?\s+(?:requirements?|obligations?)\b",
    r"\bfulfill(?:ed|s)?(?:\s+(?:all|each|every))?(?:\s+\S+){0,3}?\s+(?:requirements?|obligations?)\b",
    r"\b(?:requirements?|obligations?)\s+have\s+been\s+(?:fully\s+)?fulfilled\b",
    r"\bin\s+full\s+compliance\s+with\b",
    # Nominalization forms — "compliance"/"conformance" as a noun object.
    # LLM verdict sections frequently use these constructions instead of
    # the active-voice "is compliant" shape above: "compliance was
    # demonstrated", "GDPR compliance has been achieved", "the vendor
    # shows complete compliance".
    r"\b(?:demonstrates?|demonstrated|achieves?|achieved|establishes?|established|shows?|showed|confirms?|confirmed)\s+(?:full\s+|complete\s+|total\s+)?(?:\S+\s+){0,2}?(?:compliance|conformance)\b",
    r"\b(?:compliance|conformance)(?:\s+with\s+\S+)?\s+(?:has\s+been|have\s+been|was|were|is)\s+(?:fully\s+|completely\s+)?(?:demonstrated|achieved|established|confirmed|shown)\b",
]

# Evidence anchor phrases. Within the window around a verdict, presence
# of any of these is treated as the agent having shown its source.
_EVIDENCE_PATTERNS = [
    r"\bper\s+(?:section|§|clause|article|art\.)",
    r"\baccording\s+to\b",
    r"\bas\s+(?:shown|evidenced|stated|documented|described)\s+in\b",
    r"\bas\s+per\b",
    r"\bbased\s+on\b.{0,40}\b(?:report|audit|attestation|certificate|assessment|evidence|questionnaire)\b",
    r"\[(?:ref|doc|cite|source):",
    r"\(§\s*\d",
    r"\b(?:Section|§|Art\.?|Article|Chapter|Clause)\s+\d",
    r"\bas\s+shown\s+by\s+the\b",
    r"\b(?:SOC\s?2|ISAE\s?3402|ISO\s?\d{4,5})\s+(?:report|attestation|certificate)\b",
]

# Window of characters around a verdict in which to look for an anchor.
ANCHOR_WINDOW_CHARS = 200

_verdict_re = re.compile("|".join(_VERDICT_PATTERNS), re.IGNORECASE)
_evidence_re = re.compile("|".join(_EVIDENCE_PATTERNS), re.IGNORECASE)


@dataclass
class VerdictFinding:
    """A verdict phrase located in the scanned text."""

    phrase: str
    start: int
    end: int
    has_evidence: bool


def find_unfounded_verdicts(
    text: str, window: int = ANCHOR_WINDOW_CHARS
) -> list[VerdictFinding]:
    """Return verdicts in `text`, each flagged founded or unfounded.

    A verdict is "founded" if an evidence anchor appears within `window`
    characters before or after the verdict match. Otherwise unfounded.
    """
    findings: list[VerdictFinding] = []
    for match in _verdict_re.finditer(text):
        start = max(0, match.start() - window)
        end = min(len(text), match.end() + window)
        surrounding = text[start:end]
        has_evidence = bool(_evidence_re.search(surrounding))
        findings.append(
            VerdictFinding(
                phrase=match.group(0),
                start=match.start(),
                end=match.end(),
                has_evidence=has_evidence,
            )
        )
    return findings


def verdict_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_unfounded_verdicts(text)
    unfounded = [f for f in findings if not f.has_evidence]
    return {
        "has_unfounded_verdict": bool(unfounded),
        "verdict_count": len(findings),
        "unfounded_count": len(unfounded),
        "samples": [f.phrase for f in unfounded[:3]],
    }
