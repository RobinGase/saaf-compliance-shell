"""Pure-Python detection of absolutist security/compliance claims.

Sibling rail to `verdict_rule.py`. Where the verdict rail catches
"vendor is compliant" with no evidence anchor, this rail catches
claims that are inappropriate in audit language regardless of
whether an anchor is present — "100% secure", "zero risk",
"impossible to breach". Audit conclusions are probabilistic and
point-in-time; unqualified absolutes are a hallucination signature.

Kept narrow: only phrases that are effectively never valid in an
audit deliverable. Ordinary hedged language ("designed to be
resilient", "expected to pass") is not flagged.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# Phrases that claim absolute security, absolute compliance, or
# absolute absence of risk. Case-insensitive. Tight by design —
# each pattern here is something an auditor would not write.
_ABSOLUTISM_PATTERNS = [
    # "100% secure" / "100 % compliant" / "100% guaranteed" / "100% uptime"
    r"\b100\s*%\s+(?:secure|safe|compliant|protected|guaranteed|reliable|available|uptime|availability)\b",
    # "zero risk" / "no risk" / "zero downtime" / "no downtime"
    r"\b(?:zero|no)\s+(?:risk|risks|vulnerabilities|breaches|failures|downtime|outages)\b",
    r"\brisk[- ]free\b",
    # "completely/absolutely/fully/perfectly secure|safe|compliant|..."
    r"\b(?:completely|absolutely|perfectly)\s+(?:secure|safe|protected|compliant|tamper[- ]proof)\b",
    # "cannot be breached/compromised/hacked/exploited/penetrated"
    r"\b(?:cannot|can\s*not|will\s+never|could\s+never)\s+be\s+(?:breached|compromised|hacked|exploited|penetrated)\b",
    # "never fails" / "never fail" / "never failed" used as a claim
    r"\bnever\s+fails?\b",
    # "impossible to breach|compromise|hack|exploit|penetrate"
    r"\bimpossible\s+to\s+(?:breach|compromise|hack|exploit|penetrate)\b",
    # "guaranteed secure" / "guaranteed compliant" / "guaranteed to pass"
    r"\bguaranteed\s+(?:secure|safe|compliant|protected|to\s+pass)\b",
    # "always compliant" / "always secure"
    r"\balways\s+(?:compliant|secure|safe|protected)\b",
    # "perfect security|compliance|protection"
    r"\bperfect\s+(?:security|compliance|protection)\b",
    # "unhackable" / "unbreakable" — marketing words that should never
    # appear in an audit deliverable.
    r"\bunhackable\b",
    r"\bunbreakable\b",
]

_absolutism_re = re.compile("|".join(_ABSOLUTISM_PATTERNS), re.IGNORECASE)


@dataclass
class AbsolutismFinding:
    """An absolutist claim located in text."""

    phrase: str
    start: int
    end: int


def find_absolutist_claims(text: str) -> list[AbsolutismFinding]:
    """Return every absolutist claim located in `text`."""
    return [
        AbsolutismFinding(phrase=m.group(0), start=m.start(), end=m.end())
        for m in _absolutism_re.finditer(text)
    ]


def absolutism_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_absolutist_claims(text)
    return {
        "has_absolutist_claim": bool(findings),
        "claim_count": len(findings),
        "samples": [f.phrase for f in findings[:3]],
    }
