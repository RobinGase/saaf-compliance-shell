"""Pure-Python detection of fabricated CVE identifiers.

Generalist models routinely fabricate CVE numbers. The shape is
trivial to mimic (CVE-YYYY-NNNN) and the model is confident, but
the year or sequence number is drawn from recent attention rather
than the CVE List. Fabricated CVEs travel into vulnerability
write-ups with an air of precision that is hard to catch on review.

Approach:
- A CVE identifier matches `CVE-YYYY-NNNN+` where the sequence
  component has at least 4 digits (MITRE expanded the format in
  2014 to allow arbitrary-length sequences; the floor remains 4).
- Year must be in [1999, current_year + 1]. 1999 is the first
  year MITRE issued CVE IDs; a one-year future tolerance lets
  reserved identifiers for next year through.
- Sequence components shorter than 4 digits are flagged as
  malformed (the model has produced the right prefix but the
  wrong shape — a clear fabrication signature).
- Near-identifiers like "CVE 2024 1234" (spaces instead of
  dashes) are also flagged as malformed.

The rail does not verify that an in-range CVE actually exists in
the CVE List — that requires a live lookup and is outside scope.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date


# CVE program first issued identifiers in 1999.
_FIRST_CVE_YEAR = 1999

# A reserved CVE for next year is legitimate — MITRE pre-allocates.
_FUTURE_YEAR_TOLERANCE = 1

# Strict canonical form: CVE-YYYY-NNNN with 4+ digit sequence.
_CANONICAL_CVE = re.compile(r"\bCVE-(?P<year>\d{4})-(?P<seq>\d{4,})\b")

# Malformed shapes the model emits when it half-remembers the
# format: a 3-or-fewer-digit sequence, or spaces in place of the
# dashes. These are fabricated by construction — a real CVE ID
# never takes either shape.
_MALFORMED_SHORT_SEQ = re.compile(r"\bCVE-(?P<year>\d{4})-(?P<seq>\d{1,3})\b")
_MALFORMED_SPACED = re.compile(
    r"\bCVE[\s]+(?P<year>\d{4})[\s]+(?P<seq>\d+)\b"
)


@dataclass
class CVEFinding:
    """A fabricated CVE identifier located in text."""

    cve: str
    year: int | None
    sequence: str | None
    reason: str


def _canonical_findings(
    text: str, current_year: int
) -> list[CVEFinding]:
    findings: list[CVEFinding] = []
    upper = current_year + _FUTURE_YEAR_TOLERANCE
    for match in _CANONICAL_CVE.finditer(text):
        year = int(match.group("year"))
        seq = match.group("seq")
        if year < _FIRST_CVE_YEAR:
            findings.append(
                CVEFinding(
                    cve=match.group(0),
                    year=year,
                    sequence=seq,
                    reason=(
                        f"year predates the CVE program ({_FIRST_CVE_YEAR})"
                    ),
                )
            )
        elif year > upper:
            findings.append(
                CVEFinding(
                    cve=match.group(0),
                    year=year,
                    sequence=seq,
                    reason=f"year is in the far future (> {upper})",
                )
            )
    return findings


def _malformed_findings(text: str) -> list[CVEFinding]:
    findings: list[CVEFinding] = []
    for match in _MALFORMED_SHORT_SEQ.finditer(text):
        findings.append(
            CVEFinding(
                cve=match.group(0),
                year=int(match.group("year")),
                sequence=match.group("seq"),
                reason="sequence component shorter than 4 digits",
            )
        )
    for match in _MALFORMED_SPACED.finditer(text):
        findings.append(
            CVEFinding(
                cve=match.group(0),
                year=int(match.group("year")),
                sequence=match.group("seq"),
                reason="CVE identifier uses spaces instead of dashes",
            )
        )
    return findings


def find_fabricated_cves(
    text: str,
    *,
    today: date | None = None,
) -> list[CVEFinding]:
    """Return every fabricated CVE identifier in `text`."""
    reference = today or date.today()
    findings: list[CVEFinding] = []
    findings.extend(_canonical_findings(text, reference.year))
    findings.extend(_malformed_findings(text))
    return findings


def cve_report(
    text: str,
    *,
    today: date | None = None,
) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_fabricated_cves(text, today=today)
    return {
        "has_fabricated_cve": bool(findings),
        "fabrication_count": len(findings),
        "samples": [f"{f.cve} — {f.reason}" for f in findings[:3]],
    }
