"""Pure-Python detection of stale attestation references.

Compliance evidence has a shelf life. SOC 2 Type II reports cover a
12-month window and are considered current for roughly 12–18 months
after issuance; ISAE 3402 and ISO 27001 certificates have similar
windows. When a model writes "per the 2019 SOC 2 report" in 2026,
the citation is technically a real document but no longer valid as
current evidence — the control environment it describes may have
changed substantially.

This rail flags attestation references with an embedded year that
is older than `max_age_years` (default: 2) relative to a reference
date. Year-granularity only — sharper windows would need issue-date
extraction, which models rarely provide in running prose.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date


# Attestation/audit-report shapes the rail cares about. Kept narrow:
# each pattern must name a recognised attestation/report family so
# ordinary year references (e.g. "the 2019 incident", "per the 2019
# contract") don't trigger the rail.
_ATTESTATION_WORDS = (
    r"SOC\s?[12](?:\s+Type\s+[I1]{1,2})?"
    r"|ISAE\s?\d{4}"
    r"|ISO\s?/?IEC\s?\d{4,5}(?:[:\-]\d{4})?"
    r"|ISO\s?\d{4,5}(?:[:\-]\d{4})?"
    r"|PCI\s+DSS"
    r"|NIST\s+\d{3}-\d+"
    r"|(?:Type\s+[I1]{1,2})"
)

_ATTESTATION_KIND = r"(?:report|attestation|certificate|audit|assessment)"

# Three phrasings a model produces:
#   "per the 2019 SOC 2 report"
#   "SOC 2 report from 2019"
#   "ISO 27001 certificate dated 2020"
# Year captured as group "year".
_PATTERNS = [
    # "(per the|the|a) YYYY <attestation-word>[ report]"
    re.compile(
        rf"(?:per\s+the\s+|the\s+|a\s+)?(?P<year>\d{{4}})\s+"
        rf"(?:{_ATTESTATION_WORDS})(?:\s+{_ATTESTATION_KIND})?\b",
        re.IGNORECASE,
    ),
    # "<attestation-word> [report] (from|dated|issued in|of) YYYY"
    re.compile(
        rf"(?:{_ATTESTATION_WORDS})(?:\s+{_ATTESTATION_KIND})?\s+"
        rf"(?:from|dated|issued\s+in|of)\s+(?P<year>\d{{4}})\b",
        re.IGNORECASE,
    ),
]


@dataclass
class StaleDateFinding:
    """A stale attestation reference located in text."""

    phrase: str
    year: int
    age_years: int
    start: int
    end: int


def find_stale_attestations(
    text: str,
    *,
    today: date | None = None,
    max_age_years: int = 2,
) -> list[StaleDateFinding]:
    """Return attestation references older than `max_age_years`.

    `today` defaults to `date.today()`; tests pass an explicit value so
    fixtures don't rot over calendar time.
    """
    today = today or date.today()
    findings: list[StaleDateFinding] = []
    seen: set[tuple[int, int]] = set()
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            span = (match.start(), match.end())
            if span in seen:
                continue
            seen.add(span)
            year = int(match.group("year"))
            age = today.year - year
            # Skip obvious non-years (future dates, 4-digit numbers
            # that are not years — e.g. ISO 27001 has "27001" but the
            # regex captures YYYY separately).
            if year < 1990 or year > today.year:
                continue
            if age > max_age_years:
                findings.append(
                    StaleDateFinding(
                        phrase=match.group(0),
                        year=year,
                        age_years=age,
                        start=match.start(),
                        end=match.end(),
                    )
                )
    findings.sort(key=lambda f: f.start)
    return findings


def stale_date_report(
    text: str,
    *,
    today: date | None = None,
    max_age_years: int = 2,
) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_stale_attestations(
        text, today=today, max_age_years=max_age_years
    )
    return {
        "has_stale_attestation": bool(findings),
        "stale_count": len(findings),
        "max_age_years": max_age_years,
        "samples": [
            f"{f.phrase.strip()} ({f.age_years}y old)" for f in findings[:3]
        ],
    }
