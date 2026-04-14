"""Pure-Python detection of fabricated standards-version numbers.

Generalist models routinely hallucinate version/year stamps on
standards — "ISO 27001:3000", "ISO 9001:2030", "PCI DSS v9.0",
"NIST SP 800-53 Rev 12". The standard exists, the citation shape
is correct, but the version token is drawn from the model's
near-term attention rather than the standard's actual revision
history. These pass a casual reader because the prefix is real.

Approach:
- Per-standard maps of (a) known-valid year stamps for year-versioned
  standards (ISO 27001:YYYY) and (b) known-valid revision numbers
  for version-numbered standards (NIST SP 800-53 Rev N, PCI DSS vN).
- A year above `current_year + 1` is always flagged — the near-future
  window allows pre-announcements where the next revision is
  officially dated.
- A year below the first-published year for that standard is flagged.
- A revision number outside the known range is flagged.
- The rule ignores bare standard citations without a version token —
  "per ISO 27001" on its own is not this rail's job.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date


# Known year revisions per standard. Sources:
#   ISO/IEC 27001 — 2005, 2013, 2022.
#   ISO/IEC 27002 — 2005, 2013, 2022.
#   ISO 9001     — 1987, 1994, 2000, 2008, 2015.
#   ISO 22301    — 2012, 2019.
#   ISO 14001    — 1996, 2004, 2015.
#   ISO 20000-1  — 2005, 2011, 2018.
#   ISO 27017    — 2015.
#   ISO 27018    — 2014, 2019.
#   ISO 27701    — 2019.
#
# Years not in the set but within [first, current_year + 1] are not
# flagged here — the rail only refuses out-of-range fabrications, not
# every non-canonical year.
_ISO_STANDARDS: dict[str, tuple[int, int]] = {
    # label → (first_published_year, last_known_revision_year)
    "ISO 27001": (2005, 2022),
    "ISO/IEC 27001": (2005, 2022),
    "ISO 27002": (2005, 2022),
    "ISO/IEC 27002": (2005, 2022),
    "ISO 9001": (1987, 2015),
    "ISO 22301": (2012, 2019),
    "ISO 14001": (1996, 2015),
    "ISO 20000-1": (2005, 2018),
    "ISO/IEC 20000-1": (2005, 2018),
    "ISO 27017": (2015, 2015),
    "ISO/IEC 27017": (2015, 2015),
    "ISO 27018": (2014, 2019),
    "ISO/IEC 27018": (2014, 2019),
    "ISO 27701": (2019, 2019),
    "ISO/IEC 27701": (2019, 2019),
}


# PCI DSS version numbers that have actually been published. Current
# major branches are 3.x and 4.x; any version number outside this set
# is a fabrication candidate.
_PCI_DSS_VERSIONS: set[str] = {
    "1.0", "1.1", "1.2", "1.2.1",
    "2.0",
    "3.0", "3.1", "3.2", "3.2.1",
    "4.0", "4.0.1",
}


# NIST SP 800-53 revision numbers that have been published.
_NIST_800_53_REVISIONS: set[int] = {1, 2, 3, 4, 5}


# NIST CSF version numbers.
_NIST_CSF_VERSIONS: set[str] = {"1.0", "1.1", "2.0"}


# How far ahead of today a pre-announced revision is permitted before
# the rail refuses. One calendar year covers normal pre-publication
# cycles without tolerating obvious future-year fabrications.
_FUTURE_YEAR_TOLERANCE = 1


def _iso_pattern(label: str) -> re.Pattern[str]:
    """Build a pattern that matches "<label>:<YYYY>" with flexible spacing."""
    escaped = re.escape(label).replace(r"\ ", r"\s*")
    return re.compile(
        rf"\b{escaped}\s*[:\-]\s*(?P<year>\d{{4}})\b",
        re.IGNORECASE,
    )


_ISO_PATTERNS: list[tuple[re.Pattern[str], str, tuple[int, int]]] = [
    (_iso_pattern(label), label, window) for label, window in _ISO_STANDARDS.items()
]


# "PCI DSS v4.0" / "PCI DSS version 4.0" / "PCI DSS 4.0".
_PCI_DSS_PATTERN = re.compile(
    r"\bPCI\s*DSS\s*(?:v(?:ersion)?\s*)?(?P<ver>\d+(?:\.\d+){1,2})\b",
    re.IGNORECASE,
)


# "NIST SP 800-53 Rev. 5" / "NIST 800-53 Revision 5" / "800-53r5".
_NIST_800_53_PATTERN = re.compile(
    r"\b(?:NIST\s+)?(?:SP\s+)?800[-\s]?53\s*(?:Rev\.?|Revision|r)\s*(?P<rev>\d+)\b",
    re.IGNORECASE,
)


# "NIST CSF v2.0" / "Cybersecurity Framework 2.0".
_NIST_CSF_PATTERN = re.compile(
    r"\b(?:NIST\s+)?(?:Cybersecurity\s+Framework|CSF)\s*(?:v(?:ersion)?\s*)?(?P<ver>\d+(?:\.\d+)?)\b",
    re.IGNORECASE,
)


@dataclass
class StandardsVersionFinding:
    """A fabricated standards-version citation."""

    standard: str
    version: str
    reason: str
    phrase: str


def _iso_findings(
    text: str, current_year: int
) -> list[StandardsVersionFinding]:
    findings: list[StandardsVersionFinding] = []
    upper_bound = current_year + _FUTURE_YEAR_TOLERANCE
    for pattern, label, (first, _last_known) in _ISO_PATTERNS:
        for match in pattern.finditer(text):
            year = int(match.group("year"))
            if year < first:
                findings.append(
                    StandardsVersionFinding(
                        standard=label,
                        version=str(year),
                        reason=f"year predates first publication ({first})",
                        phrase=match.group(0),
                    )
                )
            elif year > upper_bound:
                findings.append(
                    StandardsVersionFinding(
                        standard=label,
                        version=str(year),
                        reason=f"year is in the far future (> {upper_bound})",
                        phrase=match.group(0),
                    )
                )
    return findings


def _pci_findings(text: str) -> list[StandardsVersionFinding]:
    findings: list[StandardsVersionFinding] = []
    for match in _PCI_DSS_PATTERN.finditer(text):
        version = match.group("ver")
        if version not in _PCI_DSS_VERSIONS:
            findings.append(
                StandardsVersionFinding(
                    standard="PCI DSS",
                    version=version,
                    reason="version not in the published set",
                    phrase=match.group(0),
                )
            )
    return findings


def _nist_800_53_findings(text: str) -> list[StandardsVersionFinding]:
    findings: list[StandardsVersionFinding] = []
    for match in _NIST_800_53_PATTERN.finditer(text):
        rev = int(match.group("rev"))
        if rev not in _NIST_800_53_REVISIONS:
            findings.append(
                StandardsVersionFinding(
                    standard="NIST SP 800-53",
                    version=f"Rev {rev}",
                    reason="revision outside the published range",
                    phrase=match.group(0),
                )
            )
    return findings


def _nist_csf_findings(text: str) -> list[StandardsVersionFinding]:
    findings: list[StandardsVersionFinding] = []
    for match in _NIST_CSF_PATTERN.finditer(text):
        version = match.group("ver")
        # Normalise bare "2" to "2.0" for set membership.
        normalized = version if "." in version else f"{version}.0"
        if normalized not in _NIST_CSF_VERSIONS:
            findings.append(
                StandardsVersionFinding(
                    standard="NIST CSF",
                    version=version,
                    reason="version not in the published set",
                    phrase=match.group(0),
                )
            )
    return findings


def find_fabricated_standards_versions(
    text: str,
    *,
    today: date | None = None,
) -> list[StandardsVersionFinding]:
    """Return every fabricated standards-version citation in `text`."""
    reference = today or date.today()
    findings: list[StandardsVersionFinding] = []
    findings.extend(_iso_findings(text, reference.year))
    findings.extend(_pci_findings(text))
    findings.extend(_nist_800_53_findings(text))
    findings.extend(_nist_csf_findings(text))
    return findings


def standards_version_report(
    text: str,
    *,
    today: date | None = None,
) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_fabricated_standards_versions(text, today=today)
    return {
        "has_fabricated_version": bool(findings),
        "fabrication_count": len(findings),
        "samples": [
            f"{f.standard} {f.version} — {f.reason}"
            for f in findings[:3]
        ],
    }
