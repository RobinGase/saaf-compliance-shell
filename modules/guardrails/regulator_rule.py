"""Pure-Python detection of fabricated regulator / supervisory-body names.

Generalist models routinely invent plausible-sounding regulators —
"European Privacy Authority", "EU Cybersecurity Commission",
"Federal Data Protection Agency" (in a US context), "UK Privacy
Authority". The name sounds official, the citation shape is
authoritative, and a casual reader may not notice that the body
does not exist. The real body usually does (EDPB, ENISA, ICO),
which makes the fabrication especially misleading.

Approach:
- A narrow list of fabricated body names that models emit when they
  half-remember which acronym belongs to which jurisdiction.
- Each pattern is matched as a whole phrase (word-boundary anchored)
  so substrings of legitimate names do not trip the rail.
- The rail does NOT try to validate every regulator reference — that
  would require a full directory of supervisory authorities and
  their correct English / local-language names. It flags only the
  common confabulation patterns where the name is definitively wrong.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Fabricated body names. Each entry is (pattern, canonical suggestion).
# The suggestion is carried into the refusal so reviewers know which
# real body the fabrication probably meant.
_FABRICATED_REGULATORS: list[tuple[re.Pattern[str], str]] = [
    # EU — data protection.
    (
        re.compile(r"\bEuropean Privacy Authority\b", re.IGNORECASE),
        "European Data Protection Board (EDPB)",
    ),
    (
        re.compile(r"\bEU Privacy Authority\b", re.IGNORECASE),
        "European Data Protection Board (EDPB)",
    ),
    (
        re.compile(r"\bEuropean Data Authority\b", re.IGNORECASE),
        "European Data Protection Board (EDPB)",
    ),
    (
        re.compile(r"\bEU Privacy Commission\b", re.IGNORECASE),
        "European Data Protection Board (EDPB)",
    ),
    (
        re.compile(r"\bEuropean Privacy Commission\b", re.IGNORECASE),
        "European Data Protection Board (EDPB)",
    ),
    (
        re.compile(r"\bEuropean Data Protection Agency\b", re.IGNORECASE),
        "European Data Protection Board (EDPB) or European Data Protection Supervisor (EDPS)",
    ),
    # EU — cybersecurity.
    (
        re.compile(r"\bEU Cybersecurity Commission\b", re.IGNORECASE),
        "European Union Agency for Cybersecurity (ENISA)",
    ),
    (
        re.compile(r"\bEuropean Cybersecurity Commission\b", re.IGNORECASE),
        "European Union Agency for Cybersecurity (ENISA)",
    ),
    (
        re.compile(r"\bEuropean Cybersecurity Authority\b", re.IGNORECASE),
        "European Union Agency for Cybersecurity (ENISA)",
    ),
    # EU — AI.
    (
        re.compile(r"\bEU AI Commission\b", re.IGNORECASE),
        "European AI Office (within the European Commission)",
    ),
    (
        re.compile(r"\bEuropean AI Authority\b", re.IGNORECASE),
        "European AI Office (within the European Commission)",
    ),
    (
        re.compile(r"\bEuropean AI Agency\b", re.IGNORECASE),
        "European AI Office (within the European Commission)",
    ),
    # US — data protection. There is no federal US DPA.
    (
        re.compile(r"\bFederal Data Protection Agency\b", re.IGNORECASE),
        "no federal US DPA exists — sector regulators apply (FTC, HHS OCR, SEC)",
    ),
    (
        re.compile(r"\bUS Data Protection Agency\b", re.IGNORECASE),
        "no federal US DPA exists — sector regulators apply (FTC, HHS OCR, SEC)",
    ),
    (
        re.compile(r"\bUS Privacy Commission\b", re.IGNORECASE),
        "no federal US privacy commission exists — FTC leads on privacy enforcement",
    ),
    (
        re.compile(r"\bFederal Privacy Commission\b", re.IGNORECASE),
        "no federal US privacy commission exists — FTC leads on privacy enforcement",
    ),
    # UK — data protection.
    (
        re.compile(r"\bUK Privacy Authority\b", re.IGNORECASE),
        "Information Commissioner's Office (ICO)",
    ),
    (
        re.compile(r"\bUK Data Protection Agency\b", re.IGNORECASE),
        "Information Commissioner's Office (ICO)",
    ),
    (
        re.compile(r"\bBritish Data Protection Agency\b", re.IGNORECASE),
        "Information Commissioner's Office (ICO)",
    ),
    (
        re.compile(r"\bBritish Privacy Authority\b", re.IGNORECASE),
        "Information Commissioner's Office (ICO)",
    ),
]


@dataclass
class RegulatorFinding:
    """A fabricated regulator reference located in text."""

    phrase: str
    suggested: str
    start: int
    end: int


def find_fabricated_regulators(text: str) -> list[RegulatorFinding]:
    """Return every fabricated regulator reference in `text`."""
    findings: list[RegulatorFinding] = []
    for pattern, suggestion in _FABRICATED_REGULATORS:
        for match in pattern.finditer(text):
            findings.append(
                RegulatorFinding(
                    phrase=match.group(0),
                    suggested=suggestion,
                    start=match.start(),
                    end=match.end(),
                )
            )
    findings.sort(key=lambda f: f.start)
    return findings


def regulator_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_fabricated_regulators(text)
    return {
        "has_fabricated_regulator": bool(findings),
        "fabrication_count": len(findings),
        "samples": [
            f"{f.phrase} — likely meant: {f.suggested}"
            for f in findings[:3]
        ],
    }
