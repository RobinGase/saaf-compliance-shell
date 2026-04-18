"""Pure-Python detection of fabricated case-law / enforcement-action IDs.

Generalist models routinely fabricate references to CJEU decisions
("In Case C-521/29, the Court of Justice held...") and to national
DPA enforcement actions ("CNIL Délibération SAN-2099-047"). The
citation shape is canonical and confident, but the case number,
year, or combination is drawn from training-frequency rather than a
judgment list. Because case IDs cannot be range-checked against a
live court registry from inside the rail, this module takes a
narrow, allowlist-first approach: it only recognises the **canonical
citation shapes** and flags them when a verifiable component
(the year) falls outside the statutory window.

Approach (v1, two shapes):

1. **CJEU / General Court case identifiers.** Canonical shape
   ``[CTF]-NNN/YY`` or ``[CTF]-NNN/YYYY`` where the letter denotes
   the court (``C`` = Court of Justice, ``T`` = General Court,
   ``F`` = Civil Service Tribunal, abolished in 2016 but historical
   references remain valid). The ``[CTF]-NNN/YY`` numbering scheme
   was introduced in 1989 when the Court of First Instance (now
   General Court) was created. Year outside ``[1989, current_year +
   1]`` is a fabrication signature.

2. **CNIL SAN decision identifiers.** Canonical shape
   ``SAN-YYYY-NNN``, used by the French Commission Nationale de
   l'Informatique et des Libertés for formal sanctions. Year outside
   ``[2000, current_year + 1]`` is a fabrication signature (lower
   bound conservative pending OJ/CNIL registry verification — see
   proof/constant_audit_checklist.md §10).

The rail does NOT try to verify that an in-range case ID actually
exists in the court registry — that requires a live lookup and is
outside scope. Malformed shapes that look like CJEU IDs but use the
wrong separator (``C.237/23``, ``C-237-23``, ``C_237/23``) or an
impossible court prefix while explicitly referencing the CJEU are
also flagged as fabrications-by-construction.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

# CJEU numbering reform of 1989 introduced the [CTF]-NNN/YY scheme.
_CJEU_FIRST_YEAR = 1989

# CNIL SAN numbering — conservative lower bound pending verification
# against the CNIL sanctions registry (see constant_audit_checklist.md §10).
_CNIL_SAN_FIRST_YEAR = 2000

# Pre-allocated case numbers for the next calendar year are legitimate.
_FUTURE_YEAR_TOLERANCE = 1

# Canonical CJEU / General Court case ID.
# Court prefix is C, T, or F. Number is 1-4 digits. Year is 2 or 4 digits.
_CJEU_CANONICAL = re.compile(
    r"\b(?P<court>[CTF])-(?P<num>\d{1,4})/(?P<year>\d{4}|\d{2})\b"
)

# Malformed shapes a model emits when it half-remembers the separator.
# Two failure modes: wrong first separator (C.237/23, C_237/23, C--237/23),
# or wrong second separator (C-237-23, C-237.23, C-237_23). The canonical
# shape is C-NNN/YY, so these regexes deliberately exclude that combination.
_CJEU_MALFORMED_SEP1 = re.compile(
    r"\b(?P<court>[CTF])"
    r"(?P<sep>[._]|--)"
    r"(?P<num>\d{1,4})"
    r"[-/._]"
    r"(?P<year>\d{4}|\d{2})\b"
)
_CJEU_MALFORMED_SEP2 = re.compile(
    r"\b(?P<court>[CTF])"
    r"-"
    r"(?P<num>\d{1,4})"
    r"(?P<sep>[-._])"
    r"(?P<year>\d{4}|\d{2})\b"
)

# CNIL SAN canonical shape. Allow optional "Délibération n°" prefix
# but do not require it — SAN IDs appear bare in most citations.
_CNIL_SAN = re.compile(
    r"\bSAN-(?P<year>\d{4})-(?P<num>\d{1,4})\b"
)


def _normalise_year(raw: str) -> int:
    """Map 2-digit years to 4-digit using CJEU-appropriate windowing.

    Cases numbered in 1989 and later use the [CTF]-NNN/YY scheme, so
    ``YY`` in ``[89, 99]`` maps to ``19YY`` and ``YY`` in ``[00, 99]``
    otherwise to ``20YY``. We treat 89-99 as 1989-1999 and 00-88 as
    2000-2088 (the scheme will hit a genuine ambiguity around 2089
    but that window is not our problem yet).
    """
    if len(raw) == 4:
        return int(raw)
    yy = int(raw)
    if yy >= 89:
        return 1900 + yy
    return 2000 + yy


@dataclass
class CaseLawFinding:
    """A fabricated case-law or enforcement-action reference."""

    citation: str
    year: int | None
    court: str | None
    reason: str
    start: int
    end: int


def _cjeu_canonical_findings(
    text: str, current_year: int
) -> list[CaseLawFinding]:
    findings: list[CaseLawFinding] = []
    upper = current_year + _FUTURE_YEAR_TOLERANCE
    for match in _CJEU_CANONICAL.finditer(text):
        year = _normalise_year(match.group("year"))
        court = match.group("court")
        if year < _CJEU_FIRST_YEAR:
            findings.append(
                CaseLawFinding(
                    citation=match.group(0),
                    year=year,
                    court=court,
                    reason=(
                        "year predates the [CTF]-NNN/YY numbering scheme "
                        f"({_CJEU_FIRST_YEAR})"
                    ),
                    start=match.start(),
                    end=match.end(),
                )
            )
        elif year > upper:
            findings.append(
                CaseLawFinding(
                    citation=match.group(0),
                    year=year,
                    court=court,
                    reason=f"year is in the far future (> {upper})",
                    start=match.start(),
                    end=match.end(),
                )
            )
    return findings


def _cjeu_malformed_findings(text: str) -> list[CaseLawFinding]:
    """Flag obviously-mangled CJEU shapes.

    Only fires when the malformed match does NOT overlap a canonical
    hit and the surrounding context names the CJEU explicitly — this
    keeps us from claiming every ``A-1/23`` in unrelated text is a
    fabricated case reference.
    """
    findings: list[CaseLawFinding] = []
    canonical_spans = [
        (m.start(), m.end()) for m in _CJEU_CANONICAL.finditer(text)
    ]

    def overlaps_canonical(start: int, end: int) -> bool:
        return any(
            not (end <= cs or start >= ce)
            for cs, ce in canonical_spans
        )

    seen_spans: set[tuple[int, int]] = set()
    for pattern in (_CJEU_MALFORMED_SEP1, _CJEU_MALFORMED_SEP2):
        for match in pattern.finditer(text):
            if overlaps_canonical(match.start(), match.end()):
                continue
            span = (match.start(), match.end())
            if span in seen_spans:
                continue
            seen_spans.add(span)
            # Require CJEU context within a 120-char window on either side
            # so we do not fire on model/serial numbers.
            window_start = max(0, match.start() - 120)
            window_end = min(len(text), match.end() + 120)
            window = text[window_start:window_end]
            if not re.search(
                r"\b(CJEU|ECJ|Court of Justice|General Court|"
                r"Civil Service Tribunal)\b",
                window,
                re.IGNORECASE,
            ):
                continue
            findings.append(
                CaseLawFinding(
                    citation=match.group(0),
                    year=None,
                    court=match.group("court"),
                    reason=(
                        "case identifier uses non-canonical separators — "
                        "CJEU IDs take the form [CTF]-NNN/YY"
                    ),
                    start=match.start(),
                    end=match.end(),
                )
            )
    findings.sort(key=lambda f: f.start)
    return findings


def _cnil_san_findings(
    text: str, current_year: int
) -> list[CaseLawFinding]:
    findings: list[CaseLawFinding] = []
    upper = current_year + _FUTURE_YEAR_TOLERANCE
    for match in _CNIL_SAN.finditer(text):
        year = int(match.group("year"))
        if year < _CNIL_SAN_FIRST_YEAR:
            findings.append(
                CaseLawFinding(
                    citation=match.group(0),
                    year=year,
                    court="CNIL",
                    reason=(
                        "year predates the CNIL SAN numbering scheme "
                        f"(lower bound {_CNIL_SAN_FIRST_YEAR})"
                    ),
                    start=match.start(),
                    end=match.end(),
                )
            )
        elif year > upper:
            findings.append(
                CaseLawFinding(
                    citation=match.group(0),
                    year=year,
                    court="CNIL",
                    reason=f"year is in the far future (> {upper})",
                    start=match.start(),
                    end=match.end(),
                )
            )
    return findings


def find_fabricated_case_law(
    text: str,
    *,
    today: date | None = None,
) -> list[CaseLawFinding]:
    """Return every fabricated case-law / enforcement-action reference."""
    reference = today or date.today()
    findings: list[CaseLawFinding] = []
    findings.extend(_cjeu_canonical_findings(text, reference.year))
    findings.extend(_cjeu_malformed_findings(text))
    findings.extend(_cnil_san_findings(text, reference.year))
    findings.sort(key=lambda f: f.start)
    return findings


def case_law_report(
    text: str,
    *,
    today: date | None = None,
) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_fabricated_case_law(text, today=today)
    return {
        "has_fabricated_case_law": bool(findings),
        "fabrication_count": len(findings),
        "samples": [f"{f.citation} — {f.reason}" for f in findings[:3]],
    }
