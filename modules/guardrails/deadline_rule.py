"""Pure-Python detection of fabricated incident-notification deadlines.

General-purpose LLMs are confidently wrong about statutory reporting
windows. "NIS2 requires 48-hour notification" and "GDPR notification
within 24 hours" are common failure modes — the model knows the
regulation name and the shape of the answer, but picks a plausible-
sounding number rather than the statutory one. The auditor reading
the output has no easy way to spot the error unless they already
know the rule.

Real windows (sources: regulation text):

    GDPR Art. 33        — 72h to the supervisory authority
    NIS2 Art. 23        — 24h early warning, 72h incident
                          notification, 1 month final report
    DORA Art. 19 + RTS  — 4h initial, 72h intermediate, 1 month
                          final report (Commission Delegated
                          Regulation (EU) 2024/1772)

Approach:
- Find deadline phrases: "within N hours/days", "in N hours", "no
  later than N hours", and a "1 month" literal.
- For each deadline, look for a nearby framework anchor (GDPR, NIS2,
  DORA, AVG) within a configurable window.
- Normalise the deadline to hours and compare against the framework's
  set of valid windows. Anything outside is flagged.

Separated from the @action wrapper so CI can run these tests without
a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Valid notification windows per framework, expressed in hours.
# 720h = 30 days ≈ "1 month" — accepted with ±24h tolerance so
# "within 28 days" / "within 31 days" pass for NIS2 / DORA final
# reports.
_VALID_WINDOWS_HOURS: dict[str, set[int]] = {
    "GDPR": {72},
    "NIS2": {24, 72, 720},
    "DORA": {4, 72, 720},
}


# Framework aliases. Kept narrow — the citation rail is the broad
# alias surface; this rail only needs to associate a deadline with a
# named framework when one is clearly in the neighbourhood.
_FRAMEWORK_ALIASES: dict[str, list[str]] = {
    "GDPR": [
        r"GDPR",
        r"AVG",
        r"General Data Protection Regulation",
        r"Article\s*33",
        r"Art\.\s*33",
    ],
    "NIS2": [
        r"NIS\s*2",
        r"NIS2",
        r"Directive\s*\(EU\)\s*2022/2555",
    ],
    "DORA": [
        r"DORA",
        r"Digital Operational Resilience Act",
    ],
}


def _alias_pattern() -> re.Pattern[str]:
    parts: list[str] = []
    for framework, aliases in _FRAMEWORK_ALIASES.items():
        inner = "|".join(aliases)
        parts.append(rf"(?P<{framework}>{inner})")
    return re.compile("|".join(parts), re.IGNORECASE)


_ALIAS_RE = _alias_pattern()


# Deadline phrases. The connective is tight on purpose: "within N",
# "in N", "no later than N", "not later than N", "binnen N" (Dutch).
# Adding looser phrasings ("reports in 24 hours" without "within") is
# future work — tight match reduces false positives on ordinary
# duration mentions ("ran for 4 hours", "3 days later").
_DEADLINE_RE = re.compile(
    r"\b(?:within|in|no\s+later\s+than|not\s+later\s+than|binnen)\s+"
    r"(?:a\s+|an\s+|one\s+|1\s+)?"
    r"(?P<num>\d+)?\s*"
    r"(?P<unit>hours?|hrs?|hour|days?|uur|uren|dag(?:en)?|months?|maand(?:en)?)\b",
    re.IGNORECASE,
)


# Window (in characters) around a deadline to look for a framework
# anchor. 150 chars ≈ 25-30 words — enough to cover a leading clause
# like "Under NIS2, covered entities must submit an early warning
# within 24 hours of becoming aware of an incident."
_ANCHOR_WINDOW = 200


def _to_hours(num: int, unit: str) -> int | None:
    """Normalise a (num, unit) pair to hours, or None if unrecognised."""
    u = unit.lower().rstrip("s").rstrip(".")
    if u in {"h", "hr", "hour", "uur", "uren"}:
        return num
    if u in {"d", "day", "dag", "dagen"}:
        return num * 24
    if u in {"month", "maand", "maanden"}:
        return num * 720
    return None


def _matches_valid_window(hours: int, valid: set[int]) -> bool:
    """Accept an exact hour match, with ±24h tolerance on the 720h bucket.

    "1 month" is not a fixed-length interval — regulators state the
    deadline as "one month" and courts read that pragmatically.
    Accepting 28-31 days as equivalent keeps the rail from firing on
    phrasings the statute itself treats as compliant.
    """
    for v in valid:
        if hours == v:
            return True
        if v == 720 and 672 <= hours <= 744:
            return True
    return False


@dataclass
class DeadlineFinding:
    """A notification-deadline citation located in text."""

    framework: str
    hours: int
    phrase: str
    start: int
    end: int
    valid_windows: set[int]

    @property
    def is_fabricated(self) -> bool:
        return not _matches_valid_window(self.hours, self.valid_windows)


def _nearest_framework(
    text: str, anchor_start: int, anchor_end: int
) -> str | None:
    """Return the framework alias that governs an anchor position.

    In English and Dutch, the framework name almost always precedes
    the deadline clause ("NIS2 requires … within 24 hours"). So we
    prefer the nearest preceding alias within the window; only if no
    preceding alias exists do we fall back to a following one. This
    avoids misattributing "GDPR requires within 72 hours; NIS2 …" to
    NIS2 just because NIS2 happens to be a few characters past the
    match.
    """
    window_start = max(0, anchor_start - _ANCHOR_WINDOW)
    window_end = min(len(text), anchor_end + _ANCHOR_WINDOW)
    surrounding = text[window_start:window_end]
    preceding: tuple[int, str] | None = None
    following: tuple[int, str] | None = None
    for match in _ALIAS_RE.finditer(surrounding):
        abs_start = window_start + match.start()
        abs_end = window_start + match.end()
        framework: str | None = None
        for name in _FRAMEWORK_ALIASES:
            if match.group(name):
                framework = name
                break
        if framework is None:
            continue
        if abs_end <= anchor_start:
            distance = anchor_start - abs_end
            if preceding is None or distance < preceding[0]:
                preceding = (distance, framework)
        elif abs_start >= anchor_end:
            distance = abs_start - anchor_end
            if following is None or distance < following[0]:
                following = (distance, framework)
        else:
            return framework
    if preceding is not None:
        return preceding[1]
    if following is not None:
        return following[1]
    return None


def find_deadline_citations(text: str) -> list[DeadlineFinding]:
    """Return every incident-notification deadline detected in `text`."""
    findings: list[DeadlineFinding] = []
    for match in _DEADLINE_RE.finditer(text):
        num_str = match.group("num")
        unit = match.group("unit")
        num = int(num_str) if num_str else 1
        hours = _to_hours(num, unit)
        if hours is None:
            continue
        framework = _nearest_framework(text, match.start(), match.end())
        if framework is None:
            continue
        findings.append(
            DeadlineFinding(
                framework=framework,
                hours=hours,
                phrase=match.group(0),
                start=match.start(),
                end=match.end(),
                valid_windows=_VALID_WINDOWS_HOURS[framework],
            )
        )
    return findings


def deadline_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_deadline_citations(text)
    fabricated = [f for f in findings if f.is_fabricated]
    return {
        "has_fabricated_deadline": bool(fabricated),
        "deadline_count": len(findings),
        "fabricated_count": len(fabricated),
        "samples": [
            f"{f.framework}: '{f.phrase}' ({f.hours}h, valid {sorted(f.valid_windows)})"
            for f in fabricated[:3]
        ],
    }
