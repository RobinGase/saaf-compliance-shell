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
                          final report. The timeframes come from
                          Article 19 of Regulation (EU) 2022/2554
                          plus the separate RTS on reporting
                          timeframes under DORA Art. 20, NOT from
                          Commission Delegated Regulation (EU)
                          2024/1772 (which covers classification
                          criteria and materiality thresholds, not
                          deadlines — verified against the OJ text
                          on 2026-04-19 as part of the hardening
                          wave S5 batch, closing the deferred P2-1
                          "24h-from-awareness backstop" finding as
                          reviewer-wrong-about-location).

The 24h number in 2024/1772 Art. 9(3)(a) is a duration-materiality
threshold for classifying an incident as major (how long the
incident ran), NOT a notification deadline. A LLM output claiming
"DORA requires initial notification within 24 hours under
Regulation 2024/1772" is fabricated and must fire this rail; the
regression is pinned by
``test_dora_24h_initial_notification_claim_is_flagged_as_fabricated``
in tests/test_deadline_check.py.

Approach:
- Find deadline phrases in several shapes: "within N hours", "in N
  hours", "no later than N", Dutch "binnen N uur", plus paraphrases
  "N-hour notification window", "has N hours to notify", "N hours
  after becoming aware".
- Require a *trigger term* (notification, breach, incident, early
  warning, report, melding, …) in the enclosing sentence. A deadline
  without one of these is likely a non-notification clock (GDPR Art.
  12 DSAR response, retention period, SLA) and must not be flagged.
- For each trigger-confirmed deadline, find the framework aliases in
  the enclosing sentence preceding the deadline. If the nearest ones
  are conjoined ("GDPR and NIS2"), attribute to all of them. Emit one
  finding per attributed framework.
- Normalise the deadline to hours and compare against the framework's
  valid window set. Anything outside is flagged.

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
# named framework when one is clearly in the neighbourhood. "AVG"
# (Dutch GDPR) is matched *case-sensitively* via an inline flag to
# avoid colliding with English "avg" (shorthand for "average")
# that appears in audit-metrics prose; all other aliases are case-
# insensitive under the outer flag. "Article 33" is deliberately
# NOT an alias here — a bare Article-number reference without a
# regulation name is the citation rail's concern, not this one.
_FRAMEWORK_ALIASES: dict[str, list[str]] = {
    "GDPR": [
        r"GDPR",
        r"(?-i:AVG)",
        r"General Data Protection Regulation",
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


# Trigger terms that make a duration clause a *notification* deadline.
# Without one of these in the enclosing sentence, a "within 1 month"
# clause is likely a GDPR Art. 12 DSAR response, a retention period,
# or an SLA — not a breach/incident notification — and must not be
# evaluated against the notification-window set.
_TRIGGER_TERMS = (
    r"notif(?:y|ied|ies|ying|ication|ications)",
    r"report(?:ed|ing|s)?",
    r"breach(?:es|ed)?",
    r"incident(?:s)?",
    r"early\s+warning",
    r"classif(?:y|ied|ies|ication)",
    r"disclos(?:e|ed|es|ing|ure)",
    r"aware(?:ness)?",
    r"becoming\s+aware",
    # Dutch
    r"melding(?:en)?",
    r"melden",
    r"gemeld",
    r"waarschuwing(?:en)?",
)
_TRIGGER_RE = re.compile("|".join(_TRIGGER_TERMS), re.IGNORECASE)


# Deadline patterns. Four alternatives, one named group per value so
# the matcher can pull the number and unit regardless of branch.
#
#   (A) Canonical connective: "within N unit", "in N unit", "no later
#       than N unit", Dutch "binnen N unit". Word-number "a/an/one/één"
#       is accepted for month paraphrases ("within a month"). The num
#       is REQUIRED in some form — "within hours" (no number, no word-
#       number) no longer matches, closing the P3-1 false-positive.
#   (B) "N-hour notification window / deadline / clock / mark / period".
#   (C) "has/have/gets/is given N hours/days to …".
#   (D) "N hours after becoming aware / classification / detection /
#       discovery / the breach / notification".
#
# Named groups are branch-suffixed because Python's re module refuses
# duplicate names across alternations.
_DEADLINE_PATTERNS = [
    r"\b(?:within|in|no\s+later\s+than|not\s+later\s+than|binnen)\s+"
    r"(?:(?P<word_num_a>a|an|one|één)\s+|(?P<digit_num_a>\d+)\s*)"
    r"(?P<unit_a>hours?|hrs?|hour|days?|uur|uren|dag(?:en)?|months?|maand(?:en)?)\b",

    r"\b(?P<digit_num_b>\d+)[-\s](?P<unit_b>hour|day|month)s?\s+"
    r"(?:notification\s+|reporting\s+)?"
    r"(?:window|deadline|clock|mark|period)\b",

    r"\b(?:has|have|had|gets?|got|is\s+given|are\s+given)\s+"
    r"(?P<digit_num_c>\d+)\s+"
    r"(?P<unit_c>hours?|days?|months?)\s+to\b",

    r"\b(?P<digit_num_d>\d+)\s+"
    r"(?P<unit_d>hours?|days?|months?)\s+after\s+"
    r"(?:becoming\s+aware|awareness|classification|detection|"
    r"discovery|notification|the\s+breach|the\s+incident)\b",
]
_DEADLINE_RE = re.compile("|".join(_DEADLINE_PATTERNS), re.IGNORECASE)


# Sentence boundaries. Period (`.`) is only a boundary when followed
# by whitespace + capital letter, or end-of-text — otherwise "Art."
# in "GDPR Art. 33 requires notification within 72 hours" splits the
# framework alias away from the deadline clause. Semicolons,
# exclamation, question marks, and newlines are always boundaries.
_SENTENCE_BOUNDARIES = re.compile(r"[;!?\n]|\.(?=\s+[A-Z]|\s*$)")


# Conjunction tokens joining two framework aliases into a shared
# attribution group: "GDPR and NIS2", "GDPR or DORA", "GDPR/NIS2",
# "GDPR, NIS2". Dutch "en" / "of" also accepted.
_CONJUNCTION_BETWEEN = re.compile(
    r"^\s*(?:and|or|en|of|,|/|&)\s*$", re.IGNORECASE
)


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


def _enclosing_sentence_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """Return the [start, end) bounds of the sentence containing the span."""
    prev_boundary = 0
    for match in _SENTENCE_BOUNDARIES.finditer(text, 0, start):
        prev_boundary = match.end()
    next_match = _SENTENCE_BOUNDARIES.search(text, end)
    next_boundary = next_match.start() if next_match else len(text)
    return prev_boundary, next_boundary


def _extract_match_value(match: re.Match[str]) -> tuple[int, str] | None:
    """Pull (hours, unit-for-phrase) from whichever branch matched, or None."""
    word_num = match.group("word_num_a")
    digit_groups = ("digit_num_a", "digit_num_b", "digit_num_c", "digit_num_d")
    unit_groups = ("unit_a", "unit_b", "unit_c", "unit_d")
    digit: str | None = None
    unit: str | None = None
    for g in digit_groups:
        if match.group(g):
            digit = match.group(g)
            break
    for g in unit_groups:
        if match.group(g):
            unit = match.group(g)
            break
    if unit is None:
        return None
    if digit is not None:
        num = int(digit)
    elif word_num is not None:
        num = 1
    else:
        return None
    hours = _to_hours(num, unit)
    if hours is None:
        return None
    return hours, unit


def _alias_framework(alias_match: re.Match[str]) -> str | None:
    """Return the framework whose named group matched, if any."""
    for framework in _FRAMEWORK_ALIASES:
        if alias_match.group(framework):
            return framework
    return None


def _attributed_frameworks(
    text: str, sent_start: int, deadline_start: int
) -> list[str]:
    """Return the framework(s) that govern a deadline at ``deadline_start``.

    Strategy: collect framework aliases in the enclosing sentence,
    preceding the deadline. Start from the rightmost preceding alias
    and walk backwards, including every alias whose span-gap to the
    current one is only a conjunction token (``and``/``or``/``,``/
    ``/`` or Dutch ``en``/``of``). Stop at the first alias not joined
    by a conjunction. This gives the multi-framework attribution
    needed to catch "Under GDPR and NIS2, … within 24 hours" without
    over-attributing on independent mentions.
    """
    aliases: list[re.Match[str]] = []
    for alias_match in _ALIAS_RE.finditer(text, sent_start, deadline_start):
        aliases.append(alias_match)
    if not aliases:
        return []
    attributed: list[re.Match[str]] = [aliases[-1]]
    for candidate in reversed(aliases[:-1]):
        between = text[candidate.end():attributed[-1].start()]
        if not _CONJUNCTION_BETWEEN.match(between):
            break
        attributed.append(candidate)
    frameworks: list[str] = []
    for alias_match in attributed:
        framework = _alias_framework(alias_match)
        if framework is not None and framework not in frameworks:
            frameworks.append(framework)
    return frameworks


def _following_framework(
    text: str, sent_start: int, sent_end: int, deadline_end: int
) -> str | None:
    """Pick the nearest following alias in the sentence, if any.

    Only used when no preceding alias exists in the sentence. This
    handles inverted phrasing like "Within 24 hours, NIS2 requires
    an early warning" — rare but real.
    """
    first: re.Match[str] | None = None
    for alias_match in _ALIAS_RE.finditer(text, deadline_end, sent_end):
        first = alias_match
        break
    if first is None:
        return None
    return _alias_framework(first)


def find_deadline_citations(text: str) -> list[DeadlineFinding]:
    """Return every incident-notification deadline detected in `text`.

    A deadline becomes a finding only when (a) a trigger term appears
    in the same sentence and (b) at least one framework alias appears
    in the same sentence. Deadlines in non-notification contexts (no
    trigger) are silently ignored — the rail will not block audit text
    discussing GDPR DSAR response windows, retention periods, or SLAs.
    """
    findings: list[DeadlineFinding] = []
    for match in _DEADLINE_RE.finditer(text):
        value = _extract_match_value(match)
        if value is None:
            continue
        hours, _unit = value
        sent_start, sent_end = _enclosing_sentence_bounds(
            text, match.start(), match.end()
        )
        sentence = text[sent_start:sent_end]
        if not _TRIGGER_RE.search(sentence):
            continue
        frameworks = _attributed_frameworks(text, sent_start, match.start())
        if not frameworks:
            framework = _following_framework(
                text, sent_start, sent_end, match.end()
            )
            if framework is None:
                continue
            frameworks = [framework]
        for framework in frameworks:
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
