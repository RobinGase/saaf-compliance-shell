"""Pure-Python detection of chain-of-thought leakage markers in model output.

Reasoning-capable LLMs (Nemotron, DeepSeek-R1, Qwen-thinking, etc.)
sometimes emit scratchpad markup in their final response — <think>
blocks, "My reasoning:" prefaces, [REASONING] tags, and so on. The
SAAF architecture depends on the agent's visible output being the
artefact an auditor reviews; raw CoT leaking into that artefact
defeats the unredacted-CoT-to-auditor / redacted-to-log split the
shell is built around.

This module provides a regex-based check the Guardrails output rail
can use to refuse responses that contain leaked reasoning markup.
Separated from the nemoguardrails @action wrapper so CI tests don't
need the nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# Opening-tag / preamble patterns that signal a scratchpad block or a
# reasoning preface. Kept deliberately narrow — generic phrases like
# "I think" must not trigger this rail or it will block half of normal
# English. The patterns target markup shapes models actually emit.
_COT_PATTERNS = [
    # XML-style thinking blocks emitted by reasoning models.
    r"<think(?:ing)?\s*>",
    r"</think(?:ing)?\s*>",
    r"<reason(?:ing)?\s*>",
    r"</reason(?:ing)?\s*>",
    r"<scratch(?:pad)?\s*>",
    r"</scratch(?:pad)?\s*>",
    r"<internal\s*>",
    # Bracketed markers.
    r"\[REASONING\]",
    r"\[INTERNAL\]",
    r"\[SCRATCHPAD\]",
    r"\[THINKING\]",
    # Line-prefix preambles. Must be at start of a line (after optional
    # whitespace) and followed by a colon so "my reasoning was sound" in
    # prose does not trip the rail.
    r"^\s*(?:my\s+)?(?:internal\s+)?reasoning\s*:",
    r"^\s*chain[\s\-]of[\s\-]thought\s*:",
    r"^\s*cot\s*:",
    r"^\s*scratchpad\s*:",
    r"^\s*(?:let\s+me\s+)?think\s+(?:step[\s\-]by[\s\-]step|through\s+this)\s*:",
]

# IGNORECASE lets us match <THINK>/<think> uniformly; MULTILINE makes ^
# match at every newline, which is how the line-prefix preambles work.
_cot_re = re.compile("|".join(_COT_PATTERNS), re.IGNORECASE | re.MULTILINE)


@dataclass
class CoTFinding:
    """A chain-of-thought marker located in the scanned text."""

    marker: str
    start: int
    end: int


def find_cot_markers(text: str) -> list[CoTFinding]:
    """Return every CoT leakage marker in `text`, in order."""
    return [
        CoTFinding(marker=m.group(0), start=m.start(), end=m.end())
        for m in _cot_re.finditer(text)
    ]


def cot_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_cot_markers(text)
    return {
        "has_cot_leakage": bool(findings),
        "marker_count": len(findings),
        "samples": [f.marker for f in findings[:3]],
    }
