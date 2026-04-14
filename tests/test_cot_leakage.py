"""Tests for the chain-of-thought leakage rail.

Each fixture represents a kind of output a reasoning-capable LLM can
emit. The rail must flag scratchpad / reasoning markup and leave
normal prose alone.
"""

from __future__ import annotations

import pytest

from modules.guardrails.cot_leakage_rule import (
    cot_report,
    find_cot_markers,
)

# ---- Cases that MUST be flagged -------------------------------------------

LEAK_CASES = [
    # XML-style thinking blocks (Nemotron / DeepSeek / Qwen-thinking).
    "<think>\nLet me analyse the vendor questionnaire.\n</think>\nControl A.5.1 is implemented.",
    "<thinking>Re-reading the SOC2 report now.</thinking>\nFinding: evidence gap on A.8.",
    "<reasoning>Weighing the evidence quality.</reasoning>\nStatus: AMBER.",
    "<scratchpad>Draft notes go here.</scratchpad>\nFinal answer: see below.",
    # Bracketed preamble markers.
    "[REASONING] This would be hidden from the user normally. [/REASONING]\nAnswer: A.5 is met.",
    "[THINKING] Pondering the gap. [/THINKING]\nControl A.8: partial.",
    # Line-prefix preambles.
    "My reasoning: the questionnaire shows encryption at rest.\nConclusion: A.8 is met.",
    "Chain-of-thought: step 1 is verify; step 2 is document.\nAnswer: A.5 is met with evidence.",
    "CoT: I considered both the policy and the attestation.\nResult: partial evidence.",
    "Let me think step by step: first, the scope...\nFinal: see findings.",
    # Mid-document leakage.
    (
        "Here is the scorecard.\n\n"
        "<think>Should I soften the AMBER rating?</think>\n\n"
        "Control A.8: AMBER with gap."
    ),
]


@pytest.mark.parametrize("text", LEAK_CASES)
def test_cot_markers_are_flagged(text: str) -> None:
    findings = find_cot_markers(text)
    assert findings, f"no CoT marker detected in: {text!r}"


# ---- Cases that MUST NOT trigger (normal prose) ----------------------------

PASS_CASES = [
    # Normal prose uses "think" and "reasoning" without being scratchpad.
    "I think the control is implemented. Evidence supports this finding.",
    "The vendor's reasoning was sound — they provided a SOC 2 attestation.",
    "Let me think about this: no wait, that would be CoT. Actually this is fine prose because it has no trailing colon marker. Scratchpad note is a misnomer here.",
    # Audit-style findings without any CoT markup.
    "Control A.5.1 is implemented; evidence: staff handbook p. 12.",
    "Status: AMBER. Partial evidence. Gap noted in access control review.",
    # A paragraph that happens to contain "reasoning" as a plain noun.
    "The auditor's reasoning is documented in section 4 of the memo.",
    # "Think step by step" in quoted advice rather than as a CoT preface.
    'The prompt "think step by step" is often overused in agentic workflows.',
    # Discussing CoT as a concept.
    "Chain of thought prompting is a known technique but should not leak.",
]


@pytest.mark.parametrize("text", PASS_CASES)
def test_normal_prose_does_not_trigger(text: str) -> None:
    findings = find_cot_markers(text)
    assert findings == [], (
        f"false positive on normal prose: {text!r} → {findings!r}"
    )


# ---- Report shape ----------------------------------------------------------


def test_report_shape_for_leak() -> None:
    result = cot_report("<think>planning</think>\nAnswer: A.5 is met.")
    assert result["has_cot_leakage"] is True
    assert result["marker_count"] == 2  # opening and closing tags
    assert "<think>" in result["samples"]


def test_report_shape_for_clean() -> None:
    result = cot_report("Control A.5.1 is implemented; evidence: staff handbook.")
    assert result == {
        "has_cot_leakage": False,
        "marker_count": 0,
        "samples": [],
    }
