"""Unfounded-verdict detection — registered as a NeMo Guardrails action.

The detection logic itself lives in `modules/guardrails/verdict_rule.py`
so it can be unit-tested without a nemoguardrails install. This module
is the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.verdict_rule import verdict_report

from modules.guardrails.audit_emit import emit_rail_fire


@action(name="VerdictCheckAction", execute_async=True)
async def verdict_check(text: str) -> dict:
    """Output-rail check: flag absolutist compliance verdicts without evidence.

    Returns:
        has_unfounded_verdict: bool — if True, the output rail should refuse.
        verdict_count: int — total number of verdict phrases detected.
        unfounded_count: int — verdicts without a nearby evidence anchor.
        samples: list[str] — up to 3 unfounded verdict phrases, for logging.
    """
    report = verdict_report(text)
    if report.get("has_unfounded_verdict"):
        emit_rail_fire("unfounded_verdict", report)
    return report
