"""Chain-of-thought leakage detection — registered as a NeMo Guardrails action.

Detection logic lives in `modules/guardrails/cot_leakage_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.audit_emit import emit_rail_fire
from modules.guardrails.cot_leakage_rule import cot_report


@action(name="CoTLeakageCheckAction", execute_async=True)
async def cot_leakage_check(text: str) -> dict:
    """Output-rail check: flag chain-of-thought markers in model output.

    Returns:
        has_cot_leakage: bool — if True, the output rail should refuse.
        marker_count: int — total markers detected.
        samples: list[str] — up to 3 marker strings, for logging.
    """
    report = cot_report(text)
    if report.get("has_cot_leakage"):
        emit_rail_fire("cot_leakage", report)
    return report
