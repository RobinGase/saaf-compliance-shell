"""Jurisdiction-mismatch detection — registered as a NeMo Guardrails action.

Detection logic lives in `modules/guardrails/jurisdiction_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.jurisdiction_rule import jurisdiction_report

from modules.guardrails.audit_emit import emit_rail_fire


@action(name="JurisdictionCheckAction", execute_async=True)
async def jurisdiction_check(text: str) -> dict:
    """Output-rail check: flag regulations applied to the wrong jurisdiction.

    Returns:
        has_jurisdiction_mismatch: bool — if True, the rail should refuse.
        mismatch_count: int — number of mismatches detected.
        samples: list[str] — up to 3 offending phrases, for logging.
    """
    report = jurisdiction_report(text)
    if report.get("has_jurisdiction_mismatch"):
        emit_rail_fire("jurisdiction_mismatch", report)
    return report
