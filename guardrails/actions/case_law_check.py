"""Fabricated case-law / enforcement-action detection — NeMo Guardrails action.

Detection logic lives in ``modules/guardrails/case_law_rule.py`` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.case_law_rule import case_law_report

from modules.guardrails.audit_emit import emit_rail_fire


@action(name="CaseLawCheckAction", execute_async=True)
async def case_law_check(text: str) -> dict:
    """Output-rail check: flag fabricated case-law / enforcement-action IDs.

    Returns:
        has_fabricated_case_law: bool — if True, the rail should refuse.
        fabrication_count: int — number of fabrications detected.
        samples: list[str] — up to 3 offending citations with reason,
            for logging.
    """
    report = case_law_report(text)
    if report.get("has_fabricated_case_law"):
        emit_rail_fire("fabricated_case_law", report)
    return report
