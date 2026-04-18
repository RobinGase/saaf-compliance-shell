"""Fabricated-incident-deadline detection — NeMo Guardrails action.

Detection logic lives in `modules/guardrails/deadline_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.deadline_rule import deadline_report

from modules.guardrails.audit_emit import emit_rail_fire


@action(name="DeadlineCheckAction", execute_async=True)
async def deadline_check(text: str) -> dict:
    """Output-rail check: flag wrong statutory notification windows.

    Returns:
        has_fabricated_deadline: bool — if True, the rail should refuse.
        deadline_count: int — total framework-linked deadlines detected.
        fabricated_count: int — deadlines that don't match any statutory
            window for the associated framework.
        samples: list[str] — up to 3 offending phrases, for logging.
    """
    report = deadline_report(text)
    if report.get("has_fabricated_deadline"):
        emit_rail_fire("fabricated_deadline", report)
    return report
