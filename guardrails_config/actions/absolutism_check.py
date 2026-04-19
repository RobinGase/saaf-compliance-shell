"""Absolutist-claim detection — registered as a NeMo Guardrails action.

Detection logic lives in `modules/guardrails/absolutism_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.absolutism_rule import absolutism_report
from modules.guardrails.audit_emit import emit_rail_fire


@action(name="AbsolutismCheckAction", execute_async=True)
async def absolutism_check(text: str) -> dict:
    """Output-rail check: flag absolutist security/compliance claims.

    Returns:
        has_absolutist_claim: bool — if True, the rail should refuse.
        claim_count: int — total absolutist phrases detected.
        samples: list[str] — up to 3 phrases, for logging.
    """
    report = absolutism_report(text)
    if report.get("has_absolutist_claim"):
        emit_rail_fire("absolutist_claim", report)
    return report
