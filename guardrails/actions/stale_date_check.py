"""Stale-attestation detection — registered as a NeMo Guardrails action.

Detection logic lives in `modules/guardrails/stale_date_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.stale_date_rule import stale_date_report

from ._audit_emit import emit_rail_fire


@action(name="StaleDateCheckAction", execute_async=True)
async def stale_date_check(text: str) -> dict:
    """Output-rail check: flag attestation references older than 2 years.

    Returns:
        has_stale_attestation: bool — if True, the rail should refuse.
        stale_count: int — number of stale references detected.
        max_age_years: int — threshold currently applied (default 2).
        samples: list[str] — up to 3 stale phrases, for logging.
    """
    report = stale_date_report(text)
    if report.get("has_stale_attestation"):
        emit_rail_fire("stale_attestation", report)
    return report
