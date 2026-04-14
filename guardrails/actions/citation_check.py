"""Fabricated-citation detection — registered as a NeMo Guardrails action.

Detection logic lives in `modules/guardrails/citation_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.citation_rule import citation_report

from ._audit_emit import emit_rail_fire


@action(name="CitationCheckAction", execute_async=True)
async def citation_check(text: str) -> dict:
    """Output-rail check: flag out-of-range regulation article citations.

    Returns:
        has_fabricated_citation: bool — if True, the rail should refuse.
        citation_count: int — total article citations detected.
        fabricated_count: int — citations whose article number exceeds
            the regulation's known maximum.
        samples: list[str] — up to 3 fabricated citations, for logging.
    """
    report = citation_report(text)
    if report.get("has_fabricated_citation"):
        emit_rail_fire("fabricated_citation", report)
    return report
