"""Fabricated-standards-version detection — NeMo Guardrails action.

Detection logic lives in `modules/guardrails/standards_version_rule.py`
so it can be unit-tested without a nemoguardrails install. This module
is the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.audit_emit import emit_rail_fire
from modules.guardrails.standards_version_rule import standards_version_report


@action(name="StandardsVersionCheckAction", execute_async=True)
async def standards_version_check(text: str) -> dict:
    """Output-rail check: flag fabricated standards version/year stamps.

    Returns:
        has_fabricated_version: bool — if True, the rail should refuse.
        fabrication_count: int — number of fabrications detected.
        samples: list[str] — up to 3 offending phrases, for logging.
    """
    report = standards_version_report(text)
    if report.get("has_fabricated_version"):
        emit_rail_fire("fabricated_standards_version", report)
    return report
