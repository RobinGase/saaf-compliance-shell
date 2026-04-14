"""Fabricated-regulator-name detection — NeMo Guardrails action.

Detection logic lives in `modules/guardrails/regulator_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.regulator_rule import regulator_report


@action(name="RegulatorCheckAction", execute_async=True)
async def regulator_check(text: str) -> dict:
    """Output-rail check: flag fabricated supervisory-body names.

    Returns:
        has_fabricated_regulator: bool — if True, the rail should refuse.
        fabrication_count: int — number of fabrications detected.
        samples: list[str] — up to 3 offending phrases with canonical
            suggestion, for logging.
    """
    return regulator_report(text)
