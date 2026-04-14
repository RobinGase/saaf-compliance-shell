"""Fabricated-CVE detection — NeMo Guardrails action.

Detection logic lives in `modules/guardrails/cve_rule.py` so it can
be unit-tested without a nemoguardrails install. This module is the
thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.cve_rule import cve_report


@action(name="CVECheckAction", execute_async=True)
async def cve_check(text: str) -> dict:
    """Output-rail check: flag fabricated CVE identifiers.

    Returns:
        has_fabricated_cve: bool — if True, the rail should refuse.
        fabrication_count: int — number of fabrications detected.
        samples: list[str] — up to 3 offending phrases, for logging.
    """
    return cve_report(text)
