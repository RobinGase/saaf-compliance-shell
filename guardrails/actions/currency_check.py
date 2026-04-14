"""Currency/regulation-zone mismatch detection — NeMo Guardrails action.

Detection logic lives in `modules/guardrails/currency_rule.py` so it
can be unit-tested without a nemoguardrails install. This module is
the thin wrapper that registers the action with Colang.
"""

from __future__ import annotations

from nemoguardrails.actions import action

from modules.guardrails.currency_rule import currency_report


@action(name="CurrencyCheckAction", execute_async=True)
async def currency_check(text: str) -> dict:
    """Output-rail check: flag regulation fines cited in wrong currency.

    Returns:
        has_currency_mismatch: bool — if True, the rail should refuse.
        mismatch_count: int — number of mismatches detected.
        samples: list[str] — up to 3 offending phrases, for logging.
    """
    return currency_report(text)
