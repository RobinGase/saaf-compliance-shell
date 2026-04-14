"""Run the eleven pure-Python output rails against a block of assistant text.

The nemoguardrails pipeline normally invokes each rule through a Colang
flow + `@action` wrapper. When the service falls back to the main model
directly (oversized payloads, empty rail output), that path has to run
the same rules itself or the rails are effectively off. This module is
the shared entry point for both cases.

Each rule module under ``modules/guardrails/*_rule.py`` exposes a
``*_report`` function that returns a dict with a ``has_*`` flag. We call
them in a fixed order and collect the names of the rails that fired,
along with the report payload, so the caller can (a) refuse the response
when any rail fires and (b) write one audit event per fired rail.
"""

from __future__ import annotations

from dataclasses import dataclass

from .absolutism_rule import absolutism_report
from .citation_rule import citation_report
from .cot_leakage_rule import cot_report
from .currency_rule import currency_report
from .cve_rule import cve_report
from .deadline_rule import deadline_report
from .jurisdiction_rule import jurisdiction_report
from .regulator_rule import regulator_report
from .stale_date_rule import stale_date_report
from .standards_version_rule import standards_version_report
from .verdict_rule import verdict_report


@dataclass(frozen=True)
class RailFiring:
    """A single rail that matched the scanned text."""

    name: str
    flag: str
    report: dict


# (rail_name, report_callable, has_key)
_RAILS = (
    ("unfounded_verdict", verdict_report, "has_unfounded_verdict"),
    ("cot_leakage", cot_report, "has_cot_leakage"),
    ("fabricated_citation", citation_report, "has_fabricated_citation"),
    ("absolutist_claim", absolutism_report, "has_absolutist_claim"),
    ("stale_attestation", stale_date_report, "has_stale_attestation"),
    ("jurisdiction_mismatch", jurisdiction_report, "has_jurisdiction_mismatch"),
    ("currency_mismatch", currency_report, "has_currency_mismatch"),
    ("fabricated_standards_version", standards_version_report, "has_fabricated_version"),
    ("fabricated_cve", cve_report, "has_fabricated_cve"),
    ("fabricated_regulator", regulator_report, "has_fabricated_regulator"),
    ("fabricated_deadline", deadline_report, "has_fabricated_deadline"),
)


def scan_output(text: str) -> list[RailFiring]:
    """Return every rail that would block ``text`` if its rail fired in the Colang flow."""
    firings: list[RailFiring] = []
    for name, report_fn, flag in _RAILS:
        report = report_fn(text)
        if report.get(flag):
            firings.append(RailFiring(name=name, flag=flag, report=report))
    return firings
