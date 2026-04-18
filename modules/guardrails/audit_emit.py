"""Shared audit-emit helper for the @action wrappers.

Each output-rail wrapper calls ``emit_rail_fire`` when its ``has_*``
flag is True so the Colang-driven rail-fire joins the hash-chained
audit log. Without this, rail fires from the normal (rails-on) path
are invisible — only the service's bypass paths would write them.

Failures to write are swallowed and logged. An audit write must not
break the request path.
"""

from __future__ import annotations

import logging
import os

from modules.audit.log import append_chained_event

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_LOG_PATH = "/var/log/openshell/audit.jsonl"


def emit_rail_fire(rail_name: str, report: dict) -> None:
    log_path = os.environ.get("AUDIT_LOG_PATH", DEFAULT_AUDIT_LOG_PATH)
    try:
        append_chained_event(
            log_path,
            "guardrails_rail_fire",
            source="colang_flow",
            rail=rail_name,
            report=report,
        )
    except OSError as exc:
        logger.warning("Could not write rail_fire(%s) to audit log: %s", rail_name, exc)
