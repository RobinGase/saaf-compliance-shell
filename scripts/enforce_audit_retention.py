"""Delete rotated audit-log archives older than a retention window.

Reads ``SAAF_AUDIT_LOG_DIR`` (default ``/var/log/openshell``) and
``SAAF_AUDIT_RETENTION_DAYS`` (default ``0`` — meaning "do nothing")
from the environment. Any file matching ``audit.jsonl.*`` in the log
directory whose mtime is older than the retention window is deleted.

The live ``audit.jsonl`` is never touched — rotation is a separate,
operator-controlled step (see ``docs/RUNBOOK.md``). This script only
enforces retention of already-rotated archives so operators can run
it blindly from a daily systemd timer without risking the active
hash chain.

Exit codes:
    0 — pruning ran cleanly, or retention is disabled (0 days).
    1 — a permission or I/O error stopped pruning partway through.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

DEFAULT_LOG_DIR = "/var/log/openshell"
DEFAULT_RETENTION_DAYS = 0  # 0 == disabled
ARCHIVE_GLOB = "audit.jsonl.*"

logger = logging.getLogger("enforce_audit_retention")


def _retention_seconds() -> int:
    try:
        days = int(os.environ.get("SAAF_AUDIT_RETENTION_DAYS", DEFAULT_RETENTION_DAYS))
    except ValueError:
        logger.error("SAAF_AUDIT_RETENTION_DAYS is not an integer; refusing to prune")
        return -1
    if days < 0:
        logger.error("SAAF_AUDIT_RETENTION_DAYS is negative; refusing to prune")
        return -1
    return days * 86400


def _log_dir() -> Path:
    return Path(os.environ.get("SAAF_AUDIT_LOG_DIR", DEFAULT_LOG_DIR))


def prune(log_dir: Path, retention_seconds: int) -> tuple[int, int]:
    """Delete archives older than ``retention_seconds``.

    Returns ``(pruned_count, error_count)``.
    """
    if retention_seconds == 0:
        logger.info("Retention disabled (0 days). Nothing to do.")
        return 0, 0

    cutoff = time.time() - retention_seconds
    pruned = 0
    errors = 0

    if not log_dir.is_dir():
        logger.warning("Log directory %s does not exist — nothing to prune.", log_dir)
        return 0, 0

    for archive in log_dir.glob(ARCHIVE_GLOB):
        if not archive.is_file():
            continue
        try:
            mtime = archive.stat().st_mtime
        except OSError as exc:
            logger.error("Could not stat %s: %s", archive, exc)
            errors += 1
            continue
        if mtime >= cutoff:
            continue
        try:
            archive.unlink()
            logger.info("Pruned %s (age %.1f days)", archive, (time.time() - mtime) / 86400)
            pruned += 1
        except OSError as exc:
            logger.error("Could not delete %s: %s", archive, exc)
            errors += 1

    return pruned, errors


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    retention = _retention_seconds()
    if retention < 0:
        return 1

    pruned, errors = prune(_log_dir(), retention)
    logger.info("Done. Pruned %d archive(s), %d error(s).", pruned, errors)
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
