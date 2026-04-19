"""Regression test for the v0.8.4-era silent-rails-off bug.

In v0.8.4 the deployed service exhibited a latent failure: every
``@action`` file in ``guardrails_config/actions/`` used a relative import
(``from ._audit_emit import emit_rail_fire``), but nemoguardrails
loads each action file via ``importlib.util.spec_from_file_location``
with no parent package attached. Python therefore couldn't resolve
the ``.`` in the relative import and every action failed to register
with the message ``No module named '<stem>'``. The Colang rails
evaluated but ``execute *CheckAction()`` silently no-op'd, so every
fabrication passed through HTTP 200.

The bypass-path scanner (``scan_output``) kept working because it
imports the rule modules directly — which is why unit tests passed
and the bug survived four release cycles. This test reproduces the
exact loader nemoguardrails uses, so any future regression (new
relative import in an action file, missing absolute target module)
breaks CI instead of silently disabling rails in production.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ACTIONS_DIR = Path(__file__).resolve().parent.parent / "guardrails_config" / "actions"

# Files starting with ``_`` are support modules (e.g. ``_audit_emit``
# historically), not @action-registered files. If any such file is
# reintroduced it should also load cleanly, but it's fine if it doesn't
# emit an action — we only care that ``exec_module`` runs without
# raising. presidio_redact is skipped because it imports the optional
# presidio-analyzer dep not installed on the Windows dev venv.
SKIPPED_STEMS = {"__init__", "presidio_redact"}


def _action_files() -> list[Path]:
    return sorted(
        p for p in ACTIONS_DIR.glob("*.py") if p.stem not in SKIPPED_STEMS
    )


_NEMOGUARDRAILS_AVAILABLE = (
    importlib.util.find_spec("nemoguardrails") is not None
)


@pytest.mark.skipif(
    not _NEMOGUARDRAILS_AVAILABLE,
    reason="nemoguardrails not installed in this venv (e.g. Windows dev)",
)
@pytest.mark.parametrize("path", _action_files(), ids=lambda p: p.stem)
def test_action_file_loads_via_spec_loader(path: Path) -> None:
    """Mimic nemoguardrails' action dispatcher on each action file.

    ``spec_from_file_location(filename, filepath)`` with no
    ``submodule_search_locations`` gives the loaded module no parent
    package — relative imports like ``from ._X import Y`` fail with
    the misleading ``No module named '<stem>'`` (Python is looking up
    the stem as a parent package to resolve the ``.``). Absolute
    imports like ``from modules.guardrails.X import Y`` work as long
    as the project root is on ``sys.path``.
    """
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        pytest.fail(
            f"{path.name} cannot be loaded by nemoguardrails' action "
            f"dispatcher: {exc!s}. If this is a relative import, "
            f"switch to an absolute one (e.g. "
            f"'from modules.guardrails.audit_emit import emit_rail_fire')."
        )


def test_no_relative_imports_in_action_files() -> None:
    """Block relative imports at the source level, before the loader runs.

    A faster-to-diagnose companion to the spec-loader test: relative
    imports in action files are flat-out incompatible with how
    nemoguardrails loads them, so catch them by string match too.
    """
    offenders: list[str] = []
    for path in _action_files():
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("from .") or stripped.startswith("from.."):
                offenders.append(f"{path.name}:{lineno}: {line}")
    assert not offenders, (
        "Action files must not use relative imports — nemoguardrails "
        "loads them as top-level modules with no parent package. "
        "Offenders:\n" + "\n".join(offenders)
    )
