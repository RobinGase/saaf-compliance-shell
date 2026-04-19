"""Structural regression test for the v0.8.4-era silent-rails-off bug.

In v0.8.0–v0.8.4 the Colang 2.x output rails silently no-op'd on the
happy path. Two root causes compounded:

1. ``main.co`` did ``import passthrough`` but not ``import guardrails``
   — so nemoguardrails' ``_bot_say`` override that calls ``run output
   rails`` was never loaded. Rails could not be invoked even when
   flows were defined correctly.

2. The config directory is named ``guardrails``. When the service ran
   from the repo root, ``import guardrails`` in ``main.co`` resolved
   CWD-relative (nemoguardrails checks ``os.path.exists(import_path)``
   before consulting COLANGPATH) and re-loaded *our own config dir* as
   the library — producing duplicate ``flow main`` definitions and a
   ``Multiple non-overriding flows with name 'main'`` error at
   ``LLMRails()`` construction.

The fix:
- ``guardrails/main.co`` adds ``import guardrails`` alongside
  ``import passthrough``.
- ``modules/guardrails/service.py._build_rails`` chdirs to a neutral
  temp dir before ``RailsConfig.from_path`` + ``LLMRails(cfg)`` so the
  CWD-shadow path cannot reopen.

This test builds ``LLMRails`` with the real config and asserts the
shape of the resulting flow registry. A future regression that breaks
either wiring fix will fail this test at build time (construction
raises ``ColangSyntaxError``) or at the assertion layer (missing
dispatcher flows, missing library ``_bot_say`` override, missing our
own rail flows). The end-to-end live-LLM smoke lives as an operator
script; this test is the always-on CI guard.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

CONFIG_DIR = Path(__file__).resolve().parent.parent / "guardrails_config"

_NEMOGUARDRAILS_AVAILABLE = (
    importlib.util.find_spec("nemoguardrails") is not None
)

pytestmark = pytest.mark.skipif(
    not _NEMOGUARDRAILS_AVAILABLE,
    reason="nemoguardrails not installed in this venv (e.g. Windows dev)",
)


@pytest.fixture(scope="module")
def built_rails():
    """Build ``LLMRails`` via the service helper so the CWD-neutralisation
    fix is exercised. If the guardrails-import shadowing regresses, the
    collision fires here and every test in the module errors.
    """
    from modules.guardrails.service import _build_rails

    _build_rails.cache_clear()  # pytest-cache isolation across runs
    rails = _build_rails(str(CONFIG_DIR), None, "", 0.0)
    return rails


def _flow_names(rails) -> set[str]:
    return {cfg.id for cfg in rails.runtime.flow_configs.values()}


def test_llm_rails_constructs_without_flow_collision(built_rails) -> None:
    """If ``main.co`` re-resolves to the config dir, construction raises
    ``Multiple non-overriding flows with name 'main'``. The fixture's
    success already proves it; this assertion just pins the single-main
    invariant explicitly."""
    mains = [
        cfg
        for cfg in built_rails.runtime.flow_configs.values()
        if cfg.id == "main"
    ]
    assert len(mains) == 1, (
        "expected exactly one 'main' flow; got "
        f"{len(mains)} — CWD-shadow regression likely."
    )


def test_library_guardrails_dispatcher_flows_are_loaded(built_rails) -> None:
    """``import guardrails`` in main.co must bring in the library's
    ``run input rails`` / ``run output rails`` orchestrators, else
    ``_bot_say`` never invokes our output rails."""
    names = _flow_names(built_rails)
    assert "run input rails" in names, (
        "library 'run input rails' dispatcher missing — "
        "main.co likely lost 'import guardrails'"
    )
    assert "run output rails" in names, (
        "library 'run output rails' dispatcher missing — "
        "main.co likely lost 'import guardrails'"
    )


def test_library_bot_say_override_is_active(built_rails) -> None:
    """The library ``_bot_say`` override is what hooks ``run output
    rails`` into every ``bot say`` in the graph. Losing it means rails
    silently no-op even if the orchestrator flows exist."""
    bot_say = built_rails.runtime.flow_configs.get("_bot_say")
    assert bot_say is not None, "core '_bot_say' flow missing entirely"
    assert bot_say.is_override, (
        "'_bot_say' is not overridden — library guardrails.co did not "
        "register its override. 'import guardrails' likely missing or "
        "shadowed."
    )


def test_our_output_rail_flow_is_registered(built_rails) -> None:
    """Our 'output rails' flow is the one the dispatcher awaits when
    ``CheckFlowDefinedAction(flow_id='output rails')`` returns True.
    Without it, ``run output rails`` completes as a no-op regardless of
    content."""
    names = _flow_names(built_rails)
    assert "output rails" in names, (
        "project 'output rails' flow missing from rails.co — "
        "output dispatch has nothing to await"
    )
    assert "input rails" in names, (
        "project 'input rails' flow missing from rails.co"
    )


@pytest.mark.parametrize(
    "rail_flow",
    [
        "check cot leakage",
        "check citation validity",
        "check verdict evidence",
        "check absolutist language",
        "check stale attestations",
        "check jurisdiction scope",
        "check currency scope",
        "check standards version",
        "check cve validity",
        "check regulator validity",
        "check deadline validity",
        "check case law validity",
    ],
)
def test_every_output_rail_check_flow_is_registered(built_rails, rail_flow: str) -> None:
    """Each of the 12 fabrication rails must resolve to a flow the
    'output rails' dispatcher can call. Missing one would silently skip
    that class of fabrication without breaking the others."""
    assert rail_flow in _flow_names(built_rails), (
        f"output-rail flow {rail_flow!r} missing — rails.co drift"
    )


def test_every_rail_action_is_registered(built_rails) -> None:
    """Every ``check *`` flow calls an ``@action`` — if action
    registration silently failed (e.g. relative-import regression in
    ``guardrails/actions/``), the flow resolves but the action call
    no-ops. Cross-check the action registry by name.
    """
    expected_actions = {
        "CoTLeakageCheckAction",
        "CitationCheckAction",
        "VerdictCheckAction",
        "AbsolutismCheckAction",
        "StaleDateCheckAction",
        "JurisdictionCheckAction",
        "CurrencyCheckAction",
        "StandardsVersionCheckAction",
        "CVECheckAction",
        "RegulatorCheckAction",
        "DeadlineCheckAction",
        "CaseLawCheckAction",
        "SelfCheckInputDirectAction",
        "SelfCheckOutputDirectAction",
    }
    registered = set(built_rails.runtime.action_dispatcher.registered_actions.keys())
    missing = expected_actions - registered
    assert not missing, (
        f"@action registration missing for: {sorted(missing)}. "
        "Check guardrails/actions/*.py for import errors (relative "
        "imports break under nemoguardrails' spec-loader — see "
        "tests/test_action_loader.py)."
    )
