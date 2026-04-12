from pathlib import Path

import yaml

from modules.guardrails.routing_check import prepare_validation_config, run_guardrails_routing_validation


def test_prepare_validation_config_rewrites_main_and_self_check_urls(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    (source / "config.yml").write_text(
        """
colang_version: "2.x"
models:
  - type: main
    engine: openai
    model: test-main
    parameters:
      base_url: http://127.0.0.1:8089/v1
  - type: self_check
    engine: openai
    model: test-self
    parameters:
      base_url: http://127.0.0.1:8000/v1
""".strip(),
        encoding="utf-8",
    )
    (source / "main.co").write_text("flow main\n  pass\n", encoding="utf-8")

    prepare_validation_config(
        source_dir=source,
        target_dir=target,
        router_url="http://127.0.0.1:18089/v1",
        direct_url="http://127.0.0.1:18000/v1",
    )

    config = yaml.safe_load((target / "config.yml").read_text(encoding="utf-8"))
    models = {entry["type"]: entry for entry in config["models"]}

    assert models["main"]["parameters"]["base_url"] == "http://127.0.0.1:18089/v1"
    assert models["self_check"]["parameters"]["base_url"] == "http://127.0.0.1:18000/v1"
    assert (target / "main.co").read_text(encoding="utf-8") == "flow main\n  pass\n"


def test_run_guardrails_routing_validation_reports_urls_and_hit_counts(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.yml").write_text(
        """
colang_version: "2.x"
models:
  - type: main
    engine: openai
    model: test-main
    parameters:
      base_url: http://127.0.0.1:8089/v1
  - type: self_check
    engine: openai
    model: test-self
    parameters:
      base_url: http://127.0.0.1:8000/v1
""".strip(),
        encoding="utf-8",
    )
    (source / "main.co").write_text("flow main\n  pass\n", encoding="utf-8")

    async def fake_run_validation(config_dir):
        return None

    monkeypatch.setattr("modules.guardrails.routing_check._run_validation", fake_run_validation)
    monkeypatch.setattr("modules.guardrails.routing_check._serve", lambda port, mode: type("Server", (), {"shutdown": lambda self: None})())
    result = run_guardrails_routing_validation(source)

    assert result == {
        "router_hits": 0,
        "direct_hits": 0,
        "main_url": "http://127.0.0.1:18089/v1",
        "self_check_url": "http://127.0.0.1:18000/v1",
    }
