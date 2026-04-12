from pathlib import Path

import pytest
import yaml


def test_guardrails_routes_main_traffic_via_router_and_self_check_direct() -> None:
    config_path = Path(__file__).resolve().parent.parent / "guardrails" / "config.yml"
    config = yaml.safe_load(config_path.read_text())

    models = {entry["type"]: entry for entry in config["models"]}

    assert models["main"]["model"] == "Randomblock1/nemotron-nano:8b"
    assert models["main"]["parameters"]["base_url"] == "http://127.0.0.1:8089/v1"
    assert models["self_check"]["model"] == "Randomblock1/nemotron-nano:8b"
    assert models["self_check"]["parameters"]["base_url"] == "http://127.0.0.1:8000/v1"


def test_guardrails_input_flows_include_self_check_and_topical_control() -> None:
    rails_path = Path(__file__).resolve().parent.parent / "guardrails" / "rails.co"
    content = rails_path.read_text()

    assert "flow input rails $input_text" in content
    assert "mask pii in user input" in content
    assert "SelfCheckInputDirectAction" in content
    assert "check topical relevance" in content


def test_guardrails_defines_required_self_check_prompts() -> None:
    config_path = Path(__file__).resolve().parent.parent / "guardrails" / "config.yml"
    config = yaml.safe_load(config_path.read_text())

    prompts = {prompt["task"]: prompt for prompt in config.get("prompts", [])}

    assert "self_check_input" in prompts
    assert "{{ user_input }}" in prompts["self_check_input"]["content"]
    assert "self_check_output" in prompts
    assert "{{ bot_response }}" in prompts["self_check_output"]["content"]


def test_guardrails_config_loads_colang_v2_flows() -> None:
    RailsConfig = pytest.importorskip("nemoguardrails").RailsConfig
    config_dir = Path(__file__).resolve().parent.parent / "guardrails"

    cfg = RailsConfig.from_path(str(config_dir))

    assert cfg.colang_version == "2.x"
    assert len(cfg.flows) > 0


def test_guardrails_config_uses_colang_flows_not_yaml_rails() -> None:
    config_path = Path(__file__).resolve().parent.parent / "guardrails" / "config.yml"
    config = yaml.safe_load(config_path.read_text())

    assert config["colang_version"] == "2.x"
    assert "rails" not in config


def test_presidio_action_is_registered_for_guardrails() -> None:
    action_source = (Path(__file__).resolve().parent.parent / "guardrails" / "actions" / "presidio_redact.py").read_text()

    assert "@action" in action_source
    assert "PresidioRedactAction" in action_source
