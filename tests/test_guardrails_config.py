from pathlib import Path

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
    config_path = Path(__file__).resolve().parent.parent / "guardrails" / "config.yml"
    config = yaml.safe_load(config_path.read_text())

    assert config["rails"]["input"]["flows"] == [
        "mask pii in user input",
        "self check input",
        "check topical relevance",
    ]
