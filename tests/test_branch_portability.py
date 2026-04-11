from pathlib import Path

from scripts.check_branch_portability import check_paths, should_enforce_portability


def test_should_enforce_portability_for_main_and_modular() -> None:
    assert should_enforce_portability("main") is True
    assert should_enforce_portability("modular/single-host-phase2") is True
    assert should_enforce_portability("robin/local-phase2-devstack") is False


def test_check_paths_reports_forbidden_machine_specific_strings(tmp_path: Path) -> None:
    target = tmp_path / "config.yml"
    target.write_text("base_url: http://100.87.245.60:8000/v1\n")

    violations = check_paths([target])

    assert len(violations) == 1
    assert "100.87.245.60" in violations[0]


def test_check_paths_ignores_local_branch_only_patterns_when_absent(tmp_path: Path) -> None:
    target = tmp_path / "config.yml"
    target.write_text("base_url: http://127.0.0.1:8000/v1\n")

    assert check_paths([target]) == []
