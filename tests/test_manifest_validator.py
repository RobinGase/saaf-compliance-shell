"""Tests for the saaf-manifest.yaml validator."""

from pathlib import Path

from modules.manifest.validator import validate_manifest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestValidManifest:
    def test_valid_manifest_passes(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_valid.yaml")
        assert result.valid is True
        assert result.errors == []

    def test_manifest_name_parsed(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_valid.yaml")
        assert result.manifest["name"] == "vendor-guard"

    def test_manifest_version_is_1(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_valid.yaml")
        assert result.manifest["version"] == 1


class TestInvalidManifest:
    def test_invalid_manifest_fails(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_invalid.yaml")
        assert result.valid is False
        assert len(result.errors) > 0

    def test_missing_version_reported(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_invalid.yaml")
        error_fields = [e.field for e in result.errors]
        assert "version" in error_fields

    def test_invalid_classification_reported(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_invalid.yaml")
        error_fields = [e.field for e in result.errors]
        assert "data_classification.default" in error_fields

    def test_invalid_pii_entity_reported(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_invalid.yaml")
        error_fields = [e.field for e in result.errors]
        assert "pii.entities" in error_fields

    def test_missing_agent_reported(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_invalid.yaml")
        error_fields = [e.field for e in result.errors]
        assert "agent" in error_fields

    def test_missing_resources_reported(self):
        result = validate_manifest(FIXTURES_DIR / "manifest_invalid.yaml")
        error_fields = [e.field for e in result.errors]
        assert "resources" in error_fields


class TestEdgeCases:
    def test_nonexistent_file(self):
        result = validate_manifest("/nonexistent/path/manifest.yaml")
        assert result.valid is False
        assert "not found" in result.errors[0].message

    def test_reports_all_errors(self):
        """Invalid manifest should report multiple errors, not just the first."""
        result = validate_manifest(FIXTURES_DIR / "manifest_invalid.yaml")
        assert len(result.errors) >= 4


class TestBootArgValidation:
    """H1: reject shell metachars that would malform the kernel cmdline."""

    def _write_manifest(self, tmp_path: Path, overrides: dict) -> Path:
        base = {
            "version": 1,
            "name": "vendor-guard",
            "agent": {
                "entrypoint": "python3 -m vendor_guard.agent",
                "working_directory": "/audit_workspace",
                "env": {"INFERENCE_URL": "http://172.16.0.1:8088/v1/chat/completions"},
            },
            "data_classification": {"default": "sensitive"},
            "filesystem": {"read_write": ["/audit_workspace"]},
            "network": {"allow": [{"host": "gateway", "port": 8088, "purpose": "nemo_guardrails"}]},
            "resources": {"vcpu_count": 2, "mem_size_mib": 2048},
            "pii": {"entities": ["PERSON"]},
            "audit": {"retention_days": 2555},
        }
        # Shallow merge "agent.env" so a test can add a single bad env var
        # without clobbering INFERENCE_URL.
        if "agent" in overrides:
            agent = overrides["agent"]
            if "env" in agent:
                merged_env = {**base["agent"]["env"], **agent["env"]}
                agent = {**base["agent"], **agent, "env": merged_env}
            else:
                agent = {**base["agent"], **agent}
            base["agent"] = agent
        path = tmp_path / "manifest.yaml"
        import yaml as _yaml
        path.write_text(_yaml.safe_dump(base), encoding="utf-8")
        return path

    def test_entrypoint_with_dollar_is_rejected(self, tmp_path: Path):
        path = self._write_manifest(tmp_path, {"agent": {"entrypoint": "python3 -c 'import os;os.system(\"rm -rf $HOME\")'"}})
        result = validate_manifest(path)
        assert not result.valid
        assert any(e.field == "agent.entrypoint" for e in result.errors)

    def test_entrypoint_with_semicolon_is_rejected(self, tmp_path: Path):
        path = self._write_manifest(tmp_path, {"agent": {"entrypoint": "python3 -m x; rm -rf /"}})
        result = validate_manifest(path)
        assert not result.valid
        assert any(e.field == "agent.entrypoint" for e in result.errors)

    def test_entrypoint_with_newline_is_rejected(self, tmp_path: Path):
        path = self._write_manifest(tmp_path, {"agent": {"entrypoint": "python3\nmalicious=true"}})
        result = validate_manifest(path)
        assert not result.valid
        assert any(e.field == "agent.entrypoint" for e in result.errors)

    def test_env_value_with_quote_is_rejected(self, tmp_path: Path):
        path = self._write_manifest(tmp_path, {"agent": {"env": {"EVIL": 'bad"value'}}})
        result = validate_manifest(path)
        assert not result.valid
        assert any(e.field == "agent.env.EVIL" for e in result.errors)

    def test_env_key_with_space_is_rejected(self, tmp_path: Path):
        path = self._write_manifest(tmp_path, {"agent": {"env": {"HAS SPACE": "value"}}})
        result = validate_manifest(path)
        assert not result.valid
        assert any(e.field == "agent.env.HAS SPACE" for e in result.errors)

    def test_normal_entrypoint_with_space_still_valid(self, tmp_path: Path):
        """Regression guard: spaces in entrypoint are fine — they get escaped."""
        path = self._write_manifest(tmp_path, {"agent": {"entrypoint": "python3 -m vendor_guard.agent --verbose"}})
        result = validate_manifest(path)
        assert result.valid, result.errors

    def test_url_in_env_value_still_valid(self, tmp_path: Path):
        """Regression guard: the default INFERENCE_URL shape must pass."""
        path = self._write_manifest(tmp_path, {})
        result = validate_manifest(path)
        assert result.valid, result.errors
