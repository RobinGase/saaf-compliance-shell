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
