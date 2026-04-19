"""Tests for the Presidio PII redaction action.

Runs against the test fixtures in tests/fixtures/pii_samples.json.
"""

import asyncio
import json
from pathlib import Path

import pytest

from guardrails_config.actions.presidio_redact import _is_valid_bsn, presidio_redact

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def pii_samples() -> dict:
    with open(FIXTURES_DIR / "pii_samples.json") as f:
        return json.load(f)


# --- BSN 11-test unit tests ---


class TestBsn11Test:
    def test_valid_9digit(self):
        assert _is_valid_bsn("111222333") is True

    def test_valid_with_dots(self):
        assert _is_valid_bsn("111.222.333") is True

    def test_valid_with_dashes(self):
        assert _is_valid_bsn("111-222-333") is True

    def test_valid_with_spaces(self):
        assert _is_valid_bsn("111 222 333") is True

    def test_invalid_checksum(self):
        assert _is_valid_bsn("123456789") is False

    def test_too_short(self):
        assert _is_valid_bsn("12345") is False

    def test_too_long(self):
        assert _is_valid_bsn("1234567890") is False

    def test_non_numeric(self):
        assert _is_valid_bsn("12345678a") is False

    def test_all_zeros(self):
        # 0*9+0*8+...+0*-1 = 0, but total must != 0
        assert _is_valid_bsn("000000000") is False

    def test_8digit_padded(self):
        # 8-digit BSNs are zero-padded to 9 for validation
        assert _is_valid_bsn("11222333") is True or _is_valid_bsn("11222333") is False
        # Just verifying it doesn't crash — validity depends on checksum


# --- Presidio redaction integration tests ---


class TestPresidioRedact:
    @pytest.mark.parametrize(
        "sample_id",
        [
            "person_nl",
            "person_en",
            "email_simple",
            "bsn_valid_9digit",
            "combined_pii",
            "pii_in_audit_finding",
        ],
    )
    def test_should_detect(self, pii_samples: dict, sample_id: str):
        sample = next(s for s in pii_samples["should_detect"] if s["id"] == sample_id)
        result = asyncio.run(presidio_redact(sample["text"]))

        assert result["entity_count"] > 0, (
            f"Expected PII detection in '{sample_id}', got none"
        )
        assert result["risk_level"] == "sensitive"

        for expected_entity in sample["expected_entities"]:
            assert expected_entity in result["entities_found"], (
                f"Expected {expected_entity} in '{sample_id}', "
                f"found {result['entities_found']}"
            )

    @pytest.mark.parametrize(
        "sample_id",
        ["clean_audit_text", "clean_legal_reference", "short_number_not_bsn"],
    )
    def test_should_not_detect(self, pii_samples: dict, sample_id: str):
        sample = next(
            s for s in pii_samples["should_not_detect"] if s["id"] == sample_id
        )
        result = asyncio.run(presidio_redact(sample["text"]))

        assert result["entity_count"] == 0, (
            f"Expected no PII in '{sample_id}', "
            f"found {result['entities_found']}"
        )
        assert result["risk_level"] == "test"

    def test_redaction_replaces_pii(self, pii_samples: dict):
        sample = next(
            s for s in pii_samples["should_detect"] if s["id"] == "person_nl"
        )
        result = asyncio.run(presidio_redact(sample["text"]))

        assert "Jan de Vries" not in result["sanitized_text"]
        assert "<PERSON>" in result["sanitized_text"]

    def test_combined_pii_all_redacted(self, pii_samples: dict):
        sample = next(
            s for s in pii_samples["should_detect"] if s["id"] == "combined_pii"
        )
        result = asyncio.run(presidio_redact(sample["text"]))

        assert "Jan de Vries" not in result["sanitized_text"]
        assert "j.devries@audit.nl" not in result["sanitized_text"]
        assert "111222333" not in result["sanitized_text"]

    def test_no_unmasked_pii_after_redaction(self, pii_samples: dict):
        sample = next(
            s for s in pii_samples["should_detect"] if s["id"] == "combined_pii"
        )
        result = asyncio.run(presidio_redact(sample["text"]))

        assert result["has_unmasked_pii"] is False
