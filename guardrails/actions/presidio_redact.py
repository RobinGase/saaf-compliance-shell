"""Presidio PII detection and redaction — registered as a NeMo Guardrails action.

Handles Dutch names, email addresses, and BSN numbers (with 11-test validation).
"""

import re

from nemoguardrails.actions import action
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


def _is_valid_bsn(digits: str) -> bool:
    """Dutch BSN 11-test validation."""
    cleaned = re.sub(r"[\s.\-]", "", digits)
    if len(cleaned) not in (8, 9):
        return False
    cleaned = cleaned.zfill(9)
    if not cleaned.isdigit():
        return False
    weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
    total = sum(int(d) * w for d, w in zip(cleaned, weights))
    return total % 11 == 0 and total != 0


class BsnRecognizer(PatternRecognizer):
    """Custom Presidio recognizer for Dutch BSN numbers.

    Matches 8-9 digit sequences and validates with the 11-test checksum.
    Numbers that look like BSNs but fail the 11-test are flagged at lower
    confidence (0.4) to catch typos and OCR errors.
    """

    PATTERNS = [
        Pattern(
            "BSN_STRICT",
            r"\b\d{9}\b",
            0.3,
        ),
        Pattern(
            "BSN_WITH_SEPARATORS",
            r"\b\d{3}[\.\-\s]\d{3}[\.\-\s]\d{3}\b",
            0.3,
        ),
        Pattern(
            "BSN_8DIGIT",
            r"\b\d{8}\b",
            0.2,
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="BSN_NL",
            patterns=self.PATTERNS,
            supported_language="nl",
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        cleaned = re.sub(r"[\s.\-]", "", pattern_text)
        if _is_valid_bsn(cleaned):
            # Valid 11-test — high confidence
            self.PATTERNS[0].score = 0.85
            return True
        else:
            # Fails 11-test but looks like a BSN — lower confidence
            # Catches typos, OCR errors in audit documents
            self.PATTERNS[0].score = 0.4
            return True


def _build_analyzer() -> AnalyzerEngine:
    """Build Presidio analyzer with Dutch NLP model and BSN recognizer."""
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [
            {"lang_code": "nl", "model_name": "nl_core_news_lg"},
            {"lang_code": "en", "model_name": "en_core_web_lg"},
        ],
    }
    provider = NlpEngineProvider(nlp_configuration=nlp_config)
    nlp_engine = provider.create_engine()

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["nl", "en"])
    analyzer.registry.add_recognizer(BsnRecognizer())
    return analyzer


# Module-level singletons — initialized once at import
_analyzer = _build_analyzer()
_anonymizer = AnonymizerEngine()


@action(name="PresidioRedactAction", execute_async=True)
async def presidio_redact(
    text: str,
    entities: list[str] | None = None,
    threshold: float = 0.6,
) -> dict:
    """Detect and redact PII from text.

    Returns a dict with sanitized_text, risk_level, entity_count,
    entities_found, and has_unmasked_pii.
    """
    target_entities = entities or ["PERSON", "EMAIL_ADDRESS", "BSN_NL"]

    results = _analyzer.analyze(
        text=text,
        entities=target_entities,
        language="nl",
        score_threshold=threshold,
    )

    # Build per-entity operators so each PII type gets its own placeholder
    operators = {
        r.entity_type: OperatorConfig("replace", {"new_value": f"<{r.entity_type}>"})
        for r in results
    }
    if not operators:
        operators = {"DEFAULT": OperatorConfig("replace", {"new_value": "<PII>"})}

    anonymized = _anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators,
    )

    # Check if any PII survived redaction (shouldn't happen, but defense in depth)
    post_check = _analyzer.analyze(
        text=anonymized.text,
        entities=target_entities,
        language="nl",
        score_threshold=threshold,
    )

    return {
        "sanitized_text": anonymized.text,
        "risk_level": "sensitive" if results else "test",
        "entity_count": len(results),
        "entities_found": list({r.entity_type for r in results}),
        "has_unmasked_pii": len(post_check) > 0,
    }
