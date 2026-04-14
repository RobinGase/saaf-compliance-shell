"""Pure-Python detection of currency/regulation-zone mismatches.

Generalist models routinely hallucinate fine amounts in the wrong
currency — "the GDPR fine of $20 million", "SOX penalties of up to
€25 million". The statute for each regulation denominates its fines
in a specific currency (GDPR and DORA in euros, SOX and HIPAA in
dollars, UK GDPR in pounds), so a currency mismatch is a clean
fabrication signal that does not require reading the model's actual
numbers — the wrong currency alone is the tell.

Approach:
- Each regulation is mapped to the currency zone its statute uses.
- Currency tokens are detected in three shapes: symbol ($/€/£),
  ISO code (USD/EUR/GBP), and word (dollars/euros/pounds).
- For each sentence-level window, if a regulation co-occurs with a
  currency from a different zone, and the sentence is not negated,
  compared, or flagged as a conversion, the sentence is flagged.

The goal is not to verify amounts — that requires live statute
lookups — but to refuse obvious wrong-currency confabulations
before they land in a report.

Separated from the @action wrapper so CI can run these tests
without a nemoguardrails install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Regulations whose fines are denominated in a single currency by
# statute. GDPR (Art. 83) and the AI Act (Art. 99) both denominate
# fines in euros, so a US entity subject to either of them still
# receives a euro-denominated fine — the currency rail flags the
# wrong currency, not the wrong jurisdiction.
_REGULATION_CURRENCY: list[tuple[re.Pattern[str], str]] = [
    # US — dollars
    (re.compile(r"\bHIPAA\b", re.IGNORECASE), "USD"),
    (re.compile(r"\bCCPA\b"), "USD"),
    (re.compile(r"\bCPRA\b"), "USD"),
    (re.compile(r"\bSarbanes[-\s]?Oxley\b", re.IGNORECASE), "USD"),
    (re.compile(r"\bSOX\b"), "USD"),
    (re.compile(r"\bGLBA\b"), "USD"),
    (re.compile(r"\bGramm[-\s]?Leach[-\s]?Bliley\b", re.IGNORECASE), "USD"),
    (re.compile(r"\bHITECH\b"), "USD"),
    (re.compile(r"\bFERPA\b"), "USD"),
    (re.compile(r"\bFISMA\b"), "USD"),
    # EU — euros. GDPR and AI Act are included here (unlike the
    # jurisdiction rail) because fines are denominated in euros by
    # statute regardless of where the entity is based.
    (re.compile(r"\bGDPR\b"), "EUR"),
    (re.compile(r"\bAVG\b"), "EUR"),  # Dutch alias for GDPR
    (re.compile(r"\bGeneral Data Protection Regulation\b", re.IGNORECASE), "EUR"),
    (re.compile(r"\bDORA\b"), "EUR"),
    (re.compile(r"\bNIS\s?2\b"), "EUR"),
    (re.compile(r"\beIDAS\b", re.IGNORECASE), "EUR"),
    (re.compile(r"\bEU\s+AI\s+Act\b", re.IGNORECASE), "EUR"),
    (re.compile(r"\bAI\s+Act\b"), "EUR"),
    # UK — pounds. Must match before bare "GDPR" would catch
    # "UK GDPR" as EUR-scope.
    (re.compile(r"\bUK\s+GDPR\b", re.IGNORECASE), "GBP"),
    (re.compile(r"\bData Protection Act 2018\b", re.IGNORECASE), "GBP"),
    (re.compile(r"\bDPA\s?2018\b", re.IGNORECASE), "GBP"),
]


# Currency tokens grouped by zone. Symbols come first so longest
# alternations inside each regex pattern fire before shorter ones.
# The word "pounds" is ambiguous (it's a unit of weight too) but in
# the same sentence as a regulation name it is overwhelmingly money.
_CURRENCY_MARKERS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?:\$|\bUS\$|\bUSD\b|\bdollars?\b)",
            re.IGNORECASE,
        ),
        "USD",
    ),
    (
        re.compile(
            r"(?:€|\bEUR\b|\beuros?\b)",
            re.IGNORECASE,
        ),
        "EUR",
    ),
    (
        re.compile(
            r"(?:£|\bGBP\b|\bpounds?\b|\bsterling\b)",
            re.IGNORECASE,
        ),
        "GBP",
    ),
]


# Phrases that neutralise an apparent mismatch: explicit conversion,
# comparison, negation, or hypothetical framing. A sentence that
# explicitly converts one currency to another (e.g. "the €20M fine,
# equivalent to $22M") is not a fabrication and must not be flagged.
_NEGATION_OR_CONVERSION = re.compile(
    r"\b(?:"
    r"does not apply|do not apply|doesn'?t apply|don'?t apply|"
    r"not applicable|not denominated|"
    r"equivalent to|equivalent of|"
    r"converted to|converted into|conversion|"
    r"in USD terms|in EUR terms|in GBP terms|"
    r"expressed as|expressed in|denominated in|"
    r"approximately|roughly|circa|"
    r"unlike|whereas|compared to|compared with|in contrast to|"
    r"versus|vs\.?|"
    r"\bif\b[^.;]{0,80}?\b(?:were|was)\b|"
    r"would (?:be|have been)|"
    r"hypothetically"
    r")\b",
    re.IGNORECASE,
)


# Light sentence split — semicolons treated as clause breaks,
# same as the jurisdiction rail.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|;\s+")


@dataclass
class CurrencyFinding:
    """A currency/regulation-zone mismatch located in text."""

    sentence: str
    regulation: str
    regulation_zone: str
    currency: str
    currency_zone: str


def find_currency_mismatches(text: str) -> list[CurrencyFinding]:
    """Return every currency/regulation-zone mismatch in `text`."""
    findings: list[CurrencyFinding] = []
    for sentence in _SENTENCE_SPLIT.split(text):
        sentence = sentence.strip()
        if not sentence:
            continue
        if _NEGATION_OR_CONVERSION.search(sentence):
            continue

        # Find regulation matches first so we can exclude their
        # spans when scanning for currency markers (prevents a
        # token inside the regulation name from being misread).
        raw_reg_matches: list[tuple[str, str, tuple[int, int]]] = []
        for pattern, zone in _REGULATION_CURRENCY:
            for match in pattern.finditer(sentence):
                raw_reg_matches.append(
                    (match.group(0), zone, (match.start(), match.end()))
                )
        if not raw_reg_matches:
            continue

        # Drop any match whose span is strictly contained inside a
        # longer one — "UK GDPR" must win over bare "GDPR" so the
        # sentence maps cleanly to GBP, not to a GDPR/EUR + UK-GDPR/GBP
        # ambiguity that would self-mismatch against a £ currency.
        raw_reg_matches.sort(key=lambda m: (m[2][0], -(m[2][1] - m[2][0])))
        reg_matches: list[tuple[str, str, tuple[int, int]]] = []
        for candidate in raw_reg_matches:
            c_start, c_end = candidate[2]
            if any(
                rs <= c_start and c_end <= re_ and (rs, re_) != (c_start, c_end)
                for _, _, (rs, re_) in reg_matches
            ):
                continue
            reg_matches.append(candidate)

        def _inside_regulation_span(span: tuple[int, int], _regs=reg_matches) -> bool:
            return any(
                rs <= span[0] and span[1] <= re_
                for _, _, (rs, re_) in _regs
            )

        currency_matches: list[tuple[str, str]] = []
        for pattern, zone in _CURRENCY_MARKERS:
            for match in pattern.finditer(sentence):
                if _inside_regulation_span((match.start(), match.end())):
                    continue
                currency_matches.append((match.group(0), zone))
        if not currency_matches:
            continue

        for reg_text, reg_zone, _ in reg_matches:
            for cur_text, cur_zone in currency_matches:
                if cur_zone != reg_zone:
                    findings.append(
                        CurrencyFinding(
                            sentence=sentence,
                            regulation=reg_text,
                            regulation_zone=reg_zone,
                            currency=cur_text,
                            currency_zone=cur_zone,
                        )
                    )

    return findings


def currency_report(text: str) -> dict:
    """Return the same shape the Guardrails action returns."""
    findings = find_currency_mismatches(text)
    return {
        "has_currency_mismatch": bool(findings),
        "mismatch_count": len(findings),
        "samples": [
            f"{f.regulation} ({f.regulation_zone}) cited with "
            f"{f.currency} ({f.currency_zone})"
            for f in findings[:3]
        ],
    }
