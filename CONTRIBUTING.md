# Contributing

## What fits here

This shell is intentionally single-host and modular. Contributions that add cloud dependencies, multi-host dispatch, or embedded Tailscale/wireguard topology do not fit — that belongs in a private dev overlay. If you are unsure, open an issue before building.

Things that do fit:
- New guardrails rules under `modules/guardrails/` (additional hallucination-refusal patterns, new jurisdiction checks, additional PII recognizer types)
- Manifest schema extensions (new constraint fields, new resource limit types)
- Isolation improvements (AgentFS, Firecracker boot, TAP/iptables rules)
- Audit log improvements (rotation enforcement, new event types)
- Documentation gaps

## Setup

Requires Linux with KVM. The guardrails service and router run as plain uvicorn processes; the full isolation path (Firecracker + AgentFS) requires KVM access and a built rootfs image.

```bash
git clone https://github.com/RobinGase/saaf-compliance-shell
cd saaf-compliance-shell
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock
pip install -e ".[dev]"
```

For PII redaction (BSN recognizer + Dutch NLP):

```bash
pip install -e ".[dev,nlp]"
python -m spacy download nl_core_news_lg
python -m spacy download en_core_web_lg
```

## Tests

Two suites — run both before opening a PR.

```bash
# Main suite (no NLP models required)
pytest tests/ --ignore=tests/test_presidio_redact.py -q

# PII / Presidio suite (requires nlp extras + spaCy models above)
pytest tests/test_presidio_redact.py -q
```

CI runs both in separate jobs. If you are adding a new guardrails rule, add matrix-style positive/negative cases alongside it (see `tests/test_citation_rule.py` as a reference).

## Lint and type-check

```bash
ruff check .
mypy
```

Both gates run in CI on every push. Fix all ruff errors before submitting; mypy runs with `ignore_missing_imports = true` for the heavy optional deps (NeMo, Presidio) so there is no exemption needed for those.

## Portability rule

The `main` branch and any `modular/*` branch must not contain machine-specific strings: hostnames, IP addresses, absolute user paths, or topology-specific setup scripts. `scripts/check_branch_portability.py` enforces this in CI. The forbidden list is in that script. Violating the portability check blocks merge.

If you want to contribute something that requires host-specific config, it belongs behind an environment variable with a documented default, not hardcoded.

## Commit style

Conventional commits: `type(scope): description`. Types used in this repo: `feat`, `fix`, `docs`, `hardening`, `test`, `refactor`, `release`. Scope is the module or area (`isolation`, `guardrails`, `audit`, `router`, `manifest`, `ci`, `deps`). Keep the subject line under 72 characters; use the body for the "why" when it is not obvious.

## Pull requests

- One logical change per PR. If you are fixing a bug and noticed an unrelated issue, open a second PR.
- Link to any relevant ROADMAP item or open issue.
- If you are adding a new guardrails rule, include the regulatory basis (article number + regulation) for the pattern it refuses. The jurisdiction rule's comment explaining why GDPR is excluded from its own mismatch detection (`modules/guardrails/jurisdiction_rule.py`) is the model to follow.
- The branch portability, lint, and test CI gates all need to pass before review.

## Security issues

Report via the process in [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability.
