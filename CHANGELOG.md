# Changelog

All notable changes to `saaf-compliance-shell` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Annotated git tags carry the authoritative release notes; this file is a
curated narrative. For full commit detail per release, run
`git log <prev>..<tag>` or `git tag -l --format='%(contents)' <tag>`.

## [Unreleased]

### Changed
- CLI output now flows through the `logging` module (logger name
  `saaf_shell`) with a `-v` / `--verbose` flag for `DEBUG` level. A
  dynamically-resolving stdout handler keeps pytest's `capsys` capture
  working. (L1, L2)
- `cmd_run`, `cmd_diff`, `cmd_sessions`, and `cmd_test` now catch only
  the narrow `_EXPECTED_ERRORS` tuple. An unexpected exception produces
  a traceback rather than being swallowed as `FAIL — ...`. (L3)
- `_count_session_events` scans the audit log backward in fixed-size
  binary chunks, stopping at this session's `session_start`. Cost is now
  proportional to the session size, not the whole retention window. (H6)
- Privacy router reuses a single `httpx.AsyncClient` owned by a FastAPI
  lifespan hook, removing a per-request TCP handshake against
  `127.0.0.1`. Tests use `TestClient` as a context manager and swap
  `app.state.http_client` for a mock. (H8)
- `validate_manifest` folds in the v1 network-policy check (exactly one
  rule, gateway host + `GUARDRAILS_PORT`) that previously lived behind a
  separate `validate_v1_network_rules` call. Runtime still re-checks as
  belt-and-suspenders. (M1)

### Added
- Manifest validator rejects shell-metachar injection in `agent.entrypoint`,
  `agent.working_directory`, and `agent.env` keys / values via a single
  allowlist regex (`_BOOT_ARG_SAFE_RE`) before the Firecracker layer ever
  sees the value. Complements `firecracker._encode_boot_value`. (H1)
- `VALID_PII_ENTITIES` carries a Presidio docs pointer comment so
  maintainers know where to check when extending the set. (M2)

### Documentation
- `pyproject.toml` carries a `TODO(v0.9)` note above the Python version
  cap (`>=3.11,<3.14`) so the next release bump is an explicit decision. (M5)

## [0.8.6] — 2026-04-18

### Fixed
- **C1–C7 + H4, H5, H7 (partial), H9, H10** from the 2026-04-18
  independent review. See `docs/REVIEW_2026-04-18.md` for the full punch
  list.
- Preflight pattern lists moved to `guardrails/config.yml` with
  mtime-keyed hot-reload; tripwire-not-filter framing made explicit.
- Firecracker console streams to disk instead of buffering in memory.
- Runtime failures now emit explicit `vm_exit` + `command_failed` audit
  events with captured stderr.
- `/health` actively probes audit-log writability and returns 503 on
  failure.
- CWD-chdir workaround wrapped in `threading.Lock` with explicit
  `workers=1`; full rename deferred to v0.9.

## [0.8.5] — 2026-04-17

### Fixed
- Colang pipeline now actually fires output rails on the happy path. All
  12 output rails were defined in prior v0.8.x releases but the
  `_bot_say` override was never loaded because `main.co` lacked
  `import guardrails`; the fix also had to neutralise a CWD-shadow
  collision because the config dir is also named `guardrails`.
- Silent action-registration bug (relative → absolute imports).

### Added
- Structural regression test pinning the Colang import wiring.
- `AUDIT_LOG_PATH` note in the runbook.

## [0.8.4] — 2026-04-16

### Added
- **12th output rail**: CJEU / General Court case-ID and CNIL SAN
  enforcement-action-ID plausibility check
  (`modules/guardrails/case_law_check.py`).
- CJEU canonical `[CTF]-NNN/YY` must have year ≥ 1989
  (numbering-scheme start) and ≤ `current_year + 1`.
- CNIL `SAN-YYYY-NNN` must have year ≥ 2000.
- Malformed CJEU shapes (`C.237/23`, `C-237-23`, `C_237/23`) flagged
  only when CJEU/ECJ/Court-of-Justice context appears within a 120-char
  window.
- Wired on all three enforcement paths: Colang flow, `@action` wrapper,
  bypass-path scanner. Registry-pin test extended.

### Documentation
- `SECURITY.md` Known Limits updated: no live court-registry lookup;
  national courts other than CJEU and national DPAs other than CNIL are
  out of scope in v1. ENISA/NIS2, Garante, AEPD, AP queued for later
  iterations.

## [0.8.3] — 2026-04-15

### Fixed
- Fourth-round review: 9 of 10 findings closed. P2-1 (DORA 24 h
  backstop) deferred pending OJ verification.
- **P1-1 regression**: deadline rail was wired into the Colang flow but
  not into the shared bypass-path scanner (`output_scan`). Fixed plus a
  registry-pin test so this class of bug can't happen silently again.
- Trigger-term guard: deadlines evaluated only in notification contexts.
  GDPR Art. 12 DSAR windows, retention periods, and SLAs no longer
  false-positive.
- Multi-framework attribution: *"Under GDPR and NIS2, within 24 hours"*
  now flags for GDPR regardless of word order.
- AVG matched case-sensitively so English *"avg"* (average) doesn't
  anchor the rail.
- *"within hours"* without a number is no longer synthesised as `num=1`.
- Bare `Article 33` dropped from GDPR aliases — the citation rail's job.
- Sentence-boundary detection updated so *"Art."* doesn't split
  framework attribution off from the deadline clause.

### Added
- Three paraphrase shapes: N-hour window, *"has N to …"*, *"N after
  awareness"* — all passed through the trigger guard.
- 25 new tests; 531 passed total, 1 skipped.

## [0.8.2] — 2026-04-14

### Added
- **11th output rail**: incident-notification-deadline plausibility
  check for GDPR / NIS2 / DORA fabrications.
- Detects deadline phrases (*"within N hours/days"*, *"no later than N
  hours"*, Dutch *"binnen N uur"*) linked to a framework alias within
  200 chars, normalises to hours, and compares against the statutory
  set:
  - GDPR Art. 33 — 72 h
  - NIS2 Art. 23 — 24 h early warning, 72 h incident, 1 mo final
  - DORA Art. 19 + RTS — 4 h initial, 72 h intermediate, 1 mo final
- Month-length paraphrases (28–31 days) pass via ±24 h tolerance on the
  720 h bucket.
- English + Dutch connectives. Preceding-alias preference so chained
  clauses attribute correctly.
- 26 new tests; 506 passed total.

## [0.8.1] — 2026-04-13

### Fixed
- Third-round review findings (D + E):
  - **P2**: `audit.event_count` isolates concurrent sessions by
    filtering records on `session_id` rather than scanning after
    `session_start`.
  - **P2**: verdict rail nominalisation patterns with intervening-word
    slop catch *"compliance was demonstrated"*, *"vendor achieved GDPR
    compliance"*, and siblings.
  - **P3**: citation rail reverse-phrase connective rewritten into a
    four-branch group covering paraphrased prepositions, possessive
    prefixes, em-dash / comma parentheticals, and intervening generic
    nouns with parenthesised aliases.
  - **P3**: `lru_cache` keyed on `SAAF_SELF_CHECK_URL` so config
    rebuilds when the URL changes between requests.
- 480 tests passing (1 presidio-only skip) across `main` and
  `modular/single-host-phase2`.

## [0.8.0] — 2026-04-12

First major review-closure release. Independent review closed the last
bypass paths and sharpened four output rails against adversarial
paraphrases.

### Added
- **Safety posture**
  - Salvage-bypass path (content recovered from LLM-adapter error
    strings) now runs the pure-Python output rails before returning.
  - IPv6 guest isolation via `disable_ipv6` sysctl on the tap plus
    `ip6tables` INPUT/FORWARD DROP mirrors. Startup refuses to run when
    `/proc/sys/net/ipv6/conf/all/forwarding=1` unless the operator
    acknowledges with `SAAF_ALLOW_IP_FORWARD=1`.
  - `self_check_input` / `self_check_output` refusals emit
    `guardrails_rail_fire` into the audit chain alongside the ten regex
    rails.
- **CI**
  - Runtime deps installed from `requirements.lock` on every run.
  - `ruff` + `mypy` gate.
  - Presidio PII-redaction coverage in CI.
  - `pip-audit` job.
- Operator runbook + automated audit-log retention.

### Fixed
- **Rail precision**
  - Citation rail catches *"under"*, *"in"*, *"within"*, *"from"*,
    *"as part of"* connectives.
  - Verdict rail catches passive-voice *"have been fulfilled"* and
    non-hedged *"in full compliance with"*.
  - Absolutism rail no longer false-positives on SLA uptime /
    availability quotations.
  - CoT-leakage rail HTML-unescapes its input so `&lt;think&gt;` cannot
    slip past.
- **Correctness**
  - `session_end.event_count` reflects cross-writer totals.
  - Privacy router audits the model from the request body, not a
    hardcoded constant.

## [0.7.1] and earlier

See `git log v0.7.1` and earlier annotated tags. Pre-0.8 history is the
initial buildup of the Firecracker + AgentFS + NeMo Guardrails
compliance shell: manifest validator, audit log, network policy, VM
lifecycle, initial rail set.
