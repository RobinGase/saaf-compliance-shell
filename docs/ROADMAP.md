# Roadmap

Where the shell is today, what is next, and what was intentionally deferred.

## Status at a glance

| Area | State |
|---|---|
| Manifest validation | Working. 11 tests. |
| Audit log (hash chain + verify) | Working. 11 tests. |
| Guardrails HTTP wrapper (`:8088`) | Working. PII masking, injection preflight, topical rail, and 10 output rails (verdict / CoT / citation / absolutism / stale-attestation / jurisdiction / currency / standards-version / CVE / regulator-name). |
| Privacy Router (`:8089`) | Working. Local-only routing. 6 tests. |
| Presidio + BSN recognizer | Working. 22 tests. Dutch NLP model wired. |
| Firecracker VM launcher | Working. Unit-tested + live boot verified on Linux. |
| AgentFS overlay + diff | Working. Repeatable probe passes. |
| TAP + iptables policy | Working. Setup and teardown verified. |
| End-to-end probe | Working. `scripts/run_vm_probe.py` produces expected guest artefacts. |
| Vendor_Guard integration | Working. Full pipeline runs inside the VM and produces real scorecard, gap register, and audit memo artefacts in the AgentFS overlay. |

The modular branch is considered "proven enough to support real testing work." It is not yet considered production-ready.

## What is next (short term)

1. **Red-team coverage completion.** `saaf-shell test --suite red-team` passes the initial seed set. The full attack matrix from [`SECURITY.md`](SECURITY.md) needs to be translated into automated cases and run on every push.
2. **Kernel cmdline hardening.** Manifest `agent.env` values are only space-escaped when building Firecracker boot args. Newline / quote validation is still open — see `SECURITY_AUDIT.md` finding 1.
3. **HTTPS default for the rootfs builder.** `scripts/build-rootfs.sh` defaults to `http://archive.ubuntu.com`. Package signing still protects integrity, but flipping the default to HTTPS removes the MITM metadata concern.
4. **Dependency lock + `pip-audit` in CI.** `pyproject.toml` only pins lower bounds. CI should fail on known advisories.
5. **Output-rail matrix expansion.** Ten rails land in v0.7.0 (regulator-name fabrication added). Candidates still queued: fabricated case-law and enforcement-action IDs, fabricated incident-notification deadlines (GDPR 72h, NIS2 24h/72h/1mo, DORA 4h). Each new rail follows the established pattern — pure-Python rule under `modules/guardrails/*_rule.py`, thin `@action` wrapper, matrix tests, `rails.co` wiring, `docs/SECURITY.md` row.

## What is next (medium term)

1. **Remote-host run.** Full pipeline over SSH from a workstation to the Linux host. Smoke path exists manually; needs to be a repeatable command.
2. **Guardrails circular-dependency validation.** Verify under load that self-check LLM calls go direct to `:8000` and never through the router, regardless of failure modes.
3. **VM crash recovery.** Overlay preservation + audit log chain continuity across a mid-session host crash. `verify-log` handles truncation today; the full recovery runbook is not written.
4. **Log rotation.** Retention of rotated archives is enforced as of v0.7.1 via `scripts/enforce_audit_retention.py` + `saaf-log-retention.{service,timer}` under a daily systemd timer (see `docs/RUNBOOK.md`). What is *not* automated yet is the rotation step itself — cutting the live `audit.jsonl` to `audit.jsonl.<date>` in a way that preserves chain continuity across files. Today that is a manual operator action.
5. **Shell CLI polish.** `run`, `validate`, `verify-log`, `diff`, `sessions`, `test` all exist. Output formatting and error messages are still rough.

## Deferred to a later version

| Item | Reason for deferral |
|---|---|
| WORM / HSM-backed audit log | Out of scope for a single-host dev shell; add when there is a production deployment story |
| Landlock fallback path | Firecracker works on every target host today; fallback is theoretical |
| Three-tier data classification | v1 supports `sensitive` and `test`; a third tier needs a real use case first |
| Cloud inference fallback | Intentionally excluded — local-first is the whole point in v1 |
| Automated data-subject rights workflow | Manual runbooks are enough while the system is not processing production data |
| vLLM-TurboQuant inference backend | Phase 4. Blocked on GPU availability and SM86 build verification. |
| Automated DPIA review tooling | Human process; out of scope for code |

## Open decisions

| # | Question | Status |
|---|---|---|
| D2 | Who owns the DPIA for a production deployment? | Open |
| D3 | Vendor_Guard agent framework — LangChain / custom / other | Open; informs manifest env contract |
| D6 | Guardrails self-check model — same as main, or a smaller one? | Open; matters under concurrent load |
| D7 | Per-process UID separation for guardrails / router / audit writer | Open; security win vs deployment complexity |
| D8 | vLLM-TurboQuant on SM86 GPUs | Open; blocks Phase 4 |

`D1` (primary model host) and `D5` (NIM licensing) are both resolved — Ollama for Phase 1-3, vLLM-TurboQuant evaluated in Phase 4.

## How to read the longer plan

[`implementation_plan.md`](implementation_plan.md) has the full phased build sequence, the complete test matrices, and the GDPR / DORA / AI Act control mapping. Treat it as the reference spec; treat this roadmap as the operational view.
