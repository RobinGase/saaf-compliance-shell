# NAP — control-to-article mapping

This document maps the controls the shell actually enforces to the
articles in GDPR, DORA, and the EU AI Act that an auditor will most
often read against them. It is the evidence-surface companion to
[`SECURITY.md`](SECURITY.md) — SECURITY describes *what* the shell
defends, this document describes *which article* each defence is
evidence for.

Scope is intentionally narrow: only controls that produce a machine-
verifiable artefact (audit event, refusal code, or structural
property of the runtime) are listed. Policy controls that live in
DPIA / ROPA / vendor contracts are out of scope — they are a
compliance programme's job, not the shell's.

Regulatory coverage is about **evidence**, not certification. Each
row below produces an auditable artefact (a hash-chained audit event,
a refusal code, or a structural property of the runtime) that an
auditor can quote when demonstrating the article is operationalised.
Rows do not replace the DPIA, legal basis register, DPO sign-off, or
human review of model outputs.

## GDPR

| Article | Control in the shell | Evidence surface |
|---|---|---|
| Art. 5(1)(c) — data minimisation | Presidio masking on input path (Dutch BSN recognizer + default entity set); `mask pii in user input` Colang flow replaces matches with stable placeholders before the model is invoked. | Audit record `guardrails_preflight_block` (category `pii`) and `refusal_recorded` events with `content_sha256` digests instead of raw payload. |
| Art. 5(1)(f) — integrity & confidentiality | Firecracker microVM isolation; single TAP interface with iptables `-I` on INPUT/FORWARD; IPv6 disabled per tap with mirrored ip6tables DROP. | `/opt/saaf/` systemd units, `modules/isolation/network.py::build_setup_commands`, audit event `session_start` with network topology. |
| Art. 25 — data protection by design and by default | PII masking on input (Presidio) + PII-digested refusal events (SHA-256 + length only) + local-only inference (no cloud fallback in v1) + default-deny egress. | `guardrails_config/actions/self_check_direct.py::_digest_for_audit`; router refusal `router_bound_to_nonloopback`; TAP + iptables posture per `docs/SECURITY.md` §2. |
| Art. 30 — records of processing activities | Hash-chained JSONL audit log with `session_start` / `session_end` records; every rail decision, route decision, refusal, and host-wide lock event is chained. | `modules/audit/log.py`; head-pointer sidecar at `<log>.head` for tamper-detection; `saaf-shell verify-log` exit code. |
| Art. 32 — security of processing | Firecracker VM isolation + AgentFS per-session overlay + append-only hash-chained log + host-wide `fcntl` session lock. | `modules/isolation/runtime.py`, `modules/isolation/session_lock.py`, `docs/SECURITY.md` §1, §2, §6, §8. |
| Art. 33 — notification of a personal data breach | Output rail `check deadline validity` flags deadlines cited outside the GDPR 72-hour window when the sentence anchors a notification trigger (not a DSAR or retention clock). | Refusal code `has_fabricated_deadline`; paraphrase baseline in `tests/harness/rail_paraphrases_baseline.json`. |
| Art. 83 — administrative fines | Output rail `check currency scope` flags GDPR fine references denominated in USD / GBP when no conversion phrasing is present. | Refusal code `has_currency_mismatch`. |

## DORA — Regulation (EU) 2022/2554

| Article | Control in the shell | Evidence surface |
|---|---|---|
| Art. 19 — reporting of ICT-related incidents (+ RTS) | Output rail `check deadline validity` pins DORA windows to {4h initial, 72h intermediate, 1 month final} and flags any deviation on a sentence that anchors a notification trigger. The 1-month bound accepts 28–31-day paraphrases (±24h). | Refusal code `has_fabricated_deadline`; see `modules/guardrails/deadline_rule.py`. |
| Operational resilience (whole-of-Ch.II) | Firecracker resource limits (`vcpu_count`, `mem_size_mib` from manifest); documented teardown path (`modules/isolation/runtime.py`); recoverable audit chain with crash-heal + sidecar acknowledgement event `audit_tail_heal_acknowledged`. | `modules/isolation/runtime.py`, `docs/SECURITY.md` §6, §7; `docs/RUNBOOK.md` recovery flows. |
| Art. 28 — ICT third-party risk (supply chain of the shell itself) | Reproducible tarball (`scripts/make-release-tarball.sh`) + SPDX SBOM + cosign keyless signature (Sigstore Fulcio, bound to workflow OIDC identity). | `.github/workflows/release.yml`; `scripts/verify-release.sh`; Rekor transparency log entries per release. |

## EU AI Act — Regulation (EU) 2024/1689

| Article | Control in the shell | Evidence surface |
|---|---|---|
| Art. 12 — record-keeping (logs) | Hash-chained audit log with model target, per-request latency, rail decisions, preflight blocks, session-start config hash, and `retention_days` from the manifest. | `modules/audit/log.py`; `modules/router/privacy_router.py::_log_route_decision`. |
| Art. 13 — transparency & provision of information | Router refusal codes (`payload_too_large_refused`, `router_bound_to_nonloopback`, `guardrails_preflight_block`) and rail refusal codes are documented in `docs/SECURITY.md` and raised as machine-readable `detail` strings. | FastAPI 400/403/413 response bodies; audit event catalogue. |
| Art. 14 — human oversight | No rail returns a compliance *verdict* — every refusal is a signal for human review, never a green-light. `check verdict evidence` specifically refuses unfounded verdict claims in model output. | Refusal codes `has_unfounded_verdict`, `has_absolutist_claim`, `has_unfounded_verdict` events in the audit chain. |
| Art. 15 — accuracy, robustness & cybersecurity | Firecracker isolation + default-deny egress + base rootfs immutable per session + AgentFS overlay reset per session + twelve output rails targeting accuracy-critical failure modes (fabricated citations, CVEs, regulators, case-law identifiers, standards versions, jurisdictions). | `modules/isolation/network.py`, `modules/guardrails/*_rule.py`, twelve-rail table in `docs/SECURITY.md` §9. |
| Art. 53 — obligations for providers of general-purpose AI models (downstream use) | All inference is routed via the local router; no cloud fallback; every call is logged with model ID from the payload; router refuses non-loopback binds by default. | `modules/router/privacy_router.py`; audit event `route_decision`; SECURITY.md §10. |

## Rail-to-article index

A reverse index: which article each of the twelve output rails is
most relevant to when quoted as evidence. Use this when writing an
audit response keyed by rail refusal code.

| Refusal code | Rail | Primary article |
|---|---|---|
| `has_unfounded_verdict` | `check verdict evidence` | AI Act Art. 14 (human oversight — no autonomous verdict) |
| `has_cot_leakage` | `check cot leakage` | AI Act Art. 13 (transparency — scratchpad is not the output) |
| `has_fabricated_citation` | `check citation validity` | AI Act Art. 15 (accuracy — no fabricated article numbers) |
| `has_absolutist_claim` | `check absolutist language` | AI Act Art. 14 (no absolute guarantees that cannot hold) |
| `has_stale_attestation` | `check stale attestations` | AI Act Art. 15 + GDPR Art. 32 (freshness of cited controls) |
| `has_jurisdiction_mismatch` | `check jurisdiction scope` | AI Act Art. 15 (regulator-to-jurisdiction accuracy) |
| `has_currency_mismatch` | `check currency scope` | GDPR Art. 83 (fine-denomination accuracy) |
| `has_fabricated_version` | `check standards version` | AI Act Art. 15 (no fabricated ISO/PCI/NIST revisions) |
| `has_fabricated_cve` | `check cve validity` | AI Act Art. 15 (no fabricated CVE IDs) |
| `has_fabricated_regulator` | `check regulator validity` | AI Act Art. 13 + GDPR Art. 30 (supervisory body accuracy) |
| `has_fabricated_deadline` | `check deadline validity` | GDPR Art. 33 + DORA Art. 19 + NIS2 Art. 23 (statutory windows) |
| `has_fabricated_case_law` | `check case law validity` | AI Act Art. 15 (no fabricated CJEU / CNIL IDs) |

## What this doc is not

- Not a conformity assessment template. Auditors want a DPIA + ROPA +
  DPO sign-off + control test evidence; this document only supplies
  the last of those.
- Not a claim that a shell-protected workload is a "compliant" AI
  system. Compliance is about a deployment's full lifecycle —
  training data, fine-tuning records, human review of outputs,
  contractual flow-down to downstream processors — none of which
  lives in this repo.
- Not a substitute for legal review of any specific deployment. The
  mapping highlights the articles most often cited against each
  control; it does not guarantee that the control is legally
  sufficient for those articles in any particular Member State or
  deployment context.
