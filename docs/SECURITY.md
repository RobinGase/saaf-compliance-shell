# Security Model

This document describes what saaf-compliance-shell defends against, what it does not, and how each defence is enforced in code.

## Threat model

The shell assumes the workload is **not trusted**. The workload is an AI agent that processes sensitive material — it may be buggy, jailbroken, prompt-injected, or simply careless with outputs. The operator of the shell is trusted: they configure the manifest, run the host, and hold the audit log.

The shell does **not** assume the host is hostile. A compromised host is game-over for audit integrity and no in-process defence can recover from that.

## What the shell defends against

### 1. Filesystem reach beyond the declared working area

**Defence:** The workload runs in a Firecracker microVM. The host filesystem is never mounted into the guest. Inside the guest, `/audit_workspace` is read-write via an AgentFS overlay. The base rootfs is read-only.

**Result:** `cat /etc/shadow` inside the workload reads the guest's `/etc/shadow`, not the host's. Writes to `/audit_workspace` are captured in a SQLite DB on the host that the guest cannot reach.

### 2. Outbound network escape

**Defence:** The VM has a single TAP interface. Host iptables rules forward port 8088 (guardrails) from the TAP gateway to `127.0.0.1:8088` and drop everything else on that interface. There is no masquerade rule, so there is no path to the internet.

**Result:** Any outbound request that is not `gateway:8088` is dropped at the host kernel. The workload cannot reach `127.0.0.1:8000` (the model), `127.0.0.1:8089` (the router), DNS, or the internet.

### 3. PII leakage to the model or the logs

**Defence:** NeMo Guardrails runs input and output rails. The input rail pipes user content through Presidio (with a Dutch-specific BSN recognizer) and replaces matches with stable placeholders. The output rail does the same on model responses before returning them to the workload.

**Result:** The model never sees raw PII that Presidio recognised. The audit log contains `<PERSON>` and `<BSN_NL>` placeholders, not plaintext.

### 4. Prompt injection

**Defence:** Guardrails' `self check input` rail is active. A cheap preflight layer in `modules/guardrails/service.py` also blocks obvious direct-injection phrasing before it reaches the rails.

**Result:** `Ignore all previous instructions...` is rejected at preflight. Subtler attempts reach the self-check rail; the self-check LLM classifies them against a canonical intent set.

### 5. Off-topic use of the model

**Defence:** The `check topical relevance` rail rejects prompts outside a configured allow-list of audit-related topics (financial audit, compliance review, risk assessment, vendor evaluation, regulatory analysis, document review).

**Result:** `Write me a poem about the Netherlands` is rejected with a 400 before it reaches the model.

### 6. Audit log tampering

**Defence:** Every event is SHA-256 chained: each record embeds the previous record's hash, and the record itself is hashed over canonical JSON. `saaf-shell verify-log` walks the chain and reports the first broken link by sequence number.

**Result:** Editing an event changes its hash, which breaks the next record's `prev_hash`. Truncation is reported as such. Multi-session logs are supported — a `session_start` record resets the chain.

### 7. Resource exhaustion

**Defence:** Firecracker enforces `vcpu_count` and `mem_size_mib` from the manifest. A runaway workload OOMs its own VM, not the host.

### 8. Persistence across sessions

**Defence:** AgentFS overlays are per-session. The base rootfs is immutable. A new session gets a fresh overlay derived from the base.

**Result:** Writing a backdoor to `/usr/local/bin` in session A does not affect session B.

### 9. Unsafe claim shapes in model output

Four output rails target failure modes specific to audit-assistant agents. Each raises the floor on what a generalist LLM will let through; none replaces qualified human review. Regex-level detection lives in `modules/guardrails/*_rule.py` (CI-runnable without nemoguardrails); `@action` wrappers in `guardrails/actions/*.py` register the rails with Colang 2.0 flows in `guardrails/rails.co`.

| Rail | Targets | Refuses when |
|---|---|---|
| `check verdict evidence` | Unfounded compliance verdicts — "vendor is compliant", "meets all requirements" | A verdict phrase appears with no evidence anchor (Section / §  / Art. / attestation name) within 200 chars |
| `check cot leakage` | Scratchpad markup leaking into the final answer | `<think>`, `[REASONING]`, `My reasoning:`, `Chain-of-thought:`, `Let me think step by step:` appear in output |
| `check citation validity` | Fabricated EU-regulation article numbers | Article number exceeds the regulation's known maximum — GDPR 99, DORA 64, NIS2 46, AI Act 113 |
| `check absolutist language` | Absolute guarantees that cannot hold in an audit context | "100% secure", "zero risk", "impossible to breach", "guaranteed compliant", "always compliant" appear in output |

**Result:** a careless or jailbroken model whose output would read as marketing copy (or leak its scratchpad) is refused at the output rail, not returned to the workload. Matching is regex-based and intentionally narrow — hedged audit language ("designed to", "expected to", "per SOC 2 §CC6.7") is not flagged.

**Known limits:** the citation rail matches only `Art.` / `Article` (not the Dutch `Artikel` or variants that omit `of`). Negated absolutist phrasings ("not 100% secure") still trip the rail — rewording around the phrase is trivial and the bare phrase should not appear in deliverables anyway.

## What the shell does not defend against

| Gap | Why | Compensating control |
|---|---|---|
| Compromised host | No in-process defence survives root on the host | Audit log should be replicated to separate append-only storage (future work) |
| Base64-encoded PII | Presidio does not decode before analysis in v1 | Documented limitation; v2 will add a decode preprocessor |
| Unicode homoglyphs in PII | v1 recognizers are ASCII-biased | Documented limitation; tracked for v2 |
| Indirect identification ("the CFO mentioned in document X") | No model-free way to detect | Manual review of AgentFS outputs |
| Side-channel CoT leakage to files in `/audit_workspace` | AgentFS captures file content for the auditor, but PII in agent-written files is not redacted | Auditor access policy — who sees AgentFS dumps is governed outside the shell |
| Supply-chain compromise of Firecracker, Presidio, NeMo, or Python deps | Out of scope | Pin versions, run `pip-audit` in CI |

## Red-team test matrix (summary)

Full test specs are in [`implementation_plan.md`](implementation_plan.md#red-team-validation). The categories:

- **Isolation:** host filesystem access, internet egress, direct model access, router bypass, VM escape attempts, AgentFS tampering, resource exhaustion, audit log deletion, persistence across sessions.
- **Guardrails:** PII evasion (obfuscated BSN, base64, PII in filenames, homoglyphs), prompt injection (direct, via PII fields, indirect via documents, role-play jailbreaks), topical control (off-topic, gradual drift, disguised off-topic), CoT PII leakage, unfounded verdict refusal, fabricated article-number refusal, absolutist-language refusal, scratchpad-markup leakage refusal.
- **Router:** direct model call, guardrails bypass, cloud credential injection.
- **Audit log:** truncation, deletion, hash-chain tampering.

All automated cases run via `saaf-shell test --suite red-team`.

## Controls mapping (GDPR / DORA)

| Regulation | Article / requirement | Control in the shell |
|---|---|---|
| GDPR | Art. 25 (Privacy by Design) | PII masking at input and output, local-only inference, default-deny network |
| GDPR | Art. 30 (records of processing) | Hash-chained audit log, session start/end events, event counts |
| GDPR | Art. 32 (security of processing) | Firecracker isolation, TAP + iptables, append-only log |
| DORA | Operational resilience | Resource limits per VM, documented teardown, recoverable audit chain across crashes |
| EU AI Act | Log retention, traceability | Audit log with model target, latency, PII counts, per-session config hash |

Regulatory coverage is about **evidence**, not certification. These controls produce the artefacts an auditor needs; they do not replace the DPIA, legal basis register, or DPO sign-off.

## Reporting an issue

If you find something that weakens any of the defences listed above, open a private issue on the repo and tag it `security`. Do not include real PII or production audit material in the report.
