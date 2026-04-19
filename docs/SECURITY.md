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

**Defence:** The VM has a single TAP interface. Host iptables rules forward port 8088 (guardrails) from the TAP gateway to `127.0.0.1:8088` and drop everything else on that interface, on both the INPUT and FORWARD chains so the policy holds even if the host has `net.ipv4.ip_forward=1`. IPv6 is disabled on the tap via `net.ipv6.conf.<tap>.disable_ipv6=1` and mirrored ip6tables DROP rules catch any traffic that still reaches an ip6tables path. There is no masquerade rule, so there is no path to the internet. At startup the shell refuses to run when either `/proc/sys/net/ipv4/ip_forward` or `/proc/sys/net/ipv6/conf/all/forwarding` is `1` unless the operator sets `SAAF_ALLOW_IP_FORWARD=1` to acknowledge the shared-host risk.

**Result:** Any outbound request that is not `gateway:8088` is dropped at the host kernel on both address families. The workload cannot reach `127.0.0.1:8000` (the model), `127.0.0.1:8089` (the router), DNS, or the internet.

### 3. PII leakage to the model or the logs

**Defence — input side:** The `mask pii in user input` Colang flow pipes user content through Presidio (with a Dutch-specific BSN recognizer) and replaces matches with stable placeholders before the model is invoked. If Presidio reports `has_unmasked_pii` (a match that survived redaction — rare, defence-in-depth check), the flow refuses outright.

**Defence — audit side:** A rail that classifies an input or output as unsafe does **not** write the raw offending text into the audit chain. The refusal event carries a SHA-256 digest and the character length of the content instead (see `guardrails_config/actions/self_check_direct.py::_digest_for_audit`, RT-05). The digest is enough to correlate duplicate refusals across the log without retaining the payload the rail just rejected.

**Scope gap — output side:** The `mask pii in model output` Colang flow is a `pass` stub in the current release. Model output is **not** re-run through Presidio before being returned to the workload. Output-side defence comes from (a) the input-side redaction having already denied the model the raw PII tokens to echo back, and (b) the twelve output rails that check for other classes of unsafe content (unfounded verdicts, fabricated citations, etc.). An output-PII redaction path is tracked for a future release; the refusal-event digest covers the audit-leak surface in the meantime.

**Result:** The model never sees raw PII that Presidio recognised on the input path. The audit log contains `<PERSON>` and `<BSN_NL>` placeholders where the input rail fired, and opaque `content_sha256` digests where a rail refused — not plaintext in either case.

### 4. Prompt injection

**Defence:** Guardrails' `self check input` rail is active. A cheap preflight layer in `modules/guardrails/service.py` also blocks obvious direct-injection phrasing before it reaches the rails. The preflight scans every message in the request, not just the final turn — the full `messages` array is forwarded to `LLMRails` verbatim, so an injection stashed in an earlier user turn or a replayed `assistant` turn reaches the model just like one in the last turn would. First match wins; the emitted `guardrails_preflight_block` event carries `message_index` and `message_role` so operators can see which turn tripped the wire.

**Result:** `Ignore all previous instructions...` is rejected at preflight regardless of which turn it appears in. Subtler attempts reach the self-check rail; the self-check LLM classifies them against a canonical intent set.

### 5. Off-topic use of the model

**Defence:** Off-topic rejection is delivered by the preflight tripwire in `modules/guardrails/service.py`, using the `preflight_off_topic_patterns` list in `guardrails_config/config.yml` (lowercase substring match). The Colang `check topical relevance` flow is a `pass` stub under Colang 2.x — a proper 2.x `@action` port is tracked for a future release; the preflight is the enforcement path today. Like the preflight injection list this is a **tripwire, not a filter**: paraphrases and synonyms slip past it. The honest framing is "cheaply catch blatant off-topic phrasing and create an audit record", not "block everything outside the allow-list".

**Result:** `Write me a poem about the Netherlands` is rejected with a 400 before it reaches the model, and a `guardrails_preflight_block` event with `category="off_topic"` and the matched pattern lands in the audit chain. Subtler off-topic phrasing (e.g. "draft a short ode") is not caught at the preflight and reaches the self-check LLM rail.

### 6. Audit log tampering

**Defence:** Every event is SHA-256 chained: each record embeds the previous record's hash, and the record itself is hashed over canonical JSON. A head-pointer sidecar (`<log>.head`) is updated atomically alongside every successful append under the same file lock and carries `{last_seq, last_event_hash, event_count, ts}`. `saaf-shell verify-log` walks the chain, cross-checks the tail against the sidecar, and reports tamper when they disagree.

**Result:** Editing an event changes its hash, which breaks the next record's `prev_hash`. Rollback of trailing events (pruning the last N records so the prefix still hash-validates) is caught by the sidecar mismatch. A crash-truncated tail is healed only when the last intact record matches the sidecar; the heal itself writes a chained `audit_tail_healed` event so the healed bytes aren't silently lost. When the intact prefix doesn't match the sidecar, the append refuses with `AuditTamperDetected`; operators who know the divergence is legitimate (backup restore, log rotation) set `SAAF_ACK_AUDIT_HEAL=1` — that path emits `audit_tail_heal_acknowledged` into the chain so the override is itself audited. Multi-session logs are supported — a `session_start` record resets the chain.

**Sidecar caveats:** the sidecar lives alongside the log by default, so an attacker with write to the log usually has write to the sidecar. Its value is (a) catching accidental truncation, (b) raising attack cost (the attacker must know to update it), and (c) being a single small file operators can mirror externally (journald, remote log, WORM object storage) for a real external anchor. Cryptographic signing of the sidecar is deferred — see the Out-of-scope table.

### 7. Resource exhaustion

**Defence:** Firecracker enforces `vcpu_count` and `mem_size_mib` from the manifest. A runaway workload OOMs its own VM, not the host.

### 8. Persistence across sessions

**Defence:** AgentFS overlays are per-session. The base rootfs is immutable. A new session gets a fresh overlay derived from the base.

**Result:** Writing a backdoor to `/usr/local/bin` in session A does not affect session B.

### 9. Unsafe claim shapes in model output (overview)

Twelve output rails target failure modes specific to audit-assistant agents. Each raises the floor on what a generalist LLM will let through; none replaces qualified human review. Regex-level detection lives in `modules/guardrails/*_rule.py` (CI-runnable without nemoguardrails); `@action` wrappers in `guardrails_config/actions/*.py` register the rails with Colang 2.0 flows in `guardrails_config/rails.co`.

| Rail | Targets | Refuses when |
|---|---|---|
| `check verdict evidence` | Unfounded compliance verdicts — "vendor is compliant", "meets all requirements" | A verdict phrase appears with no evidence anchor (Section / §  / Art. / attestation name) within 200 chars |
| `check cot leakage` | Scratchpad markup leaking into the final answer | `<think>`, `[REASONING]`, `My reasoning:`, `Chain-of-thought:`, `Let me think step by step:` appear in output |
| `check citation validity` | Fabricated EU-regulation article numbers | Article number exceeds the regulation's known maximum — GDPR 99, DORA 64, NIS2 46, AI Act 113 |
| `check absolutist language` | Absolute guarantees that cannot hold in an audit context | "100% secure", "zero risk", "100% uptime", "zero downtime", "impossible to breach", "guaranteed compliant", "always compliant" appear in output |
| `check stale attestations` | Attestation references treated as current when they are no longer fresh | A SOC 2 / ISAE 3402 / ISO 27001 / PCI DSS report with an embedded year more than two years old is cited |
| `check jurisdiction scope` | Regulations applied to an entity outside that regulation's jurisdictional scope | A strict-scope regulation (HIPAA, CCPA, CPRA, SOX, GLBA, HITECH, FERPA, FISMA, DORA, NIS2, eIDAS, UK GDPR, DPA 2018) co-occurs in a sentence with a jurisdiction marker from a different zone (US / EU / UK) |
| `check currency scope` | Regulation fines cited in the wrong statutory currency | A regulation co-occurs in a sentence with a currency token from a different zone — e.g. GDPR / AI Act / DORA (EUR) with `$` or `USD`, SOX / HIPAA (USD) with `€` or `EUR`, UK GDPR / DPA 2018 (GBP) with `$` or `€` |
| `check standards version` | Fabricated standards versions or revisions | A year-versioned ISO standard (27001, 27002, 9001, 22301, 14001, 20000-1, 27017, 27018, 27701) is cited with a year below first publication or more than one year in the future; PCI DSS with a version not in the published set (through 4.0.1); NIST SP 800-53 with a revision outside 1–5; NIST CSF with a version not in {1.0, 1.1, 2.0} |
| `check cve validity` | Fabricated CVE identifiers | A CVE is cited with a year before 1999 or more than one year in the future, a sequence component shorter than 4 digits (`CVE-2024-1`), or spaces instead of dashes (`CVE 2024 12345`) |
| `check regulator validity` | Fabricated supervisory / regulatory body names | A name from a curated confabulation list appears in the output — e.g. "European Privacy Authority" / "EU Cybersecurity Commission" / "European AI Authority" / "Federal Data Protection Agency" / "UK Privacy Authority". The refusal carries the canonical body (EDPB, ENISA, European AI Office, FTC, ICO) for reviewers. |
| `check deadline validity` | Wrong statutory notification windows | A deadline clause ("within N hours/days", "no later than N hours", Dutch "binnen N uur", "N-hour notification window", "has N hours to notify", "N hours after becoming aware / classification") is evaluated only when a notification trigger term (notification, report, breach, incident, early warning, classification, awareness, Dutch melding/melden/waarschuwing) appears in the same sentence — non-notification GDPR clocks (Art. 12 DSAR response, retention, SLA) are skipped. The rail attributes the deadline to every framework in a conjunction-joined alias list ("GDPR and NIS2", "NIS2/DORA") so a window wrong for any one of them flags. Windows are compared against GDPR Art. 33 {72h}, NIS2 Art. 23 {24h early warning, 72h incident, 1 month final}, DORA Art. 19 + RTS {4h initial, 72h intermediate, 1 month final}. "1 month" is accepted with ±24h tolerance so 28–31-day paraphrases pass. AVG (Dutch GDPR) is matched case-sensitively so English "avg" (shorthand for "average") does not anchor the rail. |
| `check case law validity` | Fabricated CJEU decision IDs and CNIL enforcement-action IDs | A CJEU / General Court identifier in canonical `[CTF]-NNN/YY` shape is cited with a year before 1989 (the numbering scheme's introduction) or more than one year in the future; a non-canonical separator variant (`C.237/23`, `C_442/22`, `T-442-22`) appears with CJEU / Court-of-Justice / General Court context nearby; or a CNIL `SAN-YYYY-NNN` sanction identifier is cited with a year before 2000 (conservative lower bound) or more than one year in the future. |

**Result:** a careless or jailbroken model whose output would read as marketing copy (or leak its scratchpad) is refused at the output rail, not returned to the workload. Matching is regex-based and intentionally narrow — hedged audit language ("designed to", "expected to", "per SOC 2 §CC6.7") is not flagged.

**Known limits:** the citation rail matches `Art.` / `Article` / `Artikel` (Dutch), accepts both English `of (the)` and Dutch `van (de|het)` in reverse phrasing, and also catches the bare-juxtaposition form ("Article 237 GDPR") with no connective. The absolutism rail now ignores hits that have a negation token (`not`, `no`, `never`, `nor`, `nothing`, `n't`) within the five preceding tokens, so legitimate hedged language ("the system is not 100% secure") passes; an absolutist phrase without any nearby negation still fires. The stale-attestation rail has year-level granularity only (no issue-month extraction); the 2-year threshold is a tunable default, not a hard regulatory rule. The jurisdiction rail deliberately excludes GDPR and the EU AI Act from mismatch detection because Article 3 / Article 2 extraterritoriality means a US or UK entity can be genuinely subject to them; it also reasons per sentence, so a cross-sentence reference will not be flagged. The currency rail includes GDPR and the EU AI Act (unlike the jurisdiction rail) because their fines are denominated in euros by statute regardless of where the entity is based — a US entity subject to GDPR still pays in euros. The currency rail suppresses sentences that contain explicit conversion phrasing ("equivalent to", "converted to", "in USD terms"), and also reasons per sentence. The standards-version rail allows a one-year future tolerance so genuinely pre-announced revisions are not flagged; non-canonical years inside the historical window (e.g. ISO 27001:2010, between real revisions) are intentionally NOT flagged because that level of precision would require the full per-standard revision history. The CVE rail flags out-of-range years and malformed shapes but does NOT verify that an in-range CVE is actually present in the CVE List — that requires a live lookup and is outside this rail's scope. The regulator-name rail is deliberately narrow: it flags a curated set of well-known confabulations (EU privacy/cybersecurity/AI, US DPA variants, UK DPA variants) rather than trying to validate every supervisory-body reference — the latter would require a full international directory of regulators and their correct English / local-language names. The case-law rail flags out-of-range years and malformed canonical shapes but does NOT verify that an in-range identifier corresponds to an actually-issued judgment or sanction — that requires a live lookup against the CJEU registry / CNIL sanctions list and is outside this rail's scope; coverage is also limited to CJEU / General Court and CNIL, so fabricated national-court or other DPA identifiers (e.g. Italian Garante, Spanish AEPD, Dutch AP) pass this rail unchallenged.

### 10. Router trust boundary (RT-01)

**Defence:** The Privacy Router (`modules/router/privacy_router.py`) is the sole path into the local model endpoint. The v0.9.0 trust model is **documented-accept on loopback only**: any caller that can reach the router's bind address is treated as authorised. That model only holds when the bind is loopback; a non-loopback bind silently promotes the local model to a network-accessible service. A FastAPI middleware inspects `scope["server"]` on every request and refuses with `403 router_bound_to_nonloopback` when the bind host is not in `127.0.0.0/8`, `::1`, or `localhost`. Every refusal emits a `router_nonloopback_refused` audit event (bind host, bind port, caller) so the override surface is visible in the chain.

**Escape hatch:** An operator who owns the network boundary by other means (TLS-terminating reverse proxy with client-cert auth, mTLS sidecar, kernel-level TAP filter) can set `SAAF_ALLOW_NONLOOPBACK_ROUTER=1` to accept a non-loopback bind. The envelope is the same shape as `SAAF_ALLOW_IP_FORWARD` — an explicit acknowledgement of the externally-enforced boundary, not a silent bypass.

**Result:** `uvicorn modules.router.privacy_router:app --host 0.0.0.0` returns `403` on every request and writes a refusal event per call. The deployed systemd unit in `packaging/systemd/` binds to `127.0.0.1` by default.

**Scope gap — caller authentication:** The router does **not** cryptographically authenticate individual callers on loopback. Any process running as the `saaf` user (or root) can call it. A per-caller authentication layer (UDS with filesystem-permissioned socket, shared-secret header, or mTLS) is tracked for v0.9.1; for v0.9.0 the single-tenant VM host model makes the loopback boundary adequate — the microVM isolation path (§2) already blocks the guest workload from reaching the router, and the only remaining same-host callers are operator tooling under the same privilege.

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
| GDPR | Art. 25 (Privacy by Design) | PII masking on input (Presidio), PII-digested refusal events on audit side, local-only inference, default-deny network |
| GDPR | Art. 30 (records of processing) | Hash-chained audit log, session start/end events, event counts |
| GDPR | Art. 32 (security of processing) | Firecracker isolation, TAP + iptables, append-only log |
| DORA | Operational resilience | Resource limits per VM, documented teardown, recoverable audit chain across crashes |
| EU AI Act | Log retention, traceability | Audit log with model target, latency, PII counts, per-session config hash |

Regulatory coverage is about **evidence**, not certification. These controls produce the artefacts an auditor needs; they do not replace the DPIA, legal basis register, or DPO sign-off.

## Reporting an issue

If you find something that weakens any of the defences listed above, open a private issue on the repo and tag it `security`. Do not include real PII or production audit material in the report.
