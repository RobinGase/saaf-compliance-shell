# Changelog

All notable changes to `saaf-compliance-shell` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Annotated git tags carry the authoritative release notes; this file is a
curated narrative. For full commit detail per release, run
`git log <prev>..<tag>` or `git tag -l --format='%(contents)' <tag>`.

## [Unreleased]

Hardening wave toward v0.9.0. Each batch is tagged `v0.9.0-sN` and
logged in `docs/REVIEW_2026-04-19_hardening.md`. Latest checkpoint:
`v0.9.0-s9`.

### Security
- **S1 — oversized-input safe refusal** (`v0.9.0-s1`).
  `modules/guardrails/service.py` no longer proxies oversized payloads
  to the main model with output-rescan as the only check; a request
  exceeding `MAX_GUARDRAILS_PAYLOAD_CHARS` is refused with HTTP 413 and
  `detail = "payload_too_large_refused"`, and an `oversize_refused`
  event lands in the hash-chained audit log. Three defect-encoding
  tests were rewritten: they asserted a 200 with proxied content on
  oversized input, which was the bypass this change closes.
- **S2 — host-wide session lock** (`v0.9.0-s2`). New
  `modules/isolation/session_lock.py` wraps `run_manifest` in a
  non-blocking `fcntl.flock(LOCK_EX | LOCK_NB)` on
  `/var/run/saaf-shell/session.lock`. Two concurrent sessions on the
  same host used to race on the shared NFS port, iptables rules, and
  `ip_forward` gate; the second caller now fails fast with
  `SessionLockHeld` carrying the live holder's PID. Lock is held on the
  file descriptor so the kernel auto-releases it on crash — no cleanup
  script. Windows path is a no-op.
- **S5 — DORA notification-deadline citation verified** (`v0.9.0-s5`).
  P2-1 (Commission Delegated Regulation (EU) 2024/1772 24h backstop)
  dismissed after OJ read: 2024/1772 Art. 5 is a classification criterion
  for data losses, not a notification deadline. DORA reporting windows
  (4h / 72h / 1 month) sit in Regulation (EU) 2022/2554 Art. 19 + the
  RTS under Art. 20; the rail table is correct. Wrong citation in
  `deadline_rule.py` docstring fixed; 4 regression tests pin the
  confusion.
- **S6 — red-team quick wins** (`v0.9.0-s6`).
  *RT-04*: manifest `name` is now shell-metachar-checked before being
  interpolated into the kernel `ip=...:<name>:eth0:off` cmdline segment
  (hostname must not contain whitespace; `_check_boot_arg` given a
  `forbid_space=True` mode). *RT-09*: `session_id` no longer bleeds
  across session boundaries — `_read_chain_tail` now clears it on
  `session_end` so a post-close `route_decision` is no longer
  mis-attributed to the just-closed session. *RT-10*: systemd units
  gained `LogsDirectory=openshell` + `LogsDirectoryMode=0750` so the
  sandboxed writer can reach the default `/var/log/openshell/audit.jsonl`
  path.
- **S7 — audit integrity: head-pointer sidecar** (`v0.9.0-s7`).
  *RT-02* (rollback / suffix deletion) and *RT-03* (crash-heal
  tamper-erasure) both stayed green under `verify_log` because the log
  was self-describing. Head-pointer sidecar at `<log>.head`, atomic
  `os.replace` under the existing `fcntl` lock, carries
  `{last_seq, last_event_hash, event_count, ts}`. `verify_log`
  cross-checks tail against sidecar; `append_chained_event` classifies
  the tail state (`clean` / `first_write` / `legacy` / `heal_legit` /
  `tamper`). Legit heal emits a chained `audit_tail_healed` record;
  tamper raises `AuditTamperDetected` unless `SAAF_ACK_AUDIT_HEAL=1`
  (ack emits `audit_tail_heal_acknowledged`). Sidecar is not
  cryptographic — its value is catching accidental truncation and
  giving operators one small file to mirror externally for a real
  anchor. Signed sidecar deferred.
- **S8 — PII-digest refusal audit + full-history preflight**
  (`v0.9.0-s8`). *RT-05*: `guardrails_config/actions/self_check_direct.py`
  no longer emits the raw refused prompt / completion on the audit
  side; `_digest_for_audit` replaces the content with
  `{content_sha256, content_len}` on both input and output refusal
  paths. Refusal events are now investigator-useful without becoming a
  secondary PII store. *RT-08*: `modules/guardrails/service.py`
  preflight now scans every message in the request (every role,
  first-match-wins) via `_preflight_scan_messages`; the prior
  last-message-only scan let a jailbreak land in `messages[0]` and
  slip through. Audit event carries `message_index` + `message_role`
  for the match.
- **S9 — router loopback-bind boundary** (`v0.9.0-s9`). *RT-01*:
  `modules/router/privacy_router.py` now refuses any request with
  HTTP 403 `router_bound_to_nonloopback` when the FastAPI ASGI scope
  reports a non-loopback bind (checked via `scope["server"]` — covers
  `0.0.0.0`, `::`, and any routable address). Refusals emit a
  `router_nonloopback_refused` audit event with bind host, bind port,
  and caller. Operator escape hatch `SAAF_ALLOW_NONLOOPBACK_ROUTER=1`
  mirrors `SAAF_ALLOW_IP_FORWARD` for operators who front the router
  with an externally-enforced boundary (mTLS sidecar, filtered LB).
  `docs/SECURITY.md` §10 documents the v0.9.0 trust model
  ("documented-accept on loopback; caller authentication deferred to
  v0.9.1"). 4 new tests cover the loopback matcher, the refusal path
  (chat + health), and the allow-env escape hatch.
- **S10 — iptables `-I` on filter chains + doc alignment**
  (`v0.9.0-s10`). *RT-06*: `modules/isolation/network.py` switched all
  filter-table rules in `build_setup_commands` from `-A <chain>` to
  `-I <chain> N` with explicit contiguous positions 1..N. On a shared
  host with Tailscale / Docker / libvirt, appending SAAF's DROP after
  their pre-existing ACCEPT was defeatable under
  `SAAF_ALLOW_IP_FORWARD=1`; inserting at the top of each filter chain
  keeps the SAAF block authoritative. NAT `PREROUTING` stays `-A`
  (scoped by `-i <tap>`; can't be shadowed). *RT-07*:
  `docs/SECURITY.md` §3 and §5 rewritten to stop overclaiming — the
  output-side Presidio call is a `pass` stub (input-side masking + the
  new S8 digest on refusal are the actual PII controls), and the Colang
  topical flow is a `pass` stub (the enforcement path is the
  service-layer preflight). GDPR Art. 25 row in the Controls mapping
  updated to match.

### Added
- **S3 — rail adversarial paraphrase harness** (`v0.9.0-s3`).
  `tests/harness/rail_paraphrases_baseline.json` fixes expected flag
  state per (rail, paraphrase); `tests/test_rail_paraphrase_harness.py`
  asserts the current behaviour against that baseline across all 12
  rails (32 paraphrases). A coverage-gate test refuses the suite if a
  new rail is added to `_RAILS` without a baseline entry. Drift
  detector alongside the per-rail unit tests.
- **S4 — v0.8.7-deferred bundle** (`v0.9.0-s4`, five sub-batches):
  (S4.1) `_build_rails` cache keyed on config-dir max mtime so
  Colang/YAML edits invalidate on next request; (S4.2) NFS server log
  routing — `start_nfs_server` gets optional `log_path`; runtime writes
  `<session>.nfs.log` so guest-side mount failures surface; (S4.3)
  per-session ephemeral NFS port — `DEFAULT_NFS_PORT=11111` gone,
  `runtime._pick_free_nfs_port` picks inside `acquire_session_lock`,
  `nfs_port_selected` audit event lands in the chain; (S4.4)
  `setuptools_scm` migration — `pyproject.toml` carries dynamic
  version, `tag_regex` accepts the `vX.Y.Z-sN` wave suffix,
  `modules/_version.py` gitignored; (S4.5) `guardrails/` →
  `guardrails_config/` rename so the config dir no longer shadows
  `nemoguardrails`' `import guardrails` in `main.co`; the
  `_CWD_CHDIR_LOCK` + `os.chdir(tempfile.gettempdir())` workaround from
  v0.8.5 is removed.

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
- Manifest validator rejects shell-metachar injection in `agent.entrypoint`,
  `agent.working_directory`, and `agent.env` keys / values via a single
  allowlist regex (`_BOOT_ARG_SAFE_RE`) before the Firecracker layer ever
  sees the value. Complements `firecracker._encode_boot_value`. (H1)
- `requirements.lock` bumped `langchain-openai` ≥ 1.1.14
  (GHSA-r7w7-9xr2-qq2r) and `langchain-text-splitters` ≥ 1.1.2
  (GHSA-fv5p-p927-qmxr); `langchain-core` follows to 1.3.0 to satisfy
  both. `pip-audit --strict` CI gate now passes.

### Documentation
- `pyproject.toml` carries a `TODO(v0.9)` note above the Python version
  cap (`>=3.11,<3.14`) so the next release bump is an explicit decision. (M5)
- `VALID_PII_ENTITIES` carries a Presidio docs pointer comment. (M2)
- `docs/SECURITY.md` §3, §4, §5 and the Controls mapping brought into
  alignment with the actual enforcement paths (S8 + S10 above).

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
