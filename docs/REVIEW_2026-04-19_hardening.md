# Hardening wave — post-v0.8.7 → v0.9.0

Running log for the seven-batch hardening wave kicked off 2026-04-19.
See the plan header in the session transcript for the full ground rules;
in brief: one tag per batch (`v0.9.0-s1` … `v0.9.0-s7`), smallest
correct change wins, evidence-before-claims on every closure, ruff +
mypy clean on every touched file, no silent deferrals.

Local baseline when the wave opened: **638 passed, 0 skipped** on the
Windows dev venv (nemoguardrails 0.21.0 + langchain-openai 1.1.12
installed to match `requirements.lock`). Memory's prior figure of
`585 passed, 31 skipped` reflected a different environment (Fedora,
pre-nemoguardrails-install run); this wave regresses against the 638
local baseline.

## S1 — oversized-input safe refusal  (v0.9.0-s1)

Landed `50d5786` on `origin/main`. Tag `v0.9.0-s1`.

- Finding as stated (GPT-5.4): `MAX_GUARDRAILS_PAYLOAD_CHARS` allowed
  oversized input to skip `LLMRails` entirely; v0.8.0 added output
  rail rescanning on the salvage path, but the primary oversized
  branch was still proxy-to-model + rescan, not input-policy
  enforcement.
- Fix: `modules/guardrails/service.py::chat_completions` oversized
  branch replaced with a 4xx safe refusal. Response is HTTP 413 with
  `detail = "payload_too_large_refused"`. An `oversize_refused` audit
  event lands in the hash chain carrying `payload_chars`,
  `threshold_chars`, and `model` (`session_id` auto-propagates via
  `append_chained_event`'s tail read, matching every other event).
  Naming note: spec wording was "byte count"; emitted field names are
  `payload_chars` / `threshold_chars` because the threshold constant
  is already in chars and the distinction matters for multi-byte
  Unicode.
- `_apply_output_rails` docstring updated: two bypass paths
  (salvage-from-error, empty-rails fallback), not three.
  `modules/guardrails/output_scan.py` module docstring updated the
  same way.
- Tests: three defect-encoding tests deleted
  (`test_oversized_bypass_with_clean_proxy_logs_scan_only`,
  `test_oversized_bypass_with_rail_firing_proxy_refuses_and_logs`,
  `test_chat_completions_skips_guardrails_generation_for_oversized_payload`) —
  they asserted a 200 with proxied content, which *is* the bypass.
  Three new tests added per plan:
  - `test_oversized_injection_paraphrase_refused_with_safe_refusal_event`
    — paraphrased injection wording (not on preflight list) padded
    past the 12 000-char threshold → 413, `oversize_refused` event,
    chain valid, `get_rails` / `httpx.post` never reached.
  - `test_oversized_off_topic_refused_with_safe_refusal_event` —
    off-topic wording (not on preflight list) ≥ threshold → same.
  - `test_at_threshold_minus_one_routes_through_llmrails` — payload
    of `MAX_GUARDRAILS_PAYLOAD_CHARS - 1` chars still routes through
    a faked `LLMRails.generate_async`; no `oversize_refused` event.
- Evidence: 638 passed, 0 failed; ruff + mypy clean on touched files
  (pre-existing yaml-stub warning on `service.py` unchanged).
- Exit criterion met: no code path from request entry to model call
  can skip `LLMRails` based on size alone.

## S2 — host-wide session lock  (v0.9.0-s2)

Landed `c874cae` on `origin/main`. Tag `v0.9.0-s2`.

- Finding as stated: `run_manifest` had no cross-session mutex, so two
  concurrent invocations on the same host would race on the single NFS
  port (`DEFAULT_NFS_PORT = 11111`), on iptables INPUT/FORWARD rules
  touching the same gateway, and on the ip_forward gate. The second
  session would either fail halfway through setup or silently share
  the first session's firewall posture.
- Fix: new module `modules/isolation/session_lock.py` with
  `acquire_session_lock` as a context manager, non-blocking
  `fcntl.flock(LOCK_EX | LOCK_NB)` on
  `/var/run/saaf-shell/session.lock` (path configurable).
  `run_manifest` wraps its entire post-setup body in the lock; the
  audit log itself is not inside the lock so out-of-process writers
  (router, guardrails) still chain events normally. Lock held on the
  FD (not the inode) so the kernel drops it on SIGKILL/OOM/crash —
  crash-safe recovery is free and needs no cleanup script.
- Non-blocking rationale: queueing would let a scheduler starve the
  host with silent waiters. Fail-fast with the holder's PID makes
  retry an explicit caller decision.
- Audit events (all chained): `session_lock_acquired`,
  `session_lock_released`, and `session_lock_contended`. Every denied
  attempt lands in the log with the live holder's PID so operators can
  see concurrent-start attempts, not just successes.
- Windows: `fcntl` is not importable, so the context manager degrades
  to a no-op. Firecracker is Linux-only anyway; this keeps test
  collection and cross-platform dev working.
- Tests added in `tests/test_isolation_session_lock.py` (5, all
  POSIX-guarded with `pytest.mark.skipif`): happy-path acquire +
  release (PID written to lockfile), contention raises
  `SessionLockHeld` carrying the live holder's PID (via a
  `multiprocessing.Process` holder), acquire/release audit events,
  contended audit event, and re-acquire after an exception inside the
  body. Existing `test_isolation_runtime.py` now passes
  `session_lock_path=tmp_path / "session.lock"` so it doesn't touch
  `/var/run/` on Linux CI.
- Evidence: 638 passed + 5 skipped (the POSIX tests) on the Windows
  venv; ruff clean; mypy clean on both the default platform and
  `--platform linux`. The five POSIX tests execute on the Fedora
  re-verify (#25) — noting the gap here per the evidence-before-claims
  rule. On Windows dev the runtime test exercises the Windows no-op
  path.
- Exit criterion met: no two `run_manifest` calls can hold host
  resources concurrently; every contention attempt is auditable.

## S3 — rail adversarial paraphrase harness  (v0.9.0-s3)

Landed `cab64b3` on `origin/main`. Tag `v0.9.0-s3`.

- Finding as stated: per-rail unit tests cover each rail deeply but
  nothing protects against cross-rail drift. A regex edit in
  `deadline_rule.py` that inadvertently narrows coverage or broadens
  false positives on adjacent-rail wording would pass the per-rail
  suite while regressing a rail elsewhere.
- Fix: new `tests/harness/rail_paraphrases_baseline.json` freezes
  expected flag state per (rail, paraphrase). `tests/test_rail_paraphrase_harness.py`
  parametrizes over the JSON and asserts `report_fn(text)[flag_key]
  == should_flag`. Coverage-gate test
  (`test_harness_covers_every_rail`) refuses the suite if a rail is
  added to `_RAILS` without at least one paraphrase in the baseline.
- Coverage: all 12 rails, 32 paraphrases total — mix of positives
  (should fire) and negatives (must not fire). Negatives are the
  load-bearing ones: they catch regex-broadening regressions that
  per-rail tests might miss because they focus on inputs near the
  happy path.
- Harness is part of the default pytest run (no separate CI job
  needed — the existing `Test / pytest` workflow picks it up). A
  separate CI job was considered and rejected as extra machinery with
  no isolation benefit; the harness is pure-Python and runs in
  milliseconds.
- Evidence: 671 passed + 5 skipped (baseline 638 + 33 new harness
  cases) on the Windows dev venv. Ruff clean. Mypy clean.
- Exit criterion met: baseline commits behavior today; any rail
  change that flips a baseline entry fails CI with a message telling
  the author to update the baseline in the same commit.

## S4 — v0.8.7-deferred bundle  (v0.9.0-s4)

Landed `a6a77f8` on `main`. Tag `v0.9.0-s4`. Five sub-batches in
risk-ascending order: mtime cache → NFS log routing → per-session
NFS port → `setuptools_scm` → config-dir rename.

- **S4.1 — `_build_rails` mtime-keyed cache.** Added
  `_config_dir_mtime(config_path)` helper (max mtime across every
  file under the config dir) and threaded it through the
  `functools.lru_cache` key on `_build_rails`. `get_rails` reads
  `SAAF_SELF_CHECK_URL` and `_config_dir_mtime` fresh on every
  request, so a Colang or YAML edit invalidates the cache on the
  next call without a service restart. Cache-key param
  (`config_mtime`) is discarded inside the body via `del`. Test:
  `test_get_rails_rebuilds_when_config_file_edited` uses `os.utime`
  to bump mtime and asserts the build counter increments between
  requests.
- **S4.2 — H2 NFS server log routing.** `start_nfs_server` grew an
  optional `log_path` parameter; when set, `stdout` is redirected to
  `open(log_path, "ab", buffering=0)` and `stderr` is redirected to
  `STDOUT`. Before H2, `DEVNULL` swallowed NFS chatter and a failed
  guest mount surfaced only as an opaque boot error. `runtime.py`
  now passes `log_path = overlay_dir.parent / f"{session_id}.nfs.log"`
  on every session so operators can tail per-session mount output in
  the session workdir. Tests:
  `test_start_nfs_server_routes_stdout_to_log_path` (unit) and the
  H2 branch of `test_run_manifest_starts_agentfs_nfs_for_session`
  (wiring).
- **S4.3 — H3 per-session ephemeral NFS port.** Removed the
  `DEFAULT_NFS_PORT = 11111` constant from `network.py`.
  `build_setup_commands` / `build_teardown_commands` now take an
  `nfs_port: int` parameter (no default), so a silent fallback to
  the old static port is not syntactically possible. `runtime.py`
  picks the port inside the session lock via
  `_pick_free_nfs_port()` — `socket.bind(('', 0))` on the gateway
  address, read `getsockname`, close. Port selection, command
  assembly, and VM launch all sit inside `acquire_session_lock` so
  two concurrent sessions cannot collide on port allocation. A
  `nfs_port_selected` audit event lands in the chain. Regression
  guard: the new port must be non-zero and != 11111, so a revert to
  the static default fails the test. Tests:
  `test_run_manifest_ephemeral_port_differs_across_sessions`
  (sequential picks both ephemeral) and the H3 asserts in the
  existing runtime test.
- **S4.4 — `setuptools_scm` migration.** `pyproject.toml` now
  declares `dynamic = ["version"]` and carries a `[tool.setuptools_scm]`
  block that writes the resolved version to `modules/_version.py`
  (gitignored). `tag_regex = "^v(?P<version>\\d+\\.\\d+\\.\\d+)(?:-s\\d+)?$"`
  accepts the wave-checkpoint tags (`v0.9.0-s1`…) and normalises to
  `MAJOR.MINOR.PATCH` so PEP 440 is happy. `fallback_version =
  "0.0.0+unknown"` only kicks in when neither a git checkout nor
  `SETUPTOOLS_SCM_PRETEND_VERSION` is available; the `+unknown`
  local segment makes drift obvious in logs. The release tarball
  script no longer cross-checks a hard-coded pyproject version
  against the tag (the tag *is* the source); the tag is embedded in
  the output metadata instead.
- **S4.5 — `guardrails/` → `guardrails_config/` rename.** The
  project's Colang config dir shadowed `import guardrails` in
  `main.co` because nemoguardrails' import resolver checks
  `os.path.exists(X)` in CWD before consulting `COLANGPATH`. Running
  the service from the repo root caused `import guardrails` to
  re-resolve to our config dir, re-load `main.co`, and error with
  `Multiple non-overriding flows with name 'main'` at `LLMRails`
  construction. Workaround in v0.8.5–v0.8.7 was a process-wide
  `_CWD_CHDIR_LOCK` + `os.chdir(tempfile.gettempdir())` window
  wrapped around `RailsConfig.from_path`. Renamed the directory
  (`guardrails/` → `guardrails_config/`) across code, tests, docs,
  and packaging; removed the chdir workaround and its lock.
  `import guardrails` in `main.co` now unambiguously resolves to the
  nemoguardrails library. Touched: `modules/guardrails/service.py`
  (removed `_neutral_cwd_for_colang_imports` context manager and
  `_CWD_CHDIR_LOCK`, updated comments, `build_default_app` now
  points at `guardrails_config`), `scripts/start-guardrails-local.py`,
  `scripts/inspect_guardrails_result.py`,
  `scripts/validate_guardrails_routing.py`,
  `scripts/check_branch_portability.py`, `cli.py`,
  `pyproject.toml` (`[tool.setuptools.packages.find]` +
  `package-data`), `tests/test_guardrails_config.py` (4 paths),
  `tests/test_guardrails_colang_wiring.py`,
  `tests/test_action_loader.py`, `tests/test_presidio_redact.py`
  (`from guardrails_config.actions.presidio_redact import …`), and
  docs (README, ARCHITECTURE, SECURITY, QUICKSTART,
  implementation_plan). Historical reviews
  (`docs/REVIEW_2026-04-18.md`) are left as-is so the motivation for
  the rename stays readable at the commit that introduced it.
- Evidence: 621 passed + 36 skipped on the Windows dev venv
  (skips are the nemoguardrails-dependent tests on a venv without
  nemoguardrails installed; `test_presidio_redact.py` is ignored at
  collection for the same reason — pre-existing Windows skip). Ruff
  clean across the tree (auto-fixed 12 I001 import-sort warnings
  that had been dormant in `guardrails/actions/` on HEAD, now
  cleaned up as part of the rename touch). Mypy clean on every
  touched `modules/` file and `cli.py`.
- Exit criterion met: the CWD-shadow workaround is gone, the NFS
  log path and per-session port are wired end-to-end, the rails
  cache invalidates on config edits, and the version string is
  tag-driven.

## S5 — DORA OJ-verification backstop  (v0.9.0-s5)

Landed on `main` as `fe7d2be`, tagged `v0.9.0-s5`.

- **Deferred finding under verification (P2-1 from v0.8.3 review):**
  reviewer claimed Commission Delegated Regulation (EU) 2024/1772
  Art. 5 sets two concurrent initial-notification deadlines for
  DORA — 4h from classification AND 24h from awareness. Only 4h was
  ever in `_VALID_WINDOWS_HOURS["DORA"]`; the 24h backstop was
  deferred pending OJ verification because inventing statutory
  windows from memory is the exact failure mode this rail exists to
  catch.
- **OJ verification on 2026-04-19:** operator pasted the full EN
  text of 2024/1772 from
  `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1772`
  (ELI: `http://data.europa.eu/eli/reg_del/2024/1772/oj`, OJ L,
  2024/1772, 25.6.2024). Key finding: **Article 5 is titled "Data
  losses"** and defines a classification criterion (availability,
  authenticity, integrity, confidentiality of data), not a
  notification deadline. **Nothing in 2024/1772 imposes a 24h-from-
  awareness initial-notification deadline on DORA.** The reviewer's
  claim was wrong about the location. The only hour-counts anywhere
  in the regulation are:
  - Art. 9(3)(a) — *"the duration of the incident is longer than 24
    hours"* — a duration-materiality threshold for classifying an
    incident as *major* (how long the incident ran), NOT a reporting
    window.
  - Art. 9(3)(b) — *"the service downtime is longer than 2 hours"* —
    same kind of threshold.
  DORA's actual reporting timeframes (4h initial / 72h intermediate
  / 1-month final) are set by Article 19 of the parent Regulation
  (EU) 2022/2554 plus the separate RTS on reporting timeframes under
  DORA Art. 20 — **not** by 2024/1772.
- **Rail outcome:** `_VALID_WINDOWS_HOURS["DORA"] = {4, 72, 720}`
  stays as-is. No false-positive fix needed. A LLM output claiming
  "DORA requires 24-hour initial notification under Reg 2024/1772"
  is fabricated and must continue to fire this rail.
- **Deliverables:**
  - `modules/guardrails/deadline_rule.py` module-level docstring
    corrected. The previous text cited 2024/1772 as the source of
    the 4h/72h/1-month numbers — that citation was wrong. Replaced
    with the accurate scoping: 2024/1772 covers classification
    criteria and materiality thresholds (not deadlines); reporting
    timeframes come from 2022/2554 Art. 19 + RTS on reporting
    timeframes. Docstring also now records the 2026-04-19
    verification and closes P2-1 as reviewer-wrong-about-location.
  - Four regression tests added to `tests/test_deadline_check.py`:
    `test_dora_24h_initial_notification_claim_is_flagged_as_fabricated`
    (canonical phrasing), `..._from_awareness_variant_...` (the
    specific shape the reviewer's claim predicted),
    `test_dora_4h_initial_notification_passes` (positive control —
    statutory 4h still passes), and
    `test_dora_incident_duration_24h_is_not_a_notification_claim`
    (negative control — the exact confusion the reviewer hit,
    describing the Art. 9(3)(a) duration threshold in an audit note
    is not a notification-deadline claim and must not fire).
- **Evidence:** 52 pass in `test_deadline_check.py` (+4 new). No
  production-code value changed; the docstring correction and the
  new tests are the entire behavioural surface. Ruff + mypy clean on
  touched files.
- **Exit criterion met:** the deferred P2-1 finding is closed with
  OJ evidence; the rail's DORA window set is pinned against the
  specific misreading a reviewer (or a future LLM) might propose;
  the docstring no longer contains the wrong statutory citation.

## S6 — Red-team quick-wins (RT-04, RT-09, RT-10)  (v0.9.0-s6)

Landed on `main` as `0e4c8d4`, tagged `v0.9.0-s6`.

External red-team review (GPT-5.4, 2026-04-19T15:27:54+02:00) produced
10 findings against the v0.9.0-s5 HEAD. All 10 were verified real
against the actual code (not the docs) during intake. This batch closes
the three that are trivial single-file fixes; the remaining seven are
queued for S7–S10 (see §Re-plan below).

- **RT-04 — manifest `name` injects kernel cmdline.** `firecracker.
  build_vm_config` interpolates `manifest["name"]` directly into the
  kernel `ip=<ip>::<gw>:<netmask>:<name>:eth0:off` segment with no
  escaping. `_check_boot_arg` covered `agent.entrypoint`,
  `agent.working_directory`, and `agent.env.*` but not `name`. A
  manifest with `name: "foo init=/bin/sh"` would split the cmdline and
  inject a second kernel parameter at boot.
  - Fix: `_check_required_fields` now calls
    `_check_boot_arg(result, "name", manifest["name"],
    forbid_space=True)` on the name value. Same allowlist the other
    boot-arg fields use (alphanumeric + `_ . / : @ - +`); spaces
    explicitly rejected because the hostname segment must not contain
    whitespace.
  - Tests: `test_name_with_space_is_rejected`,
    `test_name_with_dollar_is_rejected`,
    `test_name_with_newline_is_rejected`,
    `test_normal_hyphenated_name_still_valid` (positive control —
    `vendor-guard` still passes).

- **RT-09 — session_id bleeding.** `_read_chain_tail` in
  `modules/audit/log.py` set `session_id` on `session_start` but never
  cleared it on `session_end`. The propagation block below (`if
  session_id is not None and "session_id" not in fields: record
  ["session_id"] = session_id`) then stamped the closed session's id
  onto any later event that omitted one — typically a
  `route_decision` emitted by the privacy router after the session
  had been closed. Verify_log stayed green because the hash chain
  was consistent; the session attribution was silently wrong.
  - Fix: one added `elif rec.get("event_type") == "session_end":
    session_id = None` branch in the tail scanner.
  - Tests:
    `test_post_session_event_does_not_inherit_closed_session_id`
    (router event after close has no session_id),
    `test_new_session_event_ids_do_not_bleed_into_next_session`
    (two-session interleave, confirms the fix doesn't regress the
    normal-case propagation inside an open session).

- **RT-10 — systemd sandbox vs audit path.** Both `saaf-router.
  service` and `saaf-guardrails.service` had `ReadWritePaths=/tmp`
  under `ProtectSystem=strict`, but the default `AUDIT_LOG_PATH` is
  `/var/log/openshell/audit.jsonl`. A stock deploy could not write
  the audit log — writes would fail with `EROFS` inside the sandbox.
  Either operators had to override the env var or edit the unit;
  neither was documented in the service comment.
  - Fix: `LogsDirectory=openshell` + `LogsDirectoryMode=0750` added
    to both units. `LogsDirectory=` is the systemd-native way —
    creates `/var/log/openshell` owned by `User=saaf` with mode
    0750 before `ExecStart`, and auto-adds it to the writable
    sandbox, leaving `ProtectSystem=strict` intact.

**Evidence:**
- 631 pass (+6 from S5's 625), 36 skipped. Ruff + mypy clean on
  touched files. Three single-file fixes, six regression tests.
- No production code value changed beyond the validator allowlist
  extension and the one-line tail-scanner clear; the systemd change
  is sandbox configuration.

**Re-plan after external review:**
- **S6** — RT-04, RT-09, RT-10 (this batch).
- **S7** — RT-02 + RT-03 (audit rollback/suffix-deletion +
  crash-heal tamper-erasure). External head-pointer / checkpoint +
  heal-truncation becomes loud (CRITICAL + operator ack required).
- **S8** — RT-05 + RT-08 (unredacted bot_message in audit +
  preflight-last-message-only).
- **S9** — RT-01 (router bypass boundary decision — UDS vs shared
  secret vs documented-accept).
- **S10** — RT-06 + RT-07 + original S7 NAP mapping (doc alignment +
  `-I` vs `-A` rules under `SAAF_ALLOW_IP_FORWARD` + Colang 2.x
  topical action port).
- **S11** — SBOM + cosign keyless signing (was original S6).

## S7 — audit integrity (RT-02 + RT-03)  (v0.9.0-s7)

Landed on `main` as `db5243b`, tagged `v0.9.0-s7`.

Closes the two highest-severity findings from the external GPT-5.4
red-team review — both were tail-manipulation attacks that stayed
green under `verify_log` because the log was self-describing: without
an external anchor, `verify_log` had no reference for "where should
this chain end."

- **RT-02 — rollback/suffix deletion.** Attacker with write access
  deletes the last N records. The remaining prefix is still
  internally consistent (each record's `prev_hash` matches the
  previous record's `event_hash`), so `verify_log` reported the
  shortened chain as intact. Incident evidence (a final
  `route_decision`, a `guardrails_rail_fire`, a `session_end`) could
  be erased silently.
- **RT-03 — crash-heal tamper-erasure.** `_read_chain_tail` marked
  malformed tails for truncation; `append_chained_event` truncated
  before writing the next event. A one-byte corruption of the last
  record (flip the trailing `\n`, corrupt a JSON byte) + the next
  legitimate append = silent deletion of the tampered record. The
  chain remained valid on the shortened remainder.

**Fix — head-pointer sidecar + discriminating heal.**

- **Sidecar file** `<log>.head` alongside the log, updated atomically
  under the existing `fcntl.LOCK_EX` window via `os.replace`. Content
  is JSON: `{last_seq, last_event_hash, event_count, ts}`. Design
  choices:
  - Written on *every* successful append — no batching, no
    throughput tradeoff worth catching tamper-via-process-kill
    between log append and sidecar update.
  - Atomic rename via `os.replace` (atomic on both POSIX and
    Windows) so a reader never sees a half-written sidecar.
  - Not cryptographically signed — that is deferred. Attacker with
    write to the log usually has write to the sidecar too. The
    sidecar's value is (a) catching accidental truncation, (b)
    raising attack cost (attacker must know to update it), (c)
    giving operators a single small file to mirror externally
    (journald, remote log, WORM) for a real anchor.
- **`verify_log` extended.** Reads the sidecar and returns:
  - `(True, "Verified N events. Chain intact. Head pointer matches.")`
    when tail matches sidecar — strong result.
  - `(True, "... WARNING: no head-pointer sidecar present ...")`
    when sidecar absent — weak result, back-compat with pre-S7
    logs, flags the missing anchor.
  - `(False, "TAMPER DETECTED: head pointer last_event_hash=... but
    log tail shows ...")` on any mismatch of `last_event_hash`,
    `last_seq`, or `event_count`.
- **Discriminating heal in `append_chained_event`.** New
  `_classify_tail` returns one of `clean | first_write | legacy |
  heal_legit | tamper`:
  - `clean` — sidecar matches tail, no heal needed, proceed.
  - `first_write` — log empty and no sidecar, initialise both.
  - `legacy` — log has records but no sidecar (pre-S7 upgrade
    path), trust-on-first-write; next successful append
    initialises the sidecar.
  - `heal_legit` — truncate_at is set AND the last intact record
    above the truncation matches the sidecar's `last_event_hash`.
    The malformed bytes were either a partial write from a crash
    or a tamper-append of unrecoverable bytes — in both cases the
    committed record is intact. Truncate, emit a chained
    `audit_tail_healed` record (so the heal is itself auditable),
    then write the primary event.
  - `tamper` — sidecar and tail disagree. Raise
    `AuditTamperDetected` unless `SAAF_ACK_AUDIT_HEAL=1` is set;
    the ack path emits `audit_tail_heal_acknowledged` before the
    primary write so the override is audited.
- **`AuditTamperDetected`** is a new `RuntimeError` subclass so
  callers can distinguish "audit broke" from generic OSError in
  their recovery paths.
- **`_build_and_write_record`** extracted from the old append path.
  Both the primary event and the heal/ack marker events go through
  the same hashing + write path so they're indistinguishable to
  `verify_log`.

**Deliverables:**

- `modules/audit/log.py`:
  - New: `HEAD_POINTER_SUFFIX`, `HEAL_ACK_ENV`,
    `AuditTamperDetected`, `_head_pointer_path`,
    `_read_head_pointer`, `_write_head_pointer`, `_heal_ack_env`,
    `_classify_tail`, `_build_and_write_record`.
  - Modified: `_read_chain_tail` now also returns `record_count`.
    `append_chained_event` refactored around
    `_build_and_write_record` with the classification switch.
    `verify_log` cross-checks the sidecar.
- `tests/test_audit_log.py`: new `TestHeadPointerAndTamper` class
  with 9 tests — sidecar-written-on-every-append, verify-matches-
  strong, detect-trailing-rollback, detect-last-record-rollback,
  verify-without-sidecar-warns, append-refuses-on-tampered-tail,
  ack-env-allows-override-and-audits-it, legacy-log-initialises-
  on-next-append, legacy-log-with-partial-tail-refuses-without-ack.
  Plus the two pre-existing crash-heal tests updated to verify the
  new chained `audit_tail_healed` record.
- `docs/SECURITY.md` §6 rewritten to document the sidecar, the
  discriminating heal, the ack env var, and the sidecar-caveats
  paragraph (what it buys, what it doesn't).

**Evidence:**

- 640 pass (+9 from S6's 631), 36 skipped. Ruff + mypy clean on
  `modules/audit/log.py` and the test file.
- Two pre-existing tests updated in place (same semantics, stronger
  assertions — the silent-truncate behaviour they were pinning is
  exactly the RT-03 attack surface).
- Old behaviour preserved for pre-S7 logs via the `legacy`
  classification branch; first append initialises the sidecar.
- Out-of-scope (documented): cryptographic signing of the sidecar,
  WORM/HSM storage, remote anchor service. Implementation plan
  already excludes these as v0 scope.

## S8 — PII + history (RT-05 + RT-08)  (v0.9.0-s8)

Landed on `main` (SHA filled in the follow-up commit). Tag `v0.9.0-s8`.

- **RT-05 (PII in refusal audit)** — `guardrails_config/actions/self_check_direct.py`
  previously emitted `{"user_input": user_message}` and
  `{"bot_response": bot_message}` verbatim on refusal. On a rail that
  just classified the content as unsafe, that's exactly the PII or
  attack payload we don't want in the GDPR log. Fix: new module-local
  helper `_digest_for_audit` returns
  `{"content_sha256": <hex>, "content_len": <int>}`; both refusal
  emitters were swapped to it. The output-path asymmetry in the
  original report (only `bot_response` flagged) was extended to the
  symmetric input-path leak, since the same failure mode applies.
- **RT-08 (preflight only saw `messages[-1]`)** — `modules/guardrails/service.py`
  preflighted the last message only, while `generate_async` forwards
  the full message list verbatim. Fix: new helper
  `_preflight_scan_messages` iterates the full list (every role, not
  just `user` — replayed `assistant` turns also reach the model) and
  returns the first match. The emitted `guardrails_preflight_block`
  event now carries `message_index` and `message_role` so operators
  can triage which turn tripped the wire.
- Tests:
  - New `tests/test_self_check_direct_redaction.py` (6 tests):
    digest helper behaviour (hashes + sizes + `None` handling + call
    stability), both refusal paths emit the digest instead of raw
    content (assertion form: `raw_payload not in report.values()`),
    and the safe path still emits nothing.
  - New in `tests/test_guardrails_service.py` (3 tests): injection in
    an earlier user turn fires with `message_index=0`; injection
    replayed through an `assistant` turn fires with
    `message_role="assistant"`; multi-hit scan pins
    first-match-wins behaviour.
- Evidence: 649 passed (+9), 36 skipped on the full suite (excluding
  the pre-existing `test_presidio_redact` collection error from the
  optional nemoguardrails dep). Ruff clean on all four touched files.
  Mypy on `modules/guardrails/service.py` + `self_check_direct.py`:
  2 pre-existing `no-redef` warnings in the nemoguardrails fallback
  block, unchanged by S8 (confirmed by rerunning mypy against stashed
  HEAD).
- Exit criterion met: no code path emits raw user/bot text into the
  audit chain on a refusal, and no message position can skip the
  preflight tripwire.

## S9 — router boundary (RT-01)

Pending — needs threat-model decision.

## S10 — doc alignment + NAP mapping (RT-06 + RT-07 + original S7)

Pending.

## S11 — SBOM + signed releases

Pending (was original S6).

## Deferred to v0.9.1+

(Empty — populate if a batch finds work it can't close in scope.)
