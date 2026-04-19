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

## S3 — rail adversarial paraphrase harness

Pending (task #4).

## S4 — v0.8.7-deferred bundle

Pending (task #5). Covers H2 NFS log routing, `guardrails/` rename,
`setuptools_scm`, `_build_rails` mtime cache, H3 per-session NFS port.
Batch 2 lock must land first (H3 depends on it).

## S5 — DORA OJ-verification backstop

Pending (task #6).

## S6 — SBOM + signed releases

Pending (task #7).

## S7 — NAP mapping document

Pending (task #8).

## Deferred to v0.9.1+

(Empty — populate if a batch finds work it can't close in scope.)
