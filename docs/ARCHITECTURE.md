# Architecture

## What saaf-compliance-shell is

A runtime enforcement layer that wraps a third-party AI agent workload and gives the operator four things it would not have otherwise:

1. A hardware-isolated execution environment (Firecracker microVM).
2. A complete record of every file the workload touches (AgentFS overlay).
3. A guarded channel for model traffic (NeMo Guardrails + Privacy Router).
4. A tamper-evident log of what the session did (SHA-256 chained JSONL).

Nothing in here is an end-user product. It is infrastructure — a controlled path a workload is made to travel through.

## The single-host shape

Everything runs on one Linux host with KVM. There is no multi-node story in v1.

```
┌─────────────────────── Linux host ───────────────────────┐
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Firecracker microVM                                 │  │
│  │  ┌───────────────────┐                                │  │
│  │  │ target workload    │── TAP ──▶ host :8088           │  │
│  │  │ (e.g. Vendor_Guard)│                                │  │
│  │  └───────────────────┘                                │  │
│  │  AgentFS overlay (SQLite-backed, host-owned)          │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
│  NeMo Guardrails :8088  ──▶  Privacy Router :8089  ──▶   │
│                                                   Ollama  │
│                                                   :8000   │
│                                                           │
│  Audit log   /var/log/openshell/audit.jsonl              │
└───────────────────────────────────────────────────────────┘
```

The workload sees a normal Linux userspace and one network route: the guardrails port via its TAP gateway. Everything else is dropped.

## Trust boundaries

| Boundary | Enforced by | What it stops |
|---|---|---|
| Workload / host | KVM hypervisor | Kernel or userspace escape into the host |
| Workload / outbound network | TAP device + iptables | Reaching anything except guardrails:8088 |
| Workload / audit log | Host-side file, never mounted | Tampering with the record |
| Workload / model | Guardrails + router must both pass | PII leaks, prompt injection, off-topic drift, and the audit-specific output hallucinations the output rails refuse (fabricated citations/versions/CVEs/regulator names, unfounded verdicts, CoT leakage, absolutist claims, stale attestations, jurisdiction and currency mismatches) |
| Workload / base rootfs | AgentFS overlay (writes go to overlay, base is read-only) | Modifying the image the next session sees |

## The path a request takes

For any request the workload sends to its configured inference URL:

1. Workload POSTs to `172.16.0.1:8088` (its TAP gateway). DNATted to `127.0.0.1:8088` on the host.
2. Guardrails runs input rails: Presidio PII redaction, prompt-injection self-check, topical rail.
3. Guardrails forwards the sanitized request to the Privacy Router on `:8089`.
4. Router forwards to the local model endpoint on `:8000` (Ollama). Appends a `route_decision` event to the audit log.
5. Response flows back through guardrails output rails: PII redaction again, then the ten audit-specific refusal rails documented in [`SECURITY.md`](SECURITY.md) §9. Any rail that fires replaces the response with a refusal; the workload never sees the unsafe text.
6. Workload receives the sanitized response.

Guardrails' own self-check LLM call bypasses the router and goes directly to `:8000` — self-check prompts contain no user data, so the privacy hop is not needed there.

## Manifest-driven configuration

A workload declares what it needs in `saaf-manifest.yaml` at its repo root. The shell reads this once at session start:

- `agent.entrypoint` — what to run inside the VM.
- `filesystem.read_write` — which paths the workload needs (default is `/audit_workspace` only).
- `network.allow` — v1 allows exactly one rule: `gateway:8088`. Everything else is rejected at manifest validation time.
- `resources.vcpu_count` / `mem_size_mib` — passed straight to Firecracker.
- `pii.entities` — which Presidio recognizers are active for this session.
- `audit.retention_days` — declarative policy; enforcement is the operator's job in v1.

A manifest that does not validate never boots.

## Session lifecycle

1. `saaf-shell run --manifest <path>` — manifest is validated, VM config and iptables policy are generated, audit log session_start record is written.
2. AgentFS creates `.agentfs/<session-id>.db`, NFS-exports it to the guest.
3. Firecracker boots with the generated config file.
4. The workload runs; every file change lands in the overlay DB, every model round-trip lands in the audit log.
5. On exit, `saaf-shell` writes `session_end`, tears down the TAP + iptables rules, and stops the NFS server.
6. `saaf-shell diff --agent-id <session-id>` shows what changed on disk.
7. `saaf-shell verify-log --log <path>` walks the hash chain.

## Components in depth

### Manifest — `saaf-manifest.yaml`

Single source of truth for a session. Validator lives in `modules/manifest/validator.py`. Fields:

- `agent.entrypoint` — shell command run as PID 1's child inside the guest.
- `agent.workdir` — default working directory for the entrypoint.
- `agent.env` — environment variables passed through kernel cmdline (space-escaped; see `SECURITY_AUDIT.md` finding 1 for the open hardening item).
- `filesystem.read_write` — whitelist of guest paths the workload may write to. Default: `/audit_workspace` only. The overlay DB only captures writes to declared paths.
- `network.allow` — v1 allows exactly one rule: `gateway:8088`. `validate_v1_network_rules` rejects any additional rule with `NetworkPolicyError`.
- `resources.vcpu_count` (1–16), `resources.mem_size_mib` (256–16384) — passed straight to Firecracker.
- `pii.entities` — Presidio recognizer list for this session (e.g. `PERSON`, `EMAIL_ADDRESS`, `BSN_NL`).
- `audit.retention_days` — declarative policy; the shell does not enforce deletion in v1 (see ROADMAP).

A manifest that does not validate never boots. `saaf-shell validate` returns the exact field that broke.

### Isolation layer — `modules/isolation/`

**`firecracker.py`** — builds the VM config JSON (`vmlinux`, rootfs, drives, network interface, `boot-args`), starts `firecracker --config-file …`, and owns its lifecycle. Kernel cmdline encodes manifest `agent.*` fields under a `saaf.*` prefix, read by the guest init script. Only space-escaping today (`_encode_boot_value`) — newline / quote validation is tracked in `SECURITY_AUDIT.md` finding 1.

**`agentfs.py`** — creates `.agentfs/<session-id>.db`, spawns `agentfs serve nfs`, mounts the overlay into the guest over NFS. The base rootfs is read-only; writes land in the session DB, which stays on the host. `saaf-shell diff` reads the DB directly — the guest is not consulted.

**`network.py`** — provisions one TAP device (`fc-<prefix>-<hash>`) per session, assigns the host-side `172.16.0.1/24`, and installs iptables rules:

1. DNAT `172.16.0.1:8088` → `127.0.0.1:8088` on the host's guardrails port.
2. ACCEPT on the input chain for the TAP → guardrails path.
3. DROP everything else on that TAP interface.

No masquerade rule is installed; there is no route to the internet. `validate_v1_network_rules` rejects any manifest that asks for anything beyond `gateway:8088`.

**`runtime.py`** — the session orchestrator. Runs: manifest validate → AgentFS DB create → NFS export start → TAP + iptables up → Firecracker boot → (workload runs) → Firecracker exit → iptables teardown → NFS stop → `session_end` audit event. Teardown runs in a `finally` block so a crashed session still cleans up network state.

### Guardrails service — `modules/guardrails/` (`:8088`)

HTTP wrapper around NeMo Guardrails with an OpenAI-compatible surface so the workload calls it like a model. Request lifecycle:

1. **Input preflight** (`service.py`) — cheap substring match against `INJECTION_PATTERNS` / `OFF_TOPIC_PATTERNS`. Obvious direct injection is rejected before the rail pipeline runs. This is intentionally crude; the real enforcement is the full rails chain (see `SECURITY_AUDIT.md` finding 2).
2. **Input rails** (`rails.co`) — Presidio PII redaction (stable placeholders, destructive), `SelfCheckInputDirectAction`, `check topical relevance`.
3. **Forward** to Privacy Router on `:8089`.
4. **Output rails** — PII redaction on the response, then ten regex-based output rails in order: `check cot leakage`, `check citation validity`, `check verdict evidence`, `check absolutist language`, `check stale attestations`, `check jurisdiction scope`, `check currency scope`, `check standards version`, `check cve validity`, `check regulator validity`.

Each output rail splits into two files:

- `modules/guardrails/<rail>_rule.py` — pure-Python detection logic. No nemoguardrails import. Runs in CI on Windows, on the Linux host, anywhere Python 3.11+ runs. Returns a `dict` shaped `{has_<something>: bool, count: int, samples: list[str]}`.
- `guardrails/actions/<rail>_check.py` — 10-line `@action` wrapper that calls the rule and returns the dict. Registered with Colang via `nemoguardrails.actions.action`.

The Colang flow in `guardrails/rails.co` calls the action, inspects the returned dict, and either passes through or emits a refusal. If any rail fires, the workload receives the refusal text — never the offending response. Matching is regex-based and narrow by design; hedged audit language is not flagged (full rail-by-rail refuse conditions: [`SECURITY.md`](SECURITY.md) §9).

The Guardrails self-check LLM call bypasses the router and goes directly to `:8000`. Self-check prompts contain no user data, so the privacy hop is not needed there. This asymmetry is deliberate — the router's own self-check validation would otherwise create a circular dependency.

### Privacy Router — `modules/router/privacy_router.py` (`:8089`)

A FastAPI app with one route: `POST /v1/chat/completions`. It receives the sanitized request from Guardrails, forwards it to `LOCAL_NIM_URL` (default `http://127.0.0.1:8000`), and appends a `route_decision` audit event with target, latency, and outcome. The router is a separate process from the saaf-shell runtime, so it writes via `modules.audit.log.append_chained_event` — a cross-process writer that holds an exclusive file lock, re-reads the chain tail, and links the new record into the same hash chain the runtime's `AuditLog` writes. Router events and runtime events can interleave freely and `verify_log` still passes end-to-end.

The router has no auth (`SECURITY_AUDIT.md` finding 4); the iptables rule set in `modules/isolation/network.py` is what stops traffic from any other interface. In production, start under the systemd units in `ops/systemd/` — they bind explicitly to the gateway IP.

`AUDIT_LOG_PATH` and `LOCAL_NIM_URL` are read from environment at startup (finding 3). No secrets are read from env — `OPENAI_API_KEY=not-used` is the documented NeMo fallback (finding 6).

### Audit log — `modules/audit/`

Append-only JSONL at `/var/log/openshell/audit.jsonl`. Writer (`AuditLog`) holds a single-process lock; concurrent writers are rejected rather than interleaved.

Each record: canonical JSON of `{seq, ts, session_id, event, …fields}`, SHA-256 hashed, with the previous record's hash embedded as `prev_hash`. The first record of a session is a `session_start` with a genesis `prev_hash` (all zeros) — this is how multi-session logs are handled, and how the verifier detects session boundaries vs. chain breaks.

`saaf-shell verify-log` walks the chain top-to-bottom, re-hashing each record and comparing to the next record's `prev_hash`. It reports three possible outcomes:

- **OK** — chain intact through EOF.
- **Truncated record at offset N** — last record is incomplete (expected after a crash; everything before N replays).
- **Chain break at seq N** — a record was edited or inserted; a real tampering signal.

### CLI — `cli.py`

Thin `argparse` dispatcher over the subcommands above. All subcommands read from `SAAF_SHELL_ROOT` (default: the installed repo), the manifest path (where given), and the audit log path (`/var/log/openshell/audit.jsonl` by default or `--log`). No hidden state; everything a session does is visible in the manifest, the AgentFS overlay, and the audit log.

## Why this shape instead of something simpler

Previous design iterations used Landlock + seccomp-bpf. That boundary is a kernel syscall filter: an escape requires a kernel bug, but the attacker is in the same kernel. Firecracker moves the boundary to the hypervisor, which is much smaller and more scrutinized. For a workload that processes regulated audit material, that is a better story to tell and a better one to defend.

## What lives outside the shell

- Governance, DPIA, legal basis register, Article 30 records — human process, not code.
- Production retention enforcement — the audit config declares the period; operator tooling has to honour it.
- Policy for who may read AgentFS diffs and unredacted chain-of-thought — access control sits above the shell.

## Deeper detail

[`implementation_plan.md`](implementation_plan.md) is the long-form technical reference: full Colang flows, Presidio BSN recognizer, per-module test matrices, GDPR control mapping, and the full build sequence.
