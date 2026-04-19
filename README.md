# saaf-compliance-shell

A runtime enforcement layer for AI agent workloads that need a controlled execution path and an auditable record of what happened.

## What this is

A Linux-host shell that boots an AI workload inside a Firecracker microVM, tracks every filesystem change through an AgentFS overlay, gates model traffic through NeMo Guardrails (input-side PII redaction, full-history prompt-injection preflight, topical preflight, and twelve output rails that refuse audit-specific hallucinations: fabricated citations, wrong-currency fines, unfounded verdicts, chain-of-thought leakage, stale attestations, absolutist claims, jurisdiction mismatches, fabricated standards versions, fabricated CVEs, fabricated regulator names, fabricated incident-notification deadlines, fabricated case-law / enforcement-action IDs), routes inference through a local-only privacy router, and writes a SHA-256 hash-chained audit log anchored by an external head-pointer sidecar. The workload declares what it needs in `saaf-manifest.yaml`; anything not declared is denied. One host, one VM per session, no cloud dependencies.

## What this is not

Not a compliance program. Not a certification. Not a drop-in GDPR or DORA solution. The shell produces the technical evidence an auditor would look for, but governance (the DPIA, legal basis register, retention policy approval, DPO sign-off, incident-response process) still lives outside it. "100% approved" is not a property any tool can have; the shell is one layer in a larger programme.

## Who this is for

Teams running AI agents against sensitive business material (compliance notes, audit evidence, vendor documents, regulated internal records) who want the agent to run on infrastructure they control, through a path they can inspect afterward. If you need the agent to talk to hosted APIs or reach the open internet, this is not the shape of shell you want.

## Architecture at a glance

```
┌─────────────────────── Linux host ───────────────────────┐
│                                                           │
│  ┌─── Firecracker microVM ─────────────────────────────┐  │
│  │  target workload ── TAP ──▶ host :8088              │  │
│  │  AgentFS overlay (SQLite-backed, host-owned)        │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
│  NeMo Guardrails :8088  ──▶  Privacy Router :8089  ──▶   │
│                                                   Ollama  │
│                                                   :8000   │
│                                                           │
│  Audit log   /var/log/openshell/audit.jsonl              │
└───────────────────────────────────────────────────────────┘
```

Full walkthrough: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start

```bash
saaf-shell validate   --manifest /path/to/saaf-manifest.yaml
saaf-shell run        --manifest /path/to/saaf-manifest.yaml
saaf-shell diff       --agent-id <session-id>
saaf-shell verify-log --log /path/to/audit.jsonl
```

Full host setup and smoke test: [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## Components

Six pieces. Each is loosely coupled, so you can inspect, configure, or replace any of them without unpicking the others. In-depth walkthroughs: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#components-in-depth).

### 1. Manifest: `saaf-manifest.yaml`

The declarative contract between a workload and the shell. A workload ships one at its repo root listing what it needs (entrypoint, writable paths, network rule, resource limits, PII recognizers, retention). Anything not declared is denied.

```bash
saaf-shell validate --manifest /path/to/saaf-manifest.yaml
```

Validation runs before every `run`; an invalid manifest never boots. Schema: [`modules/manifest/validator.py`](modules/manifest/validator.py). Fixtures: [`tests/fixtures/`](tests/fixtures/).

### 2. Isolation layer: `modules/isolation/`

Firecracker microVM + AgentFS overlay + TAP device + iptables. The workload runs inside a guest; the host filesystem is never mounted, and outbound traffic is restricted to `gateway:8088`.

- `firecracker.py`: VM config + boot.
- `agentfs.py`: SQLite-backed overlay, NFS-exported to the guest, host-owned.
- `network.py`: TAP + iptables; validates `network.allow` against the v1 single-rule policy.
- `runtime.py`: orchestrates setup and teardown around a session.

Driven by `saaf-shell run`. To inspect what the workload wrote to disk:

```bash
saaf-shell diff --agent-id <session-id>
```

### 3. Guardrails service: `modules/guardrails/` (HTTP on `:8088`)

The guarded channel the workload talks to instead of the model. Request flow: input-side PII redaction (Presidio + Dutch BSN) → prompt-injection preflight (scans every message, every role) → topical preflight → forward to Privacy Router → response runs the twelve output rails listed in [SECURITY.md §9](docs/SECURITY.md#9-unsafe-claim-shapes-in-model-output). Refusal events on the audit side carry a SHA-256 content digest rather than the raw prompt or completion. The output-side Presidio hook and the Colang topical flow are documented `pass` stubs today — the actual enforcement paths are the input-side mask and the service-layer preflight; see [SECURITY.md §3 and §5](docs/SECURITY.md).

```bash
python -m modules.guardrails.service --config-path guardrails_config/
curl -s http://127.0.0.1:8088/health
```

Each rail is a thin `@action` in `guardrails_config/actions/` wrapping a pure-Python rule in `modules/guardrails/*_rule.py`. Colang 2.0 flows: [`guardrails_config/rails.co`](guardrails_config/rails.co). Rules are regex-based and CI-runnable without a nemoguardrails install.

### 4. Privacy Router: `modules/router/privacy_router.py` (HTTP on `:8089`)

Local-only proxy between Guardrails and the inference endpoint. Every inference call must resolve to a local endpoint; the router appends a `route_decision` event to the audit log. v1 has no cloud fallback, by design.

```bash
python -m modules.router.privacy_router
curl -s http://127.0.0.1:8089/health
```

Target endpoint comes from `LOCAL_NIM_URL` (default `http://127.0.0.1:8000`).

### 5. Audit log: `modules/audit/`

Every session event (start, route decision, rail fire, end) lands as canonical JSON in `/var/log/openshell/audit.jsonl`, SHA-256 chained. Single-writer lock; never mounted into the guest.

```bash
saaf-shell verify-log --log /var/log/openshell/audit.jsonl
```

Verifier walks the chain and reports the first broken link. Truncation is expected on crash and handled gracefully; the log is replayable up to the last complete record. Multi-session logs are supported (a `session_start` record resets the chain).

### 6. CLI: `cli.py` (entry point `saaf-shell`)

Single operator entry point.

| Subcommand | Purpose |
|---|---|
| `saaf-shell validate --manifest <path>` | Check a manifest without booting anything |
| `saaf-shell run --manifest <path>` | Full session: validate → setup → VM → teardown |
| `saaf-shell diff --agent-id <id>` | Show what the workload wrote to `/audit_workspace` |
| `saaf-shell sessions` | List past sessions recorded in the audit log |
| `saaf-shell verify-log --log <path>` | Walk the hash chain and report the first break |
| `saaf-shell test --suite <name>` | Run a named test suite (e.g. `red-team`) |

## Documentation

Grouped by what you're trying to do.

| If you want to... | Read |
|---|---|
| Understand what the shell is and how the pieces fit together | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Bring the shell up on a host and run the smoke test | [`docs/QUICKSTART.md`](docs/QUICKSTART.md) |
| Know what the shell defends against (and what it does not) | [`docs/SECURITY.md`](docs/SECURITY.md) |
| See status, next steps, and open decisions | [`docs/ROADMAP.md`](docs/ROADMAP.md) |
| Recover from a crash, broken chain, or orphan network state | [`docs/RUNBOOK.md`](docs/RUNBOOK.md) |
| Read the full technical spec, test matrices, and control mapping | [`docs/implementation_plan.md`](docs/implementation_plan.md) |
| Review the security audit | [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) |
| Install services the production way (systemd) | [`ops/systemd/README.md`](ops/systemd/README.md) |

## Requirements

- KVM-capable Linux host
- Firecracker and AgentFS installed (see the host setup steps in `docs/QUICKSTART.md`)
- Local OpenAI-compatible inference endpoint (e.g. Ollama)
- Python `>=3.11,<3.14`. `3.14` is excluded because the `nemoguardrails` / `langchain` stack was not reliable there during integration work.

## Repository layout

| Path | Purpose |
|---|---|
| `cli.py` | command-line entry point |
| `modules/isolation/` | Firecracker, AgentFS, TAP policy, runtime orchestration |
| `modules/guardrails/` | repo-owned Guardrails HTTP service |
| `modules/router/` | local model routing proxy |
| `modules/audit/` | tamper-evident audit log |
| `guardrails_config/` | Guardrails config and Colang flows |
| `scripts/` | setup, smoke test, rootfs, kernel, release tooling |
| `ops/systemd/` | systemd units for the production install path |
| `tests/` | unit tests and integration fixtures |
| `docs/` | architecture, quickstart, security, roadmap, full spec |

## Current status

Latest release: **v0.8.6** (2026-04-18). Active work is the post-v0.8.6 hardening wave toward v0.9.0; the most recent checkpoint tag is **v0.9.0-s10** (2026-04-19). Each batch in the wave is published as a `v0.9.0-sN` pre-release tag and logged in [`docs/REVIEW_2026-04-19_hardening.md`](docs/REVIEW_2026-04-19_hardening.md). Twelve output rails, CI-gated branch policy, reproducible release tarball on `dev/main`, and `pip-audit --strict` green on the current lock.

Highlights of the hardening wave so far:

- **S1** oversized-input safe refusal (HTTP 413 + `oversize_refused` audit event instead of proxy-with-output-rescan).
- **S2** host-wide non-blocking session lock (`/var/run/saaf-shell/session.lock`); crash-safe via kernel fd release.
- **S3** 12-rail adversarial paraphrase harness with a coverage gate.
- **S4** `_build_rails` mtime cache; NFS server log routing; per-session ephemeral NFS port; `setuptools_scm` migration; `guardrails/` → `guardrails_config/` rename removing the v0.8.5 CWD-chdir workaround.
- **S5** DORA notification-deadline citation verified against the OJ — 2024/1772 dismissed; 2022/2554 Art. 19 + RTS is the source of truth; 4 regression tests pin the confusion.
- **S6** red-team quick wins — manifest-`name` kernel-cmdline injection closed (RT-04); `session_id` bleed on `session_end` fixed (RT-09); systemd `LogsDirectory=openshell` so the sandboxed writer can reach `/var/log/openshell/` (RT-10).
- **S7** audit integrity — head-pointer sidecar at `<log>.head` (atomic `os.replace` under `fcntl`), tail classification (`clean` / `first_write` / `legacy` / `heal_legit` / `tamper`), `AuditTamperDetected` with `SAAF_ACK_AUDIT_HEAL=1` escape valve (closes RT-02 rollback and RT-03 heal-erasure).
- **S8** PII-safe refusal audits — `self_check_direct` emits `{content_sha256, content_len}` instead of the raw prompt or completion (RT-05); full-message-history preflight scans every role, first-match-wins (RT-08).
- **S10** shared-host iptables safety — filter-table rules switched from `-A` to `-I <chain> N` with explicit contiguous positions so Tailscale / Docker / libvirt ACCEPTs can't shadow SAAF's DROP (RT-06); NAT `PREROUTING` stays `-A` (scoped by `-i <tap>`). `docs/SECURITY.md` §3, §5, and the Controls mapping aligned to the actual enforcement paths (RT-07).

The end-to-end path is working: Firecracker + AgentFS + Guardrails + Router + audit log run on a single Linux host, and Vendor_Guard produces real scorecard, gap register, and audit memo artefacts through the VM path. The modular branch is proven enough to support real testing work; it is not yet production-ready. Tracked next steps and open decisions live in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Development workflow

`main` is the modular, upstream-safe version. Local-machine-specific or private-environment work belongs on a personal branch. `scripts/check_branch_portability.py` enforces "no personal hostnames, no Tailscale IPs" on `main` and `modular/*` to keep the upstream-safe shape intact.

`requirements.lock` pins the full transitive dependency closure. After changing anything in `pyproject.toml`'s `dependencies`, regenerate it:

```bash
pip install pip-tools
pip-compile --strip-extras --output-file requirements.lock pyproject.toml
```

CI runs `pip-audit` against the lockfile on every push and weekly, so newly disclosed CVEs fail the build even without a code change.

Lint and type-check gates run on every push and PR (`ruff check` + `mypy` over `modules/` and `cli.py`). Run them locally with:

```bash
pip install -e .[dev]
ruff check .
mypy
```

## Scope note

The shell enforces technical controls around an agent workload. Governance process, legal review, retention policy approval, and production operating procedures sit outside it and are the operator's responsibility.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
