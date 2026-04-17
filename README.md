# saaf-compliance-shell

A runtime enforcement layer for AI agent workloads that need a controlled execution path and an auditable record of what happened.

## What this is

A Linux-host shell that boots an AI workload inside a Firecracker microVM, tracks every filesystem change through an AgentFS overlay, gates model traffic through NeMo Guardrails (PII redaction, injection preflight, topical rail, and eleven output rails that refuse audit-specific hallucinations: fabricated citations, wrong-currency fines, unfounded verdicts, chain-of-thought leakage, stale attestations, absolutist claims, jurisdiction mismatches, fabricated standards versions, fabricated CVEs, fabricated regulator names, fabricated incident-notification deadlines), routes inference through a local-only privacy router, and writes a SHA-256 hash-chained audit log. The workload declares what it needs in `saaf-manifest.yaml`; anything not declared is denied. One host, one VM per session, no cloud dependencies.

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

The guarded channel the workload talks to instead of the model. Request flow: PII redaction (Presidio + Dutch BSN) → prompt-injection preflight → topical rail → forward to Privacy Router → response re-runs PII redaction plus the eleven output rails listed in [SECURITY.md §9](docs/SECURITY.md#9-unsafe-claim-shapes-in-model-output).

```bash
python -m modules.guardrails.service --config-path guardrails/
curl -s http://127.0.0.1:8088/health
```

Each rail is a thin `@action` in `guardrails/actions/` wrapping a pure-Python rule in `modules/guardrails/*_rule.py`. Colang 2.0 flows: [`guardrails/rails.co`](guardrails/rails.co). Rules are regex-based and CI-runnable without a nemoguardrails install.

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
| `guardrails/` | Guardrails config and Colang flows |
| `scripts/` | setup, smoke test, rootfs, kernel, release tooling |
| `ops/systemd/` | systemd units for the production install path |
| `tests/` | unit tests and integration fixtures |
| `docs/` | architecture, quickstart, security, roadmap, full spec |

## Current status

Latest release: **v0.8.3**. Eleven output rails, CI-gated branch policy, reproducible release tarball on `dev/main`. The v0.8.x line closed the bypass paths surfaced by successive independent reviews and tightened the output rails against adversarial paraphrases: the salvage path (content recovered from LLM-adapter error strings) runs the Python output rails before returning; guest isolation extends to IPv6 via `disable_ipv6` on the tap, mirrored ip6tables DROP rules, and a startup gate that refuses to run when either `net.ipv4.ip_forward` or `net.ipv6.conf.all.forwarding` is enabled; `self_check_input`/`self_check_output` refusals join the hash chain as `guardrails_rail_fire` events. v0.8.2 added the eleventh output rail (incident-notification-deadline) covering statutory reporting windows for GDPR Art. 33 (72h), NIS2 Art. 23 (24h / 72h / 1mo) and DORA Art. 19 + RTS (4h / 72h / 1mo). v0.8.3 wired the deadline rail into `output_scan._RAILS` (previously only wired in Colang, so bypass paths skipped it), added a trigger-term guard so the rule fires only when notification/reporting language is present, added multi-framework attribution walking preceding aliases, made AVG case-sensitive to stop English "avg" shorthand from anchoring the rail, and pinned the 11-rail registry with a regression test. The end-to-end path is working: Firecracker + AgentFS + Guardrails + Router + audit log run on a single Linux host, and Vendor_Guard produces real scorecard, gap register, and audit memo artefacts through the VM path. The modular branch is proven enough to support real testing work; it is not yet production-ready. Tracked next steps and open decisions live in [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
