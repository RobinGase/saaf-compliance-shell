# saaf-compliance-shell

A runtime enforcement layer for AI agent workloads that need a controlled execution path and an auditable record of what happened.

## What this is

A Linux-host shell that boots an AI workload inside a Firecracker microVM, tracks every filesystem change through an AgentFS overlay, gates model traffic through NeMo Guardrails (PII redaction, injection preflight, topical rail, and ten output rails that refuse audit-specific hallucinations — fabricated citations, wrong-currency fines, unfounded verdicts, chain-of-thought leakage, stale attestations, absolutist claims, jurisdiction mismatches, fabricated standards versions, fabricated CVEs, fabricated regulator names), routes inference through a local-only privacy router, and writes a SHA-256 hash-chained audit log. The workload declares what it needs in `saaf-manifest.yaml`; anything not declared is denied. One host, one VM per session, no cloud dependencies.

## What this is not

Not a compliance program. Not a certification. Not a drop-in GDPR or DORA solution. The shell produces the technical evidence an auditor would look for, but governance — the DPIA, legal basis register, retention policy approval, DPO sign-off, incident-response process — still lives outside it. "100% approved" is not a property any tool can have; the shell is one layer in a larger programme.

## Who this is for

Teams running AI agents against sensitive business material — compliance notes, audit evidence, vendor documents, regulated internal records — who want the agent to run on infrastructure they control, through a path they can inspect afterward. If you need the agent to talk to hosted APIs or reach the open internet, this is not the shape of shell you want.

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

## Documentation

Grouped by what you're trying to do.

| If you want to... | Read |
|---|---|
| Understand what the shell is and how the pieces fit together | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Bring the shell up on a host and run the smoke test | [`docs/QUICKSTART.md`](docs/QUICKSTART.md) |
| Know what the shell defends against (and what it does not) | [`docs/SECURITY.md`](docs/SECURITY.md) |
| See status, next steps, and open decisions | [`docs/ROADMAP.md`](docs/ROADMAP.md) |
| Read the full technical spec, test matrices, and control mapping | [`docs/implementation_plan.md`](docs/implementation_plan.md) |
| Review the security audit | [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) |
| Install services the production way (systemd) | [`ops/systemd/README.md`](ops/systemd/README.md) |

## Requirements

- KVM-capable Linux host
- Firecracker and AgentFS installed (see the host setup steps in `docs/QUICKSTART.md`)
- Local OpenAI-compatible inference endpoint (e.g. Ollama)
- Python `>=3.11,<3.14` — `3.14` excluded because the `nemoguardrails` / `langchain` stack was not reliable there during integration work

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

Latest release: **v0.7.0** — ten output rails (regulator-name rail added), CI-gated branch policy, reproducible release tarball on `dev/main`. The end-to-end path works: Firecracker + AgentFS + Guardrails + Router + audit log run on a single Linux host, and Vendor_Guard produces real scorecard, gap register, and audit memo artefacts through the VM path. The modular branch is proven enough to support real testing work; it is not yet production-ready. Tracked next steps and open decisions live in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Development workflow

`main` is the modular, upstream-safe version. Local-machine-specific or private-environment work belongs on a personal branch. `scripts/check_branch_portability.py` enforces "no personal hostnames, no Tailscale IPs" on `main` and `modular/*` to keep the upstream-safe shape intact.

## Scope note

The shell enforces technical controls around an agent workload. Governance process, legal review, retention policy approval, and production operating procedures sit outside it and are the operator's responsibility.
