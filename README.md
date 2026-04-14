# saaf-compliance-shell

## Vision

`saaf-compliance-shell` is a reusable enforcement layer for AI agent workloads that need a controlled runtime, clear policy boundaries, and an auditable record of what happened.

The goal is simple. An agent should be able to do useful work on local infrastructure without getting unrestricted filesystem access, unrestricted network access, or an untraceable execution path.

This repository is the modular single host version of that shell. It is the branch shape intended for upstream use and eventual integration into a broader `saaf` project.

## Use Case

The primary use case is an AI agent that needs to inspect sensitive business material such as compliance notes, audit evidence, vendor documents, or regulated internal records.

Instead of running that agent directly on a host with broad permissions, `saaf-compliance-shell` wraps it in a constrained path:

1. The workload declares its requirements in `saaf-manifest.yaml`
2. The shell boots the workload inside a Firecracker microVM
3. Filesystem changes are tracked through AgentFS
4. Model traffic passes through Guardrails and the local router
5. Execution is recorded in a tamper evident audit log

This is meant for teams that want a local first agent runtime with clear operational controls and evidence they can inspect afterward.

## What It Does

`saaf-compliance-shell` provides four core controls.

- Runtime isolation through Firecracker
- Filesystem tracking through AgentFS
- Guarded model access through NeMo Guardrails, Presidio, and a local router
- Tamper evident audit logging with chained hashes

At a high level:

```text
Target workload
  -> Firecracker microVM
  -> AgentFS tracked filesystem
  -> Guardrails service
  -> Privacy Router
  -> Local model endpoint
  -> Audit log
```

## Architecture

This modular branch assumes a single Linux host.

| Component | Role |
|---|---|
| Firecracker | Runs the agent workload inside a microVM |
| AgentFS | Tracks guest filesystem mutations and produces diffs |
| Guardrails service | Applies prompt rails and PII controls before inference |
| Privacy Router | Restricts model traffic to the configured local endpoint |
| Audit log | Records session events in a chained JSONL log |
| Local model | Serves the actual inference endpoint |

## Current Status

The modular shell path is now proven far enough to support real testing work.

- Manifest validation works
- Audit log verification works
- Guardrails service works through the repo owned HTTP wrapper
- Router to local model path works
- Firecracker plus AgentFS plus NFS root boot works on the validated host setup
- Repeatable VM probe works and produces AgentFS visible artifacts

The current focus is Phase 3 integration and workload level testing.

## Quick Start

Core CLI commands:

```bash
saaf-shell validate --manifest /path/to/saaf-manifest.yaml
saaf-shell run --manifest /path/to/saaf-manifest.yaml
saaf-shell diff --agent-id <session-id>
saaf-shell verify-log --log /path/to/audit.jsonl
```

Repeatable VM smoke test on a prepared Linux host:

```bash
python scripts/run_vm_probe.py --manifest tests/fixtures/manifest_probe.yaml
```

That smoke path is expected to produce guest visible artifacts such as:

- `/audit_workspace/init.log`
- `/audit_workspace/probe.log`
- `/audit_workspace/response.json`

## Requirements

This branch is designed for a single Linux host with:

- KVM support
- Firecracker
- AgentFS
- a local model endpoint such as Ollama
- Python `>=3.11,<3.14`

Python `3.14` is intentionally excluded for now because the current `nemoguardrails` and `langchain` stack was not reliable there during integration work.

## Repository Layout

| Path | Purpose |
|---|---|
| `cli.py` | command line entry point |
| `modules/isolation/` | Firecracker, AgentFS, TAP policy, runtime orchestration |
| `modules/guardrails/` | repo owned Guardrails HTTP service |
| `modules/router/` | local model routing proxy |
| `modules/audit/` | tamper evident audit log |
| `guardrails/` | Guardrails config and Colang flows |
| `scripts/` | setup, smoke, rootfs, and kernel helpers |
| `tests/` | unit tests and integration fixtures |

## Development Workflow

This repository currently uses two working modes.

- `main` is intended to remain modular and upstream safe
- local machine specific or private environment work belongs on the personal branch

The modular branch is the version that should read cleanly without personal hostnames, private network assumptions, or one off operator notes.

CI is branch aware:

- the main test workflow runs the non Presidio suite on pushes and pull requests
- the modular branch policy checks for machine specific strings that should not leak into the upstream safe branch

## Documentation

Start here:

- [Architecture](docs/ARCHITECTURE.md) — system shape, trust boundaries, and the path a request takes
- [Security Model](docs/SECURITY.md) — what the shell defends against, what it does not, and the red-team matrix
- [Quickstart](docs/QUICKSTART.md) — bring up the shell on a Linux host and run the VM smoke test
- [Roadmap](docs/ROADMAP.md) — current status, what is next, what was deferred

Deep reference:

- [Implementation Plan](docs/implementation_plan.md) — full phased build sequence, per-module specs, GDPR / DORA / AI Act control mapping

## Scope Note

This repository is not trying to be a full compliance program on its own. It is the runtime shell that enforces technical controls around an agent workload. Governance process, legal review, retention policy approval, and production operating procedures still sit outside the shell.
