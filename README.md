# saaf-compliance-shell

Modular compliance wrapper for AI agent workloads. Enforces runtime isolation, PII masking, local-first model routing, and tamper-evident audit logging.

Built for GDPR/AVG, DORA, Privacy by Design, and EU AI Act compliance.

## What it does

`saaf-compliance-shell` wraps a target repository's AI agent inside a hardware-isolated Firecracker microVM. All agent behavior is constrained by a per-repo manifest (`saaf-manifest.yaml`), and all activity is logged in a tamper-evident audit trail.

```
Target repo (e.g. Vendor_Guard)
    │
    ▼
┌─ saaf-compliance-shell ──────────────────────────┐
│  Firecracker microVM     → Agent runs here        │
│  NeMo Guardrails         → PII masking + rails    │
│  Privacy Router          → Local-only inference   │
│  Audit Log + AgentFS     → Tamper-evident trail   │
└───────────────────────────────────────────────────┘
    │
    ▼
Local model (Ollama / vLLM-TurboQuant)
```

## Modules

| Module | Purpose | Tech |
|---|---|---|
| **Isolation** | Hardware-level agent sandboxing | Firecracker microVM + AgentFS |
| **Guardrails** | PII masking, prompt injection defense, topical control | NeMo Guardrails (Colang 2.0) + Presidio |
| **Router** | Local-only model routing | FastAPI |
| **Audit** | Tamper-evident evidence trail | JSONL + SHA-256 hash chain + AgentFS |

## Quick start

```bash
# Launch a target repo inside the compliance shell
saaf-shell run --manifest /path/to/repo/saaf-manifest.yaml

# Validate a manifest
saaf-shell validate --manifest /path/to/repo/saaf-manifest.yaml

# Inspect agent filesystem changes
saaf-shell diff --agent-id <session-id>

# Verify audit log integrity
saaf-shell verify-log --log /var/log/openshell/audit.jsonl
```

## Deployment topology

| Machine | Role |
|---|---|
| **fedoraserver** | Runs the shell, Firecracker VMs, guardrails, router |
| **maindev** | GPU compute — Ollama / vLLM-TurboQuant (RTX 3080) |
| **laptop** | Client access via SSH over Tailscale |

## Documentation

- [Implementation Plan](docs/implementation_plan.md) — full architecture, build phases, compliance mapping

## Status

Phase 1 — Foundations (in progress)
