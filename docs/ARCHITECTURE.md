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

## Why this shape instead of something simpler

Previous design iterations used Landlock + seccomp-bpf. That boundary is a kernel syscall filter: an escape requires a kernel bug, but the attacker is in the same kernel. Firecracker moves the boundary to the hypervisor, which is much smaller and more scrutinized. For a workload that processes regulated audit material, that is a better story to tell and a better one to defend.

## What lives outside the shell

- Governance, DPIA, legal basis register, Article 30 records — human process, not code.
- Production retention enforcement — the audit config declares the period; operator tooling has to honour it.
- Policy for who may read AgentFS diffs and unredacted chain-of-thought — access control sits above the shell.

## Deeper detail

[`implementation_plan.md`](implementation_plan.md) is the long-form technical reference: full Colang flows, Presidio BSN recognizer, per-module test matrices, GDPR control mapping, and the full build sequence.
