# Quickstart

Bring up saaf-compliance-shell on a Linux host and run the VM smoke test end-to-end.

## Prerequisites

A single Linux host with:

- KVM available (`ls /dev/kvm` returns a device)
- `firecracker` v1.15+ on `PATH`
- `agentfs` v0.6+ on `PATH` at `/usr/local/bin/agentfs`
- A local OpenAI-compatible inference endpoint on `127.0.0.1:8000` (e.g. Ollama with a small local model)
- Python `>=3.11,<3.14`
- sudo access (needed for iptables, TAP device, NFS server)

## One-time host setup

```bash
# 1. Install host tooling and open the right groups for your user.
bash scripts/setup-linux-host.sh

# 2. Confirm KVM is usable.
bash scripts/check-kvm.sh

# 3. Build the base guest rootfs at /opt/saaf/rootfs/ubuntu-24.04-python-base.
bash scripts/build-rootfs.sh

# 4. Fetch or compile the microVM kernel into /opt/saaf/kernels/vmlinux.
bash scripts/fetch-kernel.sh
```

If anything in 1–4 fails, stop and fix it before moving on. None of the later steps have a fallback path.

## Install the shell

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Start the support services

These two run on the host, outside any VM. Run them in separate terminals or under a process supervisor.

```bash
# Guardrails HTTP service on :8088
python -m modules.guardrails.service --config-path guardrails/

# Privacy Router on :8089
python -m modules.router.privacy_router
```

Check they are both alive:

```bash
curl -s http://127.0.0.1:8088/health
curl -s http://127.0.0.1:8089/health
```

## Validate a manifest

```bash
saaf-shell validate --manifest tests/fixtures/manifest_probe.yaml
```

Expected: `Manifest valid.` with no errors. A failure here lists the exact field that broke validation.

## Run the VM smoke test

```bash
python scripts/run_vm_probe.py --manifest tests/fixtures/manifest_probe.yaml
```

What happens:

1. Manifest is validated.
2. AgentFS creates an overlay DB.
3. TAP device and iptables rules come up.
4. NFS server starts and exports the overlay.
5. Firecracker boots the VM with the probe payload.
6. VM exits, teardown runs, audit log gets a `session_end` record.

You should see these files on the host after the run (paths vary with the session ID):

- `/opt/saaf/<session-id>.console.log` — VM stdout/stderr
- `.agentfs/<session-id>.db` — AgentFS overlay database
- `/var/log/openshell/audit.jsonl` — session events, hash-chained

Inside the guest (captured in the overlay) you should find:

- `/audit_workspace/init.log`
- `/audit_workspace/probe.log`
- `/audit_workspace/response.json`

## Inspect the results

```bash
# What did the workload change on disk?
saaf-shell diff --agent-id <session-id>

# Is the audit log chain intact?
saaf-shell verify-log --log /var/log/openshell/audit.jsonl
```

## Running a real workload (Vendor_Guard)

Assuming Vendor_Guard is checked out next to this repo and its `saaf-manifest.yaml` points at its own `saaf_run.sh` entrypoint:

```bash
saaf-shell run --manifest /path/to/vendor_guard/saaf-manifest.yaml
```

The workload boots inside the VM, reaches the guardrails port, produces its outputs in `/audit_workspace`, and exits. The outputs (scorecard, gap register, audit memo) appear in the AgentFS overlay and can be inspected via `saaf-shell diff`.

## Common problems

| Symptom | Likely cause | Fix |
|---|---|---|
| `Manifest valid` but VM boot hangs | Kernel missing or wrong path | Check `/opt/saaf/kernels/vmlinux` exists and is readable by your user |
| `iptables: Operation not permitted` | Not running with sudo or CAP_NET_ADMIN | Re-run under sudo or add the capability |
| `connection refused` on `:8088` | Guardrails service not started | Start it; confirm `/health` returns `ok` |
| VM boots but workload can't reach guardrails | TAP rules not applied for this session | Check `iptables -L INPUT -n -v` for the per-session ACCEPT rules |
| `verify-log` reports `truncated record` | Process crashed mid-write | Expected on crash — log is still replayable up to the last full record |

## Cleaning up between sessions

Teardown runs automatically on normal exit. If a session is killed uncleanly, manual cleanup:

```bash
# Remove stale TAP device
ip link del fc-<session-prefix>-<hash> 2>/dev/null || true

# Remove stale iptables rules (match against the TAP name)
sudo iptables -L INPUT -n -v --line-numbers | grep fc-
sudo iptables -D INPUT <line>   # for each

# Kill any stale NFS server
pkill -f 'agentfs serve nfs'
```

## What's next

Once the smoke path works, have a look at:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — how the pieces fit together.
- [`SECURITY.md`](SECURITY.md) — what the shell defends against.
- [`implementation_plan.md`](implementation_plan.md) — the deep technical reference.

For a persistent install (systemd-managed services under `/opt/saaf/shell` instead of `nohup` under `/tmp`), see [`ops/systemd/README.md`](../ops/systemd/README.md).
