# Operator runbook

What to do when something goes wrong on a host running saaf-compliance-shell. Written for someone who has bootstrapped the host with `docs/QUICKSTART.md` and has the systemd units in `ops/systemd/` installed.

The shell is conservative by design: it would rather refuse to run a session than run one it cannot account for. Most incidents here look like "a session wouldn't boot" or "the audit log reports a broken chain". In both cases, the right move is to stop, inspect, and only then resume.

## At-a-glance incident triage

| Symptom | Likely cause | Section |
|---|---|---|
| `saaf-shell run` exits non-zero before the VM boots | Manifest invalid, stale iptables/TAP state, AgentFS DB locked | [Session won't start](#session-wont-start) |
| `verify-log` reports `Truncated record at line N` | Host or writer crashed during an append | [Truncated audit log](#truncated-audit-log) |
| `verify-log` reports `CHAIN BROKEN at seq N` | Record was edited, deleted, or inserted after the fact | [Broken hash chain](#broken-hash-chain) |
| Guardrails service is up but requests hang | NeMo self-check LLM unreachable, or router not up | [Inference pipeline hangs](#inference-pipeline-hangs) |
| Router returns 502 / 503 | Local model endpoint down or OOM | [Model endpoint down](#model-endpoint-down) |
| TAP or iptables state left over from previous session | Previous run crashed before teardown | [Leftover network state](#leftover-network-state) |
| Host ran out of disk | AgentFS overlay DBs or audit log growth | [Disk pressure](#disk-pressure) |

## Session won't start

`saaf-shell run --manifest …` exits non-zero before any `session_start` record appears in the audit log. Ordered from most common first.

1. **Manifest validation failed.** Run `saaf-shell validate --manifest <path>`. The validator reports every field that broke, not just the first. Fix the manifest and re-run.
2. **Stale TAP or iptables state.** A prior crashed session may have left `fc-*` interfaces or DROP rules in place. Run `ip link show type tuntap` and `sudo iptables -S`. If a TAP from a previous session is present, see [Leftover network state](#leftover-network-state).
3. **AgentFS DB already exists.** `.agentfs/<session-id>.db` from a previous run of the same session ID. Either delete it (losing the overlay) or pick a new session ID. Sessions IDs are generated per-run so this should not recur under normal operation.
4. **Firecracker can't open KVM.** `ls -l /dev/kvm` — the invoking user must have rw access. If the systemd unit is the caller, `User=saaf` must be in the `kvm` group.
5. **NFS server won't start.** `agentfs serve nfs` needs portmapper. `sudo systemctl status rpcbind` — start it if stopped.

## Truncated audit log

`saaf-shell verify-log` reports `Truncated record at line N (possible crash during write)`.

This is expected behavior after a crash: a partial JSON line on the last write is detected, reported, and ignored. The chain up to line N−1 is valid and replayable.

1. Inspect the tail: `tail -n 3 /var/log/openshell/audit.jsonl`. The last line will be incomplete JSON.
2. If the incomplete line is the last line in the file, truncate it. The safe way is to back up first, then keep only complete lines:
   ```bash
   sudo cp /var/log/openshell/audit.jsonl{,.bak-$(date +%s)}
   sudo python -c '
   import json, sys
   good = []
   with open("/var/log/openshell/audit.jsonl") as f:
       for line in f:
           line = line.rstrip("\n")
           if not line:
               continue
           try:
               json.loads(line)
               good.append(line)
           except json.JSONDecodeError:
               break
   with open("/var/log/openshell/audit.jsonl", "w") as f:
       f.write("\n".join(good) + "\n")
   '
   saaf-shell verify-log
   ```
3. Re-run `verify-log`. It should now return `OK`.

Do **not** attempt to reconstruct the missing record. The chain is designed to let truncation be detected, not recovered — the missing event is lost, which is accurate.

## Broken hash chain

`saaf-shell verify-log` reports `CHAIN BROKEN at seq N` or `HASH MISMATCH at seq N`.

Unlike a truncated record, this means a record was edited, deleted, or inserted *after* it was written. Treat it as a possible tampering event.

1. **Stop running sessions on the host.** `sudo systemctl stop saaf-guardrails saaf-router`. No more writers.
2. **Preserve the current log.** `sudo cp /var/log/openshell/audit.jsonl /var/log/openshell/audit.jsonl.broken-$(date +%s)`.
3. **Identify the break point.** The `verify-log` message gives the sequence number and line number. Compare the record before and after to see what differs.
4. **Determine the attacker model.** If the host is shared, the hash-chain guarantee is only meaningful if write access to the log was restricted. Check `ls -l /var/log/openshell/audit.jsonl` — it should be owned by the `saaf` user, mode 0640.
5. **Archive the broken log and start a new session.** There is no supported repair — the whole point of the chain is that tampering is permanent. Start a new session; a new `session_start` record at the head of the file will establish a fresh chain from genesis.
6. **Escalate to whoever owns audit trail integrity.** A broken chain is reportable evidence under most audit regimes.

## Inference pipeline hangs

Workload calls `172.16.0.1:8088`, request sits forever.

1. `sudo systemctl status saaf-guardrails saaf-router` — both must be `active (running)`.
2. `curl -sf http://127.0.0.1:8088/health` and `curl -sf http://127.0.0.1:8089/health`. The router's `/health` also probes the model endpoint and returns `"model_status": "unreachable"` when the upstream model is down.
3. If guardrails is up but the router isn't, the guardrails self-check LLM call bypasses the router anyway, so input rails will still run. The forward step to the router is what fails.
4. Check guardrails logs: `journalctl -u saaf-guardrails -n 200`. Look for NeMo import errors or missing Colang files.
5. If the workload is looping on retries, its timeout should catch it. The router's `REQUEST_TIMEOUT` is 120 seconds by default.

## Model endpoint down

Router returns 502 or the health check reports `model_status: unreachable`.

1. Confirm the model endpoint responds: `curl -sf http://127.0.0.1:8000/v1/models`.
2. If it's Ollama, `systemctl status ollama` (if the systemd unit is installed) or check for the process directly.
3. Model OOM is common on the 10GB VRAM Nemotron-3 8B setup. Check `nvidia-smi` — if the GPU is full and the model has been evicted, restart the model host.
4. No cloud fallback is configured by design (privacy router v1 is local-only). Fix the local endpoint; there is no switchover.

## Leftover network state

Previous run crashed before teardown. `ip link show` lists a `fc-*` TAP device; `sudo iptables -S` lists matching DNAT and DROP rules.

1. Identify the orphan TAP: `ip link show type tuntap | grep fc-`.
2. Remove it: `sudo ip link delete fc-<prefix>-<hash>`.
3. Flush the associated iptables rules. The shell writes them in three places:
   - `sudo iptables -t nat -D PREROUTING -i fc-<...> -p tcp --dport 8088 -j DNAT --to-destination 127.0.0.1:8088`
   - `sudo iptables -D INPUT -i fc-<...> -p tcp --dport 8088 -j ACCEPT`
   - `sudo iptables -D FORWARD -i fc-<...> -j DROP`
   If you cannot match the exact interface name, dump the full ruleset and remove what looks orphaned: `sudo iptables -S | grep fc-`.
4. Verify nothing else is bound to the gateway IP: `ip -4 addr show`. `172.16.0.1` should not be assigned after teardown.
5. Retry `saaf-shell run`.

## Disk pressure

Host is out of disk. Two likely offenders:

1. **AgentFS overlays.** `.agentfs/*.db` files accumulate one per session. In normal operation they are tied to a session and can be cleaned once the session has been diffed and the diff archived. `saaf-shell sessions` lists known session IDs. To reclaim, remove `.agentfs/<session-id>.db` after confirming the diff has been saved.
2. **Audit log.** `/var/log/openshell/audit.jsonl` grows forever in v1 — the manifest's `audit.retention_days` is declarative only. Rotate manually: move the current file to `audit.jsonl.<date>`, verify the rotated log with `verify-log`, and archive it. A new `session_start` in a fresh file begins a new chain from genesis.

Rotation must not be done while a session is running. Stop the shell first.

Once archives exist, `saaf-log-retention.timer` (installed from `ops/systemd/`, runs daily at 03:00) will prune `audit.jsonl.*` files older than `SAAF_AUDIT_RETENTION_DAYS` via `scripts/enforce_audit_retention.py`. The live `audit.jsonl` is never touched by the pruner; it only sweeps rotated archives, so the active hash chain is unaffected. Default retention is `0` (disabled) — set a non-zero value in `/etc/saaf-shell/services.env` to turn pruning on. Manual invocation:

```bash
sudo -u saaf SAAF_AUDIT_RETENTION_DAYS=90 \
    /opt/saaf/shell/.venv/bin/python \
    /opt/saaf/shell/scripts/enforce_audit_retention.py
```

## Health checks worth adding to your own monitoring

The shell doesn't prescribe a monitoring stack, but these are the signals a remote operator would want:

- `curl -sf http://127.0.0.1:8088/health` → guardrails liveness.
- `curl -sf http://127.0.0.1:8089/health` → router liveness + model reachability in one shot.
- `saaf-shell verify-log` exit code → nonzero means the chain is broken or truncated.
- `df -h /var/log/openshell /path/to/.agentfs` → disk pressure on the two writable paths.
- `systemctl is-active saaf-guardrails saaf-router` → services up.

If any of these go red, the correct reflex is usually to stop new sessions and investigate — not to restart the service until you understand why it went down.
