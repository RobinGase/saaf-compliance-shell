# SAAF shell systemd units

Replaces the `nohup … &` pattern in the fresh-boot runbook with proper units so
the Guardrails and router services survive logout, restart on failure, and log
to journald.

## Files

| File | Role |
|---|---|
| `saaf-guardrails.service` | Guardrails HTTP service on `127.0.0.1:8088` |
| `saaf-router.service` | Privacy router on `127.0.0.1:8089`, depends on guardrails |
| `services.env.example` | Environment file template (install as `/etc/saaf-shell/services.env`) |

Both units run as the `robindev` user, read their configuration from
`/etc/saaf-shell/services.env`, and expect a persistent install under
`$SAAF_SHELL_ROOT` (default `/opt/saaf/shell`) with `.venv/` alongside.

## Install (one-time, as root)

```bash
# 1. Persistent repo location (once). /tmp is wiped on reboot; don't use it
#    for a service install.
install -d -o robindev -g robindev /opt/saaf/shell
# (ship and extract the shell tarball here, build .venv, install deps —
#  same steps as the fresh-boot runbook, just at /opt/saaf/shell instead
#  of /tmp/saaf-shell-live)

# 2. Environment file
install -d -m 0755 /etc/saaf-shell
install -m 0640 -o root -g robindev \
    ops/systemd/services.env.example /etc/saaf-shell/services.env
# Edit /etc/saaf-shell/services.env to set LOCAL_NIM_URL for this host.

# 3. Install unit files
install -m 0644 ops/systemd/saaf-guardrails.service /etc/systemd/system/
install -m 0644 ops/systemd/saaf-router.service     /etc/systemd/system/
systemctl daemon-reload

# 4. Start + enable on boot
systemctl enable --now saaf-guardrails saaf-router
```

## Verify

```bash
systemctl status saaf-guardrails saaf-router
curl -s http://127.0.0.1:8088/health
curl -s http://127.0.0.1:8089/health
journalctl -u saaf-guardrails -u saaf-router -n 50 --no-pager
```

## Hardening notes

Both units apply a conservative sandbox:

- `NoNewPrivileges` + `ProtectSystem=strict` + `ProtectHome=read-only`
- `PrivateTmp` (own `/tmp` namespace, no cross-service leakage)
- `ReadWritePaths=/tmp` (for log files only — service state lives under
  `$SAAF_SHELL_ROOT`)
- Kernel tunables / modules / cgroups / namespaces locked down

`MemoryDenyWriteExecute` is deliberately **not** set — the Python stack uses
cffi and JIT-capable libraries that need writeable-executable pages on load.

## Relationship to the fresh-boot runbook

The runbook at `proof/fresh_boot_runbook.md` is the *dev* workflow: ship the
repo to `/tmp/saaf-shell-live`, start services with `nohup`, tear down after.
These units are the *production* path: install once under `/opt/saaf/shell`,
manage via `systemctl`. Pick one — do not run both against the same ports.
