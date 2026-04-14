# Security Audit — saaf-compliance-shell (public main)

**Scope:** code read-only review of modules/, scripts/, pyproject.toml, guardrails/.
**Status:** Reviewed and committed. Findings 1–5 remain open as tracked hardening items; findings 6 is documented as intentional.

## Summary

No critical findings. The public main branch has sound defensive defaults (list-form subprocess, `yaml.safe_load`, hash-chained audit log, default-deny v1 network policy, strict manifest validation). Findings below are hardening items, not exploits.

## Findings

### 1. Kernel cmdline injection via manifest env values (low)
`modules/isolation/firecracker.py:_encode_boot_value` only escapes spaces. Newlines, quotes, or `saaf.` prefix collisions in manifest `agent.env` values could inject additional kernel params.
**Risk:** low — manifest is trusted local input, but a compromised manifest supplier could alter boot state.
**Fix:** reject values containing `\n`, `\r`, `"`, or leading `saaf.`; cap length.

### 2. Preflight injection/off-topic patterns are literal strings (accepted limitation)
`modules/guardrails/service.py` INJECTION_PATTERNS and OFF_TOPIC_PATTERNS are substring matches. Trivial paraphrases bypass preflight and fall back to the full Guardrails pipeline.
**Risk:** acceptable — preflight is a cheap first gate; the real enforcement is the full rails chain.
**Fix:** none required for v1. Document the intent.

### 3. AUDIT_LOG_PATH / LOCAL_NIM_URL env overrides in privacy router (low)
`modules/router/privacy_router.py` trusts env vars with no validation. An attacker on the host could point audit writes or inference at an arbitrary endpoint.
**Risk:** low — requires host compromise, at which point audit integrity is already gone.
**Fix:** optionally restrict LOCAL_NIM_URL to loopback/link-local on startup.

### 4. Privacy router has no auth on /v1/chat/completions (accepted)
Router is bound via iptables to the VM's tap gateway only. In a misconfigured host (iptables rules not applied), the router would accept anything from any interface.
**Risk:** depends on iptables setup in `modules/isolation/network.py` being applied.
**Fix:** add a startup bind to 127.0.0.1 or 172.16.0.1 rather than 0.0.0.0 (confirm via uvicorn launch config).

### 5. debootstrap mirror is HTTP (accepted)
`scripts/build-rootfs.sh` defaults `ROOTFS_MIRROR` to `http://archive.ubuntu.com/ubuntu`. debootstrap verifies package signatures via apt keyring, so package integrity is preserved, but metadata is MITM-able.
**Risk:** low — signatures still protect against tampered packages.
**Fix:** default to `https://`; keep HTTP as override.

### 6. guardrails service tolerates missing OPENAI_API_KEY (intentional)
`OPENAI_API_KEY=not-used` fallback is deliberate for local NeMo. Confirmed not a leak vector — no real key is ever read from env.

## Clean items
- No `shell=True`, no `eval`/`exec`, no `pickle`/`yaml.load` (all `yaml.safe_load`).
- `AuditLog` uses canonical JSON + SHA-256, single-writer lock, genesis-on-session-start. Chain verification handles multi-session logs.
- All `subprocess.run` / `Popen` use list form; arguments from `session_id` are sanitised via `tap_device_name` regex before reaching `ip`/`iptables`.
- `validate_v1_network_rules` enforces single-rule gateway:8088; anything else raises `NetworkPolicyError`.
- Manifest schema validator enforces required fields and v1 resource bounds.

## Dependency snapshot
`pyproject.toml` pins lower bounds only. For a hardened build, produce a `requirements.lock` and scan with `pip-audit` before each release.

## Recommended follow-ups (ordered)
1. Kernel cmdline value sanitisation (finding 1).
2. Bind privacy router explicitly to gateway IP (finding 4).
3. HTTPS default for rootfs mirror (finding 5).
4. Add `pip-audit` check to CI for public main.
