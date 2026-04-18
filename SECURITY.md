# Security policy

This file exists so GitHub's "Report a vulnerability" flow has somewhere
to land. It is the disclosure policy only. For the shell's threat
model, defences, and known limits, see [`docs/SECURITY.md`](docs/SECURITY.md).

## Reporting a vulnerability

If you believe you have found a security issue in saaf-compliance-shell,
please report it privately first. Two channels, in order of preference:

1. **GitHub private vulnerability report.** On the repository's Security
   tab, click *Report a vulnerability*. This creates a private advisory
   visible only to the maintainer until disclosure.
2. **Email.** If GitHub is not an option, email the maintainer at the
   address listed on [the maintainer's GitHub profile](https://github.com/RobinGase).
   Use the subject line `saaf-compliance-shell security`.

Do **not** open a public issue and do **not** include real PII, real
audit material, or production secrets in your report. If the issue
involves a specific prompt that triggers a defect, redact any
identifying content before sharing.

## What to include

A useful report tells us:

- Which defence in [`docs/SECURITY.md`](docs/SECURITY.md) the issue
  weakens, or which control it bypasses.
- The version / commit of saaf-compliance-shell affected
  (`git rev-parse HEAD` output or the tag you are running).
- A minimal reproducer — a prompt, a manifest fragment, or a command
  sequence — that a maintainer can run without needing your
  environment.
- Your assessment of severity: does this leak PII, bypass a rail,
  compromise the audit chain, or escape the VM?

We prefer reports that stay scoped to the shell itself. Issues in
upstream dependencies (NeMo Guardrails, Presidio, Firecracker,
FastAPI, etc.) should be reported to those projects directly; we
track them via `pip-audit` in CI and pin versions in
`requirements.lock`.

## Response expectations

This project is maintained part-time by a single engineer. We aim to:

- Acknowledge a report within **7 days**.
- Assess and confirm (or dispute) within **30 days**.
- Ship a fix or mitigation, with credit to the reporter, within **90
  days** of acknowledgement — sooner if the issue is actively
  exploitable.

If a report sits without acknowledgement past 7 days, assume the
notification was lost and resend via the alternate channel.

## Scope

In scope:

- Anything listed under "What the shell defends against" in
  [`docs/SECURITY.md`](docs/SECURITY.md) — defence bypasses are
  always in scope.
- Audit-log integrity issues (chain breakage that the verifier does
  not catch, hash collisions, race conditions that interleave
  events).
- VM-escape paths from the workload to the host.
- Network-policy bypasses that let the workload reach anything other
  than `gateway:8088`.
- PII leakage paths that evade Presidio before logging or before
  reaching the model.

Out of scope (ack but won't fix as security):

- "The shell does not make you compliant" — this is by design and
  documented in the README. Scope claims are not vulnerabilities.
- Known limits already listed in [`docs/SECURITY.md`](docs/SECURITY.md)
  ("What the shell does not defend against" section and the "Known
  limits" paragraph on the output rails). Use a feature request
  instead of a security report.
- Missing hardening on the operator host itself — the threat model
  assumes the host is trusted. Host hardening is the operator's
  responsibility; see [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for
  guidance.
