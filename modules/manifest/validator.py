"""saaf-manifest.yaml schema validator.

Validates target repo manifests against the required schema before
the shell accepts them. Used by `saaf-shell validate` and at boot time.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_DATA_CLASSIFICATIONS = {"sensitive", "test"}
# Presidio ships dozens of additional recognizers (CREDIT_CARD, IBAN_CODE,
# IP_ADDRESS, PHONE_NUMBER, US_SSN, ...). See
# https://microsoft.github.io/presidio/supported_entities/ and the custom
# BSN_NL recognizer in ``guardrails_config/actions/presidio_redact.py``. Add new
# entries here when extending PII coverage — the validator rejects anything
# unknown so a typo can't silently become a no-op mask.
VALID_PII_ENTITIES = {"PERSON", "EMAIL_ADDRESS", "BSN_NL"}
REQUIRED_FILESYSTEM_PATHS = {"/audit_workspace"}

# Kernel cmdline / boot-args must not carry shell metacharacters.
# ``_encode_boot_value`` in ``modules/isolation/firecracker.py`` only
# escapes space — anything else (``"``, ``'``, ``\``, ``$``, newline,
# ``=`` embedded mid-value) would malform the parameter or let the
# manifest inject a second kernel parameter. Validate at manifest
# time so the Firecracker config never gets built from a poisoned
# entrypoint/workdir/env value.
_BOOT_ARG_SAFE_RE = re.compile(r"^[A-Za-z0-9_./:@\-+ ]*$")
_BOOT_ARG_SAFE_DESCRIPTION = (
    "alphanumeric, space, and any of: _ . / : @ - +"
)


@dataclass
class ValidationError:
    field: str
    message: str


@dataclass
class ValidationResult:
    valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    manifest: dict | None = None

    def add_error(self, field_name: str, message: str) -> None:
        self.errors.append(ValidationError(field=field_name, message=message))
        self.valid = False


def validate_manifest(path: str | Path) -> ValidationResult:
    """Validate a saaf-manifest.yaml file.

    Returns a ValidationResult with all errors found. A manifest can have
    multiple errors — we report all of them, not just the first.
    """
    result = ValidationResult(valid=True)
    path = Path(path)

    if not path.exists():
        result.add_error("file", f"Manifest not found: {path}")
        return result

    try:
        with open(path) as f:
            manifest = yaml.safe_load(f)
    except yaml.YAMLError as e:
        result.add_error("file", f"Invalid YAML: {e}")
        return result

    if not isinstance(manifest, dict):
        result.add_error("file", "Manifest must be a YAML mapping")
        return result

    result.manifest = manifest

    _check_required_fields(manifest, result)
    _check_agent(manifest, result)
    _check_data_classification(manifest, result)
    _check_filesystem(manifest, result)
    _check_network(manifest, result)
    _check_resources(manifest, result)
    _check_pii(manifest, result)
    _check_audit(manifest, result)

    return result


def _check_required_fields(manifest: dict, result: ValidationResult) -> None:
    if "version" not in manifest:
        result.add_error("version", "Missing required field 'version'")
    elif manifest["version"] != 1:
        result.add_error("version", f"Unsupported version: {manifest['version']}. Only version 1 is supported.")

    if "name" not in manifest:
        result.add_error("name", "Missing required field 'name'")
    else:
        # RT-04: ``name`` is interpolated into the kernel cmdline as the
        # hostname segment of ``ip=<ip>::<gw>:<netmask>:<name>:eth0:off``
        # (see ``modules/isolation/firecracker.build_vm_config``).
        # Whitespace or shell metachars in ``name`` would split the
        # cmdline and inject a second kernel parameter — same failure
        # mode ``_check_boot_arg`` guards for entrypoint/workdir/env.
        _check_boot_arg(result, "name", manifest["name"], forbid_space=True)


def _check_agent(manifest: dict, result: ValidationResult) -> None:
    agent = manifest.get("agent")
    if not agent:
        result.add_error("agent", "Missing required section 'agent'")
        return

    entrypoint = agent.get("entrypoint")
    if entrypoint is None:
        result.add_error("agent.entrypoint", "Missing required field 'agent.entrypoint'")
    else:
        _check_boot_arg(result, "agent.entrypoint", entrypoint)

    workdir = agent.get("working_directory")
    if workdir is None:
        result.add_error("agent.working_directory", "Missing 'agent.working_directory' — should be /audit_workspace")
    else:
        _check_boot_arg(result, "agent.working_directory", workdir)

    env = agent.get("env", {})
    if "INFERENCE_URL" not in env:
        result.add_error("agent.env.INFERENCE_URL", "Missing INFERENCE_URL — agent must use the shell's guardrails endpoint")
    for key, value in env.items():
        # Kernel-cmdline keys must themselves be shell-safe; values go through
        # ``_encode_boot_value`` which only escapes spaces, so the same
        # restrictions apply.
        _check_boot_arg(result, f"agent.env.{key}", str(key), forbid_space=True)
        _check_boot_arg(result, f"agent.env.{key}", str(value))


def _check_boot_arg(
    result: ValidationResult,
    field_name: str,
    value: object,
    *,
    forbid_space: bool = False,
) -> None:
    """Reject manifest values that would malform the kernel cmdline.

    Called for every value that ``firecracker.build_vm_config`` folds
    into ``boot_args``. Only a conservative allowlist is accepted; a
    reject here is preferable to a silently-truncated or
    second-parameter-injecting boot arg at VM start.
    """
    if not isinstance(value, str):
        result.add_error(field_name, f"Must be a string, got {type(value).__name__}")
        return
    pattern = _BOOT_ARG_SAFE_RE
    if forbid_space and " " in value:
        result.add_error(field_name, "Env var name must not contain spaces")
        return
    if not pattern.fullmatch(value):
        result.add_error(
            field_name,
            f"Value contains characters not allowed on the kernel cmdline. "
            f"Allowed: {_BOOT_ARG_SAFE_DESCRIPTION}.",
        )


def _check_data_classification(manifest: dict, result: ValidationResult) -> None:
    dc = manifest.get("data_classification")
    if not dc:
        result.add_error("data_classification", "Missing required section 'data_classification'")
        return

    default = dc.get("default")
    if default not in VALID_DATA_CLASSIFICATIONS:
        result.add_error(
            "data_classification.default",
            f"Invalid classification '{default}'. Must be one of: {VALID_DATA_CLASSIFICATIONS}",
        )


def _check_filesystem(manifest: dict, result: ValidationResult) -> None:
    fs = manifest.get("filesystem")
    if not fs:
        result.add_error("filesystem", "Missing required section 'filesystem'")
        return

    rw = set(fs.get("read_write", []))
    if not rw:
        result.add_error("filesystem.read_write", "Must declare at least one read_write path")
    elif not REQUIRED_FILESYSTEM_PATHS.issubset(rw):
        result.add_error(
            "filesystem.read_write",
            f"Must include {REQUIRED_FILESYSTEM_PATHS}",
        )


def _check_network(manifest: dict, result: ValidationResult) -> None:
    """Validate the network section *including* the v1-only policy.

    M1: ``modules/isolation/network.validate_v1_network_rules`` used
    to live outside this function, raising ``NetworkPolicyError`` at
    runtime. Programmatic callers of ``validate_manifest`` would
    green-light a manifest that then failed inside
    ``run_manifest``. The v1 checks are folded in here so every
    caller sees a single authoritative answer.
    """
    # Deferred import keeps the validator callable in environments
    # where the isolation layer's dependencies aren't installed
    # (e.g. a minimal container running only the manifest linter).
    from modules.isolation.network import GUARDRAILS_PORT

    net = manifest.get("network")
    if not net:
        result.add_error("network", "Missing required section 'network'")
        return

    allow = net.get("allow", [])
    if not allow:
        result.add_error("network.allow", "Must declare at least one allowed endpoint (guardrails)")
        return

    for i, rule in enumerate(allow):
        if "host" not in rule:
            result.add_error(f"network.allow[{i}].host", "Missing 'host'")
        if "port" not in rule:
            result.add_error(f"network.allow[{i}].port", "Missing 'port'")
        if "purpose" not in rule:
            result.add_error(f"network.allow[{i}].purpose", "Missing 'purpose'")

    # v1 policy: exactly one rule, gateway:8088. Intentionally narrow;
    # the one-rule limit stops being v1 once routed egress lands in v0.9.
    if len(allow) != 1:
        result.add_error(
            "network.allow",
            f"v1 network policy permits exactly one rule (gateway:{GUARDRAILS_PORT}); "
            f"got {len(allow)}",
        )
        return

    rule = allow[0]
    if rule.get("host") != "gateway":
        result.add_error(
            "network.allow[0].host",
            f"v1 network policy requires host='gateway'; got {rule.get('host')!r}",
        )
    if rule.get("port") != GUARDRAILS_PORT:
        result.add_error(
            "network.allow[0].port",
            f"v1 network policy requires port={GUARDRAILS_PORT}; got {rule.get('port')!r}",
        )


def _check_resources(manifest: dict, result: ValidationResult) -> None:
    res = manifest.get("resources")
    if not res:
        result.add_error("resources", "Missing required section 'resources'")
        return

    vcpu = res.get("vcpu_count")
    if not isinstance(vcpu, int) or vcpu < 1:
        result.add_error("resources.vcpu_count", "Must be a positive integer")

    mem = res.get("mem_size_mib")
    if not isinstance(mem, int) or mem < 512:
        result.add_error("resources.mem_size_mib", "Must be at least 512 MiB")


def _check_pii(manifest: dict, result: ValidationResult) -> None:
    pii = manifest.get("pii")
    if not pii:
        result.add_error("pii", "Missing required section 'pii'")
        return

    entities = set(pii.get("entities", []))
    invalid = entities - VALID_PII_ENTITIES
    if invalid:
        result.add_error("pii.entities", f"Unrecognized PII entities: {invalid}")


def _check_audit(manifest: dict, result: ValidationResult) -> None:
    audit = manifest.get("audit")
    if not audit:
        result.add_error("audit", "Missing required section 'audit'")
        return

    days = audit.get("retention_days")
    if not isinstance(days, int) or days < 1:
        result.add_error("audit.retention_days", "Must be a positive integer")
