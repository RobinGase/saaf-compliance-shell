"""saaf-manifest.yaml schema validator.

Validates target repo manifests against the required schema before
the shell accepts them. Used by `saaf-shell validate` and at boot time.
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_DATA_CLASSIFICATIONS = {"sensitive", "test"}
VALID_PII_ENTITIES = {"PERSON", "EMAIL_ADDRESS", "BSN_NL"}
REQUIRED_FILESYSTEM_PATHS = {"/audit_workspace"}


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


def _check_agent(manifest: dict, result: ValidationResult) -> None:
    agent = manifest.get("agent")
    if not agent:
        result.add_error("agent", "Missing required section 'agent'")
        return

    if "entrypoint" not in agent:
        result.add_error("agent.entrypoint", "Missing required field 'agent.entrypoint'")

    if "working_directory" not in agent:
        result.add_error("agent.working_directory", "Missing 'agent.working_directory' — should be /audit_workspace")

    env = agent.get("env", {})
    if "INFERENCE_URL" not in env:
        result.add_error("agent.env.INFERENCE_URL", "Missing INFERENCE_URL — agent must use the shell's guardrails endpoint")


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
