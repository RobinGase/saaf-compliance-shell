#!/usr/bin/env bash
# verify-release.sh — cosign-keyless verify a saaf-compliance-shell
# release tarball against the Sigstore Rekor transparency log.
#
# The .github/workflows/release.yml pipeline signs each tarball with
# cosign's keyless flow, binding the signature to the GitHub OIDC
# identity of the workflow run (repo + ref + job). This script walks
# that chain: it pulls .sig + .crt next to the tarball, runs
# ``cosign verify-blob`` with the expected OIDC issuer and identity
# regex pinned to this repo + tag, and reports pass/fail.
#
# Usage:
#   scripts/verify-release.sh <tarball> [--tag <tag>] [--repo <slug>]
#
#   <tarball>   path to the release tarball (.sig + .crt must live beside it)
#   --tag       git tag the release was cut from (default: infer from filename)
#   --repo      GitHub owner/repo slug (default: RobinGase/saaf-compliance-shell)
#
# Exits 0 on successful verification, non-zero otherwise.

set -euo pipefail

REPO_DEFAULT="RobinGase/saaf-compliance-shell"
ISSUER="https://token.actions.githubusercontent.com"

if [ $# -lt 1 ]; then
    echo "usage: $0 <tarball> [--tag <tag>] [--repo <slug>]" >&2
    exit 64
fi

TARBALL="$1"; shift
TAG=""
REPO="${REPO_DEFAULT}"

while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2;;
        --repo) REPO="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 64;;
    esac
done

if [ ! -f "${TARBALL}" ]; then
    echo "FATAL: tarball not found: ${TARBALL}" >&2
    exit 2
fi

SIG="${TARBALL}.sig"
CRT="${TARBALL}.crt"

for f in "${SIG}" "${CRT}"; do
    if [ ! -f "${f}" ]; then
        echo "FATAL: missing signature material: ${f}" >&2
        echo "       Download .sig and .crt from the GitHub release next to the tarball." >&2
        exit 2
    fi
done

if ! command -v cosign >/dev/null 2>&1; then
    echo "FATAL: cosign not installed. See https://docs.sigstore.dev/cosign/system_config/installation/" >&2
    exit 3
fi

# Identity regex matches the workflow's OIDC subject:
#   https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>
# When --tag is not set we allow any tag on this repo's release workflow,
# which is useful for ad-hoc verification; pass --tag to pin a specific
# release when verifying in production.
if [ -n "${TAG}" ]; then
    IDENTITY="^https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}$"
else
    IDENTITY="^https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v.*$"
fi

echo "Verifying ${TARBALL}"
echo "  repo:     ${REPO}"
echo "  tag:      ${TAG:-<any release tag>}"
echo "  issuer:   ${ISSUER}"

COSIGN_EXPERIMENTAL=1 cosign verify-blob \
    --certificate "${CRT}" \
    --signature "${SIG}" \
    --certificate-identity-regexp "${IDENTITY}" \
    --certificate-oidc-issuer "${ISSUER}" \
    "${TARBALL}"

SHA="$(sha256sum "${TARBALL}" | awk '{print $1}')"
echo ""
echo "OK — signature verified via Rekor transparency log."
echo "Tarball sha256: ${SHA}"
