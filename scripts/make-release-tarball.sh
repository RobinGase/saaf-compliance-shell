#!/usr/bin/env bash
# make-release-tarball.sh — Produce a reproducible tarball of the shell repo
# suitable for shipping to a host for install under /opt/saaf/shell.
#
# Deterministic: sorted entries, fixed mtime, UID/GID stripped, gzip -n.
# Two identical runs on the same commit produce identical bytes.
#
# Usage:
#   scripts/make-release-tarball.sh [output.tar.gz]
#
# Default output is ./dist/saaf-compliance-shell-<short-sha>.tar.gz
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

if [ ! -d .git ]; then
    echo "FATAL: not a git checkout — need commit SHA and ls-files for reproducibility." >&2
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "WARN: working tree is dirty; tarball will include uncommitted state." >&2
fi

SHORT_SHA="$(git rev-parse --short HEAD)"
OUT="${1:-dist/saaf-compliance-shell-${SHORT_SHA}.tar.gz}"
mkdir -p "$(dirname "${OUT}")"

# Fixed mtime from the HEAD commit — makes the tarball reproducible across
# machines without depending on checkout time.
COMMIT_EPOCH="$(git log -1 --format=%ct)"

# git ls-files gives us exactly the tracked set; no .git, no venv, no caches,
# no __pycache__ — and it's sorted deterministically by git.
FILE_LIST="$(mktemp)"
trap 'rm -f "${FILE_LIST}"' EXIT
git ls-files -z | sort -z > "${FILE_LIST}"

TAR_FLAGS=(
    --null --files-from="${FILE_LIST}"
    --owner=0 --group=0 --numeric-owner
    --mtime="@${COMMIT_EPOCH}"
    --sort=name
    --format=ustar
    --transform="s,^,saaf-compliance-shell/,"
)

# gzip -n strips filename + mtime from the gzip header for reproducibility.
tar "${TAR_FLAGS[@]}" -cf - | gzip -n -9 > "${OUT}"

SIZE="$(stat -c %s "${OUT}" 2>/dev/null || stat -f %z "${OUT}")"
SHA="$(sha256sum "${OUT}" | awk '{print $1}')"

echo ""
echo "Release tarball: ${OUT}"
echo "  commit: $(git rev-parse HEAD)"
echo "  size:   ${SIZE} bytes"
echo "  sha256: ${SHA}"
