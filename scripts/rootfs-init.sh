#!/bin/sh
set -eu

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /run /tmp /audit_workspace
mountpoint -q /dev/pts || mount -t devpts devpts /dev/pts
mountpoint -q /run || mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mountpoint -q /tmp || mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp

hostname saaf-vm
ip link set lo up 2>/dev/null || true
ip link set eth0 up 2>/dev/null || true

CMDLINE="$(cat /proc/cmdline)"
SAAF_ENTRYPOINT=""
SAAF_WORKDIR="/"
SAAF_INIT_LOG="/audit_workspace/init.log"

log_init() {
    printf '%s\n' "$1" >> "${SAAF_INIT_LOG}" 2>/dev/null || true
}

decode_value() {
    printf '%b' "${1}"
}

for token in ${CMDLINE}; do
    case "${token}" in
        saaf.entrypoint=*)
            SAAF_ENTRYPOINT="$(decode_value "${token#saaf.entrypoint=}")"
            ;;
        saaf.workdir=*)
            SAAF_WORKDIR="$(decode_value "${token#saaf.workdir=}")"
            ;;
        saaf.env.*=*)
            key="${token#saaf.env.}"
            key="${key%%=*}"
            value="${token#*=}"
            export "${key}=$(decode_value "${value}")"
            ;;
    esac
done

cd "${SAAF_WORKDIR}" 2>/dev/null || cd /audit_workspace 2>/dev/null || cd /

log_init "SAAF_WORKDIR=${SAAF_WORKDIR}"
log_init "SAAF_ENTRYPOINT=${SAAF_ENTRYPOINT}"

printf 'SAAF_WORKDIR=%s\n' "${SAAF_WORKDIR}" >/dev/ttyS0 2>/dev/null || true
printf 'SAAF_ENTRYPOINT=%s\n' "${SAAF_ENTRYPOINT}" >/dev/ttyS0 2>/dev/null || true

if [ -n "${SAAF_ENTRYPOINT}" ]; then
    log_init "SAAF_EXEC=1"
    printf 'SAAF_EXEC=1\n' >/dev/ttyS0 2>/dev/null || true
    exec /bin/sh -lc "$SAAF_ENTRYPOINT"
fi

log_init "SAAF_EXEC=0"
printf 'SAAF_EXEC=0\n' >/dev/ttyS0 2>/dev/null || true
exec /bin/sh
