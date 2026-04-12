#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from modules.isolation.smoke import run_vm_probe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--overlay-dir", default="/tmp/.agentfs")
    parser.add_argument("--audit-log", default="/tmp/saaf-probe-audit.jsonl")
    parser.add_argument("--kernel", default="/opt/saaf/kernels/vmlinux")
    parser.add_argument("--rootfs", default="/opt/saaf/rootfs/ubuntu-24.04-python-base")
    parser.add_argument("--nfs-port", type=int, default=11111)
    args = parser.parse_args()

    result = run_vm_probe(
        manifest_path=args.manifest,
        overlay_dir=args.overlay_dir,
        audit_log_path=args.audit_log,
        kernel_path=args.kernel,
        rootfs_path=args.rootfs,
        nfs_port=args.nfs_port,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
