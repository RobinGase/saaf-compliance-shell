#!/usr/bin/env python3
import sqlite3
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: query_agentfs_dentry.py <db-path> <pattern> [<pattern> ...]")
        return 1

    db_path = sys.argv[1]
    patterns = sys.argv[2:]
    con = sqlite3.connect(db_path)

    clauses = " or ".join(["name like ?" for _ in patterns])
    query = f"select ino,name,parent_ino from fs_dentry where {clauses} order by parent_ino,name"
    rows = con.execute(query, [f"%{pattern}%" for pattern in patterns]).fetchall()
    print(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
