#!/usr/bin/env python3
import sqlite3
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: inspect_agentfs_db.py <db-path>")
        return 1

    db_path = Path(sys.argv[1])
    print(f"DB: {db_path}")
    print(f"Exists: {db_path.exists()}")
    wal_path = db_path.with_name(db_path.name + "-wal")
    print(f"WAL: {wal_path}")
    print(f"WAL exists: {wal_path.exists()}")

    con = sqlite3.connect(str(db_path))
    tables = [row[0] for row in con.execute("select name from sqlite_master where type='table' order by name")]
    print("Tables:", tables)
    for table in tables:
        print(f"=== {table} ===")
        try:
            cols = con.execute(f"pragma table_info({table})").fetchall()
            print("Columns:", cols)
            rows = con.execute(f"select * from {table} limit 10").fetchall()
            print("Rows:", rows)
        except Exception as exc:
            print("ERR:", repr(exc))

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
