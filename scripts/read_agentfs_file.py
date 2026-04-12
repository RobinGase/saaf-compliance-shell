#!/usr/bin/env python3
import sqlite3
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: read_agentfs_file.py <db-path> <file-name>")
        return 1

    db_path, file_name = sys.argv[1], sys.argv[2]
    con = sqlite3.connect(db_path)
    row = con.execute("select ino from fs_dentry where name = ?", (file_name,)).fetchone()
    if row is None:
        print("missing")
        return 1
    ino = row[0]
    chunks = con.execute("select data from fs_data where ino = ? order by chunk_index", (ino,)).fetchall()
    body = b"".join(chunk[0] for chunk in chunks)
    try:
        print(body.decode("utf-8", errors="replace"))
    except Exception:
        print(repr(body))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
