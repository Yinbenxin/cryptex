"""
Keyword PIR (anonymous query) over TCP, end to end on one machine.

    1. The server writes a database from a CSV (offline), then applies an
       incremental change: one update, one insert, one delete.
    2. The server listens; for each connection it answers one query.
    3. The client connects and looks up a batch of phone numbers; the hits
       are written to a CSV with the label columns split back out.

Run the two roles in separate processes the same way: the server keeps the
seed and the database directory, the client only needs the address.
"""

import csv
import os
import tempfile
import threading

from cryptex import Curve, PirClient, PirDatabase, PirServer, TcpChannel
from cryptex.pir import csv_metadata, generate_seed

TIMEOUT = 30


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        # ---- server, offline ----
        users = os.path.join(tmp, "users.csv")
        write_csv(users, [
            ["phone", "name", "city"],
            ["13800000001", "张三", "北京"],
            ["13800000002", "李四", "上海"],
            ["13800000003", "王五", "广州"],
        ])
        seed = generate_seed()  # keep it secret (KMS / HSM); needed to write and to serve
        db_dir = os.path.join(tmp, "users.pir")
        with PirDatabase.create(db_dir, seed, curve=Curve.SM2,
                                metadata=csv_metadata(users, key_column="phone")) as db:
            db.load(users, key_column="phone")
        # Incremental change: labels must use the same columns as the CSV.
        with PirDatabase(db_dir, seed) as db:
            db.upsert({"13800000002": "李四,深圳",   # update
                       "13800000004": "赵六,杭州"})  # insert
            db.delete(["13800000003"])
            info = db.commit()
            print(f"database: ~{info.records} records in {info.segments} segments")

        # ---- server, online: one query per connection ----
        server = PirServer(db_dir, seed, max_keywords=10_000)
        ready = threading.Event()
        port = {}

        def serve():
            def on_listening(p):
                port["p"] = p
                ready.set()
            with TcpChannel.listen("127.0.0.1", 0, timeout=TIMEOUT,
                                   on_listening=on_listening) as ch:
                server.serve(ch)

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        ready.wait(TIMEOUT)

        # ---- client ----
        queries = os.path.join(tmp, "phones.txt")
        with open(queries, "w", encoding="utf-8") as f:
            f.write("13800000001\n13800000002\n13800000003\n13800000004\n13900000000\n")
        result = os.path.join(tmp, "result.csv")
        with TcpChannel.connect("127.0.0.1", port["p"], timeout=TIMEOUT) as ch:
            hits = PirClient(ch, curve=Curve.SM2).query_file(queries, result)
        t.join(TIMEOUT)
        server.close()

        print(f"{hits} of 5 keywords found:")
        with open(result, encoding="utf-8") as f:
            print(f.read(), end="")


if __name__ == "__main__":
    main()
