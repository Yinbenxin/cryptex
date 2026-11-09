"""
Keyword PIR through the Python binding.
"""

import csv
import os
import tempfile
import threading
import unittest

from cryptex import (
    CryptexError, Curve, MemoryChannel, Padding, PirClient, PirDatabase, PirServer,
)
from cryptex.pir import csv_metadata, generate_seed

TIMEOUT = 60
SEED = bytes(range(32))


def serve_once(server, channel, err):
    try:
        server.serve(channel)
    except BaseException as e:
        err["s"] = e


def query(server, keywords, **kw):
    """Client here, server in a thread; returns (labels, server error)"""
    ca, sa = MemoryChannel.pair()
    err = {}
    t = threading.Thread(target=serve_once, args=(server, sa, err), daemon=True)
    t.start()
    try:
        return PirClient(ca, **kw).query(keywords), err
    except BaseException:
        ca.send(b"")  # unblock a server still waiting for the client
        raise
    finally:
        t.join(TIMEOUT)
        assert not t.is_alive(), "server thread hung"


class PirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_all_curves(self):
        data = {f"id{i}": f"label-{i}" * (i % 4) for i in range(300)}
        for curve in Curve:
            db_dir = os.path.join(self.tmp.name, curve.name)
            with PirDatabase.create(db_dir, SEED, curve=curve) as db:
                self.assertEqual(db.upsert(data), 300)
                self.assertEqual(db.pending, 300)
                info = db.commit()
            self.assertEqual((info.records, info.segments, info.curve), (300, 1, curve))
            with PirServer(db_dir, SEED, bucket_size=16) as server:
                p = server.params
                self.assertEqual((p.buckets, p.records), (32, 300))
                out, err = query(server, ["id7", "nope", "id299", "id7", b"id1", "id0"])
            self.assertFalse(err)
            self.assertEqual(out, [b"label-7" * 3, None, b"label-299" * 3, b"label-7" * 3,
                                   b"label-1", b""])

    def test_append_update_delete(self):
        with PirDatabase.create(self.db, SEED, curve=Curve.SM2) as db:
            db.upsert({"a": "1", "b": "2", "c": "3"})
            db.commit()
            with PirServer(self.db, SEED) as server:
                db.upsert([("d", "4"), ("b", "two, but much longer than before")])
                db.delete(["a", "missing"])
                db.commit()
                # The running server keeps its snapshot until reload().
                self.assertEqual(query(server, ["a", "b", "d"])[0], [b"1", b"2", None])
                self.assertTrue(server.reload())
                self.assertFalse(server.reload())
                self.assertEqual(query(server, ["a", "b", "d"])[0],
                                 [None, b"two, but much longer than before", b"4"])
                db.upsert({"e": "5"})
                db.rollback()
                self.assertEqual(db.pending, 0)
                info = db.compact()
                self.assertEqual((info.records, info.segments), (3, 1))
                server.reload()
                self.assertEqual(query(server, ["b", "c", "d", "e"])[0],
                                 [b"two, but much longer than before", b"3", b"4", None])
        # Reopen for writing with the same seed.
        with PirDatabase(self.db, SEED) as db:
            self.assertEqual(db.info.records, 3)

    def test_csv_round_trip(self):
        src = os.path.join(self.tmp.name, "in.csv")
        with open(src, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["name", "phone", "city"])
            w.writerow(["张三", "13800000001", "北京, 朝阳"])
            w.writerow(["李四", "13800000002", "上海"])
        meta = csv_metadata(src, key_column="phone")
        with PirDatabase.create(self.db, SEED, curve=Curve.SM2, metadata=meta) as db:
            self.assertEqual(db.load(src, key_column="phone"), 2)
            self.assertEqual(db.info.columns, ["name", "city"])
        q = os.path.join(self.tmp.name, "q.txt")
        with open(q, "w", encoding="utf-8") as f:
            f.write("13800000002\n13900000000\n13800000001\n")
        out = os.path.join(self.tmp.name, "out.csv")
        ca, sa = MemoryChannel.pair()
        err = {}
        with PirServer(self.db, SEED) as server:
            t = threading.Thread(target=serve_once, args=(server, sa, err), daemon=True)
            t.start()
            hits = PirClient(ca).query_file(q, out)
            t.join(TIMEOUT)
        self.assertFalse(err)
        self.assertEqual(hits, 2)
        with open(out, encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        self.assertEqual(rows, [["key", "name", "city"],
                                ["13800000002", "李四", "上海"],
                                ["13800000001", "张三", "北京, 朝阳"]])

    def test_padding(self):
        with PirDatabase.create(self.db, SEED) as db:
            db.upsert({"a": "x", "b": "y" * 5000})
            db.commit()
        for padding, lo, hi in [(Padding.MAX, 10_000, 11_000), (Padding.NONE, 5_000, 6_000)]:
            ca, sa = MemoryChannel.pair()
            sizes = []
            send = sa.send
            sa.send = lambda m: (sizes.append(len(m)), send(m))
            err = {}
            with PirServer(self.db, SEED, padding=padding) as server:
                t = threading.Thread(target=serve_once, args=(server, sa, err), daemon=True)
                t.start()
                self.assertEqual(PirClient(ca).query(["a"]), [b"x"])
                t.join(TIMEOUT)
            self.assertFalse(err)
            self.assertTrue(lo < sizes[-1] < hi, (padding, sizes))

    def test_errors(self):
        with PirDatabase.create(self.db, SEED) as db:
            db.upsert({"a": "1", "b": "2"})
            db.commit()
            with self.assertRaises(CryptexError):
                PirDatabase(self.db, SEED)  # one writer at a time
            # No label size cap beyond the 32-bit length field.
            db.upsert({"big": b"z" * (3 << 20)})
            db.commit()
        with PirServer(self.db, SEED) as server:
            self.assertEqual(query(server, ["big"])[0], [b"z" * (3 << 20)])
        with self.assertRaises(CryptexError):
            PirServer(self.db, generate_seed())
        with self.assertRaises(CryptexError):
            PirDatabase.create(self.db, SEED)  # not empty
        with self.assertRaises(ValueError):
            PirDatabase.create(os.path.join(self.tmp.name, "x"), b"short")
        with self.assertRaises(ValueError):
            PirServer(self.db, SEED, bucket_size=0)

    def test_limits_and_curve_check(self):
        with PirDatabase.create(self.db, SEED, curve=Curve.P256) as db:
            db.upsert({"a": "1", "b": "2"})
            db.commit()
        with PirServer(self.db, SEED, max_keywords=1) as server:
            with self.assertRaises(ConnectionError):
                query(server, ["a", "b"])
            out, err = query(server, ["a", "a"])  # one distinct keyword
            self.assertEqual(out, [b"1", b"1"])
            with self.assertRaises(ValueError):
                query(server, ["a"], curve=Curve.SM2)

    def test_concurrent_serving(self):
        with PirDatabase.create(self.db, SEED) as db:
            db.upsert({str(i): str(i * i) for i in range(1000)})
            db.commit()
        results = {}
        with PirServer(self.db, SEED, bucket_size=50) as server:
            def one(i):
                results[i] = query(server, [str(i), str(i + 1)])[0]
            ts = [threading.Thread(target=one, args=(i,)) for i in range(8)]
            for t in ts:
                t.start()
            for t in ts:
                t.join(TIMEOUT)
        for i in range(8):
            self.assertEqual(results[i], [str(i * i).encode(), str((i + 1) ** 2).encode()])


if __name__ == "__main__":
    unittest.main()
