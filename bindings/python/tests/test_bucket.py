"""
Bucketed PSI: bucket assignment, bucketed runs and configuration checks.
"""

import hashlib
import os
import random
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from cryptex import (
    DEFAULT_BUCKET_SIZE, MAX_BUCKETS, BucketHash, CryptexError, Curve, MemoryChannel, Pool, Protocol, Psi,
    PsiParty, Role, bucket_of,
)

TIMEOUT = 60
DST = b"CRYPTEX-PSI-BUCKET-V1"

# Independent SM3 for cross-checking (also used for the SM2 h2c vectors).
# Reference implementations live in the repo; CRYPTEX_VECTORS overrides the
# location when the tests run outside the source tree (CI wheel test).
sys.path.insert(0, os.environ.get("CRYPTEX_VECTORS")
                or str(Path(__file__).resolve().parents[3] / "core" / "tests" / "vectors"))
import contextlib, io  # noqa: E401,E402
with contextlib.redirect_stdout(io.StringIO()):
    from sm2_hash_to_curve import sm3 as ref_sm3  # noqa: E402


def ref_bucket(item, buckets, h):
    digest = hashlib.sha256(DST + item).digest() if h == BucketHash.SHA256 else ref_sm3(DST + item)
    return int.from_bytes(digest[:8], "big") % buckets


def run_pair(rx, sx, receiver_kw=None, sender_kw=None, protocol=Protocol.ECDH):
    """Receiver in this thread, sender in another; returns (result, sender error)"""
    ra, sa = MemoryChannel.pair()
    err = {}

    def sender():
        try:
            with Psi(protocol, Role.SENDER, sa, **(sender_kw or {})) as psi:
                psi.run(sx)
        except BaseException as e:
            err["e"] = e

    t = threading.Thread(target=sender, daemon=True)
    t.start()
    try:
        with Psi(protocol, Role.RECEIVER, ra, **(receiver_kw or {})) as psi:
            result = psi.run(rx)
    except BaseException as e:
        err["r"] = e
        result = None
        ra.send(b"")  # unblock the sender if it waits for us
    t.join(TIMEOUT)
    return result, err


class BucketOfTest(unittest.TestCase):
    def test_matches_independent_reference(self):
        items = ["", "alice", "13800000001", "张三", b"\x00\xff"]
        for h in BucketHash:
            for buckets in (1, 2, 7, 1000, MAX_BUCKETS):
                expected = [ref_bucket(x.encode() if isinstance(x, str) else x, buckets, h)
                            for x in items]
                self.assertEqual(bucket_of(items, buckets, h), expected, (h, buckets))

    def test_pinned_values(self):
        # Same values are pinned in core/src/algorithms/psi/bucket.rs.
        items = ["", "alice", "13800000001", "张三"]
        self.assertEqual(bucket_of(items, 1000, BucketHash.SHA256), [932, 606, 640, 771])
        self.assertEqual(bucket_of(items, 1000, BucketHash.SM3), [180, 596, 763, 861])

    def test_pool_and_empty_input(self):
        with Pool(3) as pool:
            self.assertEqual(bucket_of(["a", "b"], 4, pool=pool), bucket_of(["a", "b"], 4))
        self.assertEqual(bucket_of([], 4), [])

    def test_validation(self):
        for bad in (0, MAX_BUCKETS + 1, -1):
            with self.assertRaises(ValueError):
                bucket_of(["a"], bad)
        for bad in (2.0, "4", True):
            with self.assertRaises(TypeError):
                bucket_of(["a"], bad)
        with self.assertRaises(ValueError):
            bucket_of(["a"], 4, hash=9)


class AgreeBucketsTest(unittest.TestCase):
    def test_rule(self):
        from cryptex.psi import agree_buckets
        self.assertEqual(agree_buckets(10, 20, 0, 0), 1)
        self.assertEqual(agree_buckets(1_000_000, 900_000, 100_000, 100_000), 10)
        self.assertEqual(agree_buckets(1_000_001, 0, 100_000, 100_000), 11)
        # The smaller bucket size wins, the larger set decides.
        self.assertEqual(agree_buckets(500, 2000, 100, 1000), 20)
        self.assertEqual(agree_buckets(0, 0, 100, 100), 1)
        self.assertEqual(agree_buckets(10**12, 1, 1, 1), MAX_BUCKETS)
        with self.assertRaises(ValueError):
            agree_buckets(10, 10, 5, 0)


class BucketedPsiTest(unittest.TestCase):
    def test_same_result_as_unbucketed(self):
        rng = random.Random(7)
        rx = [f"id-{i}" for i in rng.sample(range(5000), 1500)]
        sx = [f"id-{i}" for i in rng.sample(range(5000), 2000)]
        expected = [x for x in rx if x in set(sx)]
        for size in (100_000, 1000, 64, 1):
            for h in BucketHash:
                with self.subTest(bucket_size=size, hash=h.name):
                    kw = {"bucket_size": size, "bucket_hash": h, "threads": 2}
                    got, err = run_pair(rx, sx, kw, kw)
                    self.assertEqual(err, {})
                    self.assertEqual(got, expected)  # receiver's input order

    def test_bucket_count_from_sizes(self):
        """ceil(max(n) / min(bucket_size)): 2000 / 100 = 20 buckets"""
        calls = []
        rx = [f"{i}" for i in range(500)]
        sx = [f"{i}" for i in range(2000)]
        got, err = run_pair(rx, sx, {"bucket_size": 1000, "on_bucket": lambda *a: calls.append(a)},
                            {"bucket_size": 100})
        self.assertEqual(err, {})
        self.assertEqual(got, rx)
        self.assertEqual({c[1] for c in calls}, {20})
        self.assertEqual(len(calls), 20)
        self.assertEqual(sum(c[2] for c in calls), 500)

    def test_vole_bucketed(self):
        rx = [f"id-{i}" for i in range(3000)]
        sx = [f"id-{i}" for i in range(1500, 4500)]
        kw = {"bucket_size": 500}
        got, err = run_pair(rx, sx, kw, kw, protocol=Protocol.VOLE)
        self.assertEqual(err, {})
        self.assertEqual(got, rx[1500:])

    def test_every_curve(self):
        for curve in Curve:
            with self.subTest(curve=curve.name):
                kw = {"bucket_size": 2, "curve": curve}
                got, err = run_pair(["a", "b", "c", "d"], ["d", "x", "b"], kw, kw)
                self.assertEqual(err, {})
                self.assertEqual(got, ["b", "d"])

    def test_duplicates_and_empty_sets(self):
        kw = {"bucket_size": 3}
        got, err = run_pair(["a", "b", "a", b"b", "c"], ["b", "b"], kw, kw)
        self.assertEqual(err, {})
        self.assertEqual(got, ["b"])  # first occurrence kept
        self.assertEqual(run_pair([], ["b"], kw, kw), ([], {}))
        self.assertEqual(run_pair(["a"], [], kw, kw), ([], {}))

    def test_generator_input(self):
        kw = {"bucket_size": 10}
        got, err = run_pair((f"{i}" for i in range(50)), [f"{i}" for i in range(25, 75)], kw, kw)
        self.assertEqual(err, {})
        self.assertEqual(got, [f"{i}" for i in range(25, 50)])

    def test_files_streamed_through_disk(self):
        with tempfile.TemporaryDirectory() as d:
            rx, sx = os.path.join(d, "rx.csv"), os.path.join(d, "sx.txt")
            out, work = os.path.join(d, "out.txt"), os.path.join(d, "work")
            os.mkdir(work)
            with open(rx, "w", encoding="gbk") as f:
                f.write("姓名,手机号\n" + "".join(f"用户{i},138{i:08d}\n" for i in range(3000)))
                f.write("重复,13800000007\n")  # duplicate of row 7
            with open(sx, "w", encoding="utf-8") as f:
                f.write("".join(f" 138{i:08d} \n" for i in range(1500, 4500)))
                f.write("\n\n13800000007\n")
            seen_files = []

            def peek(*_):
                seen_files.extend(os.listdir(work))

            ra, sa = MemoryChannel.pair()
            t = threading.Thread(target=lambda: Psi(
                Protocol.ECDH, Role.SENDER, sa, curve=Curve.SM2, bucket_size=200,
                bucket_hash=BucketHash.SM3, work_dir=work).run(sx))
            t.start()
            count = Psi(Protocol.ECDH, Role.RECEIVER, ra, curve=Curve.SM2, bucket_size=200,
                        bucket_hash=BucketHash.SM3, work_dir=work, on_bucket=peek).run(
                rx, column="手机号", encoding="gbk", output=out)
            t.join(TIMEOUT)
            expected = ["13800000007"] + [f"138{i:08d}" for i in range(1500, 3000)]
            with open(out, encoding="utf-8") as f:
                got = f.read().splitlines()
            self.assertEqual(count, len(expected))
            self.assertEqual(got, sorted(expected, key=lambda x: int(x)))
            # Bucket files existed during the run and are all gone afterwards.
            self.assertTrue(any(name.startswith("cryptex-psi-") for name in seen_files))
            self.assertEqual(os.listdir(work), [])

    def test_text_file_read_by_core_matches_python(self):
        """A UTF-8 text file is partitioned by the core library; the result
        must equal reading the same file in Python (same stripping, line
        endings, BOM and dedupe)"""
        raw = ("﻿ a \r\nb\rc\n\n \t\n\x1cd\x1f\n　e　\n﻿f\n张三\n"
               "b\n" + "".join(f"{i}\n" for i in range(300)) + "last")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "in.txt")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(raw)
            for encoding in ("utf-8-sig", "UTF8"):
                from cryptex import _data
                expected = _data.load_items(path, encoding=encoding)
                for protocol in Protocol:
                    for out in (None, os.path.join(d, "out.txt")):
                        ra, sa = MemoryChannel.pair()
                        t = threading.Thread(target=lambda: Psi(
                            protocol, Role.SENDER, sa, bucket_size=40).run(expected))
                        t.start()
                        got = Psi(protocol, Role.RECEIVER, ra, bucket_size=40).run(
                            path, encoding=encoding, output=out)
                        t.join(TIMEOUT)
                        if out is not None:
                            self.assertEqual(got, len(expected))
                            with open(out, encoding="utf-8") as f:
                                got = f.read().split("\n")[:-1]
                        self.assertEqual(got, expected, (encoding, protocol, out))

    def test_input_changed_during_run_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "in.txt")
            with open(path, "w") as f:
                f.write("".join(f"{i}\n" for i in range(100)))

            def shrink(b, buckets, size):
                if b == buckets - 1:
                    with open(path, "w") as f:
                        f.write("1\n")

            for out in (None, os.path.join(d, "out.txt")):
                ra, sa = MemoryChannel.pair()
                t = threading.Thread(target=lambda: Psi(
                    Protocol.ECDH, Role.SENDER, sa, bucket_size=30).run(["1", "2"]))
                t.start()
                with self.assertRaises((RuntimeError, CryptexError)) as ctx:
                    Psi(Protocol.ECDH, Role.RECEIVER, ra, bucket_size=30,
                        on_bucket=shrink).run(path, output=out)
                t.join(TIMEOUT)
                self.assertIn("input changed", str(ctx.exception))
                with open(path, "w") as f:
                    f.write("".join(f"{i}\n" for i in range(100)))

    def test_invalid_utf8_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "in.txt")
            with open(path, "wb") as f:
                f.write(b"ok\n\xff\n")
            # Only the handshake is needed from the peer: a sender header
            # announcing enough items for several buckets.
            from cryptex import psi as m
            ra, sa = MemoryChannel.pair()
            sa.send(m._HEADER.pack(m._MAGIC, m._VERSION, Protocol.ECDH, Role.SENDER, 0, 0, 0, 1, 10))
            with self.assertRaises(CryptexError) as ctx:
                Psi(Protocol.ECDH, Role.RECEIVER, ra, bucket_size=1).run(path)
            self.assertIn("UTF-8", str(ctx.exception))

    def test_progress_callback(self):
        calls = []
        kw_r = {"bucket_size": 25, "on_bucket": lambda *a: calls.append(a)}
        got, err = run_pair([f"{i}" for i in range(100)], ["5"], kw_r, {"bucket_size": 25})
        self.assertEqual(err, {})
        self.assertEqual(got, ["5"])
        self.assertEqual([c[:2] for c in calls], [(i, 4) for i in range(4)])
        self.assertEqual(sum(c[2] for c in calls), 100)

    def test_reuse_instance(self):
        ra, sa = MemoryChannel.pair()

        def sender():
            with Psi(Protocol.ECDH, Role.SENDER, sa, bucket_size=1) as psi:
                psi.run(["a", "b"])
                psi.run(["c"])

        t = threading.Thread(target=sender)
        t.start()
        with Psi(Protocol.ECDH, Role.RECEIVER, ra, bucket_size=1) as psi:
            self.assertEqual(psi.run(["b", "c"]), ["b"])
            self.assertEqual(psi.run(["b", "c"]), ["c"])
        t.join(TIMEOUT)

    def test_one_side_bucketing_rejected(self):
        got, err = run_pair(["a"], ["a"], {"bucket_size": 4}, {"bucket_size": None})
        self.assertIn("bucketing", str(err.get("r")))
        self.assertIn("bucketing", str(err.get("e")))

    def test_bucket_hash_mismatch_rejected(self):
        got, err = run_pair(["a", "b"], ["a"], {"bucket_size": 1, "bucket_hash": BucketHash.SM3},
                            {"bucket_size": 1})
        self.assertIn("bucket hash mismatch", str(err.get("r")))

    def test_bucket_hash_ignored_with_one_bucket(self):
        got, err = run_pair(["a"], ["a"], {"bucket_size": 10, "bucket_hash": BucketHash.SM3},
                            {"bucket_size": 10})
        self.assertEqual((got, err), (["a"], {}))

    def test_temp_files_removed_on_error(self):
        with tempfile.TemporaryDirectory() as work:
            ra, sa = MemoryChannel.pair()
            # A valid header, then garbage instead of the first PSI message.
            from cryptex import psi as m
            sa.send(m._HEADER.pack(m._MAGIC, m._VERSION, Protocol.ECDH, Role.SENDER, 0, 0, 0, 1, 10))
            sa.send(b"garbage")
            with self.assertRaises(CryptexError):
                Psi(Protocol.ECDH, Role.RECEIVER, ra, bucket_size=1, work_dir=work).run(
                    [f"{i}" for i in range(10)])
            self.assertEqual(os.listdir(work), [])

    def test_default_is_bucketed(self):
        ch = MemoryChannel.pair()[0]
        self.assertEqual(Psi(Protocol.ECDH, Role.SENDER, ch).bucket_size, DEFAULT_BUCKET_SIZE)
        self.assertEqual(DEFAULT_BUCKET_SIZE, 1_000_000)
        # Without a handshake the bucket count cannot be agreed on.
        self.assertIsNone(Psi(Protocol.ECDH, Role.SENDER, ch, handshake=False).bucket_size)
        self.assertIsNone(Psi(Protocol.ECDH, Role.SENDER, ch, bucket_size=None).bucket_size)

    def test_single_bucket_writes_no_files(self):
        """Sets below bucket_size run in memory, without temporary files"""
        with tempfile.TemporaryDirectory() as work:
            seen = []
            kw = {"work_dir": work, "on_bucket": lambda *a: seen.extend(os.listdir(work))}
            for protocol in Protocol:
                got, err = run_pair(["a", "b", "c"], ["b", "x"], kw, {"work_dir": work},
                                    protocol=protocol)
                self.assertEqual((got, err), (["b"], {}))
            self.assertEqual(seen, [])
            self.assertEqual(os.listdir(work), [])

    def test_default_bucketing_splits_large_sets(self):
        """Both sides on the default size agree on the same bucket count"""
        calls = []
        rx = [f"{i}" for i in range(2500)]
        kw_r = {"bucket_size": 1000, "on_bucket": lambda *a: calls.append(a)}
        got, err = run_pair(rx, rx[1000:], kw_r, {"bucket_size": 1000})
        self.assertEqual((got, err), (rx[1000:], {}))
        self.assertEqual({c[1] for c in calls}, {3})

    def test_constructor_validation(self):
        ch = MemoryChannel.pair()[0]
        for bad in (0, -1, 1 << 32):
            with self.assertRaises(ValueError):
                Psi(Protocol.ECDH, Role.SENDER, ch, bucket_size=bad)
        for bad in ("8", 1.5, True):
            with self.assertRaises(TypeError):
                Psi(Protocol.ECDH, Role.SENDER, ch, bucket_size=bad)
        with self.assertRaises(ValueError):
            Psi(Protocol.ECDH, Role.SENDER, ch, bucket_size=10, handshake=False)
        with self.assertRaises(ValueError):
            Psi(Protocol.ECDH, Role.SENDER, ch, bucket_hash=7)
        with self.assertRaises(ValueError):
            Psi(Protocol.ECDH, Role.SENDER, ch, work_dir="/no/such/dir")
        with self.assertRaises(TypeError):
            Psi(Protocol.ECDH, Role.SENDER, ch, on_bucket=5)

    def test_bucket_log(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.log")
            kw = {"bucket_size": 1, "log_file": path, "log_level": "DEBUG"}
            got, err = run_pair(["a", "b", "c"], ["a"], kw, {"bucket_size": 1})
            self.assertEqual(err, {})
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertIn("bucket_size=1", text)
            self.assertIn("3 buckets", text)
            self.assertIn("partitioned 3 values", text)
            self.assertIn("bucket 3/3", text)
            self.assertNotIn("'a'", text)


class EstimateTest(unittest.TestCase):
    def test_estimate_items(self):
        from cryptex._data import estimate_items
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            with open(p, "w") as f:
                f.write("a\nb\nc")
            self.assertEqual(estimate_items(p), 3)
            with open(p, "w") as f:
                f.write("id\n" + "x\n" * 9)
            self.assertEqual(estimate_items(p, has_header=True, column="id"), 9)
            open(p, "w").close()
            self.assertEqual(estimate_items(p), 0)
            with open(p, "w") as f:
                f.write("".join(f"{i:010d}\n" for i in range(1_000_000)))  # 11 MB
            self.assertAlmostEqual(estimate_items(p), 1_000_000, delta=10_000)


class PartyLevelTest(unittest.TestCase):
    def test_sessions_must_match(self):
        """PsiParty takes the job's bucket count to size its outputs"""
        with self.assertRaises(ValueError):
            PsiParty(Protocol.ECDH, Role.SENDER, [], sessions=0)
        with self.assertRaises(ValueError):
            PsiParty(Protocol.ECDH, Role.SENDER, [], threads=2, pool=Pool(2))


if __name__ == "__main__":
    unittest.main()
