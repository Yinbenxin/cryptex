"""
Psi constructor options: thread count and logging.
"""

import logging
import os
import tempfile
import threading
import unittest

from cryptex import MAX_THREADS, Curve, MemoryChannel, Protocol, Psi, PsiParty, Role

TIMEOUT = 30


def pair_run(receiver_kw, sender_kw, rx, sx):
    """Run receiver in this thread, sender in another; return receiver result"""
    ra, sa = MemoryChannel.pair()
    err = {}

    def sender():
        try:
            with Psi(Protocol.ECDH, Role.SENDER, sa, **sender_kw) as psi:
                psi.run(sx)
        except BaseException as e:  # surfaced below
            err["e"] = e

    t = threading.Thread(target=sender, daemon=True)
    t.start()
    with Psi(Protocol.ECDH, Role.RECEIVER, ra, **receiver_kw) as psi:
        result = psi.run(rx)
    t.join(TIMEOUT)
    if "e" in err:
        raise err["e"]
    return result


class ThreadsTest(unittest.TestCase):
    def test_validation(self):
        ch = MemoryChannel.pair()[0]
        for bad in (-1, MAX_THREADS + 1):
            with self.assertRaises(ValueError):
                Psi(Protocol.ECDH, Role.SENDER, ch, threads=bad)
        for bad in (1.5, "4", True, None):
            with self.assertRaises(TypeError):
                Psi(Protocol.ECDH, Role.SENDER, ch, threads=bad)
        with self.assertRaises(ValueError):
            PsiParty(Protocol.ECDH, Role.SENDER, [], threads=-1)
        Psi(Protocol.ECDH, Role.SENDER, ch, threads=MAX_THREADS)

    def test_results_independent_of_thread_count(self):
        rx = [f"id-{i}" for i in range(500)]
        sx = [f"id-{i}" for i in range(250, 900)]
        for threads in (0, 1, 2, 7):
            with self.subTest(threads=threads):
                got = pair_run({"threads": threads}, {"threads": threads}, rx, sx)
                self.assertEqual(got, rx[250:])

    def test_parties_may_use_different_thread_counts(self):
        got = pair_run({"threads": 1}, {"threads": 4, "curve": Curve.RISTRETTO255},
                       ["a", "b"], ["b"])
        self.assertEqual(got, ["b"])

    def test_concurrent_sessions(self):
        """Several Psi sessions at once, each on its own pool"""
        results = {}

        def job(k):
            rx = [f"{k}-{i}" for i in range(100)]
            sx = [f"{k}-{i}" for i in range(50, 150)]
            results[k] = pair_run({"threads": 2, "curve": Curve.SM2},
                                  {"threads": 2, "curve": Curve.SM2}, rx, sx)

        threads = [threading.Thread(target=job, args=(k,)) for k in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(TIMEOUT)
        self.assertEqual(sorted(results), list(range(6)))
        for k, got in results.items():
            self.assertEqual(got, [f"{k}-{i}" for i in range(50, 100)])


class LoggingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, name):
        with open(os.path.join(self.tmp.name, name), encoding="utf-8") as f:
            return f.read()

    def test_log_file_per_instance(self):
        rlog = os.path.join(self.tmp.name, "receiver.log")
        slog = os.path.join(self.tmp.name, "sender.log")
        pair_run({"log_file": rlog, "threads": 2}, {"log_file": slog},
                 ["secret-a", "secret-b"], ["secret-b"])
        r, s = self.read("receiver.log"), self.read("sender.log")

        self.assertIn("run 1: start ECDH-PSI as RECEIVER", r)
        self.assertIn("threads=2", r)
        self.assertIn("intersection size 1", r)
        self.assertIn("run 1: start ECDH-PSI as SENDER", s)
        self.assertIn("threads=auto", s)
        self.assertNotIn("RECEIVER", s)  # files are not mixed
        # Default level for a log file is INFO: no per-message details.
        self.assertNotIn("bytes", r)
        # Never log the data itself.
        for text in (r, s):
            self.assertNotIn("secret", text)

    def test_debug_level_and_appending(self):
        path = os.path.join(self.tmp.name, "psi.log")
        pair_run({"log_file": path, "log_level": "DEBUG"}, {}, ["a"], ["a"])
        pair_run({"log_file": path, "log_level": logging.DEBUG}, {}, ["a"], ["a"])
        text = self.read("psi.log")
        self.assertEqual(text.count("start ECDH-PSI"), 2)  # appended, not truncated
        self.assertIn("handshake ok", text)
        self.assertIn("sent ", text)
        self.assertIn("received ", text)
        self.assertIn("step computed in", text)

    def test_vole_debug_log_shows_both_directions(self):
        """The VOLE driver logs received messages and loaded buckets, and the
        party without a result reports the whole job"""
        rlog = os.path.join(self.tmp.name, "r.log")
        slog = os.path.join(self.tmp.name, "s.log")
        ra, sa = MemoryChannel.pair()
        kw = {"log_level": "DEBUG", "bucket_size": 50}
        t = threading.Thread(target=lambda: Psi(
            Protocol.VOLE, Role.SENDER, sa, log_file=slog, **kw).run(
                [f"secret-{i}" for i in range(100, 300)]), daemon=True)
        t.start()
        with Psi(Protocol.VOLE, Role.RECEIVER, ra, log_file=rlog, **kw) as psi:
            got = psi.run([f"secret-{i}" for i in range(200)])
        t.join(TIMEOUT)
        self.assertEqual(len(got), 100)
        r, s = self.read("r.log"), self.read("s.log")
        for text in (r, s):
            self.assertIn("sent ", text)
            self.assertIn("received ", text)
            self.assertIn("loaded bucket 1:", text)
            self.assertNotIn("secret", text)
        self.assertIn("all 4 buckets answered, 200 items", s)
        self.assertIn("matches", r)

    def test_runs_are_numbered(self):
        path = os.path.join(self.tmp.name, "psi.log")
        ra, sa = MemoryChannel.pair()

        def sender():
            psi = Psi(Protocol.ECDH, Role.SENDER, sa)
            psi.run(["a"])
            psi.run(["b"])

        t = threading.Thread(target=sender, daemon=True)
        t.start()
        with Psi(Protocol.ECDH, Role.RECEIVER, ra, log_file=path) as psi:
            psi.run(["a"])
            psi.run(["a"])
        t.join(TIMEOUT)
        text = self.read("psi.log")
        self.assertIn("run 1: done", text)
        self.assertIn("run 2: done", text)

    def test_errors_are_logged(self):
        path = os.path.join(self.tmp.name, "psi.log")
        ra, sa = MemoryChannel.pair()
        sa.send(b"not a header")  # the "peer" sends garbage
        with Psi(Protocol.ECDH, Role.RECEIVER, ra, log_file=path) as psi:
            with self.assertRaises(ValueError):
                psi.run(["a"])
        text = self.read("psi.log")
        self.assertIn("ERROR", text)
        self.assertIn("peer is not a cryptex PSI party", text)
        # The stack trace is included, pointing at where it failed.
        self.assertIn("Traceback (most recent call last)", text)
        self.assertIn("_handshake", text)

    def test_without_log_file_uses_logging_hierarchy(self):
        with self.assertLogs("cryptex.psi", level="INFO") as cm:
            pair_run({}, {}, ["a"], ["a"])
        joined = "\n".join(cm.output)
        self.assertIn("start ECDH-PSI as RECEIVER", joined)
        self.assertIn("start ECDH-PSI as SENDER", joined)

    def test_log_file_does_not_propagate(self):
        path = os.path.join(self.tmp.name, "psi.log")
        root = logging.getLogger("cryptex.psi")
        seen = []
        handler = logging.Handler()
        handler.emit = seen.append
        root.addHandler(handler)
        root.setLevel(logging.INFO)
        try:
            pair_run({"log_file": path}, {"log_file": path + ".s"}, ["a"], ["a"])
        finally:
            root.removeHandler(handler)
            root.setLevel(logging.NOTSET)
        self.assertEqual(seen, [])

    def test_close_releases_file(self):
        path = os.path.join(self.tmp.name, "psi.log")
        psi = Psi(Protocol.ECDH, Role.SENDER, MemoryChannel.pair()[0], log_file=path)
        self.assertEqual(len(psi.log.handlers), 1)
        psi.close()
        psi.close()
        self.assertEqual(psi.log.handlers, [])

    def test_bad_log_level(self):
        with self.assertRaises(ValueError):
            Psi(Protocol.ECDH, Role.SENDER, MemoryChannel.pair()[0], log_level="LOUD")


if __name__ == "__main__":
    unittest.main()
