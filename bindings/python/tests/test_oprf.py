"""
OPRF-PSI (unbalanced sets) through the Python binding.
"""

import os
import tempfile
import threading
import unittest

from cryptex import CryptexError, Curve, MemoryChannel, Protocol, Psi, PsiParty, Role

TIMEOUT = 60


def run_pair(rx, sx, kw_r=None, kw_s=None):
    """Receiver here, sender in a thread; returns (result, errors)"""
    ra, sa = MemoryChannel.pair()
    err = {}

    def sender():
        try:
            with Psi(Protocol.OPRF, Role.SENDER, sa, **(kw_s or {})) as psi:
                psi.run(sx)
        except BaseException as e:
            err["s"] = e

    t = threading.Thread(target=sender, daemon=True)
    t.start()
    try:
        with Psi(Protocol.OPRF, Role.RECEIVER, ra, **(kw_r or {})) as psi:
            result = psi.run(rx)
    except BaseException as e:
        err["r"] = e
        result = None
        ra.send(b"")
    t.join(TIMEOUT)
    return result, err


class OprfPartyTest(unittest.TestCase):
    def test_step_by_step(self):
        for curve in Curve:
            with PsiParty(Protocol.OPRF, Role.RECEIVER, ["a", "b", "c"], curve) as r, \
                    PsiParty(Protocol.OPRF, Role.SENDER, ["x", "c", "a", "y"], curve) as s:
                self.assertTrue(r.is_initiator)
                self.assertFalse(s.is_initiator)
                m1, done = r.step(None)
                self.assertFalse(done)
                m2, done = s.step(m1)
                self.assertTrue(done)
                m3, done = r.step(m2)
                self.assertTrue(done)
                self.assertEqual(m3, b"")
                self.assertEqual(r.result(), [b"a", b"c"], curve)

    def test_share_rejected(self):
        with self.assertRaises(CryptexError):
            PsiParty(Protocol.OPRF, Role.RECEIVER, ["a"], share=True)

    def test_ecdh_peer_rejected(self):
        with PsiParty(Protocol.OPRF, Role.RECEIVER, ["a"]) as r, \
                PsiParty(Protocol.ECDH, Role.SENDER, ["a"]) as s:
            m1, _ = r.step(None)
            with self.assertRaises(CryptexError):
                s.step(m1)


class OprfPsiTest(unittest.TestCase):
    def test_unbalanced_run(self):
        rx = [f"id-{i * 37}" for i in range(40)]
        sx = [f"id-{i}" for i in range(5000)]
        got, err = run_pair(rx, sx, {"curve": Curve.SM2}, {"curve": Curve.SM2})
        self.assertEqual(err, {})
        self.assertEqual(got, [x for x in rx if int(x[3:]) < 5000])

    def test_bucketed_matches_unbucketed(self):
        rx = [f"{i}" for i in range(0, 3000, 7)]
        sx = [f"{i}" for i in range(2000)]
        plain, err = run_pair(rx, sx, {"bucket_size": None}, {"bucket_size": None})
        self.assertEqual(err, {})
        bucketed, err = run_pair(rx, sx, {"bucket_size": 300}, {"bucket_size": 300})
        self.assertEqual(err, {})
        self.assertEqual(plain, bucketed)
        self.assertEqual(plain, [x for x in rx if int(x) < 2000])

    def test_file_input_and_output(self):
        with tempfile.TemporaryDirectory() as d:
            path, out = os.path.join(d, "in.txt"), os.path.join(d, "out.txt")
            with open(path, "w") as f:
                f.write("b\na\nz\nb\n")
            ra, sa = MemoryChannel.pair()
            t = threading.Thread(target=lambda: Psi(
                Protocol.OPRF, Role.SENDER, sa).run([f"{c}" for c in "abcdefg"]))
            t.start()
            n = Psi(Protocol.OPRF, Role.RECEIVER, ra).run(path, output=out)
            t.join(TIMEOUT)
            self.assertEqual(n, 2)
            with open(out) as f:
                self.assertEqual(f.read().splitlines(), ["b", "a"])

    def test_curve_mismatch_rejected_by_handshake(self):
        got, err = run_pair(["a"], ["a"], {"curve": Curve.P256}, {"curve": Curve.SM2})
        self.assertIn("curve mismatch", str(err.get("r")))

    def test_protocol_mismatch_rejected_by_handshake(self):
        ra, sa = MemoryChannel.pair()
        err = {}

        def sender():
            try:
                Psi(Protocol.ECDH, Role.SENDER, sa).run(["a"])
            except BaseException as e:
                err["s"] = e

        t = threading.Thread(target=sender, daemon=True)
        t.start()
        with self.assertRaises(ValueError) as ctx:
            Psi(Protocol.OPRF, Role.RECEIVER, ra).run(["a"])
        t.join(TIMEOUT)
        self.assertIn("protocol mismatch", str(ctx.exception))

    def test_share_result_rejected(self):
        ch = MemoryChannel.pair()[0]
        with self.assertRaises(ValueError):
            Psi(Protocol.OPRF, Role.RECEIVER, ch, share_result=True)


if __name__ == "__main__":
    unittest.main()
