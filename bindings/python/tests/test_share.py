"""
share_result: the receiver also gives the sender the intersection.
"""

import os
import tempfile
import threading
import unittest

from cryptex import (
    CryptexError, Curve, JobRole, MemoryChannel, Protocol, Psi, PsiParty, Role, VoleJob,
)

TIMEOUT = 60

# OPRF-PSI does not support share_result.
SHARING = (Protocol.ECDH, Protocol.VOLE)


def run_pair(rx, sx, protocol, receiver_kw=None, sender_kw=None, r_run=None, s_run=None):
    """Both parties over a MemoryChannel; returns (receiver, sender) results
    and errors"""
    ra, sa = MemoryChannel.pair()
    out = {}

    def party(name, role, ch, data, kw, run_kw):
        try:
            with Psi(protocol, role, ch, **kw) as psi:
                out[name] = psi.run(data, **(run_kw or {}))
        except BaseException as e:
            out[name + "_error"] = e
            ch.send(b"")  # unblock the peer if it waits for us

    t = threading.Thread(target=party, daemon=True,
                         args=("s", Role.SENDER, sa, sx, sender_kw or {}, s_run))
    t.start()
    party("r", Role.RECEIVER, ra, rx, receiver_kw or {}, r_run)
    t.join(TIMEOUT)
    return out


class ShareResultTest(unittest.TestCase):
    RX = [f"id-{i}" for i in range(0, 300)]
    SX = [f"id-{i}" for i in range(500, 150, -1)]  # different order, overlap 150..299

    def expected(self, own, other):
        other = set(other)
        return [x for x in own if x in other]

    def test_both_parties_get_the_intersection(self):
        for protocol in SHARING:
            for bucket_size in (None, 1_000_000, 64):
                kw = {"share_result": True, "bucket_size": bucket_size}
                with self.subTest(protocol=protocol.name, bucket_size=bucket_size):
                    out = run_pair(self.RX, self.SX, protocol, kw, kw)
                    self.assertNotIn("r_error", out)
                    self.assertNotIn("s_error", out)
                    # Each side gets its own matching items, in its own order.
                    self.assertEqual(out["r"], self.expected(self.RX, self.SX))
                    self.assertEqual(out["s"], self.expected(self.SX, self.RX))

    def test_default_keeps_sender_blind(self):
        for protocol in SHARING:
            out = run_pair(self.RX, self.SX, protocol)
            self.assertEqual(out["r"], self.expected(self.RX, self.SX))
            self.assertIsNone(out["s"])

    def test_sender_writes_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            sx_file = os.path.join(d, "sx.txt")
            with open(sx_file, "w", encoding="utf-8") as f:
                f.write("".join(f"{x}\n" for x in self.SX))
            for protocol in SHARING:
                for bucket_size in (None, 64):
                    out_file = os.path.join(d, f"out-{protocol.name}-{bucket_size}.txt")
                    kw = {"share_result": True, "bucket_size": bucket_size}
                    out = run_pair(self.RX, sx_file, protocol, kw, kw,
                                   s_run={"output": out_file})
                    expected = self.expected(self.SX, self.RX)
                    self.assertEqual(out.get("s"), len(expected), out)
                    with open(out_file, encoding="utf-8") as f:
                        self.assertEqual(f.read().splitlines(), expected)

    def test_mismatch_is_rejected_by_the_handshake(self):
        for protocol in SHARING:
            for r_share, s_share in ((True, False), (False, True)):
                out = run_pair(["a"], ["a"], protocol,
                               {"share_result": r_share}, {"share_result": s_share})
                self.assertIn("share_result mismatch", str(out.get("r_error")))
                self.assertIn("share_result mismatch", str(out.get("s_error")))

    def test_sender_output_needs_share_result(self):
        ch = MemoryChannel.pair()[0]
        with self.assertRaises(ValueError):
            Psi(Protocol.ECDH, Role.SENDER, ch).run(["a"], output="x.txt")
        self.assertTrue(Psi(Protocol.ECDH, Role.SENDER, ch, share_result=True).has_result)
        self.assertFalse(Psi(Protocol.VOLE, Role.SENDER, ch).has_result)
        self.assertTrue(Psi(Protocol.VOLE, Role.RECEIVER, ch).has_result)


class LowLevelShareTest(unittest.TestCase):
    def test_psi_party(self):
        with PsiParty(Protocol.ECDH, Role.RECEIVER, ["a", "b", "c"], Curve.SM2, share=True) as r, \
                PsiParty(Protocol.ECDH, Role.SENDER, ["c", "x", "a"], Curve.SM2,
                         share=True) as s:
            m1, done = r.step(None)
            m2, done = s.step(m1)
            self.assertFalse(done)  # waits for the shared result
            m3, done = r.step(m2)
            self.assertTrue(done and m3)
            m4, done = s.step(m3)
            self.assertTrue(done)
            self.assertEqual(m4, b"")
            self.assertEqual(r.result(), [b"a", b"c"])
            self.assertEqual(s.result(), [b"c", b"a"])

    def test_psi_party_mismatch(self):
        with PsiParty(Protocol.ECDH, Role.RECEIVER, ["a"], share=True) as r, \
                PsiParty(Protocol.ECDH, Role.SENDER, ["a"]) as s:
            m1, _ = r.step(None)
            with self.assertRaises(CryptexError):
                s.step(m1)

    def test_vole_job(self):
        rx = [["a", "b"], ["c"], []]
        sx = [["b", "x", "a"], [], ["d"]]
        with VoleJob(JobRole.RECEIVER, map(len, rx), share=True) as r, \
                VoleJob(JobRole.SENDER, map(len, sx), share=True) as s:
            results = {"r": {}, "s": {}}
            for _ in range(10_000):
                for job, data in ((r, rx), (s, sx)):
                    while (b := job.need()) is not None:
                        job.provide(b, data[b])
                if (m := r.next_send()) is not None:
                    s.receive(m)
                if (m := s.next_send()) is not None:
                    r.receive(m)
                for name, job in (("r", r), ("s", s)):
                    while (res := job.take_result()) is not None:
                        results[name][res[0]] = res[1]
                if r.done and s.done:
                    break
            self.assertTrue(r.done and s.done)
            self.assertEqual(results["r"], {0: [0, 1]})
            self.assertEqual(results["s"], {0: [0, 2]})


if __name__ == "__main__":
    unittest.main()
