"""
Log summaries of PSI messages (cryptex._wire) and the step/input log lines.
"""

import os
import tempfile
import threading
import unittest

from cryptex import Curve, MemoryChannel, Protocol, Psi, PsiParty, Role
from cryptex import _wire

TIMEOUT = 30


class DescribeTest(unittest.TestCase):
    def test_ecdh_and_oprf_messages(self):
        for protocol, first, second in ((Protocol.ECDH, "ECDH msg1", "ECDH msg2"),
                                        (Protocol.OPRF, "OPRF msg1", "OPRF msg2")):
            for curve, plen in ((Curve.RISTRETTO255, 32), (Curve.SM2, 33)):
                with PsiParty(protocol, Role.RECEIVER, ["a", "b", "c"], curve) as r, \
                        PsiParty(protocol, Role.SENDER, ["b", "x"], curve) as s:
                    m1, _ = r.step(None)
                    m2, _ = s.step(m1)
                d1 = _wire.describe(protocol, curve, m1)
                d2 = _wire.describe(protocol, curve, m2)
                self.assertIn(first, d1)
                self.assertIn(f"3 points × {plen} B", d1)
                self.assertIn("#0 ", d1)
                self.assertIn("… 1 more", d1)
                self.assertIn(second, d2)
                self.assertIn("2 ", d2)

    def test_previews_are_bounded(self):
        with PsiParty(Protocol.ECDH, Role.RECEIVER, [f"{i}" for i in range(1000)]) as r:
            m1, _ = r.step(None)
        d = _wire.describe(Protocol.ECDH, Curve.RISTRETTO255, m1)
        self.assertIn("1000 points", d)
        self.assertIn("… 998 more", d)
        self.assertLess(len(d), 200)

    def test_malformed_input_never_raises(self):
        for protocol in Protocol:
            for msg in (b"", b"\x01", b"\x02\x05", b"\x21" + b"\0" * 3, b"\xff" * 40,
                        b"\x26\0\0\0\0\x05" + b"\xff" * 8, b"\x27\0\0\0\0" + b"\0" * 7):
                text = _wire.describe(protocol, 0, msg)
                self.assertIsInstance(text, str)
        self.assertEqual(_wire.describe(Protocol.ECDH, 0, b""), "empty")
        self.assertIn("unrecognized", _wire.describe(Protocol.ECDH, 0, b"\x7f"))
        # A truncated message falls back instead of reading past its end.
        self.assertIn("unrecognized", _wire.describe(Protocol.ECDH, 0, b"\x01\x00\x00"))


class RunLogTest(unittest.TestCase):
    def test_csv_run_logs_file_column_steps_and_messages(self):
        with tempfile.TemporaryDirectory() as d:
            rx, sx = os.path.join(d, "customers.csv"), os.path.join(d, "ids.txt")
            out, rlog, slog = (os.path.join(d, n) for n in ("o.txt", "r.log", "s.log"))
            with open(rx, "w") as f:
                f.write("name,phone\n" + "".join(f"u{i},secret{i}\n" for i in range(300)))
            with open(sx, "w") as f:
                f.write("".join(f"secret{i}\n" for i in range(150, 600)))
            for protocol in Protocol:
                ra, sa = MemoryChannel.pair()
                kw = {"log_level": "DEBUG", "bucket_size": 200}
                t = threading.Thread(target=lambda: Psi(
                    protocol, Role.SENDER, sa, log_file=slog, **kw).run(sx), daemon=True)
                t.start()
                Psi(protocol, Role.RECEIVER, ra, log_file=rlog, **kw).run(
                    rx, column="phone", output=out)
                t.join(TIMEOUT)
            with open(rlog) as f:
                r = f.read()
            with open(slog) as f:
                s = f.read()
            self.assertIn(f"input: file {rx}, ID column 'phone'", r)
            self.assertIn(f"output: file {out}", r)
            self.assertIn(f"input: file {sx} (one item per line", s)
            self.assertIn("output: none (sender)", s)
            self.assertIn("step 1/4: handshake", r)
            self.assertIn("step 4/4: write the intersection", r)
            self.assertIn("step 3/3: ", s)
            self.assertIn("PSI bucket 3/3 done (100%)", r)
            self.assertIn("session header [v4 protocol=", r)
            for marker in ("ECDH msg2", "OPRF msg1", "VOLE setup 1/3", "VOLE bucket 1 reply"):
                self.assertIn(marker, r)
            for text in (r, s):
                self.assertNotIn("secret", text)

    def test_failure_names_the_step(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.log")
            ra, sa = MemoryChannel.pair()
            sa.send(b"not a header")
            with self.assertRaises(ValueError):
                Psi(Protocol.ECDH, Role.RECEIVER, ra, log_file=path).run(["a"])
            with open(path) as f:
                self.assertIn("failed in step 'handshake'", f.read())


if __name__ == "__main__":
    unittest.main()
