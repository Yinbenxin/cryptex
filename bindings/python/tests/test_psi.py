"""
PSI binding tests: FFI wiring, call-order checks, channels and handshake.

Both ECDH-PSI and VOLE-PSI run end to end.
"""

import os
import tempfile
import threading
import unittest

from cryptex import (
    CallbackChannel, ChannelClosed, CryptexError, Curve, JobRole, MemoryChannel,
    Protocol, Psi, PsiParty, Role, TcpChannel, VoleJob,
)
from cryptex import _ffi
from cryptex import psi as psi_module

TIMEOUT = 5


def run_in_thread(fn):
    """Run fn in a thread, return a callable that joins and yields its outcome"""
    box = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: B902 - surfaced to the test
            box["error"] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()

    def join():
        t.join(TIMEOUT)
        assert not t.is_alive(), "peer thread did not finish"
        return box

    return join


class PsiPartyTest(unittest.TestCase):
    def test_step_by_step_ecdh(self):
        with PsiParty(Protocol.ECDH, Role.RECEIVER, ["a", "b"], Curve.SM2) as r, \
                PsiParty(Protocol.ECDH, Role.SENDER, ["b", "c"], Curve.SM2) as s:
            m1, done = r.step(None)
            self.assertFalse(done)
            m2, done = s.step(m1)
            self.assertTrue(done)
            m3, done = r.step(m2)
            self.assertTrue(done)
            self.assertEqual(m3, b"")
            self.assertEqual(r.result_indices(), [1])
            self.assertEqual(r.result(), [b"b"])
            with self.assertRaises(CryptexError) as cm:
                s.result()
            self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_STATE)
            with self.assertRaises(CryptexError) as cm:
                r.step(b"again")
            self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_STATE)

    def test_malformed_peer_message(self):
        with PsiParty(Protocol.ECDH, Role.SENDER, ["a"]) as s:
            with self.assertRaises(CryptexError) as cm:
                s.step(b"\x01garbage")
            self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_INPUT)

    def test_receiver_is_initiator(self):
        with PsiParty(Protocol.ECDH, Role.RECEIVER, ["a"]) as r, \
                PsiParty(Protocol.ECDH, Role.SENDER, ["a"]) as s:
            self.assertTrue(r.is_initiator)
            self.assertFalse(s.is_initiator)

    def test_items_accept_str_bytes_and_empty(self):
        with PsiParty(Protocol.ECDH, Role.SENDER, ["x", b"\x00\x01", b"", bytearray(b"z")]):
            pass
        with PsiParty(Protocol.ECDH, Role.SENDER, []):
            pass

    def test_vole_needs_job_api(self):
        with self.assertRaises(ValueError):
            PsiParty(Protocol.VOLE, Role.SENDER, ["a"])

    def test_invalid_enum_rejected(self):
        with self.assertRaises(ValueError):
            PsiParty(9, Role.SENDER, [])

    def test_call_order_enforced(self):
        with PsiParty(Protocol.ECDH, Role.SENDER, ["a"]) as s:
            with self.assertRaises(CryptexError) as cm:
                s.step(None)
            self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_STATE)
        with PsiParty(Protocol.ECDH, Role.RECEIVER, ["a"]) as r:
            with self.assertRaises(CryptexError) as cm:
                r.step(b"x")
            self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_STATE)

    def test_vole_job_event_driven(self):
        """VoleJob without a channel: messages delivered by hand, in a
        shuffled interleaving, as a callback-based platform would"""
        import random
        rng = random.Random(3)
        rx = [["a", "b", "c"], [], ["d", "e"]]
        sx = [["c", "x", "a"], ["q"], ["e"]]
        with VoleJob(JobRole.RECEIVER, map(len, rx)) as r, \
                VoleJob(JobRole.SENDER, map(len, sx)) as s:
            to_s, to_r, results = [], [], {}
            for _ in range(100_000):
                for job, data in ((r, rx), (s, sx)):
                    while (b := job.need()) is not None:
                        job.provide(b, data[b])
                action = rng.randrange(4)
                if action == 0 and (m := r.next_send()) is not None:
                    to_s.append(m)
                elif action == 1 and (m := s.next_send()) is not None:
                    to_r.append(m)
                elif action == 2 and to_s:
                    s.receive(to_s.pop(0))
                elif action == 3 and to_r:
                    r.receive(to_r.pop(0))
                while (res := r.take_result()) is not None:
                    results[res[0]] = res[1]
                if r.done and s.done and not to_s and not to_r:
                    break
            self.assertTrue(r.done and s.done)
            self.assertEqual(results, {0: [0, 2], 2: [1]})  # bucket 1 is skipped
            with self.assertRaises(CryptexError):
                s.take_result()

    def test_vole_job_failure_poisons(self):
        with VoleJob(JobRole.SENDER, [1]) as s:
            with self.assertRaises(CryptexError) as cm:
                s.receive(b"\x25garbage")
            self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_STATE)
            with self.assertRaises(CryptexError) as cm:
                s.next_send()
            self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_STATE)

    def test_close_is_idempotent(self):
        p = PsiParty(Protocol.ECDH, Role.SENDER, ["a"])
        p.close()
        p.close()


class ChannelTest(unittest.TestCase):
    def test_tcp_roundtrip_and_empty_message(self):
        port = {}
        ready = threading.Event()

        def server():
            with TcpChannel.listen("127.0.0.1", 0, timeout=TIMEOUT,
                                   on_listening=lambda p: (port.update(p=p), ready.set())) as ch:
                ch.send(ch.recv() + b"!")
                ch.send(ch.recv())

        join = run_in_thread(server)
        ready.wait(TIMEOUT)
        with TcpChannel.connect("127.0.0.1", port["p"], timeout=TIMEOUT) as ch:
            ch.send(b"hi")
            self.assertEqual(ch.recv(), b"hi!")
            ch.send(b"")
            self.assertEqual(ch.recv(), b"")
        self.assertNotIn("error", join())

    def test_tcp_rejects_oversized_message(self):
        port = {}
        ready = threading.Event()

        def server():
            with TcpChannel.listen("127.0.0.1", 0, timeout=TIMEOUT, max_message_size=4,
                                   on_listening=lambda p: (port.update(p=p), ready.set())) as ch:
                return ch.recv()

        join = run_in_thread(server)
        ready.wait(TIMEOUT)
        with TcpChannel.connect("127.0.0.1", port["p"], timeout=TIMEOUT) as ch:
            ch.send(b"too long")
        self.assertIsInstance(join()["error"], ValueError)

    def test_tcp_detects_peer_close(self):
        port = {}
        ready = threading.Event()

        def server():
            with TcpChannel.listen("127.0.0.1", 0, timeout=TIMEOUT,
                                   on_listening=lambda p: (port.update(p=p), ready.set())) as ch:
                return ch.recv()

        join = run_in_thread(server)
        ready.wait(TIMEOUT)
        TcpChannel.connect("127.0.0.1", port["p"], timeout=TIMEOUT).close()
        self.assertIsInstance(join()["error"], ChannelClosed)

    def test_connect_retries_until_listener_is_up(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]

        def late_server():
            import time
            time.sleep(0.5)
            with TcpChannel.listen("127.0.0.1", free_port, timeout=TIMEOUT) as ch:
                return ch.recv()

        join = run_in_thread(late_server)
        with TcpChannel.connect("127.0.0.1", free_port, timeout=TIMEOUT) as ch:
            ch.send(b"ok")
        self.assertEqual(join()["value"], b"ok")


class PsiOverChannelTest(unittest.TestCase):
    def _run_tcp(self, listener_role, connector_role, **kw):
        """Listener side runs in a thread; returns (listener, connector) outcomes"""
        port = {}
        ready = threading.Event()
        listener_kw = kw.pop("listener", {})
        connector_kw = kw.pop("connector", {})

        def listener():
            with TcpChannel.listen("127.0.0.1", 0, timeout=TIMEOUT,
                                   on_listening=lambda p: (port.update(p=p), ready.set())) as ch:
                psi = Psi(listener_kw.get("protocol", Protocol.ECDH), listener_role, ch,
                          curve=listener_kw.get("curve", Curve.SM2))
                return psi.run(["a", "b"])

        join = run_in_thread(listener)
        ready.wait(TIMEOUT)
        connector = {}
        try:
            with TcpChannel.connect("127.0.0.1", port["p"], timeout=TIMEOUT) as ch:
                psi = Psi(connector_kw.get("protocol", Protocol.ECDH), connector_role, ch,
                          curve=connector_kw.get("curve", Curve.SM2))
                connector["value"] = psi.run(["b", "c"])
        except BaseException as e:
            connector["error"] = e
        return join(), connector

    # The listener holds ["a", "b"] and the connector ["b", "c"].

    def test_receiver_listens(self):
        listener, connector = self._run_tcp(Role.RECEIVER, Role.SENDER)
        self.assertEqual(listener, {"value": ["b"]})
        self.assertEqual(connector, {"value": None})

    def test_sender_listens(self):
        listener, connector = self._run_tcp(Role.SENDER, Role.RECEIVER)
        self.assertEqual(listener, {"value": None})
        self.assertEqual(connector, {"value": ["b"]})

    def test_every_curve_over_tcp(self):
        for curve in Curve:
            with self.subTest(curve=curve.name):
                listener, _ = self._run_tcp(Role.RECEIVER, Role.SENDER,
                                            listener={"curve": curve},
                                            connector={"curve": curve})
                self.assertEqual(listener, {"value": ["b"]})

    def test_same_role_rejected(self):
        a, b = self._run_tcp(Role.SENDER, Role.SENDER)
        self.assertIn("both parties", str(a.get("error")))
        self.assertIn("both parties", str(b.get("error")))

    def test_protocol_mismatch_rejected(self):
        a, b = self._run_tcp(Role.RECEIVER, Role.SENDER,
                             connector={"protocol": Protocol.VOLE})
        self.assertIn("protocol mismatch", str(a.get("error")))

    def test_curve_mismatch_rejected(self):
        a, b = self._run_tcp(Role.RECEIVER, Role.SENDER,
                             connector={"curve": Curve.P256})
        self.assertIn("curve mismatch", str(a.get("error")))

    def test_callback_channel(self):
        """Platform transport plugged in as plain functions"""
        import queue
        a_to_b, b_to_a = queue.Queue(), queue.Queue()
        sender_ch = CallbackChannel(send=a_to_b.put, recv=lambda: b_to_a.get(timeout=TIMEOUT))
        receiver_ch = CallbackChannel(send=b_to_a.put, recv=lambda: a_to_b.get(timeout=TIMEOUT))
        join = run_in_thread(
            lambda: Psi(Protocol.ECDH, Role.SENDER, sender_ch).run(["x", "y"]))
        common = Psi(Protocol.ECDH, Role.RECEIVER, receiver_ch).run(["y", "z"])
        self.assertEqual(common, ["y"])
        self.assertEqual(join(), {"value": None})

    def test_callback_channel_rejects_non_bytes(self):
        ch = CallbackChannel(send=lambda m: None, recv=lambda: None)
        with self.assertRaises(TypeError):
            ch.recv()

    def test_custom_channel_class(self):
        """Any object with send/recv works, no base class needed"""
        class Recorder:
            def __init__(self, peer_header):
                self.sent = []
                self._peer_header = peer_header

            def send(self, msg):
                self.sent.append(msg)

            def recv(self):
                return self._peer_header

        # A valid sender header, then the same header again where the first
        # protocol reply should be: the receiver rejects it.
        header = psi_module._HEADER.pack(
            psi_module._MAGIC, psi_module._VERSION, Protocol.VOLE, Role.SENDER, 0, 0, 0,
            psi_module.DEFAULT_BUCKET_SIZE, 1)
        ch = Recorder(header)
        with self.assertRaises(CryptexError):
            Psi(Protocol.VOLE, Role.RECEIVER, ch).run(["x"])
        # Full duplex: the bad reply may be noticed before or after our first
        # job message goes out.
        self.assertEqual(ch.sent[0], header[:4] + ch.sent[0][4:])
        self.assertLessEqual(len(ch.sent), 2)
        if len(ch.sent) == 2:
            self.assertEqual(ch.sent[1][0], 0x21)

    def test_handshake_disabled(self):
        sent = []
        ch = CallbackChannel(send=sent.append, recv=lambda: b"")
        with self.assertRaises(CryptexError) as cm:
            Psi(Protocol.VOLE, Role.RECEIVER, ch, handshake=False).run(["x"])
        self.assertEqual(cm.exception.code, _ffi.ERR_INVALID_INPUT)
        # No session header; at most the job's first message went out.
        self.assertLessEqual(len(sent), 1)
        if sent:
            self.assertEqual(sent[0][0], 0x21)

    def test_handshake_disabled_vole(self):
        ra, sa = MemoryChannel.pair()
        join = run_in_thread(
            lambda: Psi(Protocol.VOLE, Role.SENDER, sa, handshake=False).run(["a", "b"]))
        self.assertEqual(Psi(Protocol.VOLE, Role.RECEIVER, ra, handshake=False).run(["b"]), ["b"])
        self.assertEqual(join(), {"value": None})

    def test_memory_channel_ecdh(self):
        ra, sa = MemoryChannel.pair()
        join = run_in_thread(
            lambda: Psi(Protocol.ECDH, Role.SENDER, sa, curve=Curve.P256).run(["1", "2", "3"]))
        common = Psi(Protocol.ECDH, Role.RECEIVER, ra, curve=Curve.P256).run(["3", "4", "1"])
        self.assertEqual(common, ["3", "1"])  # receiver's input order
        self.assertEqual(join(), {"value": None})

    def test_handshake_disabled_ecdh(self):
        ra, sa = MemoryChannel.pair()
        join = run_in_thread(
            lambda: Psi(Protocol.ECDH, Role.SENDER, sa, handshake=False).run(["a"]))
        self.assertEqual(Psi(Protocol.ECDH, Role.RECEIVER, ra, handshake=False).run(["a"]), ["a"])
        self.assertEqual(join(), {"value": None})

    def test_reuse_channel_for_several_runs(self):
        ra, sa = MemoryChannel.pair()

        def sender():
            psi = Psi(Protocol.ECDH, Role.SENDER, sa)
            psi.run(["a", "b"])
            psi.run(["c"])

        join = run_in_thread(sender)
        psi = Psi(Protocol.ECDH, Role.RECEIVER, ra)
        self.assertEqual(psi.run(["b", "c"]), ["b"])
        self.assertEqual(psi.run(["b", "c"]), ["c"])
        self.assertEqual(join(), {"value": None})

    def test_files_and_output(self):
        with tempfile.TemporaryDirectory() as d:
            rx = os.path.join(d, "rx.csv")
            sx = os.path.join(d, "sx.txt")
            out = os.path.join(d, "out.txt")
            with open(rx, "w", encoding="gbk") as f:
                f.write("姓名,手机号\n张三,13800000001\n李四,13800000002\n王五,13800000003\n")
            with open(sx, "w", encoding="utf-8") as f:
                f.write("13800000003\n13800000009\n 13800000001 \n")
            ra, sa = MemoryChannel.pair()
            join = run_in_thread(
                lambda: Psi(Protocol.ECDH, Role.SENDER, sa, curve=Curve.SM2).run(sx))
            common = Psi(Protocol.ECDH, Role.RECEIVER, ra, curve=Curve.SM2).run(
                rx, column="手机号", encoding="gbk", output=out)
            self.assertEqual(join(), {"value": None})
            self.assertEqual(common, 2)  # with output=, run() returns the count
            with open(out, encoding="utf-8") as f:
                self.assertEqual(f.read(), "13800000001\n13800000003\n")

    def test_medium_sets(self):
        rx = [f"user-{i}" for i in range(0, 3000)]
        sx = [f"user-{i}" for i in range(2000, 6000)]
        ra, sa = MemoryChannel.pair()
        join = run_in_thread(lambda: Psi(Protocol.ECDH, Role.SENDER, sa).run(sx))
        common = Psi(Protocol.ECDH, Role.RECEIVER, ra).run(rx)
        self.assertEqual(common, rx[2000:])
        self.assertEqual(join(), {"value": None})

    def test_memory_channel_vole(self):
        ra, sa = MemoryChannel.pair()
        join = run_in_thread(lambda: Psi(Protocol.VOLE, Role.SENDER, sa).run(["1", "2", "3"]))
        common = Psi(Protocol.VOLE, Role.RECEIVER, ra).run(["3", "4", "1"])
        self.assertEqual(common, ["3", "1"])
        self.assertEqual(join(), {"value": None})

    def test_vole_medium_sets_and_threads(self):
        rx = [f"user-{i}" for i in range(0, 30_000)]
        sx = [f"user-{i}" for i in range(20_000, 60_000)]
        for threads in (1, 0):
            with self.subTest(threads=threads):
                ra, sa = MemoryChannel.pair()
                join = run_in_thread(
                    lambda: Psi(Protocol.VOLE, Role.SENDER, sa, threads=threads).run(sx))
                common = Psi(Protocol.VOLE, Role.RECEIVER, ra, threads=threads).run(rx)
                self.assertEqual(common, rx[20_000:])
                self.assertEqual(join(), {"value": None})

    def test_vole_over_tcp_both_directions(self):
        for listener_role in (Role.RECEIVER, Role.SENDER):
            with self.subTest(listener=listener_role.name):
                connector_role = Role.SENDER if listener_role == Role.RECEIVER else Role.RECEIVER
                listener, connector = self._run_tcp(
                    listener_role, connector_role,
                    listener={"protocol": Protocol.VOLE}, connector={"protocol": Protocol.VOLE})
                values = [listener.get("value"), connector.get("value")]
                self.assertIn(["b"], values, (listener, connector))
                self.assertIn(None, values)


class FakeParty:
    """Stands in for PsiParty: finishes in one step with fixed result indices"""

    instances = []

    def __init__(self, protocol, role, items, curve, threads=0, pool=None, sessions=1,
                 share=False):
        self.role = Role(role)
        self.threads = threads
        self.items = list(items)
        self.is_initiator = self.role == Role.RECEIVER
        FakeParty.instances.append(self)

    def step(self, incoming):
        return b"", True

    def result_indices(self):
        return [i for i, x in enumerate(self.items) if x in ("b", "c", b"b")]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


class PsiClassTest(unittest.TestCase):
    """Psi API surface; the protocol itself is faked until it is implemented"""

    def setUp(self):
        self._real = psi_module.PsiParty
        psi_module.PsiParty = FakeParty
        FakeParty.instances.clear()
        self.ch = CallbackChannel(send=lambda m: None, recv=lambda: b"")
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        psi_module.PsiParty = self._real
        self.tmp.cleanup()

    def path(self, name, content=None):
        p = os.path.join(self.tmp.name, name)
        if content is not None:
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
        return p

    def receiver(self):
        return Psi(Protocol.ECDH, Role.RECEIVER, self.ch, handshake=False)

    def test_init_validates_parameters(self):
        with self.assertRaises(ValueError):
            Psi(9, Role.SENDER, self.ch)
        with self.assertRaises(ValueError):
            Psi(Protocol.ECDH, 9, self.ch)
        with self.assertRaises(ValueError):
            Psi(Protocol.ECDH, Role.SENDER, self.ch, curve=9)
        with self.assertRaises(TypeError):
            Psi(Protocol.ECDH, Role.SENDER, object())

    def test_run_with_list_returns_items_in_input_order(self):
        self.assertEqual(self.receiver().run(["c", "a", "b", "c"]), ["c", "b"])
        self.assertEqual(FakeParty.instances[-1].items, ["c", "a", "b"])  # deduped

    def test_run_with_text_file(self):
        p = self.path("ids.txt", "a\n b \n\nc\n")
        self.assertEqual(self.receiver().run(p), ["b", "c"])

    def test_run_with_csv_column(self):
        p = self.path("ids.csv", "id,name\na,x\nb,y\nc,z\n")
        self.assertEqual(self.receiver().run(p, column="id"), ["b", "c"])
        self.assertEqual(self.receiver().run(p, column=0), ["b", "c"])

    def test_run_writes_output(self):
        out = self.path("out.txt")
        self.receiver().run(["a", "b", "c"], output=out)
        with open(out, encoding="utf-8") as f:
            self.assertEqual(f.read(), "b\nc\n")

    def test_sender_returns_none_and_rejects_output(self):
        sender = Psi(Protocol.ECDH, Role.SENDER, self.ch, handshake=False)
        self.assertIsNone(sender.run(["a"]))
        with self.assertRaises(ValueError):
            sender.run(["a"], output=self.path("out.txt"))

    def test_instance_reused_for_several_runs(self):
        psi = self.receiver()
        self.assertEqual(psi.run(["b"]), ["b"])
        self.assertEqual(psi.run(["a", "c"]), ["c"])


if __name__ == "__main__":
    unittest.main()
