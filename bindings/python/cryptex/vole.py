"""
VOLE-PSI jobs.

A job covers every bucket of one PSI run with a single setup (base OT and
silent OT) and is full duplex: both parties may send at any time. `Psi`
drives jobs for you; `VoleJob` is the low-level handle for platforms that
deliver messages through callbacks instead of a blocking channel.
"""

from __future__ import annotations

import ctypes
import threading
from enum import IntEnum

from . import _data, _ffi, _store


class JobRole(IntEnum):
    """Mirrors CRYPTEX_VOLE_* in core/src/ffi/vole.rs"""

    SENDER = 0
    RECEIVER = 1


class VoleJob:
    """Low-level, non-blocking VOLE-PSI job

    The job never blocks. A driver repeatedly:

    - while `need()` returns a bucket number, calls `provide(b, items)` with
      that bucket's distinct items (in bucket order, sizes as announced);
    - calls `next_send()` and transmits any message it returns;
    - passes every message from the peer to `receive()`;
    - receiver (and, with `share=True`, the sender): collects
      `(bucket, indices)` from `take_result()`.

    It is finished when `done` is true. Messages may be sent and received
    in any interleaving. Calls must not overlap (use one lock).
    """

    def __init__(self, role, sizes, pool=None, share=False):
        self._lib = _ffi.lib()
        self.role = JobRole(role)
        self.share = bool(share)
        sizes = list(sizes)
        if not sizes:
            raise ValueError("a job needs at least one bucket")
        arr = (ctypes.c_uint64 * len(sizes))(*sizes)
        self._handle = ctypes.c_void_p()
        _ffi.check(self._lib.cryptex_vole_job_new(
            self.role, pool.handle if pool is not None else None,
            len(sizes), arr, int(self.share), ctypes.byref(self._handle),
        ))

    def need(self):
        """Bucket whose items are needed now, or None"""
        b, has = ctypes.c_uint32(), ctypes.c_int32()
        _ffi.check(self._lib.cryptex_vole_job_need(self._handle, ctypes.byref(b), ctypes.byref(has)))
        return b.value if has.value else None

    def provide(self, bucket, items):
        if isinstance(items, _store.Packed):
            data, data_len, lens, count = items.args()
        else:
            raw = [_data.to_bytes(x) for x in items]
            data, data_len, lens, count, _keep = _ffi.pack_items(raw)
        _ffi.check(self._lib.cryptex_vole_job_provide(
            self._handle, bucket, data, data_len, lens, count))

    def receive(self, msg):
        msg = bytes(msg)
        buf = (ctypes.c_uint8 * len(msg)).from_buffer_copy(msg) if msg else None
        _ffi.check(self._lib.cryptex_vole_job_receive(self._handle, buf, len(msg)))

    def next_send(self):
        """Next message to send, or None if nothing is ready now"""
        out, has = _ffi.CryptexBuffer(), ctypes.c_int32()
        code = self._lib.cryptex_vole_job_next_send(
            self._handle, ctypes.byref(out), ctypes.byref(has))
        msg = _ffi.take_buffer(out)
        _ffi.check(code)
        return msg if has.value else None

    def take_result(self):
        """Next finished bucket as (bucket, indices), or None (receiver;
        sender only with share=True)"""
        b, ptr = ctypes.c_uint32(), ctypes.POINTER(ctypes.c_size_t)()
        count, has = ctypes.c_size_t(), ctypes.c_int32()
        _ffi.check(self._lib.cryptex_vole_job_take_result(
            self._handle, ctypes.byref(b), ctypes.byref(ptr), ctypes.byref(count),
            ctypes.byref(has)))
        if not has.value:
            return None
        return b.value, [ptr[i] for i in range(count.value)]

    def _status(self):
        done, expects = ctypes.c_int32(), ctypes.c_int32()
        _ffi.check(self._lib.cryptex_vole_job_status(
            self._handle, ctypes.byref(done), ctypes.byref(expects)))
        return bool(done.value), bool(expects.value)

    @property
    def done(self):
        return self._status()[0]

    @property
    def expects_messages(self):
        return self._status()[1]

    def close(self):
        if self._handle:
            self._lib.cryptex_vole_job_free(self._handle)
            self._handle = ctypes.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def drive(job, channel, load_bucket, on_result=None, log=None, describe=None):
    """Run a job to completion over a blocking full-duplex channel

    A background thread receives while this thread computes and sends, so
    both directions of the link are used at the same time.

    Args:
        load_bucket: function(bucket) -> list of items for that bucket
        on_result: function(bucket, indices) for each finished bucket
            (receiver; sender only when the job shares the result)
    """
    cond = threading.Condition()
    error = []
    received = [0]

    def note(what, msg):
        if log is None:
            return
        if describe is None:
            log.debug("%s %d bytes", what, len(msg))
        else:
            log.debug("%s %d bytes: %s", what, len(msg), describe(msg))

    def receiver():
        try:
            while True:
                with cond:
                    if error or not job.expects_messages:
                        return
                msg = channel.recv()
                note("received", msg)
                with cond:
                    job.receive(msg)
                    received[0] += 1
                    cond.notify_all()
        except BaseException as e:  # surfaced in the main thread
            with cond:
                error.append(e)
                cond.notify_all()

    t = threading.Thread(target=receiver, name="cryptex-vole-recv", daemon=True)
    t.start()
    try:
        while True:
            # Load inputs outside the lock: disk reads overlap with receiving.
            with cond:
                if error:
                    raise error[0]
                b = job.need()
            if b is not None:
                items = load_bucket(b)
                with cond:
                    job.provide(b, items)
                if log is not None:
                    log.debug("loaded bucket %d: %d items", b + 1, len(items))
                continue
            with cond:
                if error:
                    raise error[0]
                msg = job.next_send()
                if on_result is not None:
                    while (r := job.take_result()) is not None:
                        on_result(*r)
                if msg is None:
                    if job.done:
                        break
                    seen = received[0]
                    cond.wait_for(lambda: error or received[0] != seen
                                  or job.need() is not None)
                    continue
            channel.send(msg)
            note("sent", msg)
    finally:
        with cond:
            stuck = t.is_alive() and not error
        if not stuck:
            t.join()
    t.join()
    if error:
        raise error[0]
