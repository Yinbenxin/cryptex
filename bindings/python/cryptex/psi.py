"""
Private set intersection (semi-honest).

The sender learns nothing; the receiver learns which of its own items are in
the intersection.

    Psi       configure once, then run(data) over a channel (common case)
    PsiParty  low-level step-by-step driver for non-blocking transports

Example (two processes):

    # receiver
    psi = Psi(Protocol.ECDH, Role.RECEIVER, channel, curve=Curve.SM2)
    common = psi.run("ids.txt")

    # sender
    psi = Psi(Protocol.ECDH, Role.SENDER, channel, curve=Curve.SM2)
    psi.run(["bob", "carol"])
"""

from __future__ import annotations

import ctypes
import itertools
import logging
import math
import os
import struct
import tempfile
import time
from enum import IntEnum

from . import _data, _ffi, _store, _wire, vole


class Protocol(IntEnum):
    """PSI protocol, mirrors CRYPTEX_PSI_* in core/src/ffi/psi.rs"""

    ECDH = 0
    VOLE = 1
    #: Unbalanced sets: the receiver should hold the small set
    OPRF = 2


class Role(IntEnum):
    """PSI role"""

    SENDER = 0
    RECEIVER = 1


class Curve(IntEnum):
    """Curve for ECDH-PSI (ignored by VOLE-PSI)"""

    RISTRETTO255 = 0
    P256 = 1
    SM2 = 2
    FOURQ = 3


class BucketHash(IntEnum):
    """Hash used to assign items to buckets, mirrors CRYPTEX_BUCKET_*"""

    SHA256 = 0
    SM3 = 1


# Mirror core/src/exec.rs and core/src/algorithms/psi/bucket.rs.
MAX_THREADS = 1024
MAX_BUCKETS = 1 << 20

#: Items per bucket when `bucket_size` is not given.
DEFAULT_BUCKET_SIZE = 1_000_000

# Marks "bucket_size not given" so handshake=False can fall back to no
# bucketing without overriding an explicit choice.
_DEFAULT = object()


def _check_threads(threads):
    if isinstance(threads, bool) or not isinstance(threads, int):
        raise TypeError(f"threads must be an int, got {type(threads).__name__}")
    if not 0 <= threads <= MAX_THREADS:
        raise ValueError(f"threads must be in 0..{MAX_THREADS}, got {threads}")
    return threads


class Pool:
    """Worker threads for PSI computation, shareable across parties

    threads=0 uses a pool shared by everything with one thread per CPU;
    n > 0 starts a dedicated pool of n threads. Parties created from a pool
    keep its threads alive, so close() may be called before they finish.
    """

    def __init__(self, threads=0):
        self.threads = _check_threads(threads)
        self._lib = _ffi.lib()
        self._handle = ctypes.c_void_p()
        if self.threads:
            _ffi.check(self._lib.cryptex_pool_new(self.threads, ctypes.byref(self._handle)))

    @property
    def handle(self):
        """Raw handle for the C ABI; None means the global pool"""
        return self._handle if self._handle else None

    def close(self):
        if self._handle:
            self._lib.cryptex_pool_free(self._handle)
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


def _check_buckets(buckets):
    if isinstance(buckets, bool) or not isinstance(buckets, int):
        raise TypeError(f"buckets must be an int, got {type(buckets).__name__}")
    if not 1 <= buckets <= MAX_BUCKETS:
        raise ValueError(f"buckets must be in 1..{MAX_BUCKETS}, got {buckets}")
    return buckets


def bucket_of(items, buckets, hash=BucketHash.SHA256, pool=None):
    """Bucket number of each item, in 0..buckets-1

    Both PSI parties must use the same `buckets` and `hash`. The rule is
    public: bucket = first 8 bytes of H("CRYPTEX-PSI-BUCKET-V1" || item),
    big-endian, mod buckets.
    """
    buckets = _check_buckets(buckets)
    hash = BucketHash(hash)
    raw = [_data.to_bytes(x) for x in items]
    out = (ctypes.c_uint32 * len(raw))() if raw else None
    data, data_len, lens, count, _keep = _ffi.pack_items(raw)
    _ffi.check(_ffi.lib().cryptex_psi_bucket(
        hash, buckets, pool.handle if pool is not None else None,
        data, data_len, lens, count, out,
    ))
    return list(out) if raw else []


class PsiParty:
    """One party of a PSI session, driven by explicit step() calls

    Call order:
        initiator:      step(None) -> send, then step(peer_msg) ... until done
        non-initiator:  step(peer_msg) ... until done

    Computation runs on `pool` (a Pool), or on `threads` workers: 0 shares
    one pool (one thread per CPU) across all parties, n > 0 gives this party
    its own pool of n threads. Pass a Pool to reuse threads across parties.
    The sender starts computing as soon as it is created.

    share=True also gives the sender the result (both parties must agree):
    the receiver's last step returns a final message for the sender, after
    which the sender's result()/result_indices() are available.
    """

    def __init__(self, protocol, role, items, curve=Curve.RISTRETTO255, threads=0,
                 pool=None, sessions=1, share=False):
        self._lib = _ffi.lib()
        self.protocol = Protocol(protocol)
        self.role = Role(role)
        self.curve = Curve(curve)
        self.share = bool(share)
        self._handle = ctypes.c_void_p()
        if self.protocol == Protocol.VOLE:
            raise ValueError("VOLE-PSI is full duplex: use cryptex.VoleJob (or Psi)")
        if pool is None:
            pool = Pool(threads)
        elif threads:
            raise ValueError("pass either threads or pool, not both")
        self.threads = pool.threads
        if isinstance(items, _store.Packed):
            # A bucket loaded by the core library: passed through without
            # copying into Python objects; only result_indices() is available.
            self._items = None
            data, data_len, lens, count = items.args()
        else:
            self._items = [_data.to_bytes(x) for x in items]
            data, data_len, lens, count, _keep = _ffi.pack_items(self._items)
        _ffi.check(self._lib.cryptex_psi_new(
            self.protocol, self.role, self.curve, pool.handle, _check_buckets(sessions),
            int(self.share), data, data_len, lens, count, ctypes.byref(self._handle),
        ))
        self.done = False

    @property
    def is_initiator(self):
        out = ctypes.c_int32()
        _ffi.check(self._lib.cryptex_psi_is_initiator(self._handle, ctypes.byref(out)))
        return bool(out.value)

    def step(self, incoming):
        """Advance one step

        Args:
            incoming: Peer message, or None for the initiator's first call

        Returns:
            (message to send to the peer, done flag). When done is True an
            empty message means there is nothing left to send.
        """
        msg = _ffi.CryptexBuffer()
        done = ctypes.c_int32()
        if incoming is None:
            ptr, length, has = None, 0, 0
        else:
            incoming = bytes(incoming)
            ptr = (ctypes.c_uint8 * len(incoming)).from_buffer_copy(incoming) if incoming else None
            length, has = len(incoming), 1
        code = self._lib.cryptex_psi_step(
            self._handle, ptr, length, has, ctypes.byref(msg), ctypes.byref(done)
        )
        out = _ffi.take_buffer(msg)
        _ffi.check(code)
        self.done = bool(done.value)
        return out, self.done

    def result_indices(self):
        """Ascending indices of own items in the intersection (receiver;
        sender only with share=True)"""
        ptr = ctypes.POINTER(ctypes.c_size_t)()
        count = ctypes.c_size_t()
        _ffi.check(self._lib.cryptex_psi_result(
            self._handle, ctypes.byref(ptr), ctypes.byref(count)
        ))
        return [ptr[i] for i in range(count.value)]

    def result(self):
        """Own items in the intersection (receiver; sender only with share=True)"""
        if self._items is None:
            raise ValueError("items were passed packed; use result_indices()")
        return [self._items[i] for i in self.result_indices()]

    def close(self):
        if self._handle:
            self._lib.cryptex_psi_free(self._handle)
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


# Session header exchanged once per run(), before any PSI message: magic,
# version, protocol, role, curve, bucket hash, share flag (the receiver gives
# the sender the result), target bucket size (0 = no bucketing) and set
# size. Catches mismatched configuration and two parties with the same role
# before any cryptographic message is sent, and lets both sides derive the
# same bucket count.
_MAGIC = b"CPSI"
_VERSION = 4
_HEADER = struct.Struct(">4sBBBBBBIQ")


def agree_buckets(n_local, n_peer, size_local, size_peer):
    """Bucket count both parties derive from the exchanged headers

    ceil(max(n) / min(bucket_size)), at least 1 and at most MAX_BUCKETS.
    A bucket size of 0 means no bucketing and must be used by both sides.
    """
    if not size_local and not size_peer:
        return 1
    if not size_local or not size_peer:
        raise ValueError("one party uses bucketing (bucket_size) and the other does not")
    buckets = math.ceil(max(n_local, n_peer) / min(size_local, size_peer))
    return min(max(buckets, 1), MAX_BUCKETS)


def _handshake(psi, channel, n, log=None):
    """Exchange session headers; returns the agreed bucket count"""
    size = psi.bucket_size or 0
    fields = (_MAGIC, _VERSION, psi.protocol, psi.role, psi.curve,
              psi.bucket_hash, int(psi.share_result), size, n)
    channel.send(_HEADER.pack(*fields))
    if log is not None:
        log.debug("sent %d bytes: session header [%s]", _HEADER.size,
                  _wire.describe_header(fields))
    raw = channel.recv()
    if len(raw) < 5 or raw[:4] != _MAGIC:
        raise ValueError("peer is not a cryptex PSI party")
    if raw[4] != _VERSION:
        raise ValueError(f"PSI session version mismatch: local {_VERSION}, peer {raw[4]}")
    if len(raw) != _HEADER.size:
        raise ValueError("invalid PSI session header from peer")
    peer = _HEADER.unpack(raw)
    if log is not None:
        log.debug("received %d bytes: session header [%s]", len(raw),
                  _wire.describe_header(peer))
    _, _, protocol, role, curve, bucket_hash, share, peer_size, peer_n = peer
    if protocol != psi.protocol:
        raise ValueError(f"protocol mismatch: local {psi.protocol.name}, peer {protocol}")
    if role == psi.role:
        raise ValueError(f"both parties are {psi.role.name}")
    if psi.protocol != Protocol.VOLE and curve != psi.curve:
        raise ValueError(f"curve mismatch: local {psi.curve.name}, peer {curve}")
    if bool(share) != psi.share_result:
        raise ValueError(f"share_result mismatch: local {psi.share_result}, peer {bool(share)}")
    buckets = agree_buckets(n, peer_n, size, peer_size)
    if buckets > 1 and bucket_hash != psi.bucket_hash:
        raise ValueError(
            f"bucket hash mismatch: local {psi.bucket_hash.name}, peer {bucket_hash}")
    return buckets


def _drive(party, channel, log, describe=None):
    """Run a PsiParty to completion over a channel, logging each message
    (with `describe(msg)` -> summary, if given)"""
    def note(what, msg):
        if describe is None:
            log.debug("%s %d bytes", what, len(msg))
        else:
            log.debug("%s %d bytes: %s", what, len(msg), describe(msg))

    def recv():
        msg = channel.recv()
        note("received", msg)
        return msg

    def step(incoming):
        t0 = time.perf_counter()
        out = party.step(incoming)
        log.debug("step computed in %.3fs", time.perf_counter() - t0)
        return out

    msg, done = step(None if party.is_initiator else recv())
    while True:
        # Mid-protocol messages are always sent, even when empty; the final
        # message is sent only if there is one.
        if not done or msg:
            channel.send(msg)
            note("sent", msg)
        if done:
            return
        msg, done = step(recv())


# Logger names are cryptex.psi.<n>, one per Psi instance, so each instance
# can have its own file and level without affecting the others.
_LOGGER_IDS = itertools.count(1)
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class _RunLog(logging.LoggerAdapter):
    """Prefixes every record with the run number; tracks the run's steps"""

    def process(self, msg, kwargs):
        return f"run {self.extra['run']}: {msg}", kwargs

    def plan(self, total):
        self.extra.update(total=total, done=0, step="start")

    def step(self, name):
        """Enter the next step of the run (INFO)"""
        self.extra["done"] += 1
        self.extra["step"] = name
        self.info("step %d/%d: %s", self.extra["done"], self.extra["total"], name)

    @property
    def current(self):
        return self.extra.get("step", "-")

    def progress(self, b, buckets, what):
        """Per-bucket progress at INFO, at most about 100 lines per run"""
        every = max(1, buckets // 100)
        if buckets > 1 and ((b + 1) % every == 0 or b + 1 == buckets):
            self.info("PSI bucket %d/%d %s (%d%%)", b + 1, buckets, what,
                      100 * (b + 1) // buckets)


def _describe_input(data, column, has_header, delimiter, encoding):
    """Where the items come from, for the log (never the items)"""
    if _data.is_path(data):
        path = os.fspath(data)
        if column is None:
            return f"file {path} (one item per line, encoding {encoding})"
        header = "with header" if has_header else "no header"
        return (f"file {path}, ID column {column!r} (CSV, {header}, "
                f"delimiter {delimiter!r}, encoding {encoding})")
    if hasattr(data, "__len__"):
        return f"in-memory list of {len(data)} values"
    return "in-memory iterable"


def _make_logger(log_file, log_level):
    logger = logging.getLogger(f"{__name__}.{next(_LOGGER_IDS)}")
    if log_level is not None:
        logger.setLevel(log_level)
    handler = None
    if log_file is not None:
        handler = logging.FileHandler(os.fspath(log_file), encoding="utf-8")
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)
        # Our own file gets the records; don't also echo them to the app's
        # root handlers.
        logger.propagate = False
    return logger, handler


class Psi:
    """PSI runner: configure once, then run on a data set

    Args:
        protocol: Protocol.ECDH, Protocol.VOLE, or Protocol.OPRF (unbalanced
            sets; the receiver should hold the smaller one)
        role: Role.SENDER or Role.RECEIVER
        channel: Transport to the peer, any object with send(bytes) and
            recv() -> bytes (see cryptex.Channel / CallbackChannel)
        curve: Curve for ECDH-/OPRF-PSI, must match the peer (ignored by VOLE)
        share_result: Also give the sender the intersection (default False:
            only the receiver learns it). The receiver sends the sender the
            matching positions at the end, so run() returns the sender's own
            matching items as well. Both parties must use the same setting
            (checked by the handshake). Semi-honest: the sender trusts the
            receiver's report.
        handshake: Exchange a session header first to check that both sides
            agree on protocol/curve/version and have opposite roles. The
            peer must use the same setting. Required for bucketing. Disable
            only if the platform negotiates these out of band.
        threads: Worker threads for the computation. 0 (default) uses a pool
            shared by all instances with one thread per CPU; n > 0 gives this
            instance its own pool of n threads, at most MAX_THREADS.
        bucket_size: About this many items per bucket (default 1_000_000).
            The input is streamed once into per-bucket files under
            `work_dir`, then the parties run one PSI per bucket, so only one
            bucket is held in memory at a time. The bucket count is
            ceil(larger set size / smaller bucket_size of the two parties),
            derived during the handshake. When that count is 1 the run stays
            in memory and writes no files. None disables bucketing: the whole
            set is processed in memory. Both parties must either bucket or
            not. With handshake=False the default falls back to None.
        bucket_hash: BucketHash.SHA256 (default) or BucketHash.SM3. Both
            parties must use the same one.
        work_dir: Directory for the temporary bucket files (default: the
            system temp directory). They hold a plaintext copy of the input
            and are deleted as soon as each bucket is done.
        on_bucket: Optional callback(index, buckets, size) called after each
            bucket finishes, e.g. for progress reporting.
        log_file: Append this instance's log to the given file (UTF-8). If
            omitted, records go to the standard `logging` hierarchy under
            the "cryptex.psi" logger and appear wherever the application
            configures them.
        log_level: Level for this instance's logger, e.g. logging.DEBUG or
            "INFO". Defaults to INFO when log_file is given, otherwise
            inherited from "cryptex.psi".

    Bucketing leaks the per-bucket set sizes to the peer (a coarse histogram
    of item hashes), never the items. Both parties learn each other's
    (approximate) set size from the handshake, as PSI already reveals it.

    Logs contain stages, timings, set sizes and message lengths, never the
    items or the intersection.

    Each run() is one PSI job (all buckets); the channel may be reused for
    several runs as long as the peer runs the same number of jobs. Call
    close() (or use `with`) to release the log file and worker threads.
    """

    def __init__(self, protocol, role, channel, curve=Curve.RISTRETTO255,
                 share_result=False, handshake=True, threads=0, bucket_size=_DEFAULT,
                 bucket_hash=BucketHash.SHA256, work_dir=None, on_bucket=None,
                 log_file=None, log_level=None):
        self.protocol = Protocol(protocol)
        self.role = Role(role)
        self.curve = Curve(curve)
        self.share_result = bool(share_result)
        if self.share_result and self.protocol == Protocol.OPRF:
            raise ValueError("OPRF-PSI does not support share_result")
        if not (callable(getattr(channel, "send", None))
                and callable(getattr(channel, "recv", None))):
            raise TypeError("channel must provide send(bytes) and recv() -> bytes")
        self.channel = channel
        self.handshake = bool(handshake)
        if bucket_size is _DEFAULT:
            # Bucketing needs the handshake to agree on the bucket count.
            bucket_size = DEFAULT_BUCKET_SIZE if self.handshake else None
        if bucket_size is not None:
            if isinstance(bucket_size, bool) or not isinstance(bucket_size, int):
                raise TypeError(f"bucket_size must be an int, got {type(bucket_size).__name__}")
            if not 1 <= bucket_size < 1 << 32:
                raise ValueError(f"bucket_size must be in 1..2^32-1, got {bucket_size}")
            if not self.handshake:
                raise ValueError("bucket_size needs handshake=True to agree on the bucket count")
        self.bucket_size = bucket_size
        self.bucket_hash = BucketHash(bucket_hash)
        if work_dir is not None and not os.path.isdir(work_dir):
            raise ValueError(f"work_dir {os.fspath(work_dir)!r} is not a directory")
        self.work_dir = work_dir
        if on_bucket is not None and not callable(on_bucket):
            raise TypeError("on_bucket must be callable")
        self.on_bucket = on_bucket
        if log_level is None and log_file is not None:
            log_level = logging.INFO
        # Validate everything before acquiring resources (threads, file).
        self.pool = Pool(threads)
        self.threads = self.pool.threads
        self.log, self._log_handler = _make_logger(log_file, log_level)
        self._runs = 0

    def run(self, data, *, column=None, has_header=True, delimiter=",",
            encoding=_data.DEFAULT_ENCODING, output=None):
        """Run one PSI job

        Args:
            data: Items as a list/iterable of str/bytes, or a file path:
                text file with one item per line, or a CSV when `column` is
                given. Whitespace in files is stripped, empty values are
                skipped and duplicates are removed (first occurrence kept).
            column: CSV column by header name or 0-based index
            has_header: Whether the CSV has a header row
            delimiter: CSV delimiter
            encoding: Input file encoding
            output: Write the intersection to this file, one item per line
                (UTF-8), streaming, instead of returning it. Receiver, or
                sender with share_result=True.

        Returns:
            Own items in the intersection, in input order (items read from a
            file are str); or, when `output` is given, the number of items
            written. The sender gets None unless share_result=True.

        With bucketing, a file given as `data` is read twice (partitioning,
        then collecting the result) and must not change in between.
        """
        if output is not None and not self.has_result:
            raise ValueError("the sender has no result to write (share_result=False)")
        self._runs += 1
        log = _RunLog(self.log, {"run": self._runs})
        log.info("input: %s; output: %s",
                 _describe_input(data, column, has_header, delimiter, encoding),
                 f"file {os.fspath(output)}" if output is not None
                 else ("returned to the caller" if self.has_result else "none (sender)"))
        # Steps: [load input] [handshake] [load/partition input] PSI [result].
        in_memory = self.bucket_size is None
        log.plan(int(in_memory) + int(self.handshake) + int(not in_memory) + 1
                 + int(self.has_result))
        t0 = time.perf_counter()
        try:
            if self.bucket_size is None:
                result = self._run_in_memory(data, column, has_header, delimiter,
                                             encoding, output, log)
            else:
                result = self._run_bucketed(data, column, has_header, delimiter,
                                            encoding, output, log)
        except Exception as e:
            # Stack trace included; exception messages never contain items
            # (only sizes, paths, CSV column names, peer settings).
            log.error("failed in step '%s' after %.3fs: %s: %s", log.current,
                      time.perf_counter() - t0, type(e).__name__, e, exc_info=True)
            raise

        if result is None:
            log.info("done in %.3fs", time.perf_counter() - t0)
        else:
            size = result if isinstance(result, int) else len(result)
            log.info("done in %.3fs, intersection size %d", time.perf_counter() - t0, size)
        return result

    @property
    def has_result(self):
        """Whether run() gives this party the intersection"""
        return self.role == Role.RECEIVER or self.share_result

    def _log_start(self, log, n, approx=False):
        log.info("start %s-PSI as %s, curve=%s, share_result=%s, threads=%s, "
                 "bucket_size=%s, %s%d items",
                 self.protocol.name, self.role.name,
                 self.curve.name if self.protocol != Protocol.VOLE else "-",
                 self.share_result, self.threads or "auto", self.bucket_size or "-",
                 "~" if approx else "", n)

    def _describe(self, msg):
        return _wire.describe(self.protocol, self.curve, msg)

    def _session(self, items, buckets, log):
        """One PSI session over `items` (bytes); result indices if this
        party has a result, else None"""
        with PsiParty(self.protocol, self.role, items, self.curve,
                      pool=self.pool, sessions=buckets, share=self.share_result) as party:
            _drive(party, self.channel, log, self._describe)
            if self.has_result:
                return party.result_indices()
        return None

    def _finish(self, selected, count, output, log):
        """Return or write the selected items"""
        if output is None:
            log.step("return the intersection to the caller")
            return list(selected)
        log.step(f"write the intersection to {os.fspath(output)}")
        _data.write_items(output, selected)
        log.info("wrote intersection to %s", os.fspath(output))
        return count

    def _run_in_memory(self, data, column, has_header, delimiter, encoding, output, log):
        log.step("load input")
        items = _data.load_items(data, column=column, has_header=has_header,
                                 delimiter=delimiter, encoding=encoding)
        self._log_start(log, len(items))
        if self.handshake:
            log.step("handshake")
            _handshake(self, self.channel, len(items), log)
            log.debug("handshake ok")
        return self._run_single(items, output, log)

    def _run_single(self, items, output, log):
        """One bucket held in memory; identical on the wire to a bucketed
        run with a single bucket"""
        log.step(f"{self.protocol.name}-PSI, 1 bucket of {len(items)} items")
        if self.protocol == Protocol.VOLE:
            hits = self._vole_job([len(items)], lambda b: items, log)
            hits = hits[0] if hits is not None else None
        else:
            hits = self._session(items, 1, log)
        if hits is None:
            return None
        return self._finish((items[i] for i in hits), len(hits), output, log)

    def _vole_job(self, sizes, load_bucket, log, consume=None):
        """Run one VOLE-PSI job over all buckets

        If this party has a result, each bucket's result indices go to
        `consume(b, indices)` as soon as they arrive; without `consume`
        they are collected and returned as a list per bucket.
        """
        receiver = self.role == Role.RECEIVER
        has_result = self.has_result
        results = [[] for _ in sizes] if has_result and consume is None else None
        t0 = time.perf_counter()

        def on_result(b, indices):
            if consume is not None:
                consume(b, indices)
            else:
                results[b] = indices
            log.debug("bucket %d/%d: %d matches, %.3fs elapsed",
                      b + 1, len(sizes), len(indices), time.perf_counter() - t0)
            log.progress(b, len(sizes), "done")
            if self.on_bucket is not None:
                self.on_bucket(b, len(sizes), sizes[b])

        def load(b):
            items = load_bucket(b)
            if not has_result:
                # No per-bucket results on this side: loading is the progress.
                log.progress(b, len(sizes), "loaded")
            return items

        role = vole.JobRole.RECEIVER if receiver else vole.JobRole.SENDER
        with vole.VoleJob(role, sizes, self.pool, share=self.share_result) as job:
            vole.drive(job, self.channel, load,
                       on_result if has_result else None, log, self._describe)
        if not has_result:
            # A party without a result sees no per-bucket completion (the
            # job answers buckets internally); report the whole job.
            log.debug("all %d buckets answered, %d items, %.3fs elapsed",
                      len(sizes), sum(sizes), time.perf_counter() - t0)
            if self.on_bucket is not None:
                for b, size in enumerate(sizes):
                    self.on_bucket(b, len(sizes), size)
        return results

    def _run_bucketed(self, data, column, has_header, delimiter, encoding, output, log):
        if _data.is_path(data):
            def values():
                return _data.iter_file_items(data, column, has_header, delimiter, encoding)
            n = _data.estimate_items(data, has_header, column)
        elif isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("pass a list of items or a file path, not a single bytes value")
        else:
            if column is not None:
                raise ValueError("column only applies to file input")
            if not isinstance(data, (list, tuple)):
                data = list(data)
            values = data.__iter__
            n = len(data)
        self._log_start(log, n, approx=_data.is_path(data))

        log.step("handshake")
        buckets = _handshake(self, self.channel, n, log)
        log.info("handshake ok, %d buckets", buckets)
        if buckets == 1:
            # Small enough for one bucket: skip the temporary files.
            log.step("load input")
            items = _data.dedupe(values())
            log.debug("single bucket of %d items, kept in memory", len(items))
            return self._run_single(items, output, log)

        has_result = self.has_result  # track positions to collect the result
        # Partitioning, deduplication and position tracking run in the core
        # library; a UTF-8 text file is even read there, without passing
        # through Python.
        bom = _store.native_text(data, column, encoding)
        with tempfile.TemporaryDirectory(prefix="cryptex-psi-", dir=self.work_dir) as tmp, \
                _store.Store(tmp, buckets, self.bucket_hash, has_result, self.pool) as store:
            log.step(f"partition input into {buckets} buckets under {tmp}")
            t = time.perf_counter()
            if bom is not None:
                store.add_lines(data, bom)
            else:
                store.add_values(values())
            if self.protocol == Protocol.VOLE:
                sizes = store.compact()
                total = store.finish()
            else:
                total = store.finish()
            log.info("partitioned %d values into %d buckets in %.3fs",
                     total, buckets, time.perf_counter() - t)

            log.step(f"{self.protocol.name}-PSI over {buckets} buckets")
            if self.protocol == Protocol.VOLE:
                count = self._run_vole_buckets(store, sizes, has_result, log)
            else:
                count = self._run_ecdh_buckets(store, buckets, has_result, log)
            if not has_result:
                return None
            if output is not None and bom is not None:
                log.step(f"write the intersection to {os.fspath(output)}")
                written = store.write_lines(data, bom, output)
                log.info("wrote intersection to %s", os.fspath(output))
                return written
            bitmap = store.bitmap()
        return self._finish(_data.select_positions(values(), bitmap, total), count, output, log)

    def _run_ecdh_buckets(self, store, buckets, has_result, log):
        """One ECDH-PSI session per bucket; returns the match count"""
        count = 0
        for b in range(buckets):
            tb = time.perf_counter()
            items = store.load(b)
            n = len(items)
            hits = self._session(items, buckets, log)
            if has_result:
                store.mark(b, hits)
                count += len(hits)
            log.debug("bucket %d/%d: %d items, %s matches in %.3fs",
                      b + 1, buckets, n, len(hits) if has_result else "-",
                      time.perf_counter() - tb)
            log.progress(b, buckets, "done")
            if self.on_bucket is not None:
                self.on_bucket(b, buckets, n)
        return count

    def _run_vole_buckets(self, store, sizes, has_result, log):
        """All buckets in one pipelined VOLE-PSI job; returns the match count"""
        count = [0]

        def consume(b, hits):
            store.mark(b, hits)
            count[0] += len(hits)

        self._vole_job(sizes, store.load, log, consume if has_result else None)
        return count[0]

    def close(self):
        """Release the log file and worker threads. The channel is not closed."""
        self.pool.close()
        if self._log_handler is not None:
            self.log.removeHandler(self._log_handler)
            self._log_handler.close()
            self._log_handler = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
