"""
Keyword PIR (anonymous query), semi-honest.

The client looks up its keywords in the server's key -> label database; the
server learns only which buckets the keywords fall in (each keyword hides
among the ~bucket_size keys of its bucket), the client only the labels of
its own keywords.

    PirDatabase  create / open a database directory; upsert, delete,
                 commit, compact (incremental, labels of any length)
    PirServer    open a database, serve() one query per call, reload()
    PirClient    query(keywords) -> labels, or query_file(...)

Example:

    seed = cryptex.pir.generate_seed()      # keep it secret, e.g. in a KMS
    with PirDatabase.create("users.pir", seed) as db:
        db.load("users.csv", key_column="phone")      # upsert + commit
        db.delete(["13800000009"]); db.commit()

    # server, per connection
    with PirServer("users.pir", seed) as server:
        server.serve(channel)

    # client
    labels = PirClient(channel).query(["13800000001", "13800000002"])
"""

from __future__ import annotations

import csv
import ctypes
import io
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from enum import IntEnum

from . import _data, _ffi
from .psi import Curve, Pool

#: Records per bucket when `bucket_size` is not given.
DEFAULT_BUCKET_SIZE = 1024
#: Mirror core/src/algorithms/pir/mod.rs.
MAX_KEY_LEN = 65535
SEED_LEN = 32

# Operations handed to the core library per call.
_BATCH = 1 << 16

log = logging.getLogger(__name__)


class Padding(IntEnum):
    """How the server pads labels in replies, mirrors CRYPTEX_PIR_PAD_*"""

    #: Pad to the longest label: the client learns no label lengths
    MAX = 0
    #: Real lengths: the client learns the length of every label it downloads
    NONE = 1


def generate_seed():
    """A fresh random 32-byte server seed"""
    return secrets.token_bytes(SEED_LEN)


def _seed(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    return (ctypes.c_uint8 * SEED_LEN).from_buffer_copy(bytes(seed))


def _path(p):
    raw = os.fsencode(os.fspath(p))
    return (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw), len(raw)


def _buf(data):
    data = bytes(data)
    return ((ctypes.c_uint8 * len(data)).from_buffer_copy(data) if data else None), len(data)


def _meta(raw):
    return ctypes.string_at(raw.metadata, raw.metadata_len) if raw.metadata_len else b""


def _columns(metadata):
    try:
        meta = json.loads(metadata)
    except ValueError:
        return None
    return meta.get("columns") if isinstance(meta, dict) else None


@dataclass(frozen=True)
class DbInfo:
    """State of a database as its writer sees it

    `records` and `max_label_len` are exact after compact(); in between,
    updates count twice and `max_label_len` only grows.
    """

    curve: Curve
    records: int
    segments: int
    max_label_len: int
    generation: int
    metadata: bytes

    @classmethod
    def _from(cls, raw):
        return cls(Curve(raw.curve), raw.records, raw.segments, raw.max_label_len,
                   raw.generation, _meta(raw))

    @property
    def columns(self):
        """Label column names when the metadata came from a CSV, else None"""
        return _columns(self.metadata)


@dataclass(frozen=True)
class PirParams:
    """Public parameters of a served snapshot (known to every client)"""

    curve: Curve
    buckets: int
    records: int
    padded_len: int
    generation: int
    metadata: bytes

    @classmethod
    def _from(cls, raw):
        return cls(Curve(raw.curve), 1 << raw.log2_buckets, raw.records, raw.padded_len,
                   raw.generation, _meta(raw))

    @property
    def columns(self):
        """Label column names when the metadata came from a CSV, else None"""
        return _columns(self.metadata)


def _csv_rows(path, key_column, label_columns, has_header, delimiter, encoding):
    """(key, label) pairs of a CSV; labels are the label columns re-encoded
    as one CSV row."""
    """Returns (label column names or None, open file, row iterator); the
    caller closes the file."""
    f = open(path, encoding=encoding, newline="")
    try:
        names, rows = _csv_open(f, path, key_column, label_columns, has_header, delimiter)
    except BaseException:
        f.close()
        raise
    return names, f, rows


def _csv_open(f, path, key_column, label_columns, has_header, delimiter):
    reader = csv.reader(f, delimiter=delimiter)
    header = None
    if has_header:
        header = [h.strip() for h in next(reader, [])]

    def index(c):
        if isinstance(c, int):
            return c
        if header is None:
            raise ValueError("columns given by name require has_header=True")
        if c not in header:
            raise ValueError(f"column {c!r} not found in header {header}")
        return header.index(c)

    k = index(key_column)
    if label_columns is None:
        if header is None:
            raise ValueError("label_columns is required without a header")
        label_idx = [i for i in range(len(header)) if i != k]
    else:
        label_idx = [index(c) for c in label_columns]
    names = [header[i] for i in label_idx] if header else None

    def rows():
        for n, row in enumerate(reader, start=2 if has_header else 1):
                if not row:
                    continue
                if max(label_idx + [k]) >= len(row):
                    raise ValueError(f"{os.fspath(path)}: line {n} has {len(row)} columns")
                key = row[k].strip()
                if not key:
                    continue
                out = io.StringIO()
                csv.writer(out, delimiter=delimiter, lineterminator="").writerow(
                    [row[i] for i in label_idx])
                yield key, out.getvalue()

    return names, rows()


def _pairs(data):
    if isinstance(data, dict):
        return iter(data.items())
    return iter(data)


def csv_metadata(path, key_column, label_columns=None, has_header=True, delimiter=",",
                 encoding=_data.DEFAULT_ENCODING):
    """Metadata describing the label columns of a CSV, for
    PirDatabase.create(metadata=...); PirClient.query_file uses it to split
    labels back into columns."""
    columns, f, _rows = _csv_rows(path, key_column, label_columns, has_header, delimiter,
                                  encoding)
    f.close()
    if columns is None:
        return b""
    return json.dumps({"format": "csv", "delimiter": delimiter, "columns": columns},
                      ensure_ascii=False).encode()


class PirDatabase:
    """A PIR database directory opened for writing

    Use PirDatabase.create(...) for a new database and PirDatabase(dir,
    seed) to open an existing one. Only one writer per directory at a time;
    PirServer instances can serve it meanwhile and pick up commits with
    reload().

    upsert() and delete() are buffered (spilled to disk for large batches)
    and become visible together on commit(); within one batch the last
    operation on a key wins. Every commit adds a segment; compact() merges
    them and drops deleted and replaced records.

    Records are `F(key)[:16]` and `CTR_{F(key)[16:32]}(IV = 0, label)`: an
    update re-encrypts the key under the same keystream, so a client that
    downloads its bucket before and after learns old XOR new label (see
    docs/algorithm/pir.md).
    """

    def __init__(self, directory, seed, threads=0, _create=None):
        self._lib = _ffi.lib()
        self._handle = ctypes.c_void_p()
        self._pool = Pool(threads)
        self.directory = os.fspath(directory)
        d, dlen = _path(directory)
        if _create is None:
            _ffi.check(self._lib.cryptex_pir_db_open(
                d, dlen, _seed(seed), self._pool.handle, ctypes.byref(self._handle)))
        else:
            curve, metadata = _create
            meta, meta_len = _buf(metadata)
            _ffi.check(self._lib.cryptex_pir_db_create(
                d, dlen, Curve(curve), _seed(seed), meta, meta_len, self._pool.handle,
                ctypes.byref(self._handle)))

    @classmethod
    def create(cls, directory, seed, *, curve=Curve.RISTRETTO255, metadata=b"", threads=0):
        """Create an empty database in `directory` (created if missing,
        otherwise it must be empty)

        Args:
            seed: The server's 32-byte secret (see generate_seed). Keep it:
                the database can only be written or served with it.
            curve: OPRF curve; Curve.SM2 keeps everything on SM2/SM3/SM4.
            metadata: bytes given to clients as is, e.g. csv_metadata(...)
                so that PirClient.query_file can split labels into columns.
        """
        return cls(directory, seed, threads, _create=(curve, bytes(metadata)))

    def _check_handle(self):
        if not self._handle:
            raise ValueError("database is closed")

    def upsert(self, data):
        """Insert or replace records: a dict key -> label or an iterable of
        (key, label) pairs, str or bytes, labels of any length.
        Returns the number of records added to the batch."""
        self._check_handle()
        keys, labels, total = [], [], 0

        def flush():
            kd, kdl, kl, n, _k = _ffi.pack_items(keys)
            ld, ldl, ll, _n, _l = _ffi.pack_items(labels)
            _ffi.check(self._lib.cryptex_pir_db_upsert(self._handle, kd, kdl, kl, ld, ldl, ll, n))
            keys.clear()
            labels.clear()

        for key, label in _pairs(data):
            keys.append(_data.to_bytes(key))
            labels.append(_data.to_bytes(label))
            if len(keys) >= _BATCH:
                total += len(keys)
                flush()
        if keys:
            total += len(keys)
            flush()
        return total

    def delete(self, keys):
        """Delete records by key (missing keys are ignored). Returns the
        number of keys added to the batch."""
        self._check_handle()
        batch, total = [], 0

        def flush():
            kd, kdl, kl, n, _k = _ffi.pack_items(batch)
            _ffi.check(self._lib.cryptex_pir_db_delete(self._handle, kd, kdl, kl, n))
            batch.clear()

        for key in keys:
            batch.append(_data.to_bytes(key))
            if len(batch) >= _BATCH:
                total += len(batch)
                flush()
        if batch:
            total += len(batch)
            flush()
        return total

    def load(self, path, *, key_column, label_columns=None, has_header=True, delimiter=",",
             encoding=_data.DEFAULT_ENCODING, commit=True):
        """Upsert the rows of a CSV: the label is the `label_columns`
        (default: all other columns) re-encoded as one CSV row. Commits
        unless commit=False. Returns the number of rows."""
        _columns, f, rows = _csv_rows(path, key_column, label_columns, has_header, delimiter,
                                      encoding)
        t0 = time.perf_counter()
        with f:
            n = self.upsert(rows)
        if commit:
            self.commit()
        log.info("PIR: loaded %d rows from %s in %.3fs", n, os.fspath(path),
                 time.perf_counter() - t0)
        return n

    def _info_call(self, fn):
        raw = _ffi.CryptexPirDbInfo()
        _ffi.check(fn(self._handle, ctypes.byref(raw)))
        return DbInfo._from(raw)

    def commit(self):
        """Publish the pending operations; returns the new DbInfo"""
        self._check_handle()
        t0 = time.perf_counter()
        info = self._info_call(self._lib.cryptex_pir_db_commit)
        log.info("PIR: commit -> generation %d, %d segments, ~%d records, %.3fs",
                 info.generation, info.segments, info.records, time.perf_counter() - t0)
        return info

    def rollback(self):
        """Discard the pending operations"""
        self._check_handle()
        _ffi.check(self._lib.cryptex_pir_db_rollback(self._handle))

    def compact(self):
        """Merge all segments into one (commits first); returns the DbInfo"""
        self._check_handle()
        t0 = time.perf_counter()
        info = self._info_call(self._lib.cryptex_pir_db_compact)
        log.info("PIR: compact -> %d records, %.3fs", info.records, time.perf_counter() - t0)
        return info

    @property
    def info(self):
        """Committed state"""
        self._check_handle()
        raw = _ffi.CryptexPirDbInfo()
        _ffi.check(self._lib.cryptex_pir_db_info(self._handle, ctypes.byref(raw), None))
        return DbInfo._from(raw)

    @property
    def pending(self):
        """Operations not yet committed"""
        self._check_handle()
        raw, n = _ffi.CryptexPirDbInfo(), ctypes.c_uint64()
        _ffi.check(self._lib.cryptex_pir_db_info(self._handle, ctypes.byref(raw),
                                                 ctypes.byref(n)))
        return n.value

    def close(self):
        """Close the writer; uncommitted operations are discarded"""
        if self._handle:
            self._lib.cryptex_pir_db_free(self._handle)
            self._handle = ctypes.c_void_p()
        self._pool.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# ---- serving ----

class PirServer:
    """A database opened for queries; serve() answers one query per call

    serve() may run on several threads at once (one per connection) on the
    same PirServer. Commits made by a PirDatabase become visible after
    reload() (sessions already running keep their snapshot).

    Args:
        directory: The database directory.
        seed: The seed the database was created with.
        bucket_size: About this many records per bucket; the bucket count is
            the next power of two of records / bucket_size. Each keyword
            hides among about this many keys; the client downloads that many
            records per distinct bucket it hits.
        padding: Padding.MAX (default) pads every label to the longest one
            so clients learn no label lengths; Padding.NONE sends real
            lengths.
        max_keywords: > 0 rejects larger queries before any computation.
    """

    def __init__(self, directory, seed, *, bucket_size=DEFAULT_BUCKET_SIZE,
                 padding=Padding.MAX, max_keywords=0, threads=0, pool=None):
        if isinstance(bucket_size, bool) or not isinstance(bucket_size, int) or bucket_size < 1:
            raise ValueError("bucket_size must be a positive int")
        self._lib = _ffi.lib()
        self._handle = ctypes.c_void_p()
        self._pool = pool if pool is not None else Pool(threads)
        self.max_keywords = max_keywords
        d, dlen = _path(directory)
        _ffi.check(self._lib.cryptex_pir_server_open(
            d, dlen, _seed(seed), bucket_size, Padding(padding), self._pool.handle,
            ctypes.byref(self._handle)))

    def reload(self):
        """Switch to the latest committed state; True if it changed"""
        changed = ctypes.c_int32()
        _ffi.check(self._lib.cryptex_pir_server_reload(self._handle, ctypes.byref(changed)))
        return bool(changed.value)

    @property
    def params(self):
        """PirParams of the current snapshot"""
        session = ctypes.c_void_p()
        _ffi.check(self._lib.cryptex_pir_session_new(self._handle, ctypes.byref(session)))
        try:
            ptr, n = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
            raw = _ffi.CryptexPirParams()
            _ffi.check(self._lib.cryptex_pir_session_params(
                session, ctypes.byref(ptr), ctypes.byref(n), ctypes.byref(raw)))
            return PirParams._from(raw)
        finally:
            self._lib.cryptex_pir_session_free(session)

    def serve(self, channel):
        """Answer one query over `channel`

        Sends the params, evaluates the query, receives the bucket list and
        sends those buckets. Returns (distinct keywords, buckets fetched).
        If the client's message is rejected an empty message is sent so the
        client fails instead of waiting.
        """
        lib = self._lib
        t0 = time.perf_counter()
        session = ctypes.c_void_p()
        _ffi.check(lib.cryptex_pir_session_new(self._handle, ctypes.byref(session)))
        sent = 0

        def reply(code, buf):
            nonlocal sent
            out = _ffi.take_buffer(buf)
            if code != _ffi.OK:
                channel.send(b"")
                _ffi.check(code)
            channel.send(out)
            sent += len(out)

        try:
            ptr, n = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
            _ffi.check(lib.cryptex_pir_session_params(
                session, ctypes.byref(ptr), ctypes.byref(n), None))
            channel.send(ctypes.string_at(ptr, n.value))
            data, dlen = _buf(channel.recv())
            buf, kw = _ffi.CryptexBuffer(), ctypes.c_size_t()
            code = lib.cryptex_pir_session_query(
                session, data, dlen, self.max_keywords, ctypes.byref(buf), ctypes.byref(kw))
            reply(code, buf)
            data, dlen = _buf(channel.recv())
            buckets = ctypes.c_size_t()
            code = lib.cryptex_pir_session_fetch(session, data, dlen, ctypes.byref(buckets))
            if code != _ffi.OK:
                channel.send(b"")
                _ffi.check(code)
            while True:
                buf, done = _ffi.CryptexBuffer(), ctypes.c_int32()
                code = lib.cryptex_pir_session_next(session, ctypes.byref(buf), ctypes.byref(done))
                if done.value and code == _ffi.OK:
                    _ffi.take_buffer(buf)
                    break
                reply(code, buf)
        finally:
            lib.cryptex_pir_session_free(session)
        log.info("PIR query: %d keywords, %d buckets, %d bytes sent, %.3fs",
                 kw.value, buckets.value, sent, time.perf_counter() - t0)
        return kw.value, buckets.value

    def close(self):
        if self._handle:
            self._lib.cryptex_pir_server_free(self._handle)
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


# ---- querying ----

class PirClient:
    """Queries a PirServer over `channel`; one query per query() call

    curve: if given, refuse a server database on another curve.
    """

    def __init__(self, channel, threads=0, pool=None, curve=None):
        if not (callable(getattr(channel, "send", None))
                and callable(getattr(channel, "recv", None))):
            raise TypeError("channel must provide send(bytes) and recv() -> bytes")
        self.channel = channel
        self.curve = None if curve is None else Curve(curve)
        self._pool = pool if pool is not None else Pool(threads)
        #: PirParams of the last query's snapshot
        self.params = None

    def query(self, keywords):
        """Labels of `keywords` (str or bytes), in order: bytes, or None if
        the server has no such key. Duplicates are sent once."""
        lib = _ffi.lib()
        keys = [_data.to_bytes(k) for k in keywords]
        if any(len(k) > MAX_KEY_LEN for k in keys):
            raise ValueError(f"keywords must be at most {MAX_KEY_LEN} bytes")
        t0 = time.perf_counter()
        params = self.channel.recv()
        pdata, plen = _buf(params)
        data, data_len, lens, count, _keep = _ffi.pack_items(keys)
        handle = ctypes.c_void_p()
        _ffi.check(lib.cryptex_pir_client_new(
            pdata, plen, data, data_len, lens, count, self._pool.handle,
            ctypes.byref(handle)))
        try:
            raw = _ffi.CryptexPirParams()
            _ffi.check(lib.cryptex_pir_client_params(handle, ctypes.byref(raw)))
            self.params = PirParams._from(raw)
            if self.curve is not None and self.params.curve != self.curve:
                raise ValueError(f"server database uses {self.params.curve.name}, "
                                 f"expected {self.curve.name}")
            msg, distinct = _ffi.CryptexBuffer(), ctypes.c_size_t()
            code = lib.cryptex_pir_client_query(handle, ctypes.byref(msg), ctypes.byref(distinct))
            out = _ffi.take_buffer(msg)
            _ffi.check(code)
            self.channel.send(out)
            received = 0
            done = ctypes.c_int32()
            while not done.value:
                m = self.channel.recv()
                if not m:
                    raise ConnectionError("PIR server rejected the query")
                received += len(m)
                mdata, mlen = _buf(m)
                back = _ffi.CryptexBuffer()
                code = lib.cryptex_pir_client_receive(
                    handle, mdata, mlen, ctypes.byref(back), ctypes.byref(done))
                back = _ffi.take_buffer(back)
                _ffi.check(code)
                if back:
                    self.channel.send(back)
            lp, lt = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
            lensp, found = ctypes.POINTER(ctypes.c_size_t)(), ctypes.POINTER(ctypes.c_uint8)()
            n = ctypes.c_size_t()
            _ffi.check(lib.cryptex_pir_client_results(
                handle, ctypes.byref(lp), ctypes.byref(lt), ctypes.byref(lensp),
                ctypes.byref(found), ctypes.byref(n)))
            labels = ctypes.string_at(lp, lt.value) if lt.value else b""
            result, at = [], 0
            for i in range(n.value):
                ln = lensp[i]
                result.append(labels[at:at + ln] if found[i] else None)
                at += ln
        finally:
            lib.cryptex_pir_client_free(handle)
        log.info("PIR query: %d keywords (%d distinct), %d found, %d bytes received, %.3fs",
                 len(keys), distinct.value, sum(r is not None for r in result), received,
                 time.perf_counter() - t0)
        return result

    def query_file(self, data, output, *, column=None, has_header=True, delimiter=",",
                   encoding=_data.DEFAULT_ENCODING):
        """Query the keywords of a file (as Psi.run reads it) and write the
        hits to `output` as CSV: the keyword, then the label (split into
        the server's label columns when its metadata came from csv_metadata). Returns
        the number of hits."""
        keys = list(_data.iter_file_items(data, column, has_header, delimiter, encoding))
        labels = self.query(keys)
        columns = self.params.columns
        meta_delim = delimiter
        if columns is not None:
            meta_delim = json.loads(self.params.metadata).get("delimiter", delimiter)
        hits = 0
        with open(output, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, delimiter=delimiter)
            if columns is not None:
                w.writerow(["key"] + columns)
            for k, lab in zip(keys, labels):
                if lab is None:
                    continue
                text = lab.decode("utf-8")
                if columns is not None:
                    fields = next(csv.reader([text], delimiter=meta_delim), [])
                    w.writerow([k] + fields)
                else:
                    w.writerow([k, text])
                hits += 1
        return hits
