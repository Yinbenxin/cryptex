"""
On-disk bucket store of a bucketed PSI run (core/src/ffi/store.rs).

Partitioning, per-bucket deduplication and the receiver's position
tracking all run in the core library; Python only passes file paths or
batches of values.
"""

import codecs
import ctypes
import os

from . import _data, _ffi

_BATCH = 1 << 16  # values per call when streaming from Python


def _path(p):
    raw = os.fsencode(os.fspath(p))
    return (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw), len(raw)


def native_text(data, column, encoding):
    """Whether the core library can read `data` itself: a text file (no CSV
    column) in UTF-8. Returns None if not, else whether to drop a BOM."""
    if not _data.is_path(data) or column is not None:
        return None
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        return None
    return {"utf-8-sig": True, "utf-8": False}.get(name)


class Packed:
    """Items laid out for the C ABI (data, lengths), valid while the store
    is not called again"""

    def __init__(self, data, data_len, lens, count):
        self.data, self.data_len, self.lens, self.count = data, data_len, lens, count

    def __len__(self):
        return self.count

    def args(self):
        return self.data, self.data_len, self.lens, self.count


class Store:
    """Per-bucket files under `directory`; see core/src/algorithms/psi/store.rs"""

    def __init__(self, directory, buckets, hash, track, pool=None):
        self._lib = _ffi.lib()
        self.buckets = buckets
        self._handle = ctypes.c_void_p()
        d, n = _path(directory)
        _ffi.check(self._lib.cryptex_store_new(
            d, n, buckets, hash, int(bool(track)),
            pool.handle if pool is not None else None, ctypes.byref(self._handle)))

    def add_values(self, values):
        """Stream str/bytes values in input order"""
        batch = []
        for v in values:
            batch.append(_data.to_bytes(v))
            if len(batch) >= _BATCH:
                self._add(batch)
                batch = []
        if batch:
            self._add(batch)

    def _add(self, batch):
        data, data_len, lens, count, _keep = _ffi.pack_items(batch)
        _ffi.check(self._lib.cryptex_store_add(self._handle, data, data_len, lens, count))

    def add_lines(self, path, bom):
        p, n = _path(path)
        _ffi.check(self._lib.cryptex_store_add_lines(self._handle, p, n, int(bom)))

    def finish(self):
        """End of input; returns the number of values read"""
        total = ctypes.c_uint64()
        _ffi.check(self._lib.cryptex_store_finish(self._handle, ctypes.byref(total)))
        return total.value

    def compact(self):
        """Deduplicate every bucket; returns the distinct count per bucket"""
        sizes = (ctypes.c_uint64 * self.buckets)()
        _ffi.check(self._lib.cryptex_store_compact(self._handle, sizes, self.buckets))
        return list(sizes)

    def load(self, b):
        """Distinct items of bucket `b` as a Packed (removes its file)"""
        data, data_len = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
        lens, count = ctypes.POINTER(ctypes.c_size_t)(), ctypes.c_size_t()
        _ffi.check(self._lib.cryptex_store_load(
            self._handle, b, ctypes.byref(data), ctypes.byref(data_len),
            ctypes.byref(lens), ctypes.byref(count)))
        return Packed(data, data_len.value, lens, count.value)

    def mark(self, b, indices):
        """Receiver: indices (into bucket `b`'s loaded items) that matched"""
        arr = (ctypes.c_size_t * len(indices))(*indices) if indices else None
        _ffi.check(self._lib.cryptex_store_mark(self._handle, b, arr, len(indices), None))

    def bitmap(self):
        ptr, n = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
        _ffi.check(self._lib.cryptex_store_bitmap(self._handle, ctypes.byref(ptr), ctypes.byref(n)))
        return ctypes.string_at(ptr, n.value) if n.value else b""

    def write_lines(self, input_path, bom, output):
        """Receiver: write matched lines of `input_path` to `output`"""
        i, ni = _path(input_path)
        o, no = _path(output)
        written = ctypes.c_uint64()
        _ffi.check(self._lib.cryptex_store_write_lines(
            self._handle, i, ni, int(bom), o, no, ctypes.byref(written)))
        return written.value

    def close(self):
        """Release the store and remove any bucket files left"""
        if self._handle:
            self._lib.cryptex_store_free(self._handle)
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
