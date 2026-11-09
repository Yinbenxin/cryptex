"""
Low-level ctypes loader and error handling for the cryptex core library.
"""

import array
import ctypes
import os
import sys
from pathlib import Path

# Status codes, mirror core/src/ffi/mod.rs
OK = 0
ERR_INVALID_INPUT = -1
ERR_INVALID_KEY_SIZE = -2
ERR_OPERATION_FAILED = -3
ERR_NOT_IMPLEMENTED = -4
ERR_INVALID_STATE = -5
ERR_PANIC = -99


class CryptexError(Exception):
    """Error returned by the cryptex core library"""

    def __init__(self, code, message):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class CryptexBuffer(ctypes.Structure):
    """Library-owned byte buffer, released with cryptex_buffer_free"""

    _fields_ = [("ptr", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


class CryptexPirDbInfo(ctypes.Structure):
    """State of a PIR database, mirrors core/src/ffi/pir.rs"""

    _fields_ = [
        ("curve", ctypes.c_int32),
        ("segments", ctypes.c_uint32),
        ("records", ctypes.c_uint64),
        ("max_label_len", ctypes.c_uint32),
        ("generation", ctypes.c_uint64),
        ("metadata", ctypes.POINTER(ctypes.c_uint8)),
        ("metadata_len", ctypes.c_size_t),
    ]


class CryptexPirParams(ctypes.Structure):
    """Public parameters of a served PIR snapshot, mirrors core/src/ffi/pir.rs"""

    _fields_ = [
        ("curve", ctypes.c_int32),
        ("log2_buckets", ctypes.c_uint32),
        ("records", ctypes.c_uint64),
        ("padded_len", ctypes.c_uint32),
        ("generation", ctypes.c_uint64),
        ("metadata", ctypes.POINTER(ctypes.c_uint8)),
        ("metadata_len", ctypes.c_size_t),
    ]


def _library_name():
    if sys.platform == "win32":
        return "cryptex.dll"
    if sys.platform == "darwin":
        return "libcryptex.dylib"
    return "libcryptex.so"


def find_library():
    """Locate the cryptex shared library

    Search order: $CRYPTEX_LIB, package lib/ directory, core/target/release.
    """
    env = os.environ.get("CRYPTEX_LIB")
    if env:
        return env

    name = _library_name()
    search_paths = [
        Path(__file__).parent / "lib",
        Path(__file__).resolve().parents[3] / "core" / "target" / "release",
    ]
    for search_path in search_paths:
        lib_path = search_path / name
        if lib_path.exists():
            return str(lib_path)

    raise FileNotFoundError(f"Could not find cryptex library: {name}")


def _setup(lib):
    """Declare function signatures"""
    c_int, c_size_t, c_void_p = ctypes.c_int32, ctypes.c_size_t, ctypes.c_void_p
    u8_p = ctypes.POINTER(ctypes.c_uint8)
    size_p = ctypes.POINTER(c_size_t)

    # c_void_p (not c_char_p) keeps the raw pointer so it can be freed
    lib.cryptex_version.restype = c_void_p
    lib.cryptex_version.argtypes = []
    lib.cryptex_free_string.restype = None
    lib.cryptex_free_string.argtypes = [c_void_p]

    lib.cryptex_last_error.restype = ctypes.c_char_p
    lib.cryptex_last_error.argtypes = []
    lib.cryptex_buffer_free.restype = None
    lib.cryptex_buffer_free.argtypes = [CryptexBuffer]

    lib.cryptex_pool_new.restype = c_int
    lib.cryptex_pool_new.argtypes = [c_size_t, ctypes.POINTER(c_void_p)]
    lib.cryptex_pool_free.restype = None
    lib.cryptex_pool_free.argtypes = [c_void_p]

    lib.cryptex_psi_new.restype = c_int
    lib.cryptex_psi_new.argtypes = [
        c_int, c_int, c_int, c_void_p, ctypes.c_uint32, c_int,
        u8_p, c_size_t, size_p, c_size_t, ctypes.POINTER(c_void_p),
    ]
    lib.cryptex_psi_bucket.restype = c_int
    lib.cryptex_psi_bucket.argtypes = [
        c_int, ctypes.c_uint32, c_void_p, u8_p, c_size_t, size_p, c_size_t,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    lib.cryptex_psi_is_initiator.restype = c_int
    lib.cryptex_psi_is_initiator.argtypes = [c_void_p, ctypes.POINTER(c_int)]
    lib.cryptex_psi_step.restype = c_int
    lib.cryptex_psi_step.argtypes = [
        c_void_p, u8_p, c_size_t, c_int,
        ctypes.POINTER(CryptexBuffer), ctypes.POINTER(c_int),
    ]
    lib.cryptex_psi_result.restype = c_int
    lib.cryptex_psi_result.argtypes = [
        c_void_p, ctypes.POINTER(size_p), size_p,
    ]
    lib.cryptex_psi_free.restype = None
    lib.cryptex_psi_free.argtypes = [c_void_p]

    i32_p = ctypes.POINTER(c_int)
    u32_p = ctypes.POINTER(ctypes.c_uint32)
    lib.cryptex_vole_job_new.restype = c_int
    lib.cryptex_vole_job_new.argtypes = [
        c_int, c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64), c_int,
        ctypes.POINTER(c_void_p),
    ]
    lib.cryptex_vole_job_need.restype = c_int
    lib.cryptex_vole_job_need.argtypes = [c_void_p, u32_p, i32_p]
    lib.cryptex_vole_job_provide.restype = c_int
    lib.cryptex_vole_job_provide.argtypes = [
        c_void_p, ctypes.c_uint32, u8_p, c_size_t, size_p, c_size_t,
    ]
    lib.cryptex_vole_job_receive.restype = c_int
    lib.cryptex_vole_job_receive.argtypes = [c_void_p, u8_p, c_size_t]
    lib.cryptex_vole_job_next_send.restype = c_int
    lib.cryptex_vole_job_next_send.argtypes = [c_void_p, ctypes.POINTER(CryptexBuffer), i32_p]
    lib.cryptex_vole_job_take_result.restype = c_int
    lib.cryptex_vole_job_take_result.argtypes = [
        c_void_p, u32_p, ctypes.POINTER(size_p), size_p, i32_p,
    ]
    lib.cryptex_vole_job_status.restype = c_int
    lib.cryptex_vole_job_status.argtypes = [c_void_p, i32_p, i32_p]
    lib.cryptex_vole_job_free.restype = None
    lib.cryptex_vole_job_free.argtypes = [c_void_p]

    u64_p = ctypes.POINTER(ctypes.c_uint64)
    lib.cryptex_store_new.restype = c_int
    lib.cryptex_store_new.argtypes = [
        u8_p, c_size_t, ctypes.c_uint32, c_int, c_int, c_void_p, ctypes.POINTER(c_void_p),
    ]
    lib.cryptex_store_add.restype = c_int
    lib.cryptex_store_add.argtypes = [c_void_p, u8_p, c_size_t, size_p, c_size_t]
    lib.cryptex_store_add_lines.restype = c_int
    lib.cryptex_store_add_lines.argtypes = [c_void_p, u8_p, c_size_t, c_int]
    lib.cryptex_store_finish.restype = c_int
    lib.cryptex_store_finish.argtypes = [c_void_p, u64_p]
    lib.cryptex_store_compact.restype = c_int
    lib.cryptex_store_compact.argtypes = [c_void_p, u64_p, ctypes.c_uint32]
    lib.cryptex_store_load.restype = c_int
    lib.cryptex_store_load.argtypes = [
        c_void_p, ctypes.c_uint32, ctypes.POINTER(u8_p), size_p, ctypes.POINTER(size_p), size_p,
    ]
    lib.cryptex_store_mark.restype = c_int
    lib.cryptex_store_mark.argtypes = [c_void_p, ctypes.c_uint32, size_p, c_size_t, u64_p]
    lib.cryptex_store_bitmap.restype = c_int
    lib.cryptex_store_bitmap.argtypes = [c_void_p, ctypes.POINTER(u8_p), size_p]
    lib.cryptex_store_write_lines.restype = c_int
    lib.cryptex_store_write_lines.argtypes = [
        c_void_p, u8_p, c_size_t, c_int, u8_p, c_size_t, u64_p,
    ]
    lib.cryptex_store_free.restype = None
    lib.cryptex_store_free.argtypes = [c_void_p]

    dbinfo_p = ctypes.POINTER(CryptexPirDbInfo)
    params_p = ctypes.POINTER(CryptexPirParams)
    buf_p = ctypes.POINTER(CryptexBuffer)
    out_p = ctypes.POINTER(c_void_p)
    lib.cryptex_pir_db_create.restype = c_int
    lib.cryptex_pir_db_create.argtypes = [
        u8_p, c_size_t, c_int, u8_p, u8_p, c_size_t, c_void_p, out_p,
    ]
    lib.cryptex_pir_db_open.restype = c_int
    lib.cryptex_pir_db_open.argtypes = [u8_p, c_size_t, u8_p, c_void_p, out_p]
    lib.cryptex_pir_db_upsert.restype = c_int
    lib.cryptex_pir_db_upsert.argtypes = [
        c_void_p, u8_p, c_size_t, size_p, u8_p, c_size_t, size_p, c_size_t,
    ]
    lib.cryptex_pir_db_delete.restype = c_int
    lib.cryptex_pir_db_delete.argtypes = [c_void_p, u8_p, c_size_t, size_p, c_size_t]
    lib.cryptex_pir_db_commit.restype = c_int
    lib.cryptex_pir_db_commit.argtypes = [c_void_p, dbinfo_p]
    lib.cryptex_pir_db_rollback.restype = c_int
    lib.cryptex_pir_db_rollback.argtypes = [c_void_p]
    lib.cryptex_pir_db_compact.restype = c_int
    lib.cryptex_pir_db_compact.argtypes = [c_void_p, dbinfo_p]
    lib.cryptex_pir_db_info.restype = c_int
    lib.cryptex_pir_db_info.argtypes = [c_void_p, dbinfo_p, u64_p]
    lib.cryptex_pir_db_free.restype = None
    lib.cryptex_pir_db_free.argtypes = [c_void_p]
    lib.cryptex_pir_server_open.restype = c_int
    lib.cryptex_pir_server_open.argtypes = [
        u8_p, c_size_t, u8_p, ctypes.c_uint64, c_int, c_void_p, out_p,
    ]
    lib.cryptex_pir_server_reload.restype = c_int
    lib.cryptex_pir_server_reload.argtypes = [c_void_p, i32_p]
    lib.cryptex_pir_server_free.restype = None
    lib.cryptex_pir_server_free.argtypes = [c_void_p]
    lib.cryptex_pir_session_new.restype = c_int
    lib.cryptex_pir_session_new.argtypes = [c_void_p, out_p]
    lib.cryptex_pir_session_params.restype = c_int
    lib.cryptex_pir_session_params.argtypes = [
        c_void_p, ctypes.POINTER(u8_p), size_p, params_p,
    ]
    lib.cryptex_pir_session_query.restype = c_int
    lib.cryptex_pir_session_query.argtypes = [
        c_void_p, u8_p, c_size_t, c_size_t, buf_p, size_p,
    ]
    lib.cryptex_pir_session_fetch.restype = c_int
    lib.cryptex_pir_session_fetch.argtypes = [c_void_p, u8_p, c_size_t, size_p]
    lib.cryptex_pir_session_next.restype = c_int
    lib.cryptex_pir_session_next.argtypes = [c_void_p, buf_p, i32_p]
    lib.cryptex_pir_session_free.restype = None
    lib.cryptex_pir_session_free.argtypes = [c_void_p]
    lib.cryptex_pir_client_new.restype = c_int
    lib.cryptex_pir_client_new.argtypes = [
        u8_p, c_size_t, u8_p, c_size_t, size_p, c_size_t, c_void_p, out_p,
    ]
    lib.cryptex_pir_client_params.restype = c_int
    lib.cryptex_pir_client_params.argtypes = [c_void_p, params_p]
    lib.cryptex_pir_client_query.restype = c_int
    lib.cryptex_pir_client_query.argtypes = [c_void_p, buf_p, size_p]
    lib.cryptex_pir_client_receive.restype = c_int
    lib.cryptex_pir_client_receive.argtypes = [c_void_p, u8_p, c_size_t, buf_p, i32_p]
    lib.cryptex_pir_client_results.restype = c_int
    lib.cryptex_pir_client_results.argtypes = [
        c_void_p, ctypes.POINTER(u8_p), size_p, ctypes.POINTER(size_p), ctypes.POINTER(u8_p),
        size_p,
    ]
    lib.cryptex_pir_client_free.restype = None
    lib.cryptex_pir_client_free.argtypes = [c_void_p]


_lib = None


def lib(lib_path=None):
    """Load the library once and return the ctypes handle"""
    global _lib
    if _lib is None:
        handle = ctypes.CDLL(lib_path or find_library())
        _setup(handle)
        _lib = handle
    return _lib


def check(code):
    """Raise CryptexError for a non-zero status code"""
    if code != OK:
        msg = lib().cryptex_last_error()
        raise CryptexError(code, msg.decode("utf-8") if msg else "unknown error")


def take_buffer(buf):
    """Copy a library-owned buffer into bytes and free it"""
    try:
        return ctypes.string_at(buf.ptr, buf.len) if buf.len else b""
    finally:
        lib().cryptex_buffer_free(buf)


_SIZE_T_CODE = {4: "I", 8: "Q"}[ctypes.sizeof(ctypes.c_size_t)]
if array.array(_SIZE_T_CODE).itemsize != ctypes.sizeof(ctypes.c_size_t):  # pragma: no cover
    _SIZE_T_CODE = "L"


def pack_items(items):
    """Concatenate byte items for the C ABI

    Returns (data pointer, data length, lens pointer, count, keepalive). The
    pointers stay valid while `keepalive` is referenced.
    """
    data = b"".join(items)
    lens = array.array(_SIZE_T_CODE, map(len, items))
    data_buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data) if data else None
    lens_buf = (ctypes.c_size_t * len(lens)).from_buffer(lens) if lens else None
    return data_buf, len(data), lens_buf, len(lens), (data_buf, lens, lens_buf)
