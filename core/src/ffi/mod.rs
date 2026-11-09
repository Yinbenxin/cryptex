//! Foreign Function Interface (FFI) for C bindings
//!
//! This module provides C-compatible exports for use by other languages.
//! Only `crate::algorithms` is exposed here, never `crate::primitives`.
//!
//! Conventions:
//! - Fallible functions return an `i32` status code (`CRYPTEX_OK` or a
//!   negative `CRYPTEX_ERR_*`); details are available from
//!   [`cryptex_last_error`] on the same thread.
//! - Panics are caught and never unwind across the boundary.
//! - Memory allocated by the library is released by the library's own free
//!   functions.

use std::cell::RefCell;
use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::{Error, Result};

pub mod crypto;
pub mod pir;
pub mod psi;
pub mod store;
pub mod vole;

/// Success.
pub const CRYPTEX_OK: i32 = 0;
/// Invalid argument (null pointer, unknown enum value, malformed input).
pub const CRYPTEX_ERR_INVALID_INPUT: i32 = -1;
/// Invalid key size.
pub const CRYPTEX_ERR_INVALID_KEY_SIZE: i32 = -2;
/// Operation failed.
pub const CRYPTEX_ERR_OPERATION_FAILED: i32 = -3;
/// Not implemented.
pub const CRYPTEX_ERR_NOT_IMPLEMENTED: i32 = -4;
/// Call not allowed in the current state.
pub const CRYPTEX_ERR_INVALID_STATE: i32 = -5;
/// Internal panic (library bug).
pub const CRYPTEX_ERR_PANIC: i32 = -99;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn error_code(err: &Error) -> i32 {
    match err {
        Error::InvalidInput(_) => CRYPTEX_ERR_INVALID_INPUT,
        Error::InvalidKeySize => CRYPTEX_ERR_INVALID_KEY_SIZE,
        Error::OperationFailed(_) => CRYPTEX_ERR_OPERATION_FAILED,
        Error::NotImplemented => CRYPTEX_ERR_NOT_IMPLEMENTED,
        Error::InvalidState(_) => CRYPTEX_ERR_INVALID_STATE,
    }
}

fn set_last_error(msg: String) {
    // Interior NULs cannot occur in our messages, but never fail here.
    let msg = CString::new(msg.replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg));
}

/// Run `f`, converting errors and panics into status codes.
pub(crate) fn guard(f: impl FnOnce() -> Result<()>) -> i32 {
    LAST_ERROR.with(|e| *e.borrow_mut() = None);
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CRYPTEX_OK,
        Ok(Err(err)) => {
            set_last_error(err.to_string());
            error_code(&err)
        }
        Err(_) => {
            set_last_error("internal panic".into());
            CRYPTEX_ERR_PANIC
        }
    }
}

/// Byte buffer owned by the library. Release with [`cryptex_buffer_free`].
#[repr(C)]
#[derive(Debug)]
pub struct CryptexBuffer {
    /// Start of the data; null when `len` is 0.
    pub ptr: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

impl CryptexBuffer {
    pub(crate) fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    pub(crate) fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let len = v.len();
        let ptr = Box::into_raw(v.into_boxed_slice()).cast::<u8>();
        Self { ptr, len }
    }
}

/// Free a buffer returned by the library.
///
/// # Safety
///
/// `buf` must come from this library and not have been freed yet.
#[no_mangle]
pub unsafe extern "C" fn cryptex_buffer_free(buf: CryptexBuffer) {
    if !buf.ptr.is_null() {
        // SAFETY: `ptr`/`len` were produced by `CryptexBuffer::from_vec`
        // from a boxed slice of exactly `len` bytes.
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
    }
}

/// Message of the last error on the calling thread, or null if the last call
/// succeeded.
///
/// The pointer is owned by the library and stays valid until the next
/// cryptex call on the same thread. Do not free it.
#[no_mangle]
pub extern "C" fn cryptex_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ref().map_or(ptr::null(), |s| s.as_ptr()))
}

/// Get library version
///
/// Returns a pointer to a null-terminated string containing the version.
/// The caller must release it with [`cryptex_free_string`].
#[no_mangle]
pub extern "C" fn cryptex_version() -> *mut c_char {
    CString::new(crate::VERSION)
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

/// Free a string allocated by the library
///
/// # Safety
///
/// `ptr` must be null or a pointer returned by this library that has not
/// been freed yet.
#[no_mangle]
pub unsafe extern "C" fn cryptex_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { CString::from_raw(ptr) });
    }
}
