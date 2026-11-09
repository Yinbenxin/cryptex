//! C ABI for the on-disk bucket store of bucketed PSI runs
//! (`algorithms::psi::store`).
//!
//! Per run: `cryptex_store_new`, add the input with `cryptex_store_add` or
//! `cryptex_store_add_lines`, then `cryptex_store_compact` (VOLE-PSI, which
//! needs exact per-bucket sizes up front) or `cryptex_store_finish`
//! (ECDH-PSI). For each bucket, `cryptex_store_load` gives its distinct
//! items in the layout of `cryptex_psi_new` / `cryptex_vole_job_provide`.
//! The receiver marks each bucket's matches with `cryptex_store_mark`, then
//! reads the result with `cryptex_store_write_lines` or
//! `cryptex_store_bitmap`. `cryptex_store_free` removes any bucket files
//! that are left.
//!
//! Paths are byte strings with a length (no terminator): the OS encoding
//! on Unix, UTF-8 elsewhere. Calls on one store must not overlap.

use std::path::PathBuf;
use std::slice;

use super::guard;
use super::psi::{bucket_hash, bytes, executor, split_slices, CryptexPool};
use crate::algorithms::psi::store::{BucketStore, Loaded};
use crate::{Error, Result};

/// Opaque bucket store handle.
pub struct CryptexStore {
    store: BucketStore,
    /// Last bucket returned by `cryptex_store_load`.
    loaded: Loaded,
}

/// # Safety
///
/// `ptr` must be null or a live handle not used concurrently.
unsafe fn store<'a>(ptr: *mut CryptexStore) -> Result<&'a mut CryptexStore> {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { ptr.as_mut() }.ok_or_else(|| Error::InvalidInput("null store handle".into()))
}

/// # Safety
///
/// `ptr` must point to `len` readable bytes.
pub(crate) unsafe fn path(ptr: *const u8, len: usize) -> Result<PathBuf> {
    // SAFETY: guaranteed by the caller contract above.
    let raw = unsafe { bytes(ptr, len)? };
    if raw.is_empty() {
        return Err(Error::InvalidInput("empty path".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(raw)
            .map(PathBuf::from)
            .map_err(|_| Error::InvalidInput("path is not valid UTF-8".into()))
    }
}

/// Create a store with `buckets` files under the existing directory `dir`
/// (which should be private to this run). `hash` is a `CRYPTEX_BUCKET_*`
/// value, `track` = 1 keeps input positions for marking (the receiver),
/// `pool` as in `cryptex_psi_new`. Release with `cryptex_store_free`.
///
/// # Safety
///
/// `dir` must point to `dir_len` readable bytes, `pool` must be null or a
/// live pool handle and `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_new(
    dir: *const u8,
    dir_len: usize,
    buckets: u32,
    hash: i32,
    track: i32,
    pool: *const CryptexPool,
    out: *mut *mut CryptexStore,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(Error::InvalidInput("null output pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        let (dir, exec) = unsafe { (path(dir, dir_len)?, executor(pool)) };
        let s = BucketStore::new(&dir, buckets, bucket_hash(hash)?, track != 0, exec)?;
        let handle = Box::new(CryptexStore {
            store: s,
            loaded: Loaded::default(),
        });
        // SAFETY: `out` is writable per the caller contract.
        unsafe { *out = Box::into_raw(handle) };
        Ok(())
    })
}

/// Append items, in input order, laid out as in `cryptex_psi_new`.
///
/// # Safety
///
/// `s` must be a live handle, `data` must point to `data_len` readable
/// bytes and `lens` to `count` readable `usize` values.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_add(
    s: *mut CryptexStore,
    data: *const u8,
    data_len: usize,
    lens: *const usize,
    count: usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (s, data) = unsafe { (store(s)?, bytes(data, data_len)?) };
        let lens: &[usize] = if count == 0 {
            &[]
        } else if lens.is_null() {
            return Err(Error::InvalidInput("null lens pointer".into()));
        } else {
            // SAFETY: guaranteed by the caller contract above.
            unsafe { slice::from_raw_parts(lens, count) }
        };
        s.store.add(&split_slices(data, lens)?)
    })
}

/// Append the values of a UTF-8 text file, one per line: lines end at
/// `\n`, `\r` or `\r\n`, surrounding whitespace (as Python's `str.strip`)
/// is removed and empty values are skipped. `bom` = 1 drops a leading
/// UTF-8 BOM. Invalid UTF-8 fails with `CRYPTEX_ERR_INVALID_INPUT`.
///
/// # Safety
///
/// `s` must be a live handle and `file` point to `file_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_add_lines(
    s: *mut CryptexStore,
    file: *const u8,
    file_len: usize,
    bom: i32,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (s, file) = unsafe { (store(s)?, path(file, file_len)?) };
        s.store.add_lines(&file, bom != 0)
    })
}

/// End of input. `*out_total` (if not null) receives the number of values
/// added, duplicates included; positions run over `0..total`.
///
/// # Safety
///
/// `s` must be a live handle; `out_total` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_finish(s: *mut CryptexStore, out_total: *mut u64) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { store(s)? };
        s.store.finish()?;
        if !out_total.is_null() {
            // SAFETY: writable per the caller contract.
            unsafe { *out_total = s.store.total() };
        }
        Ok(())
    })
}

/// Finish, then drop duplicates in every bucket file; `out_sizes` receives
/// the distinct count of each of the `buckets` buckets.
///
/// # Safety
///
/// `s` must be a live handle and `out_sizes` point to `buckets` writable
/// `u64` values.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_compact(
    s: *mut CryptexStore,
    out_sizes: *mut u64,
    buckets: u32,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { store(s)? };
        if out_sizes.is_null() {
            return Err(Error::InvalidInput("null output pointer".into()));
        }
        let sizes = s.store.compact()?;
        if sizes.len() != buckets as usize {
            return Err(Error::InvalidInput(format!(
                "store has {} buckets, output has room for {buckets}",
                sizes.len()
            )));
        }
        // SAFETY: `out_sizes` holds `buckets` writable values.
        unsafe { slice::from_raw_parts_mut(out_sizes, sizes.len()) }.copy_from_slice(&sizes);
        Ok(())
    })
}

/// Load bucket `b` and delete its file. Its distinct items, in input
/// order, are returned as `*out_data` (`*out_data_len` bytes) and
/// `*out_lens` (`*out_count` lengths), owned by the store and valid until
/// the next call on it.
///
/// # Safety
///
/// `s` must be a live handle; output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_load(
    s: *mut CryptexStore,
    b: u32,
    out_data: *mut *const u8,
    out_data_len: *mut usize,
    out_lens: *mut *const usize,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { store(s)? };
        if out_data.is_null() || out_data_len.is_null() || out_lens.is_null() || out_count.is_null()
        {
            return Err(Error::InvalidInput("null output pointer".into()));
        }
        s.loaded = Loaded::default();
        s.loaded = s.store.load(b)?;
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_data = s.loaded.data.as_ptr();
            *out_data_len = s.loaded.data.len();
            *out_lens = s.loaded.lens.as_ptr();
            *out_count = s.loaded.lens.len();
        }
        Ok(())
    })
}

/// Receiver: the items at `indices` (`count` of them, into the items
/// returned by `cryptex_store_load` for bucket `b`) matched. Buckets are
/// marked in increasing order. `*out_marked` (if not null) receives the
/// total number of positions marked so far.
///
/// # Safety
///
/// `s` must be a live handle, `indices` must point to `count` readable
/// `usize` values and `out_marked` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_mark(
    s: *mut CryptexStore,
    b: u32,
    indices: *const usize,
    count: usize,
    out_marked: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { store(s)? };
        let indices: &[usize] = if count == 0 {
            &[]
        } else if indices.is_null() {
            return Err(Error::InvalidInput("null indices pointer".into()));
        } else {
            // SAFETY: guaranteed by the caller contract above.
            unsafe { slice::from_raw_parts(indices, count) }
        };
        s.store.mark(b, indices)?;
        if !out_marked.is_null() {
            // SAFETY: writable per the caller contract.
            unsafe { *out_marked = s.store.marked() };
        }
        Ok(())
    })
}

/// Receiver: the match bitmap over input positions (position `p` is bit
/// `p % 8` of byte `p / 8`), owned by the store and valid until the next
/// call on it.
///
/// # Safety
///
/// `s` must be a live handle; output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_bitmap(
    s: *mut CryptexStore,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { store(s)? };
        if out_ptr.is_null() || out_len.is_null() {
            return Err(Error::InvalidInput("null output pointer".into()));
        }
        let bm = s.store.bitmap();
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_ptr = bm.as_ptr();
            *out_len = bm.len();
        }
        Ok(())
    })
}

/// Receiver: copy the matched values of the text file `input` (read as by
/// `cryptex_store_add_lines` with the same `bom`) to `output`, one per line
/// (`\n`), in input order. `*out_written` receives the number of lines.
/// Fails with `CRYPTEX_ERR_OPERATION_FAILED` if `input` changed.
///
/// # Safety
///
/// `s` must be a live handle, `input` / `output` must point to the given
/// number of readable bytes and `out_written` must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_write_lines(
    s: *mut CryptexStore,
    input: *const u8,
    input_len: usize,
    bom: i32,
    output: *const u8,
    output_len: usize,
    out_written: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (s, input, output) = unsafe {
            (
                store(s)?,
                path(input, input_len)?,
                path(output, output_len)?,
            )
        };
        if out_written.is_null() {
            return Err(Error::InvalidInput("null output pointer".into()));
        }
        let n = s.store.write_lines(&input, bom != 0, &output)?;
        // SAFETY: writable per the caller contract.
        unsafe { *out_written = n };
        Ok(())
    })
}

/// Release a store, removing any bucket files that are left. Null is
/// ignored.
///
/// # Safety
///
/// `s` must be null or a live handle that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_store_free(s: *mut CryptexStore) {
    if !s.is_null() {
        // SAFETY: `s` came from `cryptex_store_new` and is not used again.
        drop(unsafe { Box::from_raw(s) });
    }
}
