//! C ABI exports for keyword PIR (`algorithms::pir`).
//!
//! Writer (one per database directory at a time):
//! `cryptex_pir_db_create` or `cryptex_pir_db_open`, then any number of
//! `cryptex_pir_db_upsert` / `cryptex_pir_db_delete` followed by
//! `cryptex_pir_db_commit`; `cryptex_pir_db_compact` from time to time;
//! `cryptex_pir_db_free`.
//!
//! Server: `cryptex_pir_server_open` (shared by any number of threads),
//! `cryptex_pir_server_reload` after commits. Per client:
//! `cryptex_pir_session_new`, send `cryptex_pir_session_params`, pass the
//! client's query to `cryptex_pir_session_query` and send the eval
//! message back, pass the client's fetch message to
//! `cryptex_pir_session_fetch`, then send every message from
//! `cryptex_pir_session_next` until it reports done.
//!
//! Client: `cryptex_pir_client_new` from the params message, send
//! `cryptex_pir_client_query`, feed every server message to
//! `cryptex_pir_client_receive` (sending back the message it returns,
//! if any) until it reports done, then read `cryptex_pir_client_results`.
//!
//! Paths are byte strings as in `cryptex_store_new`. The library performs
//! no network IO. A handle must not be used from two threads at once,
//! except a server handle.

use std::slice;

use super::guard;
use super::psi::{bytes, executor, parse_curve, split_slices, CryptexPool};
use super::store::path;
use super::CryptexBuffer;
use crate::algorithms::pir::{Client, Database, DbInfo, Padding, Params, Server, Session};
use crate::{Error, Result};

/// `Padding::Max`: pad bodies to the longest label (default).
pub const CRYPTEX_PIR_PAD_MAX: i32 = 0;
/// `Padding::None`: send bodies at their real length.
pub const CRYPTEX_PIR_PAD_NONE: i32 = 1;

/// State of a database as the writer sees it. `metadata` points into the
/// handle it came from.
#[repr(C)]
#[derive(Debug)]
pub struct CryptexPirDbInfo {
    /// `CRYPTEX_CURVE_*`.
    pub curve: i32,
    /// Number of segments.
    pub segments: u32,
    /// Live records (exact after compaction, an estimate otherwise).
    pub records: u64,
    /// Longest label since the last compaction.
    pub max_label_len: u32,
    /// Increases with every commit and compaction.
    pub generation: u64,
    /// Metadata stored with the database.
    pub metadata: *const u8,
    /// Metadata length.
    pub metadata_len: usize,
}

/// Public parameters of a served snapshot. `metadata` points into the
/// handle it came from.
#[repr(C)]
#[derive(Debug)]
pub struct CryptexPirParams {
    /// `CRYPTEX_CURVE_*`.
    pub curve: i32,
    /// `2^log2_buckets` buckets.
    pub log2_buckets: u32,
    /// Live records.
    pub records: u64,
    /// Bodies are padded to this length (0 = not padded).
    pub padded_len: u32,
    /// Snapshot generation.
    pub generation: u64,
    /// Metadata stored with the database.
    pub metadata: *const u8,
    /// Metadata length.
    pub metadata_len: usize,
}

fn curve_code(curve: crate::algorithms::pir::Curve) -> i32 {
    use crate::algorithms::pir::Curve;
    use crate::ffi::psi::{
        CRYPTEX_CURVE_FOURQ, CRYPTEX_CURVE_P256, CRYPTEX_CURVE_RISTRETTO255, CRYPTEX_CURVE_SM2,
    };
    match curve {
        Curve::Ristretto255 => CRYPTEX_CURVE_RISTRETTO255,
        Curve::P256 => CRYPTEX_CURVE_P256,
        Curve::Sm2 => CRYPTEX_CURVE_SM2,
        Curve::FourQ => CRYPTEX_CURVE_FOURQ,
    }
}

fn db_info_of(i: &DbInfo) -> CryptexPirDbInfo {
    CryptexPirDbInfo {
        curve: curve_code(i.curve),
        segments: i.segments,
        records: i.records,
        max_label_len: i.max_label_len,
        generation: i.generation,
        metadata: i.metadata.as_ptr(),
        metadata_len: i.metadata.len(),
    }
}

fn params_of(p: &Params) -> CryptexPirParams {
    CryptexPirParams {
        curve: curve_code(p.curve),
        log2_buckets: u32::from(p.log2_buckets),
        records: p.records,
        padded_len: p.padded_len,
        generation: p.generation,
        metadata: p.metadata.as_ptr(),
        metadata_len: p.metadata.len(),
    }
}

/// # Safety
///
/// `p` must be null or a live handle not used concurrently.
unsafe fn handle<'a, T>(p: *mut T, what: &str) -> Result<&'a mut T> {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { p.as_mut() }.ok_or_else(|| Error::InvalidInput(format!("null {what} handle")))
}

/// # Safety
///
/// `ptr` must be null or point to 32 readable bytes.
unsafe fn seed(ptr: *const u8) -> Result<[u8; 32]> {
    // SAFETY: guaranteed by the caller contract above.
    let s = unsafe { bytes(ptr, 32)? };
    Ok(s.try_into().expect("32 bytes"))
}

/// # Safety
///
/// `lens` must be null or point to `count` readable values.
unsafe fn lens<'a>(lens: *const usize, count: usize) -> Result<&'a [usize]> {
    if count == 0 {
        Ok(&[])
    } else if lens.is_null() {
        Err(Error::InvalidInput("null lens pointer".into()))
    } else {
        // SAFETY: guaranteed by the caller contract above.
        Ok(unsafe { slice::from_raw_parts(lens, count) })
    }
}

/// # Safety
///
/// `out` must be null or writable.
unsafe fn put<T>(out: *mut T, v: T) -> Result<()> {
    if out.is_null() {
        return Err(Error::InvalidInput("null output pointer".into()));
    }
    // SAFETY: guaranteed by the caller contract above.
    unsafe { out.write(v) };
    Ok(())
}

/// # Safety
///
/// `out` must be null or writable.
unsafe fn put_buffer(out: *mut CryptexBuffer, msg: Vec<u8>) -> Result<()> {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { put(out, CryptexBuffer::from_vec(msg)) }
}

// ---- writer ----

/// Opaque database writer handle.
pub struct CryptexPirDb {
    db: Database,
    info: DbInfo,
}

impl CryptexPirDb {
    fn refresh(&mut self) -> &DbInfo {
        self.info = self.db.info();
        &self.info
    }
}

/// Create an empty database in directory `dir` (created if missing; must
/// be empty otherwise). `curve` is a `CRYPTEX_CURVE_*` value (SM2 uses SM3
/// and SM4 throughout); `seed` points to the 32-byte long-term secret
/// (keep it to open the database). `metadata` is given to clients as is.
/// Release with `cryptex_pir_db_free`.
///
/// # Safety
///
/// `dir` / `metadata` must point to `dir_len` / `metadata_len` readable
/// bytes, `seed_ptr` to 32, `pool` must be null or a live pool and `out`
/// writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_create(
    dir: *const u8,
    dir_len: usize,
    curve: i32,
    seed_ptr: *const u8,
    metadata: *const u8,
    metadata_len: usize,
    pool: *const CryptexPool,
    out: *mut *mut CryptexPirDb,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (d, mut s, meta, exec) = unsafe {
            (
                path(dir, dir_len)?,
                seed(seed_ptr)?,
                bytes(metadata, metadata_len)?.to_vec(),
                executor(pool),
            )
        };
        let db = Database::create_with(&d, parse_curve(curve)?, &s, meta, exec);
        zeroize::Zeroize::zeroize(&mut s);
        let db = db?;
        let info = db.info();
        // SAFETY: `out` is writable per the caller contract.
        unsafe { put(out, Box::into_raw(Box::new(CryptexPirDb { db, info }))) }
    })
}

/// Open an existing database for writing. Fails with
/// `CRYPTEX_ERR_INVALID_STATE` if another writer has it open and
/// `CRYPTEX_ERR_INVALID_INPUT` if the seed does not match.
///
/// # Safety
///
/// As `cryptex_pir_db_create`.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_open(
    dir: *const u8,
    dir_len: usize,
    seed_ptr: *const u8,
    pool: *const CryptexPool,
    out: *mut *mut CryptexPirDb,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (d, mut s, exec) = unsafe { (path(dir, dir_len)?, seed(seed_ptr)?, executor(pool)) };
        let db = Database::open_with(&d, &s, exec);
        zeroize::Zeroize::zeroize(&mut s);
        let db = db?;
        let info = db.info();
        // SAFETY: `out` is writable per the caller contract.
        unsafe { put(out, Box::into_raw(Box::new(CryptexPirDb { db, info }))) }
    })
}

/// Insert or replace records: keys and labels each laid out as items in
/// `cryptex_psi_new`, `count` of each; key `i` maps to label `i`. Labels
/// may have any length (up to the 32-bit length field, about 4 GiB). Takes
/// effect on `cryptex_pir_db_commit`.
///
/// # Safety
///
/// `db` must be a live handle; data pointers must point to the given number
/// of readable bytes and lens pointers to `count` readable values.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_upsert(
    db: *mut CryptexPirDb,
    keys: *const u8,
    keys_len: usize,
    key_lens: *const usize,
    labels: *const u8,
    labels_len: usize,
    label_lens: *const usize,
    count: usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (db, k, kl, l, ll) = unsafe {
            (
                handle(db, "database")?,
                bytes(keys, keys_len)?,
                lens(key_lens, count)?,
                bytes(labels, labels_len)?,
                lens(label_lens, count)?,
            )
        };
        db.db.upsert(&split_slices(k, kl)?, &split_slices(l, ll)?)
    })
}

/// Delete records by key; missing keys are ignored. Takes effect on
/// `cryptex_pir_db_commit`.
///
/// # Safety
///
/// `db` must be a live handle, `keys` point to `keys_len` readable bytes
/// and `key_lens` to `count` values.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_delete(
    db: *mut CryptexPirDb,
    keys: *const u8,
    keys_len: usize,
    key_lens: *const usize,
    count: usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (db, k, kl) = unsafe {
            (
                handle(db, "database")?,
                bytes(keys, keys_len)?,
                lens(key_lens, count)?,
            )
        };
        db.db.delete(&split_slices(k, kl)?)
    })
}

/// Publish the pending operations as a new segment (within one batch the
/// last operation on a key wins). `*out` (optional) receives the new
/// state; its pointers stay valid until the next call on this handle.
///
/// # Safety
///
/// `db` must be a live handle and `out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_commit(
    db: *mut CryptexPirDb,
    out: *mut CryptexPirDbInfo,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let db = unsafe { handle(db, "database")? };
        db.db.commit()?;
        let info = db_info_of(db.refresh());
        if !out.is_null() {
            // SAFETY: non-null and writable per the caller contract.
            unsafe { out.write(info) };
        }
        Ok(())
    })
}

/// Discard the operations added since the last commit.
///
/// # Safety
///
/// `db` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_rollback(db: *mut CryptexPirDb) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        unsafe { handle(db, "database")? }.db.rollback();
        Ok(())
    })
}

/// Merge all segments into one, dropping deleted and replaced records
/// (commits pending operations first). `*out` as in `cryptex_pir_db_commit`.
///
/// # Safety
///
/// `db` must be a live handle and `out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_compact(
    db: *mut CryptexPirDb,
    out: *mut CryptexPirDbInfo,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let db = unsafe { handle(db, "database")? };
        db.db.compact()?;
        let info = db_info_of(db.refresh());
        if !out.is_null() {
            // SAFETY: non-null and writable per the caller contract.
            unsafe { out.write(info) };
        }
        Ok(())
    })
}

/// Current committed state; pointers valid until the next call on `db`.
/// `*out_pending` (optional) receives the number of uncommitted operations.
///
/// # Safety
///
/// `db` must be a live handle, `out` writable and `out_pending` null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_info(
    db: *mut CryptexPirDb,
    out: *mut CryptexPirDbInfo,
    out_pending: *mut u64,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let db = unsafe { handle(db, "database")? };
        if !out_pending.is_null() {
            // SAFETY: non-null and writable per the caller contract.
            unsafe { out_pending.write(db.db.pending()) };
        }
        let info = db_info_of(db.refresh());
        // SAFETY: as above.
        unsafe { put(out, info) }
    })
}

/// Close the writer; uncommitted operations are discarded.
///
/// # Safety
///
/// `db` must be null or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_db_free(db: *mut CryptexPirDb) {
    if !db.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { Box::from_raw(db) });
    }
}

// ---- server ----

/// Opaque handle of a database opened for queries.
pub struct CryptexPirServer(Server);

/// Open the database in `dir` for queries with its seed. `bucket_size`:
/// about this many records per bucket (the bucket count is a power of
/// two). `padding` is `CRYPTEX_PIR_PAD_*`. Release with
/// `cryptex_pir_server_free`; sessions keep their snapshot open until they
/// are freed.
///
/// # Safety
///
/// `dir` must point to `dir_len` readable bytes, `seed_ptr` to 32, `pool`
/// must be null or a live pool and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_server_open(
    dir: *const u8,
    dir_len: usize,
    seed_ptr: *const u8,
    bucket_size: u64,
    padding: i32,
    pool: *const CryptexPool,
    out: *mut *mut CryptexPirServer,
) -> i32 {
    guard(|| {
        let padding = match padding {
            CRYPTEX_PIR_PAD_MAX => Padding::Max,
            CRYPTEX_PIR_PAD_NONE => Padding::None,
            p => return Err(Error::InvalidInput(format!("unknown PIR padding {p}"))),
        };
        // SAFETY: guaranteed by the caller contract above.
        let (d, mut s, exec) = unsafe { (path(dir, dir_len)?, seed(seed_ptr)?, executor(pool)) };
        let server = Server::open_with(&d, &s, bucket_size, padding, exec);
        zeroize::Zeroize::zeroize(&mut s);
        let handle = Box::new(CryptexPirServer(server?));
        // SAFETY: `out` is writable per the caller contract.
        unsafe { put(out, Box::into_raw(handle)) }
    })
}

/// Switch to the latest committed state. `*out_changed` (optional) is 1
/// if it changed. Safe to call while other threads run sessions.
///
/// # Safety
///
/// `s` must be a live handle and `out_changed` null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_server_reload(
    s: *const CryptexPirServer,
    out_changed: *mut i32,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { s.as_ref() }
            .ok_or_else(|| Error::InvalidInput("null server handle".into()))?;
        let changed = s.0.reload()?;
        if !out_changed.is_null() {
            // SAFETY: non-null and writable per the caller contract.
            unsafe { out_changed.write(i32::from(changed)) };
        }
        Ok(())
    })
}

/// Free a server handle.
///
/// # Safety
///
/// `s` must be null or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_server_free(s: *mut CryptexPirServer) {
    if !s.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { Box::from_raw(s) });
    }
}

/// Opaque handle of one client's exchange.
pub struct CryptexPirSession {
    session: Session,
    failed: bool,
}

impl CryptexPirSession {
    fn run<T>(&mut self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        if self.failed {
            return Err(Error::InvalidState(
                "PIR session: an earlier step failed".into(),
            ));
        }
        let r = f(&mut self.session);
        if r.is_err() {
            self.failed = true;
        }
        r
    }
}

/// Start a session on the server's current snapshot. Release with
/// `cryptex_pir_session_free`.
///
/// # Safety
///
/// `s` must be a live server handle and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_session_new(
    s: *const CryptexPirServer,
    out: *mut *mut CryptexPirSession,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { s.as_ref() }
            .ok_or_else(|| Error::InvalidInput("null server handle".into()))?;
        let session = s.0.session()?;
        let h = Box::new(CryptexPirSession {
            session,
            failed: false,
        });
        // SAFETY: `out` is writable per the caller contract.
        unsafe { put(out, Box::into_raw(h)) }
    })
}

/// The params message (send it first) and, optionally, the parsed
/// parameters. Pointers point into the session; do not free them.
///
/// # Safety
///
/// `s` must be a live handle, `out` / `out_len` writable, `out_params`
/// null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_session_params(
    s: *mut CryptexPirSession,
    out: *mut *const u8,
    out_len: *mut usize,
    out_params: *mut CryptexPirParams,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let s = unsafe { handle(s, "session")? };
        let msg = s.session.params();
        // SAFETY: as above.
        unsafe {
            if !out_params.is_null() {
                out_params.write(params_of(s.session.info()));
            }
            put(out_len, msg.len())?;
            put(out, msg.as_ptr())
        }
    })
}

/// Evaluate the client's query; `*out_msg` is the eval message to send
/// back (release with `cryptex_buffer_free`). `max_keywords` > 0 rejects
/// larger queries. `*out_keywords` (optional) receives the keyword count.
/// Any error leaves the session unusable.
///
/// # Safety
///
/// `s` must be a live handle, `msg` point to `msg_len` readable bytes,
/// `out_msg` writable and `out_keywords` null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_session_query(
    s: *mut CryptexPirSession,
    msg: *const u8,
    msg_len: usize,
    max_keywords: usize,
    out_msg: *mut CryptexBuffer,
    out_keywords: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (s, m) = unsafe { (handle(s, "session")?, bytes(msg, msg_len)?) };
        let reply = s.run(|ss| ss.query(m, max_keywords))?;
        // SAFETY: as above.
        unsafe {
            if !out_keywords.is_null() {
                out_keywords.write(s.session.keywords());
            }
            put_buffer(out_msg, reply)
        }
    })
}

/// Accept the client's fetch message. `*out_buckets` (optional) receives
/// the number of buckets requested.
///
/// # Safety
///
/// `s` must be a live handle, `msg` point to `msg_len` readable bytes and
/// `out_buckets` null or writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_session_fetch(
    s: *mut CryptexPirSession,
    msg: *const u8,
    msg_len: usize,
    out_buckets: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (s, m) = unsafe { (handle(s, "session")?, bytes(msg, msg_len)?) };
        s.run(|ss| ss.fetch(m))?;
        if !out_buckets.is_null() {
            // SAFETY: non-null and writable per the caller contract.
            unsafe { out_buckets.write(s.session.buckets().len()) };
        }
        Ok(())
    })
}

/// Next chunk of the reply. `*out_done` is 1 once the reply is complete
/// (then `*out_msg` is empty); otherwise send `*out_msg` and release it
/// with `cryptex_buffer_free`.
///
/// # Safety
///
/// `s` must be a live handle and `out_msg` / `out_done` writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_session_next(
    s: *mut CryptexPirSession,
    out_msg: *mut CryptexBuffer,
    out_done: *mut i32,
) -> i32 {
    guard(|| {
        if out_msg.is_null() || out_done.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        unsafe {
            *out_msg = CryptexBuffer::empty();
            *out_done = 0;
        }
        // SAFETY: as above.
        let s = unsafe { handle(s, "session")? };
        let next = s.run(Session::next_chunk)?;
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            match next {
                Some(msg) => *out_msg = CryptexBuffer::from_vec(msg),
                None => *out_done = 1,
            }
        }
        Ok(())
    })
}

/// Free a session.
///
/// # Safety
///
/// `s` must be null or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_session_free(s: *mut CryptexPirSession) {
    if !s.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { Box::from_raw(s) });
    }
}

// ---- client ----

/// Opaque client handle for one query.
pub struct CryptexPirClient {
    client: Client,
    failed: bool,
    /// Results laid out for `cryptex_pir_client_results`.
    labels: Vec<u8>,
    lens: Vec<usize>,
    found: Vec<u8>,
    ready: bool,
}

impl CryptexPirClient {
    fn run<T>(&mut self, f: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        if self.failed {
            return Err(Error::InvalidState(
                "PIR client: an earlier step failed".into(),
            ));
        }
        let r = f(&mut self.client);
        if r.is_err() {
            self.failed = true;
        }
        r
    }
}

/// Client for `count` keywords (laid out as items in `cryptex_psi_new`)
/// against the snapshot described by the server's params message.
/// Duplicate keywords are queried once. Release with
/// `cryptex_pir_client_free`.
///
/// # Safety
///
/// `params` must point to `params_len` readable bytes, `data` to
/// `data_len`, `lens_ptr` to `count` values; `pool` must be null or a live
/// pool and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_client_new(
    params: *const u8,
    params_len: usize,
    data: *const u8,
    data_len: usize,
    lens_ptr: *const usize,
    count: usize,
    pool: *const CryptexPool,
    out: *mut *mut CryptexPirClient,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let (params, data, lens, exec) = unsafe {
            (
                bytes(params, params_len)?,
                bytes(data, data_len)?,
                lens(lens_ptr, count)?,
                executor(pool),
            )
        };
        let keywords = split_slices(data, lens)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        let client = Client::with_executor(params, keywords, exec)?;
        let handle = Box::new(CryptexPirClient {
            client,
            failed: false,
            labels: Vec::new(),
            lens: Vec::new(),
            found: Vec::new(),
            ready: false,
        });
        // SAFETY: `out` is writable per the caller contract.
        unsafe { put(out, Box::into_raw(handle)) }
    })
}

/// The server snapshot's parameters (pointers valid until the client is
/// freed).
///
/// # Safety
///
/// `c` must be a live handle and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_client_params(
    c: *const CryptexPirClient,
    out: *mut CryptexPirParams,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let c = unsafe { c.as_ref() }
            .ok_or_else(|| Error::InvalidInput("null client handle".into()))?;
        // SAFETY: as above.
        unsafe { put(out, params_of(c.client.params())) }
    })
}

/// The query message (call once). Release `*out_msg` with
/// `cryptex_buffer_free`. `*out_keywords` (optional) receives the number
/// of distinct keywords.
///
/// # Safety
///
/// `c` must be a live handle, `out_msg` writable, `out_keywords` null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_client_query(
    c: *mut CryptexPirClient,
    out_msg: *mut CryptexBuffer,
    out_keywords: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let c = unsafe { handle(c, "client")? };
        let msg = c.run(Client::query)?;
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            if !out_keywords.is_null() {
                out_keywords.write(c.client.distinct());
            }
            put_buffer(out_msg, msg)
        }
    })
}

/// Process one server message. If `*out_reply` is non-empty, send it to
/// the server (release it with `cryptex_buffer_free`); `*out_done` is 1
/// once the reply is complete. Any error leaves the client unusable.
///
/// # Safety
///
/// `c` must be a live handle, `msg` must point to `msg_len` readable bytes
/// and `out_reply` / `out_done` be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_client_receive(
    c: *mut CryptexPirClient,
    msg: *const u8,
    msg_len: usize,
    out_reply: *mut CryptexBuffer,
    out_done: *mut i32,
) -> i32 {
    guard(|| {
        if out_reply.is_null() || out_done.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        unsafe {
            *out_reply = CryptexBuffer::empty();
            *out_done = 0;
        }
        // SAFETY: as above.
        let (c, m) = unsafe { (handle(c, "client")?, bytes(msg, msg_len)?) };
        let reply = c.run(|cl| cl.receive(m))?;
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_reply = CryptexBuffer::from_vec(reply.unwrap_or_default());
            *out_done = i32::from(c.client.is_done());
        }
        Ok(())
    })
}

/// Results, one per input keyword in input order: `found[i]` is 1 if the
/// database has keyword `i`, and its label is the next `lens[i]` bytes of
/// `labels` (`lens[i]` is 0 when not found). All pointers point into the
/// handle and stay valid until it is freed. Fails until
/// `cryptex_pir_client_receive` reported done.
///
/// # Safety
///
/// `c` must be a live handle and every output pointer writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_client_results(
    c: *mut CryptexPirClient,
    out_labels: *mut *const u8,
    out_labels_len: *mut usize,
    out_lens: *mut *const usize,
    out_found: *mut *const u8,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let c = unsafe { handle(c, "client")? };
        if !c.ready {
            if c.failed {
                return Err(Error::InvalidState(
                    "PIR client: an earlier step failed".into(),
                ));
            }
            let results = c.client.results()?;
            let (mut labels, mut lens, mut found) = (Vec::new(), Vec::new(), Vec::new());
            for r in results {
                found.push(u8::from(r.is_some()));
                let l = r.unwrap_or_default();
                lens.push(l.len());
                labels.extend_from_slice(l);
            }
            (c.labels, c.lens, c.found, c.ready) = (labels, lens, found, true);
        }
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            put(out_labels, c.labels.as_ptr())?;
            put(out_labels_len, c.labels.len())?;
            put(out_lens, c.lens.as_ptr())?;
            put(out_found, c.found.as_ptr())?;
            put(out_count, c.found.len())
        }
    })
}

/// Free a client handle.
///
/// # Safety
///
/// `c` must be null or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pir_client_free(c: *mut CryptexPirClient) {
    if !c.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { Box::from_raw(c) });
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::super::{cryptex_buffer_free, CRYPTEX_ERR_INVALID_INPUT, CRYPTEX_OK};
    use super::*;
    use crate::ffi::psi::CRYPTEX_CURVE_SM2;

    fn take(buf: CryptexBuffer) -> Vec<u8> {
        let v = if buf.len == 0 {
            Vec::new()
        } else {
            // SAFETY: a live library buffer of `len` bytes.
            unsafe { slice::from_raw_parts(buf.ptr, buf.len) }.to_vec()
        };
        // SAFETY: freed once.
        unsafe { cryptex_buffer_free(buf) };
        v
    }

    fn pack(items: &[&[u8]]) -> (Vec<u8>, Vec<usize>) {
        (items.concat(), items.iter().map(|x| x.len()).collect())
    }

    /// Run one query; returns (found, lens, labels).
    unsafe fn query(s: *const CryptexPirServer, kws: &[&[u8]]) -> (Vec<u8>, Vec<usize>, Vec<u8>) {
        unsafe {
            let mut sess = ptr::null_mut();
            assert_eq!(cryptex_pir_session_new(s, &mut sess), CRYPTEX_OK);
            let (mut pp, mut pl) = (ptr::null(), 0);
            let mut params = std::mem::zeroed::<CryptexPirParams>();
            assert_eq!(
                cryptex_pir_session_params(sess, &mut pp, &mut pl, &mut params),
                CRYPTEX_OK
            );
            assert_eq!(params.curve, CRYPTEX_CURVE_SM2);

            let (q, ql) = pack(kws);
            let mut c = ptr::null_mut();
            assert_eq!(
                cryptex_pir_client_new(
                    pp,
                    pl,
                    q.as_ptr(),
                    q.len(),
                    ql.as_ptr(),
                    kws.len(),
                    ptr::null(),
                    &mut c
                ),
                CRYPTEX_OK
            );
            let mut msg = CryptexBuffer::empty();
            assert_eq!(
                cryptex_pir_client_query(c, &mut msg, ptr::null_mut()),
                CRYPTEX_OK
            );
            let query = take(msg);
            let mut eval = CryptexBuffer::empty();
            let mut kw = 0;
            assert_eq!(
                cryptex_pir_session_query(sess, query.as_ptr(), query.len(), 0, &mut eval, &mut kw),
                CRYPTEX_OK
            );
            let eval = take(eval);
            let (mut reply, mut done) = (CryptexBuffer::empty(), 0);
            assert_eq!(
                cryptex_pir_client_receive(c, eval.as_ptr(), eval.len(), &mut reply, &mut done),
                CRYPTEX_OK
            );
            let fetch = take(reply);
            assert!(!fetch.is_empty() && done == 0);
            assert_eq!(
                cryptex_pir_session_fetch(sess, fetch.as_ptr(), fetch.len(), ptr::null_mut()),
                CRYPTEX_OK
            );
            loop {
                let (mut m, mut sdone) = (CryptexBuffer::empty(), 0);
                assert_eq!(
                    cryptex_pir_session_next(sess, &mut m, &mut sdone),
                    CRYPTEX_OK
                );
                if sdone == 1 {
                    break;
                }
                let m = take(m);
                let mut r = CryptexBuffer::empty();
                assert_eq!(
                    cryptex_pir_client_receive(c, m.as_ptr(), m.len(), &mut r, &mut done),
                    CRYPTEX_OK
                );
                assert!(take(r).is_empty());
            }
            cryptex_pir_session_free(sess);
            assert_eq!(done, 1);
            let (mut lp, mut lt, mut lens, mut found, mut n) =
                (ptr::null(), 0, ptr::null(), ptr::null(), 0);
            assert_eq!(
                cryptex_pir_client_results(c, &mut lp, &mut lt, &mut lens, &mut found, &mut n),
                CRYPTEX_OK
            );
            let out = (
                slice::from_raw_parts(found, n).to_vec(),
                slice::from_raw_parts(lens, n).to_vec(),
                if lt == 0 {
                    Vec::new()
                } else {
                    slice::from_raw_parts(lp, lt).to_vec()
                },
            );
            cryptex_pir_client_free(c);
            out
        }
    }

    #[test]
    fn round_trip_through_c_abi() {
        let dir = std::env::temp_dir().join(format!("cryptex-ffi-pir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap().as_bytes();
        let seed = [1u8; 32];
        unsafe {
            let mut db = ptr::null_mut();
            assert_eq!(
                cryptex_pir_db_create(
                    d.as_ptr(),
                    d.len(),
                    CRYPTEX_CURVE_SM2,
                    seed.as_ptr(),
                    b"m".as_ptr(),
                    1,
                    ptr::null(),
                    &mut db
                ),
                CRYPTEX_OK
            );
            let (k, kl) = pack(&[b"alice", b"bob", b"carol"]);
            let (l, ll) = pack(&[b"1", b"", b"333"]);
            assert_eq!(
                cryptex_pir_db_upsert(
                    db,
                    k.as_ptr(),
                    k.len(),
                    kl.as_ptr(),
                    l.as_ptr(),
                    l.len(),
                    ll.as_ptr(),
                    3
                ),
                CRYPTEX_OK
            );
            let mut info = std::mem::zeroed::<CryptexPirDbInfo>();
            let mut pending = 0;
            assert_eq!(cryptex_pir_db_info(db, &mut info, &mut pending), CRYPTEX_OK);
            assert_eq!((pending, info.records), (3, 0));
            assert_eq!(cryptex_pir_db_commit(db, &mut info), CRYPTEX_OK);
            assert_eq!((info.records, info.segments, info.max_label_len), (3, 1, 3));
            assert_eq!(
                slice::from_raw_parts(info.metadata, info.metadata_len),
                b"m"
            );

            let mut s = ptr::null_mut();
            let wrong = [2u8; 32];
            assert_eq!(
                cryptex_pir_server_open(
                    d.as_ptr(),
                    d.len(),
                    wrong.as_ptr(),
                    2,
                    0,
                    ptr::null(),
                    &mut s
                ),
                CRYPTEX_ERR_INVALID_INPUT
            );
            assert_eq!(
                cryptex_pir_server_open(
                    d.as_ptr(),
                    d.len(),
                    seed.as_ptr(),
                    2,
                    9,
                    ptr::null(),
                    &mut s
                ),
                CRYPTEX_ERR_INVALID_INPUT
            );
            assert_eq!(
                cryptex_pir_server_open(
                    d.as_ptr(),
                    d.len(),
                    seed.as_ptr(),
                    2,
                    CRYPTEX_PIR_PAD_MAX,
                    ptr::null(),
                    &mut s
                ),
                CRYPTEX_OK
            );
            let (found, lens, labels) = query(s, &[b"bob", b"zed", b"carol", b"bob"]);
            assert_eq!(found, [1, 0, 1, 1]);
            assert_eq!(lens, [0, 0, 3, 0]);
            assert_eq!(labels, b"333");

            // Update, delete, append; visible after reload.
            let (k, kl) = pack(&[b"bob", b"dave"]);
            let (l, ll) = pack(&[b"new bob", b"4"]);
            assert_eq!(
                cryptex_pir_db_upsert(
                    db,
                    k.as_ptr(),
                    k.len(),
                    kl.as_ptr(),
                    l.as_ptr(),
                    l.len(),
                    ll.as_ptr(),
                    2
                ),
                CRYPTEX_OK
            );
            let (k, kl) = pack(&[b"alice"]);
            assert_eq!(
                cryptex_pir_db_delete(db, k.as_ptr(), k.len(), kl.as_ptr(), 1),
                CRYPTEX_OK
            );
            assert_eq!(cryptex_pir_db_commit(db, ptr::null_mut()), CRYPTEX_OK);
            let mut changed = 0;
            assert_eq!(cryptex_pir_server_reload(s, &mut changed), CRYPTEX_OK);
            assert_eq!(changed, 1);
            let (found, _, labels) = query(s, &[b"alice", b"bob", b"dave"]);
            assert_eq!(found, [0, 1, 1]);
            assert_eq!(labels, b"new bob4");
            assert_eq!(cryptex_pir_db_compact(db, &mut info), CRYPTEX_OK);
            assert_eq!((info.records, info.segments), (3, 1));
            cryptex_pir_db_free(db);
            cryptex_pir_server_free(s);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
