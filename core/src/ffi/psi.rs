//! C ABI exports for PSI.
//!
//! A PSI party is an opaque `CryptexPsi` handle driven step by step:
//!
//! 1. `cryptex_psi_new` creates a sender or receiver over the local items,
//!    computing on a `CryptexPool` (or the global pool when null). Create
//!    one pool with `cryptex_pool_new` and reuse it across sessions, e.g.
//!    for every bucket of a bucketed run.
//! 2. The initiator (`cryptex_psi_is_initiator`) calls `cryptex_psi_step`
//!    with no input; the other party waits for the peer's first message.
//! 3. Each received message is fed to `cryptex_psi_step`, which returns the
//!    next message to send (possibly empty) and whether the party is done.
//! 4. The receiver reads its result with `cryptex_psi_result`.
//! 5. `cryptex_psi_free` releases the handle.
//!
//! The library performs no network IO: the caller owns the transport.
//!
//! Concurrency: a handle must not be used from two threads at once, but
//! independent handles may run concurrently on different threads.

use std::slice;

use super::{guard, CryptexBuffer};
use crate::algorithms::psi::bucket::{self, BucketHash};
use crate::algorithms::psi::{ecdh, oprf, Intersection};
use crate::exec::Executor;
use crate::protocol::{Party, Step};
use crate::{Error, Result};

/// ECDH-PSI.
pub const CRYPTEX_PSI_ECDH: i32 = 0;
/// VOLE-PSI.
pub const CRYPTEX_PSI_VOLE: i32 = 1;
/// OPRF-PSI for unbalanced sets: the receiver holds the small set.
pub const CRYPTEX_PSI_OPRF: i32 = 2;

/// Sender: learns nothing.
pub const CRYPTEX_PSI_SENDER: i32 = 0;
/// Receiver: learns the intersection.
pub const CRYPTEX_PSI_RECEIVER: i32 = 1;

/// Ristretto255 (ECDH- and OPRF-PSI).
pub const CRYPTEX_CURVE_RISTRETTO255: i32 = 0;
/// NIST P-256 (ECDH- and OPRF-PSI).
pub const CRYPTEX_CURVE_P256: i32 = 1;
/// SM2 (ECDH- and OPRF-PSI).
pub const CRYPTEX_CURVE_SM2: i32 = 2;
/// FourQ (ECDH- and OPRF-PSI).
pub const CRYPTEX_CURVE_FOURQ: i32 = 3;

/// Bucket by SHA-256.
pub const CRYPTEX_BUCKET_SHA256: i32 = 0;
/// Bucket by SM3.
pub const CRYPTEX_BUCKET_SM3: i32 = 1;

/// A session's output: the sender's is `Some` only when the result is
/// shared with it.
type BoxedParty = Box<dyn Party<Output = Option<Intersection>> + Send>;

/// Adapts a receiver (`Output = Intersection`) to the common session output.
struct ReceiverAdapter<P>(P);

impl<P: Party<Output = Intersection>> Party for ReceiverAdapter<P> {
    type Output = Option<Intersection>;

    fn is_initiator(&self) -> bool {
        self.0.is_initiator()
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<Self::Output>> {
        Ok(self.0.step(incoming)?.map(Some))
    }
}

/// Adapts a sender that never learns the result (`Output = ()`).
struct OutputAdapter<P>(P);

impl<P: Party<Output = ()>> Party for OutputAdapter<P> {
    type Output = Option<Intersection>;

    fn is_initiator(&self) -> bool {
        self.0.is_initiator()
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<Self::Output>> {
        Ok(self.0.step(incoming)?.map(|()| None))
    }
}

enum State {
    /// Before the first `step` call.
    Fresh,
    /// Protocol in progress.
    Running,
    /// Protocol finished; holds the receiver's result.
    Done(Option<Intersection>),
    /// A step failed; the session cannot continue.
    Failed,
}

/// Opaque worker pool handle, shareable by any number of sessions.
pub struct CryptexPool(Executor);

impl CryptexPool {
    pub(crate) fn executor(&self) -> Executor {
        self.0.clone()
    }
}

/// Create a worker pool: `threads` = 0 means rayon's global pool (one thread
/// per CPU), otherwise a dedicated pool of `threads` workers, at most 1024.
/// Release with [`cryptex_pool_free`]; sessions created from it keep its
/// threads alive until they are freed, so the pool may be freed first.
///
/// # Safety
///
/// `out` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pool_new(threads: usize, out: *mut *mut CryptexPool) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(Error::InvalidInput("null output pointer".into()));
        }
        let pool = Box::new(CryptexPool(Executor::new(threads)?));
        // SAFETY: `out` is non-null and writable per the caller contract.
        unsafe { *out = Box::into_raw(pool) };
        Ok(())
    })
}

/// Release a pool handle. Null is ignored.
///
/// # Safety
///
/// `pool` must be null or a live handle that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_pool_free(pool: *mut CryptexPool) {
    if !pool.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { Box::from_raw(pool) });
    }
}

/// Executor behind a possibly-null pool pointer.
///
/// # Safety
///
/// `pool` must be null or a live handle.
pub(crate) unsafe fn executor(pool: *const CryptexPool) -> Executor {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { pool.as_ref() }.map_or_else(Executor::default, |p| p.0.clone())
}

/// Opaque PSI session handle.
pub struct CryptexPsi {
    party: BoxedParty,
    state: State,
}

impl CryptexPsi {
    fn new(
        protocol: i32,
        role: i32,
        curve: i32,
        exec: Executor,
        buckets: u32,
        share: bool,
        items: Vec<Vec<u8>>,
    ) -> Result<Self> {
        if !(1..=bucket::MAX_BUCKETS).contains(&buckets) {
            return Err(Error::InvalidInput(format!(
                "bucket count must be in 1..={}, got {buckets}",
                bucket::MAX_BUCKETS
            )));
        }
        let party: BoxedParty = match (protocol, role) {
            (CRYPTEX_PSI_ECDH, CRYPTEX_PSI_SENDER) => Box::new(ecdh::Sender::with_executor(
                parse_curve(curve)?,
                items,
                exec,
                buckets,
                share,
            )?),
            (CRYPTEX_PSI_ECDH, CRYPTEX_PSI_RECEIVER) => Box::new(ReceiverAdapter(
                ecdh::Receiver::with_executor(parse_curve(curve)?, items, exec, buckets, share)?,
            )),
            (CRYPTEX_PSI_OPRF, _) if share => {
                return Err(Error::InvalidInput(
                    "OPRF-PSI does not support sharing the result".into(),
                ))
            }
            (CRYPTEX_PSI_OPRF, CRYPTEX_PSI_SENDER) => Box::new(OutputAdapter(
                oprf::Sender::with_executor(parse_curve(curve)?, items, exec, buckets)?,
            )),
            (CRYPTEX_PSI_OPRF, CRYPTEX_PSI_RECEIVER) => Box::new(ReceiverAdapter(
                oprf::Receiver::with_executor(parse_curve(curve)?, items, exec, buckets)?,
            )),
            (CRYPTEX_PSI_VOLE, CRYPTEX_PSI_SENDER | CRYPTEX_PSI_RECEIVER) => {
                let _ = (items, exec, buckets);
                return Err(Error::InvalidInput(
                    "VOLE-PSI runs as a job: use cryptex_vole_job_new".into(),
                ));
            }
            (CRYPTEX_PSI_ECDH | CRYPTEX_PSI_VOLE | CRYPTEX_PSI_OPRF, _) => {
                return Err(Error::InvalidInput(format!("unknown PSI role {role}")))
            }
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown PSI protocol {protocol}"
                )))
            }
        };
        Ok(Self {
            party,
            state: State::Fresh,
        })
    }

    /// Advance the session, enforcing the call order. Returns the message to
    /// send (empty if none) and whether the protocol finished.
    fn step(&mut self, incoming: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        match (&self.state, incoming) {
            (State::Done(_), _) => {
                return Err(Error::InvalidState("protocol already finished".into()))
            }
            (State::Failed, _) => return Err(Error::InvalidState("session failed earlier".into())),
            (State::Fresh, None) if !self.party.is_initiator() => {
                return Err(Error::InvalidState(
                    "non-initiator must start with the peer's first message".into(),
                ))
            }
            (State::Fresh, Some(_)) if self.party.is_initiator() => {
                return Err(Error::InvalidState(
                    "initiator must start without an incoming message".into(),
                ))
            }
            (State::Running, None) => {
                return Err(Error::InvalidState(
                    "an incoming message is required".into(),
                ))
            }
            _ => {}
        }

        match self.party.step(incoming) {
            Ok(Step::Send(msg)) => {
                self.state = State::Running;
                Ok((msg, false))
            }
            Ok(Step::Done { send, output }) => {
                self.state = State::Done(output);
                Ok((send.unwrap_or_default(), true))
            }
            Err(err) => {
                self.state = State::Failed;
                Err(err)
            }
        }
    }

    fn result(&self) -> Result<&[usize]> {
        match &self.state {
            State::Done(Some(indices)) => Ok(indices),
            State::Done(None) => Err(Error::InvalidState(
                "the sender has no PSI result (the receiver does not share it)".into(),
            )),
            _ => Err(Error::InvalidState("protocol not finished".into())),
        }
    }
}

pub(crate) fn parse_curve(curve: i32) -> Result<ecdh::Curve> {
    match curve {
        CRYPTEX_CURVE_RISTRETTO255 => Ok(ecdh::Curve::Ristretto255),
        CRYPTEX_CURVE_P256 => Ok(ecdh::Curve::P256),
        CRYPTEX_CURVE_SM2 => Ok(ecdh::Curve::Sm2),
        CRYPTEX_CURVE_FOURQ => Ok(ecdh::Curve::FourQ),
        _ => Err(Error::InvalidInput(format!("unknown curve {curve}"))),
    }
}

/// Borrow `len` bytes at `ptr`, accepting a null pointer when `len` is 0.
///
/// # Safety
///
/// If `len > 0`, `ptr` must point to `len` readable bytes.
pub(crate) unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Error::InvalidInput("null data pointer".into()));
    }
    // SAFETY: guaranteed by the caller contract above.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Split `data` into borrowed items whose lengths are given by `lens`.
pub(crate) fn split_slices<'a>(data: &'a [u8], lens: &[usize]) -> Result<Vec<&'a [u8]>> {
    let mut items = Vec::with_capacity(lens.len());
    let mut rest = data;
    for &len in lens {
        if len > rest.len() {
            return Err(Error::InvalidInput("item lengths exceed data".into()));
        }
        let (item, tail) = rest.split_at(len);
        items.push(item);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Error::InvalidInput("item lengths do not cover data".into()));
    }
    Ok(items)
}

/// Split `data` into owned items whose lengths are given by `lens`.
pub(crate) fn split_items(data: &[u8], lens: &[usize]) -> Result<Vec<Vec<u8>>> {
    Ok(split_slices(data, lens)?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect())
}

/// Create a PSI party.
///
/// Items are passed concatenated in `data` (`data_len` bytes) with the length
/// of each item in `lens` (`count` entries). `curve` is ignored for VOLE-PSI.
/// `CRYPTEX_PSI_OPRF` is the unbalanced variant (see `algorithms::psi::oprf`):
/// the receiver should hold the smaller set; items are at most 65535 bytes
/// and `share` must be 0.
/// `pool` is the worker pool to compute on, or null for rayon's global pool.
/// `buckets` is the number of sessions the whole job is split into (1 when
/// not bucketing): it widens the truncated outputs so the false-positive
/// bound holds for the whole job. Both parties must pass the same value.
/// `share` = 1 also gives the sender the result: the receiver's last step
/// returns a final message for the sender, after which the sender can read
/// its own indices with [`cryptex_psi_result`]. Both parties must pass the
/// same value (a mismatch fails the sender's first step).
/// On success `*out` receives a handle to release with [`cryptex_psi_free`].
///
/// # Safety
///
/// `pool` must be null or a live pool handle, `data` must point to
/// `data_len` readable bytes, `lens` to `count` readable `usize` values, and
/// `out` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn cryptex_psi_new(
    protocol: i32,
    role: i32,
    curve: i32,
    pool: *const CryptexPool,
    buckets: u32,
    share: i32,
    data: *const u8,
    data_len: usize,
    lens: *const usize,
    count: usize,
    out: *mut *mut CryptexPsi,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(Error::InvalidInput("null output pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        let data = unsafe { bytes(data, data_len)? };
        let lens: &[usize] = if count == 0 {
            &[]
        } else if lens.is_null() {
            return Err(Error::InvalidInput("null lens pointer".into()));
        } else {
            // SAFETY: guaranteed by the caller contract above.
            unsafe { slice::from_raw_parts(lens, count) }
        };
        let items = split_items(data, lens)?;
        // SAFETY: guaranteed by the caller contract above.
        let exec = unsafe { executor(pool) };
        let psi = CryptexPsi::new(protocol, role, curve, exec, buckets, share != 0, items)?;
        // SAFETY: `out` is non-null and writable per the caller contract.
        unsafe { *out = Box::into_raw(Box::new(psi)) };
        Ok(())
    })
}

/// Whether this party sends the first message. Writes 1 or 0 to `*out`.
///
/// # Safety
///
/// `psi` must be a live handle from [`cryptex_psi_new`] and `out` a valid
/// writable pointer.
#[no_mangle]
pub unsafe extern "C" fn cryptex_psi_is_initiator(psi: *const CryptexPsi, out: *mut i32) -> i32 {
    guard(|| {
        if psi.is_null() || out.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        unsafe { *out = i32::from((*psi).party.is_initiator()) };
        Ok(())
    })
}

/// Advance the protocol by one step.
///
/// The initiator's first call passes `has_incoming = 0`; every other call
/// passes the peer's latest message in `incoming` / `incoming_len` with
/// `has_incoming = 1`. On success `*out_msg` holds the message to send to the
/// peer (send it even when `*out_done` is 1, unless it is empty) and must be
/// released with [`cryptex_buffer_free`]; `*out_done` is 1 once this party
/// has finished. Any error leaves the session unusable.
///
/// # Safety
///
/// `psi` must be a live handle, `incoming` must point to `incoming_len`
/// readable bytes when `has_incoming` is non-zero, and `out_msg` /
/// `out_done` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn cryptex_psi_step(
    psi: *mut CryptexPsi,
    incoming: *const u8,
    incoming_len: usize,
    has_incoming: i32,
    out_msg: *mut CryptexBuffer,
    out_done: *mut i32,
) -> i32 {
    guard(|| {
        if psi.is_null() || out_msg.is_null() || out_done.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        unsafe {
            *out_msg = CryptexBuffer::empty();
            *out_done = 0;
        }
        let incoming = if has_incoming != 0 {
            // SAFETY: guaranteed by the caller contract above.
            Some(unsafe { bytes(incoming, incoming_len)? })
        } else {
            None
        };
        // SAFETY: `psi` is a live, exclusively borrowed handle.
        let (msg, done) = unsafe { (*psi).step(incoming)? };
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_msg = CryptexBuffer::from_vec(msg);
            *out_done = i32::from(done);
        }
        Ok(())
    })
}

/// Read the result: indices into this party's own items that are in the
/// intersection, in ascending order. Available to the receiver, and to the
/// sender when the session was created with `share` = 1.
///
/// `*out_indices` points into memory owned by the handle and stays valid
/// until [`cryptex_psi_free`]. Do not free it.
///
/// # Safety
///
/// `psi` must be a live handle and `out_indices` / `out_count` valid
/// writable pointers.
#[no_mangle]
pub unsafe extern "C" fn cryptex_psi_result(
    psi: *const CryptexPsi,
    out_indices: *mut *const usize,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        if psi.is_null() || out_indices.is_null() || out_count.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        let indices = unsafe { (*psi).result()? };
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_indices = indices.as_ptr();
            *out_count = indices.len();
        }
        Ok(())
    })
}

/// `CRYPTEX_BUCKET_*` to the bucket hash.
pub(crate) fn bucket_hash(hash: i32) -> Result<BucketHash> {
    match hash {
        CRYPTEX_BUCKET_SHA256 => Ok(BucketHash::Sha256),
        CRYPTEX_BUCKET_SM3 => Ok(BucketHash::Sm3),
        _ => Err(Error::InvalidInput(format!("unknown bucket hash {hash}"))),
    }
}

/// Assign each item to a bucket in `0..buckets` (see
/// `algorithms::psi::bucket`). Items are passed as in [`cryptex_psi_new`];
/// `out` receives `count` bucket numbers. `pool` as in `cryptex_psi_new`.
///
/// # Safety
///
/// `pool` must be null or a live pool handle, `data` must point to
/// `data_len` readable bytes, `lens` to `count` readable `usize` values,
/// and `out` to `count` writable `u32` values.
#[no_mangle]
pub unsafe extern "C" fn cryptex_psi_bucket(
    hash: i32,
    buckets: u32,
    pool: *const CryptexPool,
    data: *const u8,
    data_len: usize,
    lens: *const usize,
    count: usize,
    out: *mut u32,
) -> i32 {
    guard(|| {
        let hash = bucket_hash(hash)?;
        // SAFETY: guaranteed by the caller contract above.
        let data = unsafe { bytes(data, data_len)? };
        let (lens, out): (&[usize], &mut [u32]) = if count == 0 {
            (&[], &mut [])
        } else if lens.is_null() || out.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        } else {
            // SAFETY: guaranteed by the caller contract above.
            unsafe {
                (
                    slice::from_raw_parts(lens, count),
                    slice::from_raw_parts_mut(out, count),
                )
            }
        };
        let items = split_slices(data, lens)?;
        // SAFETY: guaranteed by the caller contract above.
        let exec = unsafe { executor(pool) };
        bucket::assign_into(hash, buckets, &items, out, &exec)
    })
}

/// Release a PSI handle. Null is ignored.
///
/// # Safety
///
/// `psi` must be null or a live handle that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_psi_free(psi: *mut CryptexPsi) {
    if !psi.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { Box::from_raw(psi) });
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use crate::exec::MAX_THREADS;

    use super::super::{cryptex_last_error, CRYPTEX_OK};
    use super::*;

    fn ecdh(role: i32) -> CryptexPsi {
        CryptexPsi::new(
            CRYPTEX_PSI_ECDH,
            role,
            CRYPTEX_CURVE_SM2,
            Executor::default(),
            1,
            false,
            vec![b"a".to_vec()],
        )
        .unwrap()
    }

    #[test]
    fn split_items_checks_lengths() {
        assert_eq!(
            split_items(b"abcde", &[2, 0, 3]).unwrap(),
            vec![b"ab".to_vec(), vec![], b"cde".to_vec()]
        );
        assert!(split_items(b"abc", &[4]).is_err());
        assert!(split_items(b"abc", &[1]).is_err());
    }

    #[test]
    fn rejects_unknown_parameters() {
        assert!(CryptexPsi::new(
            9,
            CRYPTEX_PSI_SENDER,
            0,
            Executor::default(),
            1,
            false,
            vec![]
        )
        .is_err());
        assert!(CryptexPsi::new(
            CRYPTEX_PSI_VOLE,
            9,
            0,
            Executor::default(),
            1,
            false,
            vec![]
        )
        .is_err());
        assert!(CryptexPsi::new(
            CRYPTEX_PSI_ECDH,
            CRYPTEX_PSI_SENDER,
            9,
            Executor::default(),
            1,
            false,
            vec![]
        )
        .is_err());
    }

    #[test]
    fn ffi_bucket() {
        let items: [&[u8]; 3] = [b"alice", b"", b"13800000001"];
        let data = items.concat();
        let lens: Vec<usize> = items.iter().map(|x| x.len()).collect();
        let mut out = [u32::MAX; 3];
        let pool = new_pool(2);
        let rc = unsafe {
            cryptex_psi_bucket(
                CRYPTEX_BUCKET_SHA256,
                1000,
                pool,
                data.as_ptr(),
                data.len(),
                lens.as_ptr(),
                3,
                out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, CRYPTEX_OK);
        assert_eq!(out, [606, 932, 640]);
        unsafe { cryptex_pool_free(pool) };

        let rc = unsafe {
            cryptex_psi_bucket(
                9,
                4,
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, super::super::CRYPTEX_ERR_INVALID_INPUT);
        let rc = unsafe {
            cryptex_psi_bucket(
                CRYPTEX_BUCKET_SM3,
                0,
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, super::super::CRYPTEX_ERR_INVALID_INPUT);
    }

    fn new_pool(threads: usize) -> *mut CryptexPool {
        let mut pool = ptr::null_mut();
        assert_eq!(unsafe { cryptex_pool_new(threads, &mut pool) }, CRYPTEX_OK);
        pool
    }

    #[test]
    fn bucket_count_is_validated() {
        let new = |b| {
            CryptexPsi::new(
                CRYPTEX_PSI_ECDH,
                CRYPTEX_PSI_SENDER,
                0,
                Executor::default(),
                b,
                false,
                vec![],
            )
        };
        assert!(matches!(new(0), Err(Error::InvalidInput(_))));
        assert!(new(1).is_ok());
        assert!(new(bucket::MAX_BUCKETS).is_ok());
        assert!(matches!(
            new(bucket::MAX_BUCKETS + 1),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn pool_thread_count_is_validated() {
        let mut pool = ptr::null_mut();
        for ok in [0, 1, MAX_THREADS] {
            assert_eq!(unsafe { cryptex_pool_new(ok, &mut pool) }, CRYPTEX_OK);
            unsafe { cryptex_pool_free(pool) };
        }
        assert_eq!(
            unsafe { cryptex_pool_new(MAX_THREADS + 1, &mut pool) },
            super::super::CRYPTEX_ERR_INVALID_INPUT
        );
        unsafe { cryptex_pool_free(ptr::null_mut()) };
    }

    /// One pool shared by many sessions, freed while they are still alive.
    #[test]
    fn pool_outlives_its_handle() {
        let pool = new_pool(2);
        let r = unsafe { ffi_new(CRYPTEX_PSI_RECEIVER, CRYPTEX_CURVE_P256, pool, &[b"a"]) };
        let s = unsafe { ffi_new(CRYPTEX_PSI_SENDER, CRYPTEX_CURVE_P256, pool, &[b"a"]) };
        unsafe { cryptex_pool_free(pool) };
        unsafe {
            let (m1, _) = ffi_step(r, None);
            let (m2, _) = ffi_step(s, Some(&m1));
            ffi_step(r, Some(&m2));
            cryptex_psi_free(r);
            cryptex_psi_free(s);
        }
    }

    /// Independent sessions on different OS threads at the same time.
    #[test]
    fn sessions_run_concurrently() {
        let handles: Vec<_> = (0..8)
            .map(|k| {
                std::thread::spawn(move || {
                    let rx: Vec<Vec<u8>> =
                        (0..50).map(|i| format!("{k}-{i}").into_bytes()).collect();
                    let sx: Vec<Vec<u8>> =
                        (25..75).map(|i| format!("{k}-{i}").into_bytes()).collect();
                    let exec = Executor::new(k as usize % 3).unwrap();
                    let mut r = CryptexPsi::new(
                        CRYPTEX_PSI_ECDH,
                        CRYPTEX_PSI_RECEIVER,
                        k % 3,
                        exec,
                        1,
                        false,
                        rx,
                    )
                    .unwrap();
                    let mut s = CryptexPsi::new(
                        CRYPTEX_PSI_ECDH,
                        CRYPTEX_PSI_SENDER,
                        k % 3,
                        Executor::new(1).unwrap(),
                        1,
                        false,
                        sx,
                    )
                    .unwrap();
                    let (m1, _) = r.step(None).unwrap();
                    let (m2, _) = s.step(Some(&m1)).unwrap();
                    r.step(Some(&m2)).unwrap();
                    r.result().unwrap().to_vec()
                })
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), (25..50).collect::<Vec<_>>());
        }
    }

    #[test]
    fn receiver_initiates() {
        assert!(ecdh(CRYPTEX_PSI_RECEIVER).party.is_initiator());
        assert!(!ecdh(CRYPTEX_PSI_SENDER).party.is_initiator());
    }

    #[test]
    fn enforces_first_call() {
        let err = ecdh(CRYPTEX_PSI_SENDER).step(None).unwrap_err();
        assert!(matches!(err, Error::InvalidState(_)));
        let err = ecdh(CRYPTEX_PSI_RECEIVER).step(Some(b"x")).unwrap_err();
        assert!(matches!(err, Error::InvalidState(_)));
    }

    #[test]
    fn failure_poisons_session() {
        let mut psi = ecdh(CRYPTEX_PSI_RECEIVER);
        psi.step(None).unwrap();
        // A malformed reply fails the step...
        assert!(matches!(psi.step(Some(b"x")), Err(Error::InvalidInput(_))));
        // ...and the session cannot be resumed afterwards.
        assert!(matches!(psi.step(Some(b"x")), Err(Error::InvalidState(_))));
        assert!(matches!(psi.result(), Err(Error::InvalidState(_))));
    }

    /// Drive two sessions through the C ABI, as the bindings do.
    unsafe fn ffi_new(
        role: i32,
        curve: i32,
        pool: *const CryptexPool,
        items: &[&[u8]],
    ) -> *mut CryptexPsi {
        unsafe { ffi_new_shared(role, curve, pool, items, 0) }
    }

    unsafe fn ffi_new_shared(
        role: i32,
        curve: i32,
        pool: *const CryptexPool,
        items: &[&[u8]],
        share: i32,
    ) -> *mut CryptexPsi {
        let data = items.concat();
        let lens: Vec<usize> = items.iter().map(|x| x.len()).collect();
        let mut psi = ptr::null_mut();
        let rc = unsafe {
            cryptex_psi_new(
                CRYPTEX_PSI_ECDH,
                role,
                curve,
                pool,
                1,
                share,
                data.as_ptr(),
                data.len(),
                lens.as_ptr(),
                lens.len(),
                &mut psi,
            )
        };
        assert_eq!(rc, CRYPTEX_OK);
        psi
    }

    unsafe fn ffi_step(psi: *mut CryptexPsi, incoming: Option<&[u8]>) -> (Vec<u8>, bool) {
        let mut msg = CryptexBuffer::empty();
        let mut done = 0;
        let (p, len, has) = incoming.map_or((ptr::null(), 0, 0), |m| (m.as_ptr(), m.len(), 1));
        let rc = unsafe { cryptex_psi_step(psi, p, len, has, &mut msg, &mut done) };
        assert_eq!(rc, CRYPTEX_OK);
        let out = if msg.len == 0 {
            vec![]
        } else {
            unsafe { slice::from_raw_parts(msg.ptr, msg.len) }.to_vec()
        };
        unsafe { super::super::cryptex_buffer_free(msg) };
        (out, done != 0)
    }

    #[test]
    fn ffi_ecdh_end_to_end() {
        for curve in [
            CRYPTEX_CURVE_RISTRETTO255,
            CRYPTEX_CURVE_P256,
            CRYPTEX_CURVE_SM2,
            CRYPTEX_CURVE_FOURQ,
        ] {
            unsafe {
                // Receiver on the global pool, sender on a dedicated one.
                let pool = new_pool(3);
                let r = ffi_new(
                    CRYPTEX_PSI_RECEIVER,
                    curve,
                    ptr::null(),
                    &[b"a", b"b", b"c"],
                );
                let s = ffi_new(CRYPTEX_PSI_SENDER, curve, pool, &[b"c", b"x", b"a"]);
                cryptex_pool_free(pool);
                let (m1, done) = ffi_step(r, None);
                assert!(!done);
                let (m2, done) = ffi_step(s, Some(&m1));
                assert!(done && !m2.is_empty());
                let (m3, done) = ffi_step(r, Some(&m2));
                assert!(done && m3.is_empty());

                let mut idx = ptr::null();
                let mut count = 0;
                assert_eq!(cryptex_psi_result(r, &mut idx, &mut count), CRYPTEX_OK);
                assert_eq!(slice::from_raw_parts(idx, count), &[0, 2]);
                // The sender has no result.
                assert_eq!(
                    cryptex_psi_result(s, &mut idx, &mut count),
                    super::super::CRYPTEX_ERR_INVALID_STATE
                );
                cryptex_psi_free(r);
                cryptex_psi_free(s);
            }
        }
    }

    /// With `share` = 1 the receiver's last step carries a message for the
    /// sender, after which both parties can read their own indices.
    #[test]
    fn ffi_ecdh_shared_result() {
        unsafe {
            let r = ffi_new_shared(
                CRYPTEX_PSI_RECEIVER,
                CRYPTEX_CURVE_SM2,
                ptr::null(),
                &[b"a", b"b", b"c"],
                1,
            );
            let s = ffi_new_shared(
                CRYPTEX_PSI_SENDER,
                CRYPTEX_CURVE_SM2,
                ptr::null(),
                &[b"c", b"x", b"a"],
                1,
            );
            let (m1, _) = ffi_step(r, None);
            let (m2, done) = ffi_step(s, Some(&m1));
            assert!(!done, "sender waits for the shared result");
            let (m3, done) = ffi_step(r, Some(&m2));
            assert!(done && !m3.is_empty());
            let (m4, done) = ffi_step(s, Some(&m3));
            assert!(done && m4.is_empty());

            let mut idx = ptr::null();
            let mut count = 0;
            assert_eq!(cryptex_psi_result(r, &mut idx, &mut count), CRYPTEX_OK);
            assert_eq!(slice::from_raw_parts(idx, count), &[0, 2]);
            assert_eq!(cryptex_psi_result(s, &mut idx, &mut count), CRYPTEX_OK);
            assert_eq!(slice::from_raw_parts(idx, count), &[0, 2]);
            cryptex_psi_free(r);
            cryptex_psi_free(s);
        }
    }

    #[test]
    fn ffi_reports_error_code_and_message() {
        unsafe {
            let s = ffi_new(CRYPTEX_PSI_SENDER, CRYPTEX_CURVE_SM2, ptr::null(), &[b"a"]);
            let mut msg = CryptexBuffer::empty();
            let mut done = 0;
            let garbage = b"\x01garbage";
            let rc = cryptex_psi_step(s, garbage.as_ptr(), garbage.len(), 1, &mut msg, &mut done);
            assert_eq!(rc, super::super::CRYPTEX_ERR_INVALID_INPUT);
            assert!(!cryptex_last_error().is_null());
            assert!(msg.ptr.is_null() && msg.len == 0);
            cryptex_psi_free(s);
        }
    }

    /// OPRF-PSI through the same session API: one round trip, receiver
    /// gets the result, sender none; sharing is rejected.
    #[test]
    fn oprf_sessions() {
        let new = |role, items: &[&[u8]], share| {
            CryptexPsi::new(
                CRYPTEX_PSI_OPRF,
                role,
                CRYPTEX_CURVE_SM2,
                Executor::default(),
                1,
                share,
                items.iter().map(|x| x.to_vec()).collect(),
            )
        };
        let mut r = new(CRYPTEX_PSI_RECEIVER, &[b"a", b"b"], false).unwrap();
        let mut s = new(CRYPTEX_PSI_SENDER, &[b"x", b"b", b"y", b"z"], false).unwrap();
        assert!(r.party.is_initiator() && !s.party.is_initiator());
        let (m1, done) = r.step(None).unwrap();
        assert!(!done);
        let (m2, done) = s.step(Some(&m1)).unwrap();
        assert!(done);
        let (m3, done) = r.step(Some(&m2)).unwrap();
        assert!(done && m3.is_empty());
        assert_eq!(r.result().unwrap(), &[1]);
        assert!(matches!(s.result(), Err(Error::InvalidState(_))));

        assert!(new(CRYPTEX_PSI_RECEIVER, &[b"a"], true).is_err());
        assert!(new(9, &[b"a"], false).is_err());
        // ECDH and OPRF messages are not interchangeable.
        let mut e = CryptexPsi::new(
            CRYPTEX_PSI_ECDH,
            CRYPTEX_PSI_SENDER,
            CRYPTEX_CURVE_SM2,
            Executor::default(),
            1,
            false,
            vec![b"a".to_vec()],
        )
        .unwrap();
        let mut r = new(CRYPTEX_PSI_RECEIVER, &[b"a"], false).unwrap();
        let (m1, _) = r.step(None).unwrap();
        assert!(matches!(e.step(Some(&m1)), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn vole_needs_the_job_api() {
        let err = CryptexPsi::new(
            CRYPTEX_PSI_VOLE,
            CRYPTEX_PSI_SENDER,
            0,
            Executor::default(),
            1,
            false,
            vec![],
        );
        assert!(matches!(err, Err(Error::InvalidInput(_))));
    }
}
