//! C ABI for VOLE-PSI jobs.
//!
//! A job covers all buckets of one PSI run and is full duplex: messages may
//! be sent and received in any interleaving. A driver typically runs two
//! threads around one handle, serialized by a lock:
//!
//! - **sender loop**: feed items while `cryptex_vole_job_need` asks for a
//!   bucket, call `cryptex_vole_job_next_send`, send the message if any,
//!   otherwise wait for the receiver loop to make progress;
//! - **receiver loop**: while `cryptex_vole_job_status` says messages are
//!   expected, receive one and pass it to `cryptex_vole_job_receive`.
//!
//! The receiver role collects per-bucket results with
//! `cryptex_vole_job_take_result`. The job is finished when status reports
//! `done`. Messages from the library never need to be split or merged.

use std::slice;

use super::psi::{split_items, CryptexPool};
use super::{guard, CryptexBuffer};
use crate::algorithms::psi::vole::job::{Need, VoleJobReceiver, VoleJobSender, PRODUCTION};
use crate::algorithms::psi::Intersection;
use crate::exec::Executor;
use crate::{Error, Result};

/// Sender: learns nothing.
pub const CRYPTEX_VOLE_SENDER: i32 = 0;
/// Receiver: learns the intersection.
pub const CRYPTEX_VOLE_RECEIVER: i32 = 1;

enum Role {
    Receiver(VoleJobReceiver),
    Sender(VoleJobSender),
}

/// Opaque VOLE-PSI job handle.
pub struct CryptexVoleJob {
    role: Role,
    /// Last result handed out, kept alive until the next call.
    last: Intersection,
    failed: bool,
    /// Whether the sender gets the result too.
    share: bool,
}

impl CryptexVoleJob {
    fn check(&self) -> Result<()> {
        if self.failed {
            Err(Error::InvalidState("job failed earlier".into()))
        } else {
            Ok(())
        }
    }

    /// Run `f`, poisoning the job on error.
    fn with<T>(&mut self, f: impl FnOnce(&mut Role) -> Result<T>) -> Result<T> {
        self.check()?;
        let r = f(&mut self.role);
        if r.is_err() {
            self.failed = true;
        }
        r
    }
}

/// # Safety
///
/// `job` must be null or a live handle with no other reference in use.
unsafe fn job<'a>(job: *mut CryptexVoleJob) -> Result<&'a mut CryptexVoleJob> {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { job.as_mut() }.ok_or_else(|| Error::InvalidInput("null job".into()))
}

/// Create a job. `sizes[b]` (`buckets` entries) is the number of distinct
/// items this party will provide for bucket `b`; both parties must use the
/// same `buckets`. `pool` as in `cryptex_psi_new` (null = global pool).
/// `share` = 1 also gives the sender the result: the receiver sends each
/// bucket's matches back and the sender collects them with
/// `cryptex_vole_job_take_result`. Both parties must pass the same value
/// (a mismatch fails the sender when the first message arrives).
///
/// # Safety
///
/// `pool` must be null or a live pool handle, `sizes` must point to
/// `buckets` readable `u64` values, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_new(
    role: i32,
    pool: *const CryptexPool,
    buckets: u32,
    sizes: *const u64,
    share: i32,
    out: *mut *mut CryptexVoleJob,
) -> i32 {
    guard(|| {
        if out.is_null() || (buckets > 0 && sizes.is_null()) {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        // SAFETY: guaranteed by the caller contract above.
        let sizes: Vec<usize> = unsafe { slice::from_raw_parts(sizes, buckets as usize) }
            .iter()
            .map(|&s| usize::try_from(s).map_err(|_| Error::InvalidInput("size too large".into())))
            .collect::<Result<_>>()?;
        // SAFETY: guaranteed by the caller contract above.
        let exec = unsafe { pool.as_ref() }.map_or_else(Executor::default, |p| p.executor());
        let share = share != 0;
        let role = match role {
            CRYPTEX_VOLE_SENDER => {
                Role::Sender(VoleJobSender::new(sizes, exec, PRODUCTION, share)?)
            }
            CRYPTEX_VOLE_RECEIVER => {
                Role::Receiver(VoleJobReceiver::new(sizes, exec, PRODUCTION, share)?)
            }
            _ => return Err(Error::InvalidInput(format!("unknown role {role}"))),
        };
        let job = CryptexVoleJob {
            role,
            last: Vec::new(),
            failed: false,
            share,
        };
        // SAFETY: `out` is non-null and writable per the caller contract.
        unsafe { *out = Box::into_raw(Box::new(job)) };
        Ok(())
    })
}

/// Which bucket's items the job needs next: writes the bucket number to
/// `*out_bucket` and 1 to `*out_has`, or 0 to `*out_has` if none now.
///
/// # Safety
///
/// `job` must be a live handle; output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_need(
    job_ptr: *mut CryptexVoleJob,
    out_bucket: *mut u32,
    out_has: *mut i32,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let j = unsafe { job(job_ptr)? };
        if out_bucket.is_null() || out_has.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        j.check()?;
        let need = match &j.role {
            Role::Receiver(r) => r.need(),
            Role::Sender(s) => s.need(),
        };
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            match need {
                Need::Items(b) => {
                    *out_bucket = b;
                    *out_has = 1;
                }
                Need::Nothing => *out_has = 0,
            }
        }
        Ok(())
    })
}

/// Provide the items of `bucket` (concatenated in `data` with lengths in
/// `lens`, as in `cryptex_psi_new`). Buckets must be provided in order and
/// match the announced sizes.
///
/// # Safety
///
/// `job` must be a live handle, `data` must point to `data_len` readable
/// bytes, `lens` to `count` readable `usize` values.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_provide(
    job_ptr: *mut CryptexVoleJob,
    bucket: u32,
    data: *const u8,
    data_len: usize,
    lens: *const usize,
    count: usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let j = unsafe { job(job_ptr)? };
        // SAFETY: guaranteed by the caller contract above.
        let data = unsafe { super::psi::bytes(data, data_len)? };
        let lens: &[usize] = if count == 0 {
            &[]
        } else if lens.is_null() {
            return Err(Error::InvalidInput("null lens pointer".into()));
        } else {
            // SAFETY: guaranteed by the caller contract above.
            unsafe { slice::from_raw_parts(lens, count) }
        };
        let items = split_items(data, lens)?;
        j.with(|role| match role {
            Role::Receiver(r) => r.provide(bucket, items),
            Role::Sender(s) => s.provide(bucket, items),
        })
    })
}

/// Pass one message received from the peer.
///
/// # Safety
///
/// `job` must be a live handle and `msg` point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_receive(
    job_ptr: *mut CryptexVoleJob,
    msg: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let j = unsafe { job(job_ptr)? };
        // SAFETY: guaranteed by the caller contract above.
        let msg = unsafe { super::psi::bytes(msg, len)? };
        j.with(|role| match role {
            Role::Receiver(r) => r.receive(msg),
            Role::Sender(s) => s.receive(msg),
        })
    })
}

/// Next message to send, if one is ready now: `*out_has` is 1 and
/// `*out_msg` holds it (free with `cryptex_buffer_free`), else `*out_has`
/// is 0. May compute for a while.
///
/// # Safety
///
/// `job` must be a live handle; output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_next_send(
    job_ptr: *mut CryptexVoleJob,
    out_msg: *mut CryptexBuffer,
    out_has: *mut i32,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let j = unsafe { job(job_ptr)? };
        if out_msg.is_null() || out_has.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_msg = CryptexBuffer::empty();
            *out_has = 0;
        }
        let msg = j.with(|role| match role {
            Role::Receiver(r) => r.next_send(),
            Role::Sender(s) => s.next_send(),
        })?;
        if let Some(m) = msg {
            // SAFETY: output pointers are writable per the caller contract.
            unsafe {
                *out_msg = CryptexBuffer::from_vec(m);
                *out_has = 1;
            }
        }
        Ok(())
    })
}

/// The next finished bucket (receiver; sender only with `share` = 1). `*out_has` is 1 and
/// `*out_bucket`, `*out_indices`, `*out_count` describe the indices (into
/// that bucket's provided items, ascending) of matching items, else 0. The
/// indices stay valid until the next call on this job.
///
/// # Safety
///
/// `job` must be a live handle; output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_take_result(
    job_ptr: *mut CryptexVoleJob,
    out_bucket: *mut u32,
    out_indices: *mut *const usize,
    out_count: *mut usize,
    out_has: *mut i32,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let j = unsafe { job(job_ptr)? };
        if out_bucket.is_null() || out_indices.is_null() || out_count.is_null() || out_has.is_null()
        {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        j.check()?;
        let next = match &mut j.role {
            Role::Receiver(r) => r.take_result(),
            Role::Sender(s) if j.share => s.take_result(),
            Role::Sender(_) => {
                return Err(Error::InvalidState(
                    "the sender has no PSI result (the receiver does not share it)".into(),
                ))
            }
        };
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_has = 0;
            if let Some((b, idx)) = next {
                j.last = idx;
                *out_bucket = b;
                *out_indices = j.last.as_ptr();
                *out_count = j.last.len();
                *out_has = 1;
            }
        }
        Ok(())
    })
}

/// `*out_done` = 1 when the job has finished (nothing more to send or
/// receive); `*out_expects` = 1 while more messages from the peer are
/// expected.
///
/// # Safety
///
/// `job` must be a live handle; output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_status(
    job_ptr: *mut CryptexVoleJob,
    out_done: *mut i32,
    out_expects: *mut i32,
) -> i32 {
    guard(|| {
        // SAFETY: guaranteed by the caller contract above.
        let j = unsafe { job(job_ptr)? };
        if out_done.is_null() || out_expects.is_null() {
            return Err(Error::InvalidInput("null pointer".into()));
        }
        j.check()?;
        let (done, expects) = match &j.role {
            Role::Receiver(r) => (r.is_done(), r.expects_messages()),
            Role::Sender(s) => (s.is_done(), s.expects_messages()),
        };
        // SAFETY: output pointers are writable per the caller contract.
        unsafe {
            *out_done = i32::from(done);
            *out_expects = i32::from(expects);
        }
        Ok(())
    })
}

/// Release a job handle. Null is ignored.
///
/// # Safety
///
/// `job` must be null or a live handle that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn cryptex_vole_job_free(job: *mut CryptexVoleJob) {
    if !job.is_null() {
        // SAFETY: guaranteed by the caller contract above.
        drop(unsafe { Box::from_raw(job) });
    }
}
