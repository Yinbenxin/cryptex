//! Bucketing: split a set into `buckets` parts by a public hash, so the two
//! parties can run one PSI per bucket instead of one PSI over everything.
//!
//! `bucket(x) = u64_be(H(DST ‖ x)[..8]) mod buckets`, with `H` = SHA-256, or
//! SM3 when the whole flow must stay on GB/T algorithms. Both parties must
//! use the same hash and bucket count, otherwise matching items land in
//! different buckets and are missed.
//!
//! The rule is public and keyless: each party learns the other's per-bucket
//! set sizes, i.e. a coarse histogram of hash values. Items themselves stay
//! hidden.

use rayon::prelude::*;

use crate::exec::Executor;
use crate::primitives::hash::{sha256, sm3};
use crate::{Error, Result};

/// Largest supported bucket count.
pub const MAX_BUCKETS: u32 = 1 << 20;

const DST: &[u8] = b"CRYPTEX-PSI-BUCKET-V1";

/// Hash used to assign buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketHash {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SM3 (GB/T 32905).
    Sm3,
}

fn check_buckets(buckets: u32) -> Result<()> {
    if (1..=MAX_BUCKETS).contains(&buckets) {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "bucket count must be in 1..={MAX_BUCKETS}, got {buckets}"
        )))
    }
}

/// Bucket of a single item. `buckets` must be in `1..=MAX_BUCKETS`.
pub fn bucket_of(hash: BucketHash, buckets: u32, item: &[u8]) -> Result<u32> {
    check_buckets(buckets)?;
    Ok(bucket_unchecked(hash, buckets, item))
}

fn bucket_unchecked(hash: BucketHash, buckets: u32, item: &[u8]) -> u32 {
    let digest = match hash {
        BucketHash::Sha256 => sha256(&[DST, item]),
        BucketHash::Sm3 => sm3(&[DST, item]),
    };
    let x = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
    // Bias is at most buckets / 2^64, negligible for buckets <= 2^20.
    (x % u64::from(buckets)) as u32
}

/// Write the bucket of each item into `out` (same length), in parallel on
/// `exec`.
pub(crate) fn assign_into(
    hash: BucketHash,
    buckets: u32,
    items: &[&[u8]],
    out: &mut [u32],
    exec: &Executor,
) -> Result<()> {
    check_buckets(buckets)?;
    if items.len() != out.len() {
        return Err(Error::InvalidInput(
            "output length must match item count".into(),
        ));
    }
    exec.install(|| {
        out.par_iter_mut()
            .zip(items.par_iter())
            .for_each(|(b, x)| *b = bucket_unchecked(hash, buckets, x));
    });
    Ok(())
}

/// Bucket of each item, on rayon's global pool.
pub fn assign(hash: BucketHash, buckets: u32, items: &[&[u8]]) -> Result<Vec<u32>> {
    let mut out = vec![0; items.len()];
    assign_into(hash, buckets, items, &mut out, &Executor::default())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned values, cross-checked by an independent Python computation in
    /// bindings/python/tests/test_bucket.py. Changing them breaks
    /// compatibility between versions. Bucket count 1000.
    #[test]
    fn pinned_values() {
        let items: [&[u8]; 4] = [b"", b"alice", b"13800000001", "张三".as_bytes()];
        let sha: Vec<u32> = items
            .iter()
            .map(|x| bucket_of(BucketHash::Sha256, 1000, x).unwrap())
            .collect();
        let sm3: Vec<u32> = items
            .iter()
            .map(|x| bucket_of(BucketHash::Sm3, 1000, x).unwrap())
            .collect();
        assert_eq!(sha, PINNED_SHA256);
        assert_eq!(sm3, PINNED_SM3);
    }

    const PINNED_SHA256: [u32; 4] = [932, 606, 640, 771];
    const PINNED_SM3: [u32; 4] = [180, 596, 763, 861];

    #[test]
    fn single_bucket_is_zero() {
        for x in [&b""[..], b"a", b"zzz"] {
            assert_eq!(bucket_of(BucketHash::Sha256, 1, x).unwrap(), 0);
        }
    }

    #[test]
    fn rejects_bad_bucket_counts() {
        assert!(bucket_of(BucketHash::Sha256, 0, b"a").is_err());
        assert!(bucket_of(BucketHash::Sm3, MAX_BUCKETS + 1, b"a").is_err());
        assert!(bucket_of(BucketHash::Sm3, MAX_BUCKETS, b"a").is_ok());
        let mut out = [0u32; 1];
        assert!(assign_into(BucketHash::Sha256, 4, &[], &mut out, &Executor::default()).is_err());
    }

    #[test]
    fn parallel_matches_serial_and_is_balanced() {
        let owned: Vec<Vec<u8>> = (0..100_000)
            .map(|i| format!("id-{i}").into_bytes())
            .collect();
        let items: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let mut out = vec![0; items.len()];
        assign_into(
            BucketHash::Sm3,
            16,
            &items,
            &mut out,
            &Executor::new(3).unwrap(),
        )
        .unwrap();
        for (x, &b) in items.iter().zip(&out).step_by(997) {
            assert_eq!(bucket_of(BucketHash::Sm3, 16, x).unwrap(), b);
        }
        let mut counts = [0usize; 16];
        for b in out {
            counts[b as usize] += 1;
        }
        // Expected 6250 per bucket, std dev ~77; allow a wide margin.
        assert!(
            counts.iter().all(|&c| (5800..6700).contains(&c)),
            "{counts:?}"
        );
    }
}
