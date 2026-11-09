//! Per-curve operations behind trait objects, so the rest of PIR is not
//! generic; plus record encryption.
//!
//! - Server key: `k` = a scalar drawn from ChaCha20 seeded with
//!   `H("CRYPTEX-PIR-KEY-V1" ‖ suite ID ‖ seed)`. The 32-byte seed is the
//!   server's long-term secret; the database stores only `F_k` of a fixed
//!   string to detect a wrong seed.
//! - Record id and key: `id = F_k(x)[0..16]`, `kr = F_k(x)[16..32]` (every
//!   suite's `Finalize` output has at least 32 bytes). The id is stable, so
//!   the writer can update or delete a key without storing it.
//! - Record body: `CTR_kr(IV = 0, len (u32 BE) ‖ label)`. The IV is fixed:
//!   updating a key re-encrypts under the same keystream (see the security
//!   notes in `docs/algorithm/pir.md`).
//! - Bucket: the top `j` bits of the id, for `2^j` buckets.
//!
//! `H` is SM3 for SM2 and SHA-256 otherwise; the cipher is SM4 for SM2 and
//! AES-128 otherwise, so the SM2 suite stays on GB/T algorithms.

use rand::rngs::ChaCha20Rng;
use rand::SeedableRng;
use zeroize::Zeroize;

use super::{malformed, Curve, ID_LEN, LEN_PREFIX};
use crate::primitives::cipher::ctr::{self, Cipher};
use crate::primitives::ec::{FourQ, Ristretto255, Sm2, P256};
use crate::primitives::hash::{sha256, sm3};
use crate::primitives::oprf::{evaluate, finalize, hash_to_group, Suite};
use crate::primitives::rand::csprng;
use crate::Result;

const DST_KEY: &[u8] = b"CRYPTEX-PIR-KEY-V1";
const KEY_CHECK_INPUT: &[u8] = b"CRYPTEX-PIR-KEY-CHECK";

fn hash(curve: Curve, parts: &[&[u8]]) -> [u8; 32] {
    match curve {
        Curve::Sm2 => sm3(parts),
        _ => sha256(parts),
    }
}

fn cipher(curve: Curve) -> Cipher {
    match curve {
        Curve::Sm2 => Cipher::Sm4,
        _ => Cipher::Aes128,
    }
}

/// Bucket of `id` among `2^log2_buckets` buckets.
pub(crate) fn bucket_of(id: &[u8; ID_LEN], log2_buckets: u8) -> u32 {
    if log2_buckets == 0 {
        return 0;
    }
    u32::from_be_bytes(id[..4].try_into().expect("4 bytes")) >> (32 - log2_buckets)
}

/// Lookup id and CTR key of one record.
pub(crate) struct RecordKey {
    pub(crate) id: [u8; ID_LEN],
    key: [u8; 16],
}

impl Drop for RecordKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn record_key(prf: &[u8]) -> RecordKey {
    RecordKey {
        id: prf[..16].try_into().expect("16 bytes"),
        key: prf[16..32].try_into().expect("16 bytes"),
    }
}

/// Encrypted body of `label`: `LEN_PREFIX + label.len()` bytes.
pub(crate) fn seal(curve: Curve, rk: &RecordKey, label: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(LEN_PREFIX + label.len());
    body.extend_from_slice(&(label.len() as u32).to_be_bytes());
    body.extend_from_slice(label);
    ctr::apply(cipher(curve), &rk.key, &[0; 16], &mut body);
    body
}

/// Decrypt a body (possibly followed by padding) whose id matched `rk`.
pub(crate) fn open(curve: Curve, rk: &RecordKey, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < LEN_PREFIX {
        return Err(malformed("record body too short"));
    }
    let mut len = [0u8; LEN_PREFIX];
    len.copy_from_slice(&body[..LEN_PREFIX]);
    ctr::apply(cipher(curve), &rk.key, &[0; 16], &mut len);
    let len = u32::from_be_bytes(len) as usize;
    if len > body.len() - LEN_PREFIX {
        return Err(malformed("label length out of range"));
    }
    let mut out = body[..LEN_PREFIX + len].to_vec();
    ctr::apply(cipher(curve), &rk.key, &[0; 16], &mut out);
    out.drain(..LEN_PREFIX);
    Ok(out)
}

/// The server's long-term OPRF key.
pub(crate) trait ServerKey: Send + Sync {
    /// Encoded point length.
    fn point_len(&self) -> usize;
    /// Id and CTR key of the record for `key`.
    fn record_key(&self, key: &[u8]) -> RecordKey;
    /// `dst = src^k` for a client's blinded point, validating `src`.
    fn evaluate(&self, src: &[u8], dst: &mut [u8]) -> Result<()>;
    /// Fingerprint of the key, stored in the database.
    fn key_check(&self) -> [u8; 16];
}

struct Key<S: Suite> {
    k: S::Scalar,
}

impl<S: Suite> Drop for Key<S> {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl<S: Suite> ServerKey for Key<S> {
    fn point_len(&self) -> usize {
        S::POINT_LEN
    }

    fn record_key(&self, key: &[u8]) -> RecordKey {
        let mut prf = evaluate::<S>(key, &self.k);
        let rk = record_key(&prf);
        prf.zeroize();
        rk
    }

    fn evaluate(&self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        S::encode(&S::mul(&S::decode(src)?, &self.k), dst);
        Ok(())
    }

    fn key_check(&self) -> [u8; 16] {
        evaluate::<S>(KEY_CHECK_INPUT, &self.k)[..16]
            .try_into()
            .expect("16 bytes")
    }
}

fn key_of<S: Suite>(curve: Curve, seed: &[u8; 32]) -> Box<dyn ServerKey> {
    let mut s = hash(curve, &[DST_KEY, S::ID, seed]);
    let mut rng = ChaCha20Rng::from_seed(s);
    s.zeroize();
    Box::new(Key::<S> {
        k: S::random_scalar(&mut rng),
    })
}

/// Server key derived from `seed`.
pub(crate) fn server_key(curve: Curve, seed: &[u8; 32]) -> Box<dyn ServerKey> {
    match curve {
        Curve::Ristretto255 => key_of::<Ristretto255>(curve, seed),
        Curve::P256 => key_of::<P256>(curve, seed),
        Curve::Sm2 => key_of::<Sm2>(curve, seed),
        Curve::FourQ => key_of::<FourQ>(curve, seed),
    }
}

/// The client's blind `r` for one query.
pub(crate) trait Blinder: Send + Sync {
    /// Encoded point length.
    fn point_len(&self) -> usize;
    /// `out = H(key)^r`.
    fn blind(&self, key: &[u8], out: &mut [u8]);
    /// Record key of `key` from the server's evaluation `H(key)^(r k)`.
    fn unblind(&self, key: &[u8], evaluated: &[u8]) -> Result<RecordKey>;
}

struct Blind<S: Suite> {
    r: S::Scalar,
    r_inv: S::Scalar,
}

impl<S: Suite> Drop for Blind<S> {
    fn drop(&mut self) {
        self.r.zeroize();
        self.r_inv.zeroize();
    }
}

impl<S: Suite> Blinder for Blind<S> {
    fn point_len(&self) -> usize {
        S::POINT_LEN
    }

    fn blind(&self, key: &[u8], out: &mut [u8]) {
        S::encode(&S::mul(&hash_to_group::<S>(key), &self.r), out);
    }

    fn unblind(&self, key: &[u8], evaluated: &[u8]) -> Result<RecordKey> {
        let p = S::mul(&S::decode(evaluated)?, &self.r_inv);
        let mut prf = finalize::<S>(key, &p);
        let rk = record_key(&prf);
        prf.zeroize();
        Ok(rk)
    }
}

fn blind_of<S: Suite>() -> Result<Box<dyn Blinder>> {
    let r = S::random_scalar(&mut csprng()?);
    let r_inv = S::invert(&r);
    Ok(Box::new(Blind::<S> { r, r_inv }))
}

/// A fresh random blind.
pub(crate) fn blinder(curve: Curve) -> Result<Box<dyn Blinder>> {
    match curve {
        Curve::Ristretto255 => blind_of::<Ristretto255>(),
        Curve::P256 => blind_of::<P256>(),
        Curve::Sm2 => blind_of::<Sm2>(),
        Curve::FourQ => blind_of::<FourQ>(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURVES: [Curve; 4] = [Curve::Ristretto255, Curve::P256, Curve::Sm2, Curve::FourQ];

    /// The client's blinded path gives the same record key as the
    /// server's direct evaluation, for every curve.
    #[test]
    fn blinded_matches_direct() {
        for curve in CURVES {
            let key = server_key(curve, &[9; 32]);
            let b = blinder(curve).unwrap();
            let n = key.point_len();
            for x in [&b""[..], b"13800000001", b"some longer keyword"] {
                let (mut q, mut e) = (vec![0; n], vec![0; n]);
                b.blind(x, &mut q);
                key.evaluate(&q, &mut e).unwrap();
                let rk = b.unblind(x, &e).unwrap();
                let direct = key.record_key(x);
                assert_eq!(rk.id, direct.id, "{curve:?}");
                assert_eq!(rk.key, direct.key, "{curve:?}");
                assert_ne!(rk.id, key.record_key(b"other").id);
            }
        }
    }

    #[test]
    fn key_derivation_is_deterministic() {
        for curve in CURVES {
            let a = server_key(curve, &[1; 32]).key_check();
            assert_eq!(a, server_key(curve, &[1; 32]).key_check());
            assert_ne!(a, server_key(curve, &[2; 32]).key_check());
        }
        // Pinned: a change here (e.g. in rand's ChaCha20 or a curve's
        // scalar sampling) makes existing databases unopenable.
        for (curve, pinned) in CURVES.into_iter().zip(PINNED_KEY_CHECK) {
            assert_eq!(server_key(curve, &[0; 32]).key_check(), pinned, "{curve:?}");
        }
    }

    const PINNED_KEY_CHECK: [[u8; 16]; 4] = [
        [
            47, 229, 147, 236, 79, 72, 231, 171, 241, 8, 24, 30, 42, 25, 154, 83,
        ],
        [
            240, 249, 247, 156, 9, 29, 143, 53, 193, 60, 47, 122, 176, 200, 77, 191,
        ],
        [
            64, 187, 189, 109, 149, 224, 244, 200, 189, 239, 63, 224, 53, 76, 64, 223,
        ],
        [
            214, 224, 244, 184, 116, 19, 93, 225, 199, 237, 213, 233, 116, 216, 53, 108,
        ],
    ];

    #[test]
    fn seal_open_round_trip() {
        for curve in CURVES {
            let rk = record_key(&[3u8; 32]);
            for label in [&b""[..], b"x", b"label of some length"] {
                let body = seal(curve, &rk, label);
                assert_eq!(body.len(), LEN_PREFIX + label.len());
                assert_eq!(open(curve, &rk, &body).unwrap(), label);
                // Trailing padding is ignored.
                let padded = [body.as_slice(), &[0xab; 9]].concat();
                assert_eq!(open(curve, &rk, &padded).unwrap(), label);
                if label.len() > 4 {
                    assert!(!body.windows(label.len()).any(|w| w == label));
                }
            }
            // Garbage must fail or decode, never panic.
            let other = record_key(&[4u8; 32]);
            let _ = open(curve, &other, &seal(curve, &rk, b"abc"));
            assert!(open(curve, &rk, b"ab").is_err());
        }
    }

    #[test]
    fn buckets_are_id_prefixes() {
        let mut id = [0u8; ID_LEN];
        assert_eq!(bucket_of(&id, 0), 0);
        assert_eq!(bucket_of(&id, 20), 0);
        id[0] = 0xff;
        id[1] = 0xf0;
        assert_eq!(bucket_of(&id, 1), 1);
        assert_eq!(bucket_of(&id, 12), 0xfff);
        assert_eq!(bucket_of(&[0xff; ID_LEN], 20), (1 << 20) - 1);
    }
}
