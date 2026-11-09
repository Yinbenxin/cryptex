//! Base oblivious transfer: Chou–Orlandi "simplest OT" over Ristretto255,
//! random-OT flavour, batched.
//!
//! ```text
//! Sender (no input)                     Receiver (choice bits c_i)
//!   a ← Z_q, A = a·G
//!            ── A ──▶
//!                                       b_i ← Z_q
//!                                       B_i = b_i·G        if c_i = 0
//!                                       B_i = A + b_i·G    if c_i = 1
//!            ◀── B_1 … B_k ──
//!   k_i^0 = H(i, A, B_i, a·B_i)
//!   k_i^1 = H(i, A, B_i, a·(B_i − A))   k_i^{c_i} = H(i, A, B_i, b_i·A)
//! ```
//!
//! Semi-honest secure under CDH in the random-oracle model (the hash binds
//! the transcript and the index). Used only to seed OT extension, so `k` is
//! small (≤ a few hundred) and speed is irrelevant.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::CryptoRng;
use zeroize::Zeroize;

use super::Block;
use crate::primitives::hash::sha256;
use crate::{Error, Result};

const DST: &[u8] = b"CRYPTEX-BASE-OT-V1";
const POINT_LEN: usize = 32;

fn random_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
    loop {
        let k = Scalar::random(rng);
        if k != Scalar::ZERO {
            return k;
        }
    }
}

fn decode(bytes: &[u8]) -> Result<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes)
        .ok()
        .and_then(|c| c.decompress())
        .filter(|p| !p.is_identity())
        .ok_or_else(|| Error::InvalidInput("base OT: invalid point".into()))
}

/// Key for OT `index`: first 16 bytes of `SHA-256(DST ‖ index ‖ A ‖ B ‖ P)`.
fn kdf(index: usize, a: &[u8], b: &[u8], p: &RistrettoPoint) -> Block {
    let mut shared = p.compress().to_bytes();
    let h = sha256(&[DST, &(index as u64).to_be_bytes(), a, b, &shared]);
    shared.zeroize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// Sender state between its two messages.
pub(crate) struct BaseOtSender {
    a: Scalar,
    big_a: [u8; POINT_LEN],
}

impl BaseOtSender {
    /// First message: `A`.
    pub(crate) fn new<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self, Vec<u8>) {
        let a = random_scalar(rng);
        let big_a = (a * G).compress().to_bytes();
        (Self { a, big_a }, big_a.to_vec())
    }

    /// Process the receiver's `B_1 … B_k`; returns `(k_i^0, k_i^1)` per OT.
    pub(crate) fn finish(mut self, msg: &[u8], k: usize) -> Result<Vec<[Block; 2]>> {
        if msg.len() != k * POINT_LEN {
            return Err(Error::InvalidInput("base OT: wrong reply length".into()));
        }
        let big_a = decode(&self.big_a).expect("own point is valid");
        let a_times_a = self.a * big_a;
        let out = msg
            .as_chunks::<POINT_LEN>()
            .0
            .iter()
            .enumerate()
            .map(|(i, b_bytes)| {
                let b = decode(b_bytes)?;
                let p0 = self.a * b;
                let p1 = p0 - a_times_a;
                Ok([
                    kdf(i, &self.big_a, b_bytes, &p0),
                    kdf(i, &self.big_a, b_bytes, &p1),
                ])
            })
            .collect();
        self.a.zeroize();
        out
    }
}

/// Receiver: answers `A` with `B_1 … B_k`, learning `k_i^{c_i}`.
pub(crate) fn receive<R: CryptoRng + ?Sized>(
    rng: &mut R,
    sender_msg: &[u8],
    choices: &[bool],
) -> Result<(Vec<u8>, Vec<Block>)> {
    if sender_msg.len() != POINT_LEN {
        return Err(Error::InvalidInput(
            "base OT: wrong first message length".into(),
        ));
    }
    let big_a = decode(sender_msg)?;
    let mut reply = Vec::with_capacity(choices.len() * POINT_LEN);
    let mut keys = Vec::with_capacity(choices.len());
    for (i, &c) in choices.iter().enumerate() {
        let mut b = random_scalar(rng);
        let bg = b * G;
        let big_b = if c { big_a + bg } else { bg };
        let b_bytes = big_b.compress().to_bytes();
        keys.push(kdf(i, sender_msg, &b_bytes, &(b * big_a)));
        reply.extend_from_slice(&b_bytes);
        b.zeroize();
    }
    Ok((reply, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::rand::csprng;

    #[test]
    fn receiver_gets_chosen_key_only() {
        let mut rng = csprng().unwrap();
        let choices: Vec<bool> = (0..64).map(|i| i % 3 == 0).collect();
        let (s, m1) = BaseOtSender::new(&mut rng);
        let (m2, got) = receive(&mut rng, &m1, &choices).unwrap();
        let keys = s.finish(&m2, choices.len()).unwrap();
        for (i, &c) in choices.iter().enumerate() {
            assert_eq!(got[i], keys[i][usize::from(c)]);
            assert_ne!(got[i], keys[i][usize::from(!c)]);
        }
        // All keys distinct.
        let mut all: Vec<Block> = keys.iter().flatten().copied().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 2 * choices.len());
    }

    #[test]
    fn rejects_malformed_messages() {
        let mut rng = csprng().unwrap();
        assert!(receive(&mut rng, &[0u8; 31], &[true]).is_err());
        assert!(receive(&mut rng, &[0u8; 32], &[true]).is_err()); // identity
        let (s, _) = BaseOtSender::new(&mut rng);
        assert!(s.finish(&[0u8; 33], 1).is_err());
        let (s, _) = BaseOtSender::new(&mut rng);
        assert!(s.finish(&[0xffu8; 32], 1).is_err());
    }
}
