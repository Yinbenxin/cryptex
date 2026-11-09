//! Ristretto255 group over Curve25519.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hash2curve::ExpandMsgXmd;
use primeorder::elliptic_curve::consts::U16;
use rand::CryptoRng;
use sha2::Sha512;

use super::hash_to_curve::expand_message;
use super::Group;
use crate::primitives::hash::sha256;
use crate::{Error, Result};

/// Ristretto255 (RFC 9496).
pub(crate) struct Ristretto255;

impl Group for Ristretto255 {
    type Scalar = Scalar;
    type Point = RistrettoPoint;

    const POINT_LEN: usize = 32;
    // Same construction as RFC 9497's ristretto255 HashToGroup.
    const SUITE_ID: &'static [u8] = b"ristretto255_XMD:SHA-512_R255MAP_RO_";

    fn random_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
        loop {
            let k = Scalar::random(rng);
            if k != Scalar::ZERO {
                return k;
            }
        }
    }

    /// `expand_message_xmd` (SHA-512) to 64 bytes, then the RFC 9496 one-way
    /// map.
    fn hash_to_group(msg: &[u8], dst: &[&[u8]]) -> RistrettoPoint {
        let mut uniform = [0u8; 64];
        expand_message::<ExpandMsgXmd<Sha512>, U16>(&[msg], dst, &mut uniform);
        RistrettoPoint::from_uniform_bytes(&uniform)
    }

    fn mul(p: &RistrettoPoint, k: &Scalar) -> RistrettoPoint {
        p * k
    }

    fn invert(k: &Scalar) -> Scalar {
        k.invert()
    }

    fn encode(p: &RistrettoPoint, out: &mut [u8]) {
        out.copy_from_slice(p.compress().as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<RistrettoPoint> {
        CompressedRistretto::from_slice(bytes)
            .ok()
            .and_then(|c| c.decompress())
            .filter(|p| !p.is_identity())
            .ok_or_else(|| Error::InvalidInput("invalid ristretto255 point".into()))
    }

    fn hash(parts: &[&[u8]]) -> [u8; 32] {
        sha256(parts)
    }
}
