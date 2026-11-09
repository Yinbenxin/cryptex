//! NIST P-256.

use hash2curve::GroupDigest;
use p256::elliptic_curve::ff::Field;
use p256::elliptic_curve::Generate;
use p256::{NistP256, NonZeroScalar, ProjectivePoint, Scalar};
use rand::CryptoRng;

use super::{decode_sec1, encode_sec1, Group};
use crate::primitives::hash::sha256;
use crate::Result;

/// NIST P-256 with RFC 9380 suite `P256_XMD:SHA-256_SSWU_RO_`.
pub(crate) struct P256;

impl Group for P256 {
    type Scalar = Scalar;
    type Point = ProjectivePoint;

    const POINT_LEN: usize = 33;
    const SUITE_ID: &'static [u8] = b"P256_XMD:SHA-256_SSWU_RO_";

    fn random_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
        *NonZeroScalar::generate_from_rng(rng)
    }

    fn hash_to_group(msg: &[u8], dst: &[&[u8]]) -> ProjectivePoint {
        NistP256::hash_from_bytes(&[msg], dst).expect("non-empty DST")
    }

    fn mul(p: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
        *p * k
    }

    fn invert(k: &Scalar) -> Scalar {
        Option::from(<Scalar as Field>::invert(k)).expect("non-zero scalar")
    }

    fn encode(p: &ProjectivePoint, out: &mut [u8]) {
        encode_sec1(p, out);
    }

    fn decode(bytes: &[u8]) -> Result<ProjectivePoint> {
        decode_sec1(bytes)
    }

    fn hash(parts: &[&[u8]]) -> [u8; 32] {
        sha256(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;
    use p256::elliptic_curve::sec1::ToSec1Point;

    /// Full hash_to_curve output against RFC 9380 Appendix J.1.1.
    #[test]
    fn rfc9380_hash_to_curve() {
        let dst: &[&[u8]] = &[b"QUUX-V01-CS02-with-", P256::SUITE_ID];
        for (msg, x, y) in [
            (
                &b""[..],
                "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
                "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
            ),
            (
                b"abc",
                "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
                "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
            ),
            (
                b"abcdef0123456789",
                "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
                "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
            ),
        ] {
            let p = P256::hash_to_group(msg, dst)
                .to_affine()
                .to_sec1_point(false);
            let mut expected = vec![0x04];
            expected.extend(hex(x));
            expected.extend(hex(y));
            assert_eq!(p.as_bytes(), expected.as_slice(), "msg {msg:?}");
        }
    }
}
