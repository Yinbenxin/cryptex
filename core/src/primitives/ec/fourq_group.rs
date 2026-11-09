//! FourQ as a [`Group`]: the order-N subgroup, with hash-to-curve suite
//! `FourQ_XMD:SHA-256_ELL2_RO_` (cryptex-defined, see `fourq::h2c`).
//!
//! Encoding (32 bytes): `y0 ‖ y1` little-endian, with the top bit of the
//! last byte set to `sgn0(x)`. Decoding recovers `x` from the curve
//! equation and rejects non-canonical encodings, points off the curve, the
//! identity, and points outside the order-N subgroup.

use crypto_bigint::{Odd, U256};
use rand::CryptoRng;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use super::fourq::curve::{Affine, Ext, D};
use super::fourq::endo;
use super::fourq::fp::Fp;
use super::fourq::fp2::Fp2;
use super::fourq::h2c;
use super::Group;
use crate::primitives::hash::sha256;
use crate::{Error, Result};

/// N, the prime order of the subgroup (246 bits), little-endian limbs.
pub(crate) const ORDER: [u64; 4] = [
    0x2fb2540ec7768ce7,
    0xdfbd004dfe0f7999,
    0xf05397829cbc14e5,
    0x0029cbc14e5e0a72,
];

/// Scalar in `[1, N)`, little-endian limbs.
#[derive(Clone, Copy, Default)]
pub(crate) struct Scalar(pub(crate) [u64; 4]);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A point of the order-N subgroup.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point(Ext);

impl PartialEq for Point {
    fn eq(&self, o: &Self) -> bool {
        bool::from(self.0.ct_eq(&o.0))
    }
}

/// Little-endian 64-bit limbs as a `crypto-bigint` integer, independent of
/// its word size.
fn to_uint(limbs: &[u64; 4]) -> U256 {
    let mut bytes = [0u8; 32];
    for (c, w) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(limbs) {
        *c = w.to_le_bytes();
    }
    let x = U256::from_le_slice(&bytes);
    bytes.zeroize();
    x
}

fn lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// FourQ.
pub(crate) struct FourQ;

impl Group for FourQ {
    type Scalar = Scalar;
    type Point = Point;

    const POINT_LEN: usize = 32;
    const SUITE_ID: &'static [u8] = b"FourQ_XMD:SHA-256_ELL2_RO_";

    /// Uniform in `[1, N)` by rejection sampling on 246-bit candidates.
    fn random_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
        loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            b[30] &= 0x3f; // keep 246 bits
            b[31] = 0;
            let mut k = [0u64; 4];
            for (i, w) in k.iter_mut().enumerate() {
                *w = u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8"));
            }
            b.zeroize();
            if k != [0; 4] && lt(&k, &ORDER) {
                return Scalar(k);
            }
            k.zeroize();
        }
    }

    fn hash_to_group(msg: &[u8], dst: &[&[u8]]) -> Point {
        Point(h2c::hash_to_curve(msg, dst))
    }

    fn mul(p: &Point, k: &Scalar) -> Point {
        Point(endo::mul(&p.0, &k.0))
    }

    /// Constant-time safegcd (Bernstein–Yang) from `crypto-bigint`.
    fn invert(k: &Scalar) -> Scalar {
        let n = Odd::new(to_uint(&ORDER)).expect("N is odd");
        let mut x = to_uint(&k.0);
        let mut inv: U256 = Option::from(x.invert_odd_mod(&n)).expect("non-zero scalar below N");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(inv.to_le_bytes().as_slice());
        let mut out = [0u64; 4];
        for (w, c) in out.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *w = u64::from_le_bytes(*c);
        }
        bytes.zeroize();
        x.zeroize();
        inv.zeroize();
        Scalar(out)
    }

    fn encode(p: &Point, out: &mut [u8]) {
        let a = p.0.to_affine();
        out[..16].copy_from_slice(&a.y.a.to_le_bytes());
        out[16..32].copy_from_slice(&a.y.b.to_le_bytes());
        out[31] |= a.x.sgn0().unwrap_u8() << 7;
    }

    fn decode(bytes: &[u8]) -> Result<Point> {
        let p = decode_on_curve(bytes)?;
        // Subgroup check: N·P must be the identity; also reject the identity.
        if bool::from(p.is_identity()) || !bool::from(endo::mul(&p, &ORDER).is_identity()) {
            return Err(Error::InvalidInput(
                "FourQ point outside the subgroup".into(),
            ));
        }
        Ok(Point(p))
    }

    /// `k·392·P`: clearing the cofactor projects any curve point into the
    /// order-N subgroup (8 doublings, 2 additions) instead of the full N·P
    /// check, which costs as much as the multiplication itself. Torsion
    /// components are removed before the secret `k` is applied; small-order
    /// inputs become the identity and are rejected.
    fn decode_mul(bytes: &[u8], k: &Scalar) -> Result<Point> {
        let p = decode_on_curve(bytes)?.clear_cofactor();
        if bool::from(p.is_identity()) {
            return Err(Error::InvalidInput("FourQ point of small order".into()));
        }
        Ok(Point(endo::mul(&p, &k.0)))
    }

    fn hash(parts: &[&[u8]]) -> [u8; 32] {
        sha256(parts)
    }
}

/// Canonical encoding of a point on the curve (any order).
fn decode_on_curve(bytes: &[u8]) -> Result<Ext> {
    let bad = || Error::InvalidInput("invalid FourQ point".into());
    if bytes.len() != 32 {
        return Err(bad());
    }
    let sign = bytes[31] >> 7;
    let mut y0 = [0u8; 16];
    let mut y1 = [0u8; 16];
    y0.copy_from_slice(&bytes[..16]);
    y1.copy_from_slice(&bytes[16..]);
    y1[15] &= 0x7f;
    let y = Fp2 {
        a: Fp::from_le_bytes_canonical(&y0).ok_or_else(bad)?,
        b: Fp::from_le_bytes_canonical(&y1).ok_or_else(bad)?,
    };
    // x^2 = (y^2 - 1) / (1 + d y^2)   from  -x^2 + y^2 = 1 + d x^2 y^2.
    let y2 = y.square();
    let den = Fp2::ONE.add(D.mul(y2));
    if bool::from(den.is_zero()) {
        return Err(bad());
    }
    let x2 = y2.sub(Fp2::ONE).mul(den.invert());
    let (ok, x) = x2.sqrt();
    if !bool::from(ok) {
        return Err(bad());
    }
    // x = 0 has a single encoding (sign bit 0).
    if bool::from(x.is_zero()) && sign == 1 {
        return Err(bad());
    }
    let flip = !x.sgn0().ct_eq(&subtle::Choice::from(sign));
    let x = Fp2::conditional_select(&x, &x.neg(), flip);
    let a = Affine { x, y };
    debug_assert!(bool::from(a.is_on_curve()));
    Ok(Ext::from_affine(&a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;

    const DST: &[&[u8]] = &[b"QUUX-V01-CS02-with-", FourQ::SUITE_ID];

    fn enc(p: &Point) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        FourQ::encode(p, &mut b);
        b
    }

    /// Vectors from `core/tests/vectors/fourq_reference.py`.
    #[test]
    fn hash_to_curve_vectors() {
        let a512 = [&b"a512_"[..], &[b'a'; 507]].concat();
        let vectors: [(&[u8], &str); 4] = [
            (
                b"",
                "4a96912cf72e07b2d4a6f09aaf19917b55845c8f1b536b6d6ac2e913d7492543",
            ),
            (
                b"abc",
                "d2e78796752bb3b772529e41c971697b06d229a8ace6807af67158ea999c1dff",
            ),
            (
                b"abcdef0123456789",
                "bd65add1a0cd75f29c4136c8998a123d98ccfbd9e4f6caef7d9f9dcb28643e80",
            ),
            (
                &a512,
                "3a2f4fc9127c9cfb12dcb24145f26b47b35502a98221bf8b0bb5191a672782ef",
            ),
        ];
        for (msg, expected) in vectors {
            assert_eq!(
                enc(&FourQ::hash_to_group(msg, DST)),
                hex(expected),
                "len {}",
                msg.len()
            );
        }
    }

    /// `c · h2c("scalar")` against the reference.
    #[test]
    fn scalar_multiplication_vectors() {
        let p = FourQ::hash_to_group(b"scalar", DST);
        let n_minus_1 = [ORDER[0] - 1, ORDER[1], ORDER[2], ORDER[3]];
        let vectors: [([u64; 4], &str); 4] = [
            (
                [1, 0, 0, 0],
                "53ba73e4f5df13e4127f5141202616695fa7b7f021a4bacf99f303f21c1a06a3",
            ),
            (
                [2, 0, 0, 0],
                "a5ee8fc181c17f10b15d2f38c3459908c80ec907f72850323ef7317d6627d49e",
            ),
            (
                [0x1234567890abcdef, 0, 0, 0],
                "f88ec54e8effb177378cdcb1f4eb8c56f806d83f5f455f8dfaa4cdb5cb8bc8dc",
            ),
            // (N - 1)·P = -P: same y, opposite sign bit.
            (
                n_minus_1,
                "53ba73e4f5df13e4127f5141202616695fa7b7f021a4bacf99f303f21c1a0623",
            ),
        ];
        for (k, expected) in vectors {
            assert_eq!(enc(&FourQ::mul(&p, &Scalar(k))), hex(expected), "{k:x?}");
        }
    }

    /// `decode_mul` equals `392·k·P` on subgroup points, accepts curve points
    /// outside the subgroup by projecting them, and rejects small-order ones.
    #[test]
    fn decode_mul_clears_the_cofactor() {
        let mut rng = crate::primitives::rand::csprng().unwrap();
        let k = FourQ::random_scalar(&mut rng);
        let p = FourQ::hash_to_group(b"dm", DST);
        let got = FourQ::decode_mul(&enc(&p), &k).unwrap();
        let expect = FourQ::mul(&Point(p.0.clear_cofactor()), &k);
        assert_eq!(got, expect);

        // A curve point with a torsion component.
        let raw = Ext::from_affine(&h2c::map_to_curve(&Fp2::new(5, 7)));
        let got = FourQ::decode_mul(&enc(&Point(raw)), &k).unwrap();
        assert_eq!(got, FourQ::mul(&Point(raw.clear_cofactor()), &k));
        assert!(FourQ::decode(&enc(&Point(raw))).is_err());

        // A point of order 2: (0, -1).
        let two = Ext::from_affine(&Affine {
            x: Fp2::ZERO,
            y: Fp2::ONE.neg(),
        });
        assert!(FourQ::decode_mul(&enc(&Point(two)), &k).is_err());
    }

    /// `k · k^-1 ≡ 1 (mod N)` for edge scalars, checked with plain integer
    /// arithmetic independent of the curve code.
    #[test]
    fn scalar_inverse() {
        fn mul_mod(a: &[u64; 4], b: &[u64; 4]) -> U256 {
            let n = crypto_bigint::NonZero::new(to_uint(&ORDER)).unwrap();
            to_uint(a).mul_mod(&to_uint(b), &n)
        }
        let n_minus_1 = [ORDER[0] - 1, ORDER[1], ORDER[2], ORDER[3]];
        let mut rng = crate::primitives::rand::csprng().unwrap();
        let random = FourQ::random_scalar(&mut rng).0;
        for k in [[1, 0, 0, 0], [2, 0, 0, 0], n_minus_1, random] {
            let inv = FourQ::invert(&Scalar(k)).0;
            assert!(lt(&inv, &ORDER));
            assert_eq!(mul_mod(&k, &inv), U256::ONE, "{k:x?}");
        }
        // (N - 1)^-1 = N - 1.
        assert_eq!(FourQ::invert(&Scalar(n_minus_1)).0, n_minus_1);
    }

    #[test]
    fn decode_rejects_bad_encodings() {
        let p = FourQ::hash_to_group(b"x", DST);
        let mut b = enc(&p);
        assert_eq!(FourQ::decode(&b).unwrap(), p);
        // Wrong sign bit: the negated point, still valid; but must differ.
        b[31] ^= 0x80;
        let q = FourQ::decode(&b).unwrap();
        assert_ne!(q, p);
        // Non-canonical y0 (= p).
        let mut nc = enc(&p);
        nc[..16].copy_from_slice(&((1u128 << 127) - 1).to_le_bytes());
        assert!(FourQ::decode(&nc).is_err());
        // Identity (y = 1, x = 0).
        let mut id = [0u8; 32];
        id[0] = 1;
        assert!(FourQ::decode(&id).is_err());
        // A curve point outside the subgroup (no cofactor clearing).
        let raw = h2c::map_to_curve(&Fp2::new(5, 7));
        let raw = Point(Ext::from_affine(&raw));
        assert!(FourQ::decode(&enc(&raw)).is_err());
        // Wrong length.
        assert!(FourQ::decode(&[0u8; 31]).is_err());
    }
}
