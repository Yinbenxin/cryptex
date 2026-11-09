//! Hash-to-curve building blocks (RFC 9380).
//!
//! - [`expand_message_xmd`] wraps the audited `hash2curve` implementation.
//! - [`map_to_curve_sswu`] is the Simplified SWU map (RFC 9380 §6.6.2) for
//!   short Weierstrass curves `y^2 = x^3 + A x + B` with `A, B != 0` over
//!   `p = 3 (mod 4)`. It is generic so it can be checked against the P-256
//!   test vectors and then reused for SM2, which has no standard suite.

use core::num::NonZeroU16;

use hash2curve::{ExpandMsg, Expander};
use p256::elliptic_curve::ff::PrimeField;
use p256::elliptic_curve::subtle::{Choice, ConstantTimeEq};

/// `expand_message` (RFC 9380 §5.3) with the given `ExpandMsg` (e.g.
/// `ExpandMsgXmd<Sha256>`) at security level `K`, filling `out`.
///
/// Panics only on an empty DST or `out` longer than the expander supports,
/// both of which are programming errors with our fixed DSTs and lengths.
pub(crate) fn expand_message<X, K>(msg: &[&[u8]], dst: &[&[u8]], out: &mut [u8])
where
    X: ExpandMsg<K>,
{
    let len = u16::try_from(out.len())
        .ok()
        .and_then(NonZeroU16::new)
        .expect("expand_message output length must be in 1..=65535");
    let mut expander = X::expand_message(msg, dst, len).expect("valid DST and length");
    expander
        .fill_bytes(out)
        .expect("expander yields exactly `len` bytes");
}

/// Simplified SWU parameters for `y^2 = x^3 + A x + B`.
pub(crate) struct SswuParams<F> {
    pub a: F,
    pub b: F,
    /// Non-square `Z` chosen per RFC 9380 Appendix H.2.
    pub z: F,
    /// `(p - 3) / 4` as little-endian u64 limbs.
    pub c1: [u64; 4],
    /// `sqrt(-Z)`.
    pub c2: F,
}

/// `sqrt_ratio` for `p = 3 (mod 4)` (RFC 9380 Appendix F.2.1.2).
///
/// Returns `(true, sqrt(u/v))` if `u/v` is square, else `(false, sqrt(Z u/v))`.
fn sqrt_ratio_3mod4<F: PrimeField>(p: &SswuParams<F>, u: F, v: F) -> (Choice, F) {
    let tv1 = v.square();
    let tv2 = u * v;
    let tv1 = tv1 * tv2;
    let y1 = tv1.pow_vartime(p.c1) * tv2; // exponent is public
    let y2 = y1 * p.c2;
    let is_qr = (y1.square() * v).ct_eq(&u);
    (is_qr, F::conditional_select(&y2, &y1, is_qr))
}

/// `sgn0` for prime fields (RFC 9380 §4.1).
fn sgn0<F: PrimeField>(x: &F) -> Choice {
    x.is_odd()
}

/// Simplified SWU map, constant time (RFC 9380 Appendix F.2). Returns affine
/// `(x, y)` on the curve.
pub(crate) fn map_to_curve_sswu<F: PrimeField>(p: &SswuParams<F>, u: &F) -> (F, F) {
    let tv1 = p.z * u.square();
    let tv2 = tv1.square() + tv1;
    let tv3 = p.b * (tv2 + F::ONE);
    let tv4 = p.a * F::conditional_select(&p.z, &-tv2, !tv2.is_zero());
    let tv6 = tv4.square();
    let num = (tv3.square() + p.a * tv6) * tv3 + p.b * (tv6 * tv4);
    let den = tv6 * tv4;
    let x = tv1 * tv3;
    let (is_gx1_square, y1) = sqrt_ratio_3mod4(p, num, den);
    let y = tv1 * u * y1;
    let x = F::conditional_select(&x, &tv3, is_gx1_square);
    let y = F::conditional_select(&y, &y1, is_gx1_square);
    let y = F::conditional_select(&-y, &y, sgn0(u).ct_eq(&sgn0(&y)));
    // tv4 = A * (Z or -tv2) is never zero: A, Z != 0 and tv2 != 0 in that branch.
    let tv4_inv = Option::<F>::from(tv4.invert()).expect("tv4 is non-zero");
    (x * tv4_inv, y)
}

/// Interpret 48 big-endian bytes as an integer and reduce it mod `p`
/// (RFC 9380 §5.2, `L = 48` for 256-bit fields).
///
/// Splits the input as `hi * 2^192 + lo` with `hi`, `lo` < `2^192` < `p`.
pub(crate) fn reduce_48<F>(bytes: &[u8; 48]) -> F
where
    F: PrimeField<Repr: AsMut<[u8]>>,
{
    let from_24 = |chunk: &[u8]| -> F {
        let mut repr = F::Repr::default();
        let r = repr.as_mut();
        let off = r.len() - chunk.len();
        r[off..].copy_from_slice(chunk);
        Option::from(F::from_repr(repr)).expect("value < 2^192 < p")
    };
    let mut two_192 = F::Repr::default();
    let r = two_192.as_mut();
    r[r.len() - 25] = 1;
    let two_192: F = Option::from(F::from_repr(two_192)).expect("2^192 < p");
    from_24(&bytes[..24]) * two_192 + from_24(&bytes[24..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;
    use hash2curve::ExpandMsgXmd;
    use p256::elliptic_curve::consts::U16;
    use p256::elliptic_curve::ff::Field;
    use p256::elliptic_curve::hazmat::FieldArithmetic;
    use p256::NistP256;
    use primeorder::PrimeCurveParams;
    use sha2::Sha256;

    type Fe = <NistP256 as FieldArithmetic>::FieldElement;

    fn p256_params() -> SswuParams<Fe> {
        let z = -Fe::from(10u64);
        SswuParams {
            a: <NistP256 as PrimeCurveParams>::EQUATION_A,
            b: <NistP256 as PrimeCurveParams>::EQUATION_B,
            z,
            c1: [
                0xffff_ffff_ffff_ffff,
                0x0000_0000_3fff_ffff,
                0x4000_0000_0000_0000,
                0x3fff_ffff_c000_0000,
            ],
            c2: Option::from((-z).sqrt()).unwrap(),
        }
    }

    fn fe(h: &str) -> Fe {
        let mut repr = <Fe as PrimeField>::Repr::default();
        repr.copy_from_slice(&hex(h));
        Option::from(Fe::from_repr(repr)).unwrap()
    }

    // RFC 9380 Appendix J.1.1, P256_XMD:SHA-256_SSWU_RO_.
    // (msg, u0, u1, Q0.x, Q0.y, Q1.x, Q1.y)
    const P256_VECTORS: &[(&[u8], [&str; 6])] = &[
        (
            b"",
            [
                "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009",
                "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a",
                "ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5",
                "dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1",
                "51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
                "b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac",
            ],
        ),
        (
            b"abc",
            [
                "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1",
                "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0",
                "5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48",
                "7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d93ecf",
                "019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f",
                "589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4252715446e",
            ],
        ),
        (
            b"abcdef0123456789",
            [
                "0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c",
                "b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb",
                "a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2",
                "4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e",
                "7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66",
                "b765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9",
            ],
        ),
    ];

    /// Our generic hash_to_field + SSWU reproduces the RFC 9380 P-256 vectors.
    #[test]
    fn sswu_matches_rfc9380_p256_vectors() {
        let params = p256_params();
        let dst: &[&[u8]] = &[b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"];
        for (msg, v) in P256_VECTORS {
            let mut uniform = [0u8; 96];
            expand_message::<ExpandMsgXmd<Sha256>, U16>(&[msg], dst, &mut uniform);
            let u0: Fe = reduce_48(uniform[..48].try_into().unwrap());
            let u1: Fe = reduce_48(uniform[48..].try_into().unwrap());
            assert_eq!(u0, fe(v[0]), "u0 for {msg:?}");
            assert_eq!(u1, fe(v[1]), "u1 for {msg:?}");
            assert_eq!(map_to_curve_sswu(&params, &u0), (fe(v[2]), fe(v[3])));
            assert_eq!(map_to_curve_sswu(&params, &u1), (fe(v[4]), fe(v[5])));
        }
    }

    #[test]
    fn p256_params_are_consistent() {
        let p = p256_params();
        assert_eq!(p.c2.square(), -p.z);
        // x^((p-3)/4 * 4 + 3) = x^p = x (Fermat), so the c1 limbs encode (p-3)/4.
        let x = Fe::from(123_456_789u64);
        let y = <Fe as Field>::pow_vartime(&x, p.c1);
        assert_eq!(y.square().square() * x.square() * x, x);
    }
}
