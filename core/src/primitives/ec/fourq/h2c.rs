//! Hash-to-curve for FourQ, suite `FourQ_XMD:SHA-256_ELL2_RO_`
//! (cryptex-defined; FourQ has no standardized suite):
//!
//! - `expand_message_xmd` with SHA-256, `k = 128`, `L = 32` bytes per GF(p)
//!   coefficient, two coefficients per GF(p^2) element (RFC 9380 §5);
//! - Elligator 2 on the birationally equivalent Montgomery curve
//!   `K t^2 = s^3 + J s^2 + s`, `J = 2(1-d)/(1+d)`, `K = -4/(1+d)`
//!   (RFC 9380 §6.7.1), with `Z = 2 + i` (appendix H.3 rule);
//! - the rational map to the twisted Edwards curve (appendix D.1);
//! - `Q0 + Q1`, then clearing the cofactor 392.
//!
//! Checked against an independent Python implementation in
//! `core/tests/vectors/fourq_reference.py`.

use hash2curve::ExpandMsgXmd;
use primeorder::elliptic_curve::consts::U16;
use sha2::Sha256;
use subtle::{ConditionallySelectable, ConstantTimeEq};

use super::curve::{Affine, Ext};
use super::fp::Fp;
use super::fp2::Fp2;
use crate::primitives::ec::hash_to_curve::expand_message;

/// `J / K`.
const C1: Fp2 = Fp2::new(
    0x4000_0000_0000_0072_0000_0000_0000_00a0,
    0x6f23_97c2_332b_f07e_59c1_0a44_78fe_0646,
);
/// `1 / K^2`.
const C2: Fp2 = Fp2::new(
    0x0800_0000_0000_47d1_8000_0000_0000_6591,
    0x4a75_67c0_94ab_81a2_4d7d_9193_f3b1_931e,
);
/// `K`.
const K: Fp2 = Fp2::new(
    0x0000_0000_0000_038f_ffff_ffff_ffff_faf4,
    0x1c85_7ca4_0978_5eb0_5523_4a8c_c3ec_97e7,
);
const Z: Fp2 = Fp2::new(2, 1);

/// `hash_to_field` with `count = 2`, `m = 2`, `L = 32`.
fn hash_to_field(msg: &[u8], dst: &[&[u8]]) -> [Fp2; 2] {
    let mut uniform = [0u8; 128];
    expand_message::<ExpandMsgXmd<Sha256>, U16>(&[msg], dst, &mut uniform);
    let e = |i: usize| Fp::from_be_bytes_reduce(&uniform[32 * i..32 * (i + 1)]);
    [Fp2 { a: e(0), b: e(1) }, Fp2 { a: e(2), b: e(3) }]
}

/// Elligator 2 to the Montgomery curve, constant time (RFC 9380 §6.7.1),
/// returning `(s, t)`.
fn elligator2(u: &Fp2) -> (Fp2, Fp2) {
    let tv = Fp2::ONE.add(Z.mul(u.square()));
    let is_exc = tv.is_zero();
    // x1 = -(J/K) / (1 + Z u^2), or -(J/K) when the denominator is 0.
    let x1 = C1.neg().mul(tv.invert());
    let x1 = Fp2::conditional_select(&x1, &C1.neg(), is_exc | x1.is_zero());
    let g = |x: Fp2| x.square().mul(x).add(C1.mul(x.square())).add(x.mul(C2));
    let gx1 = g(x1);
    let x2 = x1.neg().sub(C1);
    let gx2 = g(x2);
    let e = gx1.is_square();
    // Exactly one of g(x1), g(x2) is square (Z is a non-square), so select
    // first and take a single square root.
    let x = Fp2::conditional_select(&x2, &x1, e);
    let gx = Fp2::conditional_select(&gx2, &gx1, e);
    let (_, y) = gx.sqrt();
    // sgn0(y) must be 1 for the x1 branch, 0 for the x2 branch.
    let want = e;
    let y = Fp2::conditional_select(&y.neg(), &y, y.sgn0().ct_eq(&want));
    (x.mul(K), y.mul(K))
}

/// Rational map from the Montgomery curve to the Edwards curve
/// (RFC 9380 appendix D.1): `x = s / t`, `y = (s - 1) / (s + 1)`, mapping
/// the exceptional cases to the identity.
fn to_edwards(s: &Fp2, t: &Fp2) -> Affine {
    let den1 = *t;
    let den2 = s.add(Fp2::ONE);
    let exc = den1.is_zero() | den2.is_zero();
    // One inversion for both denominators (Montgomery's trick); if either is
    // 0 the product is 0 and the result is replaced below.
    let inv = den1.mul(den2).invert();
    let x = s.mul(den2).mul(inv);
    let y = s.sub(Fp2::ONE).mul(den1).mul(inv);
    Affine {
        x: Fp2::conditional_select(&x, &Fp2::ZERO, exc),
        y: Fp2::conditional_select(&y, &Fp2::ONE, exc),
    }
}

/// Map one field element to a curve point (not yet in the subgroup).
pub(crate) fn map_to_curve(u: &Fp2) -> Affine {
    let (s, t) = elligator2(u);
    to_edwards(&s, &t)
}

/// `hash_to_curve`: a uniformly distributed point of the order-N subgroup.
pub(crate) fn hash_to_curve(msg: &[u8], dst: &[&[u8]]) -> Ext {
    let [u0, u1] = hash_to_field(msg, dst);
    let q0 = Ext::from_affine(&map_to_curve(&u0));
    let q1 = Ext::from_affine(&map_to_curve(&u1));
    q0.add(&q1).clear_cofactor()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::rand::csprng;
    use rand::Rng;

    #[test]
    fn constants_are_consistent() {
        use super::super::curve::D;
        // K = -4 / (1 + d), J/K = C1, 1/K^2 = C2.
        let one_d = Fp2::ONE.add(D);
        assert_eq!(K.mul(one_d), Fp2::new(4, 0).neg());
        let j = Fp2::new(2, 0).mul(Fp2::ONE.sub(D)).mul(one_d.invert());
        assert_eq!(j.mul(K.invert()), C1);
        assert_eq!(K.square().mul(C2), Fp2::ONE);
        assert!(!bool::from(Z.is_square()));
    }

    /// Matches the independent Python reference for a fixed input.
    #[test]
    fn map_matches_reference() {
        let u = Fp2::new(123456789, 987654321);
        let p = map_to_curve(&u);
        assert_eq!(
            p.x,
            Fp2::new(
                0x6fbb81e67d1ccd4e7170214cf46b9918,
                0x340b5aba4dd195717d5b60937719f587
            )
        );
        assert_eq!(
            p.y,
            Fp2::new(
                0x335e1d2b624ff7d72b0f3e8a70eb0dc6,
                0x05f079bb084e793dcf1261f2e2f5e991
            )
        );
    }

    #[test]
    fn map_lands_on_curve() {
        let mut rng = csprng().unwrap();
        for _ in 0..300 {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            let u = Fp2 {
                a: Fp::from_u128(u128::from_le_bytes(b[..16].try_into().unwrap())),
                b: Fp::from_u128(u128::from_le_bytes(b[16..].try_into().unwrap())),
            };
            assert!(bool::from(map_to_curve(&u).is_on_curve()));
        }
        // Exceptional input u = 0 (x1 = -J/K) and the identity paths.
        assert!(bool::from(map_to_curve(&Fp2::ZERO).is_on_curve()));
    }
}
