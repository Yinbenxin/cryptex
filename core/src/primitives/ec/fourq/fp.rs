//! GF(p), p = 2^127 - 1, in constant time.
//!
//! Elements are `u128` values kept fully reduced in `[0, p)`. Since
//! `2^127 ≡ 1 (mod p)`, reduction is a fold of the high bits.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub(crate) const P: u128 = (1 << 127) - 1;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Fp(pub(crate) u128);

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp(u128::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for Fp {}

/// Reduce any `x < 2^128` to `[0, p)`, branch-free.
///
/// Plain arithmetic rather than `subtle` on this hot path: `subtle`'s
/// optimization barrier costs more than the arithmetic itself. No step
/// depends on the value through a branch or a memory index.
#[inline]
fn reduce_once(x: u128) -> u128 {
    // x = h·2^127 + l ≡ h + l with h ≤ 1: one fold gives y ≤ 2^127 = p + 1,
    // a second fold y ≤ p. Then map p to 0: (y + 1) >> 127 is 1 iff y = p.
    let y = (x & P) + (x >> 127);
    let y = (y & P) + (y >> 127);
    let is_p = (y + 1) >> 127;
    y & is_p.wrapping_sub(1)
}

/// `a · b mod p` for `a, b < 2^127`, as a value `< 2^128` (not fully
/// reduced). Works on 64-bit limbs: with `a = a1·2^64 + a0` (`a1 < 2^63`),
///
/// ```text
///   a·b = a1b1·2^128 + (a1b0 + a0b1)·2^64 + a0b0
///       ≡ 2·a1b1 + (a1b0 + a0b1)·2^64 + a0b0        (2^128 ≡ 2)
/// ```
///
/// and the middle term is folded the same way.
#[inline]
fn mul_reduce(a: u128, b: u128) -> u128 {
    let (a0, a1) = (a as u64 as u128, a >> 64);
    let (b0, b1) = (b as u64 as u128, b >> 64);
    let lo = a0 * b0; // < 2^128
    let mid = a1 * b0 + a0 * b1; // < 2^128 (a1, b1 < 2^63)
    let hi = a1 * b1; // < 2^126
                      // mid·2^64 = (mid >> 64)·2^128 + (mid mod 2^64)·2^64
                      //          ≡ 2·(mid >> 64) + (mid mod 2^64)·2^64.
    let (mid_lo, mid_hi) = (mid as u64 as u128, mid >> 64);
    // Sum of: lo (< 2^128), mid_lo·2^64 (< 2^128), 2·hi + 2·mid_hi (< 2^128).
    // Fold each 128-bit addend to < 2^127 + 1 first so the total fits.
    let f = |x: u128| (x & P) + (x >> 127);
    f(f(lo) + f(mid_lo << 64)) + f((hi + mid_hi) << 1)
}

impl Fp {
    pub(crate) const ZERO: Fp = Fp(0);
    pub(crate) const ONE: Fp = Fp(1);

    /// From any `u128` (reduced mod p).
    #[cfg(test)]
    pub(crate) fn from_u128(x: u128) -> Fp {
        Fp(reduce_once(x))
    }

    #[inline]
    pub(crate) fn add(self, o: Fp) -> Fp {
        // Both < 2^127, so the sum fits in u128.
        Fp(reduce_once(self.0 + o.0))
    }

    #[inline]
    pub(crate) fn neg(self) -> Fp {
        // p - a for a ≠ 0, and 0 for a = 0.
        Fp(reduce_once(P - self.0))
    }

    #[inline]
    pub(crate) fn sub(self, o: Fp) -> Fp {
        // a + (p - b) < 2^128 for a, b < p.
        Fp(reduce_once(self.0 + (P - o.0)))
    }

    #[inline]
    pub(crate) fn mul(self, o: Fp) -> Fp {
        Fp(reduce_once(mul_reduce(self.0, o.0)))
    }

    #[inline]
    pub(crate) fn square(self) -> Fp {
        self.mul(self)
    }

    /// `self^(2^k)`.
    fn square_n(mut self, k: u32) -> Fp {
        for _ in 0..k {
            self = self.square();
        }
        self
    }

    /// `self^(2^125 - 1)`, shared by inversion and square roots.
    fn pow_2_125_minus_1(self) -> Fp {
        // Addition chain on exponents of the form 2^k - 1.
        let x2 = self.square().mul(self); // 2^2 - 1
        let x4 = x2.square_n(2).mul(x2); // 2^4 - 1
        let x5 = x4.square().mul(self); // 2^5 - 1
        let x10 = x5.square_n(5).mul(x5); // 2^10 - 1
        let x20 = x10.square_n(10).mul(x10);
        let x25 = x20.square_n(5).mul(x5);
        let x50 = x25.square_n(25).mul(x25);
        let x100 = x50.square_n(50).mul(x50);
        x100.square_n(25).mul(x25)
    }

    /// `self^(p - 2) = self^(2^127 - 3)`; inverse for nonzero inputs, 0 for 0.
    pub(crate) fn invert(self) -> Fp {
        // 2^127 - 3 = (2^125 - 1)·4 + 1.
        self.pow_2_125_minus_1().square_n(2).mul(self)
    }

    /// `self^((p + 1) / 4) = self^(2^125)`: a square root when one exists.
    #[cfg(test)]
    pub(crate) fn sqrt_candidate(self) -> Fp {
        self.square_n(125)
    }

    /// `self^((p - 1) / 2)` as a choice: 1 if a nonzero square.
    pub(crate) fn is_square(self) -> Choice {
        // (p - 1)/2 = 2^126 - 1 = (2^125 - 1)·2 + 1.
        let l = self.pow_2_125_minus_1().square().mul(self);
        l.ct_eq(&Fp::ONE) | self.ct_eq(&Fp::ZERO)
    }

    pub(crate) fn is_zero(self) -> Choice {
        self.0.ct_eq(&0)
    }

    pub(crate) fn is_odd(self) -> Choice {
        Choice::from((self.0 & 1) as u8)
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Canonical decoding: the top bit must be clear and the value `< p`.
    pub(crate) fn from_le_bytes_canonical(b: &[u8; 16]) -> Option<Fp> {
        let v = u128::from_le_bytes(*b);
        (v < P).then_some(Fp(v))
    }

    /// Big-endian bytes of any length, reduced mod p (for hash-to-field).
    pub(crate) fn from_be_bytes_reduce(b: &[u8]) -> Fp {
        let two_8 = Fp(256);
        b.iter()
            .fold(Fp::ZERO, |acc, &x| acc.mul(two_8).add(Fp(x as u128)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    use crate::primitives::rand::csprng;

    fn rand_fp(rng: &mut impl Rng) -> Fp {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        Fp::from_u128(u128::from_le_bytes(b) >> 1)
    }

    /// Reference product via u128 halves and Python-style big ints are not
    /// available, so check against repeated addition structure instead.
    #[test]
    fn arithmetic_laws() {
        let mut rng = csprng().unwrap();
        for _ in 0..1000 {
            let (a, b, c) = (rand_fp(&mut rng), rand_fp(&mut rng), rand_fp(&mut rng));
            assert_eq!(a.mul(b), b.mul(a));
            assert_eq!(a.mul(b).mul(c), a.mul(b.mul(c)));
            assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
            assert_eq!(a.sub(a), Fp::ZERO);
            assert_eq!(a.add(a.neg()), Fp::ZERO);
            if a != Fp::ZERO {
                assert_eq!(a.mul(a.invert()), Fp::ONE);
            }
            let s = a.square();
            assert!(bool::from(s.is_square()));
            let r = s.sqrt_candidate();
            assert_eq!(r.square(), s);
        }
        assert_eq!(Fp::ZERO.invert(), Fp::ZERO);
        assert!(bool::from(Fp::ZERO.is_square()));
        // -1 is a non-square since p ≡ 3 (mod 4).
        assert!(!bool::from(Fp::ONE.neg().is_square()));
    }

    #[test]
    fn edge_values() {
        let pm1 = Fp(P - 1);
        assert_eq!(pm1.add(Fp::ONE), Fp::ZERO);
        assert_eq!(pm1.mul(pm1), Fp::ONE); // (-1)^2
        assert_eq!(Fp::from_u128(P), Fp::ZERO);
        assert_eq!(Fp::from_u128(u128::MAX), Fp::ONE); // 2^128 - 1 = 2p + 1
        assert_eq!(Fp(1 << 126).mul(Fp(2)), Fp::ONE); // 2^127 ≡ 1
                                                      // Known product: (2^126)^2 = 2^252 = 2^(127·1 + 125) ≡ 2^125.
        assert_eq!(Fp(1 << 126).square(), Fp(1 << 125));
        assert!(Fp::from_le_bytes_canonical(&P.to_le_bytes()).is_none());
        assert!(Fp::from_le_bytes_canonical(&(P - 1).to_le_bytes()).is_some());
    }

    #[test]
    fn be_reduction() {
        // 2^127 mod p = 1.
        let mut b = [0u8; 32];
        b[16] = 0x80; // bit 127 of a 256-bit big-endian integer
        assert_eq!(Fp::from_be_bytes_reduce(&b), Fp::ONE);
        let b = (P - 5).to_be_bytes();
        assert_eq!(Fp::from_be_bytes_reduce(&b), Fp(P - 5));
    }
}
