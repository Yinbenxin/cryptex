//! GF(p^2) = GF(p)[i] / (i^2 + 1), p = 2^127 - 1, in constant time.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::fp::Fp;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Fp2 {
    pub(crate) a: Fp,
    pub(crate) b: Fp,
}

impl ConstantTimeEq for Fp2 {
    fn ct_eq(&self, o: &Self) -> Choice {
        self.a.ct_eq(&o.a) & self.b.ct_eq(&o.b)
    }
}

impl ConditionallySelectable for Fp2 {
    fn conditional_select(x: &Self, y: &Self, c: Choice) -> Self {
        Fp2 {
            a: Fp::conditional_select(&x.a, &y.a, c),
            b: Fp::conditional_select(&x.b, &y.b, c),
        }
    }
}

impl PartialEq for Fp2 {
    fn eq(&self, o: &Self) -> bool {
        bool::from(self.ct_eq(o))
    }
}
impl Eq for Fp2 {}

impl Fp2 {
    pub(crate) const ZERO: Fp2 = Fp2 {
        a: Fp::ZERO,
        b: Fp::ZERO,
    };
    pub(crate) const ONE: Fp2 = Fp2 {
        a: Fp::ONE,
        b: Fp::ZERO,
    };

    pub(crate) const fn new(a: u128, b: u128) -> Fp2 {
        Fp2 { a: Fp(a), b: Fp(b) }
    }

    #[inline]
    pub(crate) fn add(self, o: Fp2) -> Fp2 {
        Fp2 {
            a: self.a.add(o.a),
            b: self.b.add(o.b),
        }
    }

    #[inline]
    pub(crate) fn sub(self, o: Fp2) -> Fp2 {
        Fp2 {
            a: self.a.sub(o.a),
            b: self.b.sub(o.b),
        }
    }

    #[inline]
    pub(crate) fn neg(self) -> Fp2 {
        Fp2 {
            a: self.a.neg(),
            b: self.b.neg(),
        }
    }

    #[inline]
    pub(crate) fn mul(self, o: Fp2) -> Fp2 {
        // (a + bi)(c + di) = (ac - bd) + ((a + b)(c + d) - ac - bd) i
        let ac = self.a.mul(o.a);
        let bd = self.b.mul(o.b);
        let s = self.a.add(self.b).mul(o.a.add(o.b));
        Fp2 {
            a: ac.sub(bd),
            b: s.sub(ac).sub(bd),
        }
    }

    #[inline]
    pub(crate) fn square(self) -> Fp2 {
        // (a + bi)^2 = (a + b)(a - b) + 2ab i
        let ab = self.a.mul(self.b);
        Fp2 {
            a: self.a.add(self.b).mul(self.a.sub(self.b)),
            b: ab.add(ab),
        }
    }

    /// `a^2 + b^2 ∈ GF(p)`.
    pub(crate) fn norm(self) -> Fp {
        self.a.square().add(self.b.square())
    }

    /// Inverse; 0 for 0.
    pub(crate) fn invert(self) -> Fp2 {
        let n = self.norm().invert();
        Fp2 {
            a: self.a.mul(n),
            b: self.b.neg().mul(n),
        }
    }

    pub(crate) fn is_zero(self) -> Choice {
        self.a.is_zero() & self.b.is_zero()
    }

    /// Square in GF(p^2) ⟺ the norm is a square in GF(p).
    pub(crate) fn is_square(self) -> Choice {
        self.norm().is_square()
    }

    /// RFC 9380 `sgn0` for m = 2.
    pub(crate) fn sgn0(self) -> Choice {
        self.a.is_odd() | (self.a.is_zero() & self.b.is_odd())
    }

    /// Square root, constant time; `(is_square, root)`. Uses Adj and
    /// Rodríguez-Henríquez, "Square root computation over even extension
    /// fields", algorithm 9 (q = p^2 with p ≡ 3 mod 4).
    pub(crate) fn sqrt(self) -> (Choice, Fp2) {
        // a1 = x^((p - 3) / 4) — computed in GF(p^2) via Frobenius-free
        // exponentiation: (p - 3)/4 = 2^125 - 1.
        let a1 = self.pow_2_125_minus_1();
        let alpha = a1.square().mul(self); // x^((p - 1)/2)
        let x0 = a1.mul(self); // x^((p + 1)/4)
        let minus_one = Fp2::ONE.neg();
        // If alpha = -1: root = i·x0.
        let r_minus = Fp2 {
            a: x0.b.neg(),
            b: x0.a,
        };
        // Otherwise: b = (1 + alpha)^((p - 1)/2); root = b·x0.
        let b = Fp2::ONE.add(alpha).pow_2_126_minus_1();
        let r_other = b.mul(x0);
        let root = Fp2::conditional_select(&r_other, &r_minus, alpha.ct_eq(&minus_one));
        (root.square().ct_eq(&self), root)
    }

    fn square_n(mut self, k: u32) -> Fp2 {
        for _ in 0..k {
            self = self.square();
        }
        self
    }

    fn pow_2_125_minus_1(self) -> Fp2 {
        let x2 = self.square().mul(self);
        let x4 = x2.square_n(2).mul(x2);
        let x5 = x4.square().mul(self);
        let x10 = x5.square_n(5).mul(x5);
        let x20 = x10.square_n(10).mul(x10);
        let x25 = x20.square_n(5).mul(x5);
        let x50 = x25.square_n(25).mul(x25);
        let x100 = x50.square_n(50).mul(x50);
        x100.square_n(25).mul(x25)
    }

    /// `self^((p - 1) / 2) = self^(2^126 - 1)`.
    fn pow_2_126_minus_1(self) -> Fp2 {
        self.pow_2_125_minus_1().square().mul(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    use super::super::fp::P;
    use crate::primitives::rand::csprng;

    pub(crate) fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let x = u128::from_le_bytes(b[..16].try_into().unwrap()) >> 1;
        let y = u128::from_le_bytes(b[16..].try_into().unwrap()) >> 1;
        Fp2 {
            a: Fp::from_u128(x),
            b: Fp::from_u128(y),
        }
    }

    #[test]
    fn field_laws() {
        let mut rng = csprng().unwrap();
        let i = Fp2::new(0, 1);
        assert_eq!(i.square(), Fp2::ONE.neg());
        for _ in 0..500 {
            let (x, y, z) = (rand_fp2(&mut rng), rand_fp2(&mut rng), rand_fp2(&mut rng));
            assert_eq!(x.mul(y), y.mul(x));
            assert_eq!(x.mul(y).mul(z), x.mul(y.mul(z)));
            assert_eq!(x.mul(y.add(z)), x.mul(y).add(x.mul(z)));
            assert_eq!(x.square(), x.mul(x));
            if !bool::from(x.is_zero()) {
                assert_eq!(x.mul(x.invert()), Fp2::ONE);
            }
        }
    }

    #[test]
    fn square_roots() {
        let mut rng = csprng().unwrap();
        let mut non_squares = 0;
        for _ in 0..500 {
            let x = rand_fp2(&mut rng);
            let s = x.square();
            let (ok, r) = s.sqrt();
            assert!(bool::from(ok));
            assert_eq!(r.square(), s);
            assert!(bool::from(s.is_square()));
            let (ok, _) = x.sqrt();
            assert_eq!(bool::from(ok), bool::from(x.is_square()));
            non_squares += usize::from(!bool::from(x.is_square()));
        }
        assert!((150..350).contains(&non_squares), "{non_squares}");
        // Pure-real non-square in GF(p) is a square in GF(p^2).
        let (ok, r) = Fp2::ONE.neg().sqrt();
        assert!(bool::from(ok));
        assert_eq!(r.square(), Fp2::ONE.neg());
        assert!(bool::from(Fp2::ZERO.sqrt().0));
        let _ = P;
    }
}
