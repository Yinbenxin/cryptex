//! FourQ point arithmetic (Costello, Longa, ASIACRYPT 2015).
//!
//! Twisted Edwards curve `-x^2 + y^2 = 1 + d x^2 y^2` over GF(p^2) with the
//! complete addition law (a = -1 is a square, d a non-square). Points use
//! FourQlib's representations:
//!
//! - `Ext`: extended coordinates `(X, Y, Z, Ta, Tb)` with `T = Ta·Tb`,
//!   `x = X/Z`, `y = Y/Z`, `xy = T/Z`;
//! - `Cached`: `(X+Y, Y-X, 2Z, 2dT)`, the operand form of the addition.
//!
//! Formulas follow FourQlib's `eccdouble`, `eccadd_core` and friends.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::fp2::Fp2;

/// `d = 4205857648805777768770 + 125317048443780598345676279555970305165·i`.
pub(crate) const D: Fp2 = Fp2::new(
    0x0000_0000_0000_00e4_0000_0000_0000_0142,
    0x5e47_2f84_6657_e0fc_b382_1488_f1fc_0c8d,
);

/// Affine point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Affine {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
}

impl Affine {
    pub(crate) const IDENTITY: Affine = Affine {
        x: Fp2::ZERO,
        y: Fp2::ONE,
    };

    /// `-x^2 + y^2 == 1 + d x^2 y^2`.
    pub(crate) fn is_on_curve(&self) -> Choice {
        let x2 = self.x.square();
        let y2 = self.y.square();
        y2.sub(x2).ct_eq(&Fp2::ONE.add(D.mul(x2).mul(y2)))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Ext {
    x: Fp2,
    y: Fp2,
    z: Fp2,
    ta: Fp2,
    tb: Fp2,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Cached {
    xy: Fp2,
    yx: Fp2,
    z2: Fp2,
    t2: Fp2,
}

impl ConditionallySelectable for Cached {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Cached {
            xy: Fp2::conditional_select(&a.xy, &b.xy, c),
            yx: Fp2::conditional_select(&a.yx, &b.yx, c),
            z2: Fp2::conditional_select(&a.z2, &b.z2, c),
            t2: Fp2::conditional_select(&a.t2, &b.t2, c),
        }
    }
}

impl Cached {
    /// `-P`: swap `X+Y` and `Y-X`, negate `2dT`.
    fn neg(&self) -> Cached {
        Cached {
            xy: self.yx,
            yx: self.xy,
            z2: self.z2,
            t2: self.t2.neg(),
        }
    }
}

/// `(X+Y, Y-X, Z, T)`, the second operand of `add_core`.
#[derive(Clone, Copy, Debug)]
struct Plain {
    xy: Fp2,
    yx: Fp2,
    z: Fp2,
    t: Fp2,
}

impl Ext {
    pub(crate) fn from_affine(p: &Affine) -> Ext {
        Ext {
            x: p.x,
            y: p.y,
            z: Fp2::ONE,
            ta: p.x,
            tb: p.y,
        }
    }

    pub(crate) fn identity() -> Ext {
        Ext::from_affine(&Affine::IDENTITY)
    }

    pub(crate) fn to_affine(self) -> Affine {
        let zi = self.z.invert();
        Affine {
            x: self.x.mul(zi),
            y: self.y.mul(zi),
        }
    }

    /// `(X+Y, Y-X, 2Z, 2dT)` (FourQlib `R1_to_R2`).
    pub(crate) fn to_cached(self) -> Cached {
        let t = self.ta.mul(self.tb);
        Cached {
            xy: self.x.add(self.y),
            yx: self.y.sub(self.x),
            z2: self.z.add(self.z),
            t2: t.add(t).mul(D),
        }
    }

    /// `(X+Y, Y-X, Z, T)` (FourQlib `R1_to_R3`).
    fn to_plain(self) -> Plain {
        Plain {
            xy: self.x.add(self.y),
            yx: self.y.sub(self.x),
            z: self.z,
            t: self.ta.mul(self.tb),
        }
    }

    /// `2P` (FourQlib `eccdouble`); uses only X, Y, Z.
    pub(crate) fn double(&self) -> Ext {
        let t1 = self.x.square();
        let t2 = self.y.square();
        let xpy = self.x.add(self.y);
        let tb = t1.add(t2);
        let t1 = t2.sub(t1);
        let ta = xpy.square().sub(tb);
        let zz = self.z.square();
        let t2 = zz.add(zz).sub(t1);
        Ext {
            y: t1.mul(tb),
            x: t2.mul(ta),
            z: t1.mul(t2),
            ta,
            tb,
        }
    }

    /// `P + Q` with `Q` cached (FourQlib `eccadd`). Complete.
    pub(crate) fn add_cached(&self, q: &Cached) -> Ext {
        add_core(q, &self.to_plain())
    }

    pub(crate) fn add(&self, q: &Ext) -> Ext {
        self.add_cached(&q.to_cached())
    }

    #[cfg(test)]
    pub(crate) fn neg(&self) -> Ext {
        Ext {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            ta: self.ta.neg(),
            tb: self.tb,
        }
    }

    /// Projective equality: `X1·Z2 = X2·Z1` and `Y1·Z2 = Y2·Z1`.
    pub(crate) fn ct_eq(&self, o: &Ext) -> Choice {
        self.x.mul(o.z).ct_eq(&o.x.mul(self.z)) & self.y.mul(o.z).ct_eq(&o.y.mul(self.z))
    }

    pub(crate) fn is_identity(&self) -> Choice {
        self.x.is_zero() & self.y.ct_eq(&self.z)
    }

    /// `392·P` (FourQlib `cofactor_clearing`): 392 = ((2·1 + 1)·2^4 + 1)·2^3
    /// with the additions of `P` at the marked steps.
    pub(crate) fn clear_cofactor(&self) -> Ext {
        let q = self.to_cached();
        let mut p = self.double().add_cached(&q); // 3P
        for _ in 0..4 {
            p = p.double();
        }
        p = p.add_cached(&q); // 49P
        for _ in 0..3 {
            p = p.double();
        }
        p // 392P
    }

    pub(crate) fn x_y_z(&self) -> (Fp2, Fp2, Fp2) {
        (self.x, self.y, self.z)
    }

    pub(crate) fn from_parts(x: Fp2, y: Fp2, z: Fp2, ta: Fp2, tb: Fp2) -> Ext {
        Ext { x, y, z, ta, tb }
    }
}

/// `P + Q` with `P = (X+Y, Y-X, 2Z, 2dT)` and `Q = (X+Y, Y-X, Z, T)`
/// (FourQlib `eccadd_core`).
fn add_core(p: &Cached, q: &Plain) -> Ext {
    let z = p.t2.mul(q.t);
    let t1 = p.z2.mul(q.z);
    let x = p.xy.mul(q.xy);
    let y = p.yx.mul(q.yx);
    let theta = t1.sub(z);
    let alpha = t1.add(z);
    let beta = x.sub(y);
    let omega = x.add(y);
    Ext {
        x: beta.mul(theta),
        z: theta.mul(alpha),
        y: alpha.mul(omega),
        ta: omega,
        tb: beta,
    }
}

/// Constant-time `±table[digit]`: scans every entry; `negate` selects the
/// sign.
pub(crate) fn lookup(table: &[Cached], digit: u32, negate: Choice) -> Cached {
    let mut r = table[0];
    for (i, e) in table.iter().enumerate().skip(1) {
        r.conditional_assign(e, (i as u32).ct_eq(&digit));
    }
    Cached::conditional_select(&r, &r.neg(), negate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FourQlib `GENERATOR_x`, `GENERATOR_y`.
    pub(crate) const G: Affine = Affine {
        x: Fp2::new(
            0x1a34_7223_7c2f_b305_2865_92ad_7b38_33aa,
            0x1e1f_553f_2878_aa9c_9686_9fb3_60ac_77f6,
        ),
        y: Fp2::new(
            0x0e3f_ee9b_a120_785a_b924_a246_2bcb_b287,
            0x6e1c_4af8_630e_0242_49a7_c344_844c_8b5c,
        ),
    };

    #[test]
    fn generator_is_on_curve() {
        assert!(bool::from(G.is_on_curve()));
        assert!(bool::from(Affine::IDENTITY.is_on_curve()));
    }

    #[test]
    fn group_laws() {
        let g = Ext::from_affine(&G);
        let g2 = g.double();
        assert!(bool::from(g2.ct_eq(&g.add(&g))));
        let g3 = g2.add(&g);
        assert!(bool::from(g3.ct_eq(&g.add(&g2))));
        assert!(bool::from(g3.to_affine().is_on_curve()));
        assert!(bool::from(g.add(&g.neg()).is_identity()));
        assert!(bool::from(g.add(&Ext::identity()).ct_eq(&g)));
        // Doubling the identity, adding identity to itself: complete law.
        assert!(bool::from(Ext::identity().double().is_identity()));
        assert!(bool::from(
            Ext::identity().add(&Ext::identity()).is_identity()
        ));
    }

    #[test]
    fn cofactor_clearing_is_392() {
        let g = Ext::from_affine(&G);
        let mut naive = Ext::identity();
        for _ in 0..392 {
            naive = naive.add(&g);
        }
        assert!(bool::from(g.clear_cofactor().ct_eq(&naive)));
    }

    #[test]
    fn lookup_selects_and_negates() {
        let g = Ext::from_affine(&G);
        let mut t = vec![g.to_cached()];
        let mut p = g;
        for _ in 1..8 {
            p = p.add(&g);
            t.push(p.to_cached());
        }
        for d in 0..8u32 {
            for neg in [false, true] {
                let c = lookup(&t, d, Choice::from(neg as u8));
                let mut expect = Ext::identity();
                for _ in 0..=d {
                    expect = expect.add(&g);
                }
                if neg {
                    expect = expect.neg();
                }
                assert!(bool::from(Ext::identity().add_cached(&c).ct_eq(&expect)));
            }
        }
    }
}
