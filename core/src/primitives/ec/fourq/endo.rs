//! FourQ's endomorphisms ψ, φ and the 4-dimensional decomposition behind
//! variable-base scalar multiplication, ported from FourQlib (`eccp2.c`:
//! `ecc_tau`, `ecc_tau_dual`, `ecc_delphidel`, `ecc_delpsidel`,
//! `decompose`, `recode`, `ecc_precomp`, `ecc_mul`). Constants were
//! extracted mechanically from FourQlib's source.
//!
//! `k·P` for `P` in the order-N subgroup becomes `a1·P + a2·φ(P) +
//! a3·ψ(P) + a4·ψ(φ(P))` with 64-bit `a_i`, evaluated with one shared chain
//! of 64 doublings and 65 constant-time table lookups.

use subtle::Choice;
use zeroize::Zeroize;

use super::curve::{lookup, Cached, Ext};
use super::fp2::Fp2;

const CTAU1: Fp2 = Fp2::new(
    0x1964_de2c_3afa_d20c_74dc_d57c_ebce_74c3,
    0x0000_0000_0000_000c_0000_0000_0000_0012,
);
const CTAUDUAL1: Fp2 = Fp2::new(
    0x4aa7_40eb_2305_8652_9eca_a6d9_decd_f034,
    0x7fff_ffff_ffff_fff4_0000_0000_0000_0011,
);
const CPHI0: Fp2 = Fp2::new(
    0x0000_0000_0000_0005_ffff_ffff_ffff_fff7,
    0x2553_a075_9182_c329_4f65_536c_ef66_f81a,
);
const CPHI1: Fp2 = Fp2::new(
    0x0000_0000_0000_0005_0000_0000_0000_0007,
    0x62c8_caa0_c50c_62cf_334d_90e9_e282_96f9,
);
const CPHI2: Fp2 = Fp2::new(
    0x0000_0000_0000_000f_0000_0000_0000_0015,
    0x78df_262b_6c9b_5c98_2c2c_b715_4f1d_f391,
);
const CPHI3: Fp2 = Fp2::new(
    0x0000_0000_0000_0002_0000_0000_0000_0003,
    0x5084_c649_1d76_342a_9244_0457_a796_2ea4,
);
const CPHI4: Fp2 = Fp2::new(
    0x0000_0000_0000_0003_0000_0000_0000_0003,
    0x1244_0457_a796_2ea4_a109_8c92_3aec_6855,
);
const CPHI5: Fp2 = Fp2::new(
    0x0000_0000_0000_000a_0000_0000_0000_000f,
    0x4591_9541_8a18_c59e_669b_21d3_c505_2df3,
);
const CPHI6: Fp2 = Fp2::new(
    0x0000_0000_0000_0012_0000_0000_0000_0018,
    0x0b23_2a83_1431_8b3c_cd36_43a7_8a0a_5be7,
);
const CPHI7: Fp2 = Fp2::new(
    0x0000_0000_0000_0018_0000_0000_0000_0023,
    0x3963_bc1c_99e2_ea1a_66c1_8303_5f48_781a,
);
const CPHI8: Fp2 = Fp2::new(
    0x0000_0000_0000_00aa_0000_0000_0000_00f0,
    0x1f52_9f86_0316_cbe5_44e2_5158_2b5d_0ef0,
);
const CPHI9: Fp2 = Fp2::new(
    0x0000_0000_0000_0870_0000_0000_0000_0bef,
    0x0fd5_2e9c_fe00_375b_014d_3e48_976e_2505,
);
const CPSI1: Fp2 = Fp2::new(
    0x2af9_9e9a_83d5_4a02_edf0_7f47_67e3_46ef,
    0x0000_0000_0000_00de_0000_0000_0000_013a,
);
const CPSI2: Fp2 = Fp2::new(
    0x0000_0000_0000_00e4_0000_0000_0000_0143,
    0x21b8_d07b_99a8_1f03_4c7d_eb77_0e03_f372,
);
const CPSI3: Fp2 = Fp2::new(
    0x0000_0000_0000_0006_0000_0000_0000_0009,
    0x4cb2_6f16_1d7d_6906_3a6e_6abe_75e7_3a61,
);
const CPSI4: Fp2 = Fp2::new(
    0x7fff_ffff_ffff_fff9_ffff_ffff_ffff_fff6,
    0x334d_90e9_e282_96f9_c591_9541_8a18_c59e,
);

const C1: u64 = 0x72482c5251a4559c;
const C2: u64 = 0x59f95b0add276f6c;
const C3: u64 = 0x7dd2d17c4625fa78;
const C4: u64 = 0x6bc57def56ce8877;
const B11: u64 = 0x0906ff27e0a0a196;
const B12: u64 = 0x1363e862c22a2da0;
const B13: u64 = 0x07426031ecc8030f;
const B14: u64 = 0x084f739986b9e651;
const B21: u64 = 0x1d495bea84fcc2d4;
const B24: u64 = 0x25dbc5bc8dd167d0;
const B31: u64 = 0x17abad1d231f0302;
const B32: u64 = 0x02c4211ae388da51;
const B33: u64 = 0x2e4d21c98927c49f;
const B34: u64 = 0x0a9e6f44c02ecd97;
const B41: u64 = 0x136e340a9108c83f;
const B42: u64 = 0x3122df2dc3e0ff32;
const B43: u64 = 0x068a49f02aa8a9b5;
const B44: u64 = 0x18d5087896de0aea;
const ELL1: [u64; 4] = [
    0x259686e09d1a7d4f,
    0xf75682ace6a6bd66,
    0xfc5bb5c5ea2be5df,
    0x0000000000000007,
];
const ELL2: [u64; 4] = [
    0xd1ba1d84dd627afb,
    0x2bd235580f468d8d,
    0x8fd4b04caa6c0f8a,
    0x0000000000000003,
];
const ELL3: [u64; 4] = [
    0x9b291a33678c203c,
    0xc42bd6c965dca902,
    0xd038bf8d0bffbaf6,
    0x0000000000000000,
];
const ELL4: [u64; 4] = [
    0x12e5666b77e7fdc0,
    0x81cbdc3714983d82,
    0x1b073877a22d8410,
    0x0000000000000003,
];

/// Frobenius on coordinates: `(a + bi)^p = a - bi`.
fn conj(x: Fp2) -> Fp2 {
    Fp2 {
        a: x.a,
        b: x.b.neg(),
    }
}

/// `τ: E → Ê` (FourQlib `ecc_tau`), on (X, Y, Z).
fn tau(x: Fp2, y: Fp2, z: Fp2) -> (Fp2, Fp2, Fp2) {
    let t0 = x.square();
    let t1 = y.square();
    let xy = x.mul(y);
    let zz = z.square();
    let zn = t0.add(t1);
    let t0 = t1.sub(t0);
    let y2 = zz.add(zz);
    let xx = xy.mul(t0);
    let yy = y2.sub(t0);
    (xx.mul(CTAU1), yy.mul(zn), zn.mul(t0))
}

/// `τ̂: Ê → E` (FourQlib `ecc_tau_dual`), returning extended coordinates.
fn tau_dual(x: Fp2, y: Fp2, z: Fp2) -> Ext {
    let t0 = x.square();
    let ta0 = z.square();
    let t1 = y.square();
    let z2 = ta0.add(ta0);
    let ta = t1.sub(t0);
    let t0 = t0.add(t1);
    let xy = x.mul(y);
    let z2 = z2.sub(ta);
    let tb = xy.mul(CTAUDUAL1);
    let y = z2.mul(ta);
    let x = tb.mul(t0);
    let z = z2.mul(t0);
    Ext::from_parts(x, y, z, ta, tb)
}

/// `δ φ_W δ^-1` on Ê (FourQlib `ecc_delphidel`).
fn delphidel(x: Fp2, y: Fp2, z: Fp2) -> (Fp2, Fp2, Fp2) {
    let t4 = z.square();
    let t3 = y.mul(z);
    let t0 = t4.mul(CPHI4);
    let t2 = y.square();
    let t0 = t0.add(t2);
    let t1 = t3.mul(CPHI3);
    let t5 = t0.sub(t1);
    let t0 = t0.add(t1);
    let t0 = t0.mul(z);
    let t1 = t3.mul(CPHI1);
    let t0 = t0.mul(t5);
    let t5 = t4.mul(CPHI2);
    let t5 = t2.add(t5);
    let t6 = t1.sub(t5);
    let t1 = t1.add(t5);
    let t6 = t6.mul(t1);
    let t6 = t6.mul(CPHI0);
    let xx = x.mul(t6);
    let t6 = t2.square();
    let t2 = t3.square();
    let t3 = t4.square();
    let t1 = t2.mul(CPHI8);
    let t5 = t3.mul(CPHI9);
    let t1 = t1.add(t6);
    let t2 = t2.mul(CPHI6);
    let t3 = t3.mul(CPHI7);
    let t1 = t1.add(t5);
    let t2 = t2.add(t3);
    let t1 = t1.mul(y);
    let yy = t6.add(t2);
    let xx = xx.mul(t1);
    let yy = yy.mul(CPHI5);
    let xx = conj(xx);
    let yy = yy.mul(z);
    let zz = t0.mul(t1);
    let yy = yy.mul(t0);
    (xx, conj(yy), conj(zz))
}

/// `δ ψ_W δ^-1` on Ê (FourQlib `ecc_delpsidel`).
fn delpsidel(x: Fp2, y: Fp2, z: Fp2) -> (Fp2, Fp2, Fp2) {
    let (x, z, y) = (conj(x), conj(z), conj(y));
    let t2 = z.square();
    let t0 = x.square();
    let xx = x.mul(t2);
    let zz = t2.mul(CPSI2);
    let t1 = t2.mul(CPSI3);
    let t2 = t2.mul(CPSI4);
    let zz = t0.add(zz);
    let t2 = t0.add(t2);
    let t1 = t0.add(t1);
    let t2 = t2.neg();
    let zz = zz.mul(y);
    let xx = xx.mul(t2);
    let yy = t1.mul(zz);
    let xx = xx.mul(CPSI1);
    let zz = zz.mul(t2);
    (xx, yy, zz)
}

/// `φ(P)`.
pub(crate) fn phi(p: &Ext) -> Ext {
    let (x, y, z) = p.x_y_z();
    let (x, y, z) = tau(x, y, z);
    let (x, y, z) = delphidel(x, y, z);
    tau_dual(x, y, z)
}

/// `ψ(P)`.
pub(crate) fn psi(p: &Ext) -> Ext {
    let (x, y, z) = p.x_y_z();
    let (x, y, z) = tau(x, y, z);
    let (x, y, z) = delpsidel(x, y, z);
    tau_dual(x, y, z)
}

/// `⌊s · c / 2^256⌋` truncated to 64 bits (FourQlib `mul_truncate`).
fn mul_truncate(s: &[u64; 4], c: &[u64; 4]) -> u64 {
    // Full 512-bit schoolbook product, keep limb 4.
    let mut r = [0u128; 9];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = (s[i] as u128) * (c[j] as u128) + r[i + j] + carry;
            r[i + j] = t & 0xffff_ffff_ffff_ffff;
            carry = t >> 64;
        }
        r[i + 4] += carry;
    }
    r[4] as u64
}

/// Four 64-bit sub-scalars with `a1` odd (FourQlib `decompose`).
fn decompose(k: &[u64; 4]) -> [u64; 4] {
    let a1 = mul_truncate(k, &ELL1);
    let a2 = mul_truncate(k, &ELL2);
    let a3 = mul_truncate(k, &ELL3);
    let a4 = mul_truncate(k, &ELL4);
    let w = u64::wrapping_mul;
    let temp = k[0]
        .wrapping_sub(w(a1, B11))
        .wrapping_sub(w(a2, B21))
        .wrapping_sub(w(a3, B31))
        .wrapping_sub(w(a4, B41))
        .wrapping_add(C1);
    let mask = !(0u64.wrapping_sub(temp & 1)); // all ones iff temp even
    [
        temp.wrapping_add(mask & B41),
        w(a1, B12)
            .wrapping_add(a2)
            .wrapping_sub(w(a3, B32))
            .wrapping_sub(w(a4, B42))
            .wrapping_add(C2)
            .wrapping_add(mask & B42),
        w(a3, B33)
            .wrapping_sub(w(a1, B13))
            .wrapping_sub(a2)
            .wrapping_add(w(a4, B43))
            .wrapping_add(C3)
            .wrapping_sub(mask & B43),
        w(a1, B14)
            .wrapping_sub(w(a2, B24))
            .wrapping_sub(w(a3, B34))
            .wrapping_add(w(a4, B44))
            .wrapping_add(C4)
            .wrapping_sub(mask & B44),
    ]
}

/// GLV-SAC recoding into 65 digits in `[0, 8)` with signs (FourQlib
/// `recode`). `negate[i]` is true when digit `i` is negative.
fn recode(mut s: [u64; 4]) -> ([u32; 65], [bool; 65]) {
    let mut digits = [0u32; 65];
    let mut negate = [false; 65];
    for i in 0..64 {
        s[0] >>= 1;
        let bit0 = s[0] & 1;
        negate[i] = bit0 == 0;
        let mut d = 0u32;
        for (j, sj) in s.iter_mut().enumerate().skip(1) {
            let bit = *sj & 1;
            let carry = (bit0 | bit) ^ bit0;
            *sj = (*sj >> 1) + carry;
            d += (bit as u32) << (j - 1);
        }
        digits[i] = d;
    }
    digits[64] = (s[1] + (s[2] << 1) + (s[3] << 2)) as u32;
    negate[64] = false;
    s.zeroize();
    (digits, negate)
}

/// Table of `P + {0,1}·φ(P) + {0,1}·ψ(P) + {0,1}·ψ(φ(P))` (FourQlib
/// `ecc_precomp`), index bits (φ, ψ, ψφ).
fn precomp(p: &Ext) -> [Cached; 8] {
    let q = phi(p);
    let r = psi(p);
    let s = psi(&q);
    let t0 = *p;
    let t1 = t0.add(&q);
    let t2 = t0.add(&r);
    let t3 = t1.add(&r);
    [
        t0.to_cached(),
        t1.to_cached(),
        t2.to_cached(),
        t3.to_cached(),
        t0.add(&s).to_cached(),
        t1.add(&s).to_cached(),
        t2.add(&s).to_cached(),
        t3.add(&s).to_cached(),
    ]
}

/// `k·P` for `P` in the order-N subgroup, constant time in `k`
/// (FourQlib `ecc_mul` without validation or cofactor clearing). `k` is a
/// 256-bit little-endian integer; the result is `(k mod N)·P`.
pub(crate) fn mul(p: &Ext, k: &[u64; 4]) -> Ext {
    let scalars = decompose(k);
    let (mut digits, negate) = recode(scalars);
    let table = precomp(p);
    let c = lookup(&table, digits[64], Choice::from(u8::from(negate[64])));
    let mut r = Ext::identity().add_cached(&c);
    for i in (0..64).rev() {
        let c = lookup(&table, digits[i], Choice::from(u8::from(negate[i])));
        r = r.double().add_cached(&c);
    }
    digits.zeroize();
    r
}

#[cfg(test)]
mod tests {
    use super::super::curve::{Affine, Ext};
    use super::*;

    const G: Affine = Affine {
        x: Fp2::new(
            0x1a34_7223_7c2f_b305_2865_92ad_7b38_33aa,
            0x1e1f_553f_2878_aa9c_9686_9fb3_60ac_77f6,
        ),
        y: Fp2::new(
            0x0e3f_ee9b_a120_785a_b924_a246_2bcb_b287,
            0x6e1c_4af8_630e_0242_49a7_c344_844c_8b5c,
        ),
    };

    /// Double-and-add, for comparison.
    fn naive(p: &Ext, k: &[u64; 4]) -> Ext {
        let mut r = Ext::identity();
        for i in (0..256).rev() {
            r = r.double();
            if k[i / 64] >> (i % 64) & 1 == 1 {
                r = r.add(p);
            }
        }
        r
    }

    #[test]
    fn endomorphisms_map_onto_the_curve() {
        let g = Ext::from_affine(&G);
        assert!(bool::from(phi(&g).to_affine().is_on_curve()));
        assert!(bool::from(psi(&g).to_affine().is_on_curve()));
        // Homomorphisms: φ(2G) = 2φ(G), ψ(G + φG) = ψG + ψφG.
        assert!(bool::from(phi(&g.double()).ct_eq(&phi(&g).double())));
        assert!(bool::from(
            psi(&g.add(&phi(&g))).ct_eq(&psi(&g).add(&psi(&phi(&g))))
        ));
    }

    #[test]
    fn decomposition_shape() {
        for k in [
            [0u64; 4],
            [1, 0, 0, 0],
            [u64::MAX; 4],
            [0x1234, 0xabcd, 7, 9],
        ] {
            let s = decompose(&k);
            // Recoding needs an odd first sub-scalar; the 65-digit recoding
            // covers 64-bit sub-scalars, which `matches_double_and_add`
            // checks end to end.
            assert_eq!(s[0] & 1, 1, "a1 must be odd");
        }
    }

    #[test]
    fn matches_double_and_add() {
        let g = Ext::from_affine(&G);
        let ks = [
            [1u64, 0, 0, 0],
            [2, 0, 0, 0],
            [0x1234_5678_9abc_def0, 0, 0, 0],
            [0xffff_ffff_ffff_ffff, 0x1234, 0xdead_beef, 0x0012_3456],
            // N - 1
            [
                0x2fb2540ec7768ce6,
                0xdfbd004dfe0f7999,
                0xf05397829cbc14e5,
                0x0029cbc14e5e0a72,
            ],
        ];
        for k in ks {
            assert!(bool::from(mul(&g, &k).ct_eq(&naive(&g, &k))), "{k:x?}");
        }
        // N·G = identity.
        let n = [
            0x2fb2540ec7768ce7,
            0xdfbd004dfe0f7999,
            0xf05397829cbc14e5,
            0x0029cbc14e5e0a72,
        ];
        assert!(bool::from(mul(&g, &n).is_identity()));
        assert!(bool::from(naive(&g, &n).is_identity()));
    }
}
