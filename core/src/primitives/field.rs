//! Arithmetic in GF(2^128).
//!
//! Elements are 16 bytes. Addition is XOR. Multiplication is POLYVAL's
//! (RFC 8452) `a ⊗ b = a · b · x^-128 mod x^128 + x^127 + x^126 + x^121 + 1`.
//! `⊗` is commutative, associative and distributes over XOR, and `a ↦ a ·
//! x^-128` maps it onto ordinary multiplication, so (GF(2^128), ⊕, ⊗) is a
//! field. VOLE only needs a field; which representation does not matter as
//! long as both parties use the same one.

use polyval::hazmat::FieldElement;

/// A field element.
pub(crate) type Gf128 = [u8; 16];

/// `a ⊗ b`, constant time.
#[inline]
pub(crate) fn mul(a: &Gf128, b: &Gf128) -> Gf128 {
    (FieldElement::from(*a) * FieldElement::from(*b)).into()
}

/// `a ⊕= b`.
#[inline]
pub(crate) fn add_assign(a: &mut Gf128, b: &Gf128) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// `a ⊕ b`.
#[inline]
pub(crate) fn add(a: &Gf128, b: &Gf128) -> Gf128 {
    let mut out = *a;
    add_assign(&mut out, b);
    out
}

/// Combine 128 COT blocks `y_0 … y_127` into `Σ_k e_k ⊗ y_k`, where `e_k` is
/// the element with only bit `k` set.
///
/// Applied to a receiver's blocks `t_k` (choice bits `x_k`) and the sender's
/// `q_k = t_k ⊕ x_k·Δ`, this yields a VOLE correlation
/// `combine(q) = combine(t) ⊕ a ⊗ Δ` with `a = Σ_k x_k e_k`, the choice bits
/// packed into one element, because `⊗` is bilinear.
///
/// Computed as one Montgomery reduction: `Σ_k e_k ⊗ y_k = (Σ_k x^k y_k) ·
/// x^-128 mod p`, and for `S = S_hi · x^128 ⊕ S_lo` that equals
/// `S_hi ⊕ S_lo ⊗ 1`.
pub(crate) fn combine(y: &[Gf128; 128]) -> Gf128 {
    let (mut lo, mut hi) = (0u128, 0u128);
    for (k, v) in y.iter().enumerate() {
        let v = u128::from_le_bytes(*v);
        lo ^= v << k;
        if k > 0 {
            hi ^= v >> (128 - k);
        }
    }
    add(&hi.to_le_bytes(), &mul(&lo.to_le_bytes(), &ONE))
}

/// The multiplicative unit of the polynomial representation, `x^0`. (Under
/// `⊗` the unit is `x^128 mod p`; `ONE` is only used for the reduction.)
const ONE: Gf128 = 1u128.to_le_bytes();

/// Pack 128 bits (bit `k` → coefficient of `x^k`).
pub(crate) fn pack_bits(bits: &[bool]) -> Gf128 {
    let mut v = 0u128;
    for (k, &b) in bits.iter().enumerate().take(128) {
        v |= u128::from(b) << k;
    }
    v.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::RngExt;

    use crate::primitives::rand::csprng;

    /// Schoolbook carry-less product mod the POLYVAL polynomial, with bit
    /// `i` of the little-endian u128 being the coefficient of `x^i`.
    fn naive_mulmod(a: u128, b: u128) -> u128 {
        // p(x) = x^128 + x^127 + x^126 + x^121 + 1; x^128 ≡ R.
        const R: u128 = (1 << 127) | (1 << 126) | (1 << 121) | 1;
        let mut acc = 0u128;
        let mut a = a;
        for i in 0..128 {
            if b >> i & 1 == 1 {
                acc ^= a;
            }
            let carry = a >> 127 & 1 == 1;
            a <<= 1;
            if carry {
                a ^= R;
            }
        }
        acc
    }

    fn u(x: &Gf128) -> u128 {
        u128::from_le_bytes(*x)
    }

    fn rand_el(rng: &mut impl Rng) -> Gf128 {
        let mut x = [0u8; 16];
        rng.fill_bytes(&mut x);
        x
    }

    /// `a ⊗ b · x^128 = a · b` in the ordinary field.
    #[test]
    fn matches_montgomery_definition() {
        let mut rng = csprng().unwrap();
        // x^128 mod p.
        let x128 = (1u128 << 127) | (1 << 126) | (1 << 121) | 1;
        for _ in 0..200 {
            let (a, b) = (rand_el(&mut rng), rand_el(&mut rng));
            assert_eq!(
                naive_mulmod(u(&mul(&a, &b)), x128),
                naive_mulmod(u(&a), u(&b))
            );
        }
    }

    /// `combine` is the stated bilinear combination and yields a VOLE.
    #[test]
    fn combine_gives_vole() {
        let mut rng = csprng().unwrap();
        let delta = rand_el(&mut rng);
        let mut t = [[0u8; 16]; 128];
        let mut q = [[0u8; 16]; 128];
        let mut x = [false; 128];
        for k in 0..128 {
            t[k] = rand_el(&mut rng);
            x[k] = rng.random::<bool>();
            q[k] = if x[k] { add(&t[k], &delta) } else { t[k] };
        }
        let a = pack_bits(&x);
        assert_eq!(combine(&q), add(&combine(&t), &mul(&a, &delta)));

        // Direct definition with e_k = bit k.
        let mut direct = [0u8; 16];
        for (k, v) in t.iter().enumerate() {
            add_assign(&mut direct, &mul(&(1u128 << k).to_le_bytes(), v));
        }
        assert_eq!(combine(&t), direct);
    }

    #[test]
    fn field_laws() {
        let mut rng = csprng().unwrap();
        for _ in 0..200 {
            let (a, b, c) = (rand_el(&mut rng), rand_el(&mut rng), rand_el(&mut rng));
            assert_eq!(mul(&a, &b), mul(&b, &a));
            assert_eq!(mul(&mul(&a, &b), &c), mul(&a, &mul(&b, &c)));
            assert_eq!(mul(&a, &add(&b, &c)), add(&mul(&a, &b), &mul(&a, &c)));
            assert_ne!(mul(&a, &b), [0u8; 16]); // no zero divisors (a, b ≠ 0 w.h.p.)
        }
        assert_eq!(mul(&rand_el(&mut rng), &[0u8; 16]), [0u8; 16]);
    }
}
