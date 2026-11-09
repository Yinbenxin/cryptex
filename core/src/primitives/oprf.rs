//! 2HashDH OPRF in the shape of RFC 9497's OPRF mode.
//!
//! `F_k(x) = Hash(I2OSP(len(x), 2) ‖ x ‖ I2OSP(Ne, 2) ‖ enc(H(x)^k) ‖
//! "Finalize")` with `H` = HashToGroup under DST `"HashToGroup-" ‖
//! contextString`, `contextString = "OPRFV1-" ‖ 0x00 ‖ "-" ‖ suite ID`.
//! For Ristretto255 and P-256 these are exactly RFC 9497's OPRF-mode
//! suites `ristretto255-SHA512` and `P256-SHA256` (checked against the
//! RFC's test vectors); SM2 (`SM2-SM3`) and FourQ (`FourQ-SHA256`) follow
//! the same recipe with cryptex-defined suite IDs.
//!
//! Only the building blocks live here; the protocols (blinding, batching,
//! wire format) are in `algorithms::psi::oprf` and `algorithms::pir`.

use super::ec::{FourQ, Group, Ristretto255, Sm2, P256};
use super::hash::{sha256, sha512, sm3};

/// `"OPRFV1-" ‖ I2OSP(modeOPRF, 1) ‖ "-"`, followed by the suite ID.
const CONTEXT_PREFIX: &[u8] = b"OPRFV1-\x00-";
const DST_H2G: &[u8] = b"HashToGroup-";
const FINALIZE: &[u8] = b"Finalize";

/// Largest input accepted: `Finalize` frames the input with a 2-byte length.
pub(crate) const MAX_INPUT_LEN: usize = u16::MAX as usize;

/// An OPRF suite: a group and the hash used by `Finalize`.
pub(crate) trait Suite: Group {
    /// Suite identifier in the context string.
    const ID: &'static [u8];
    /// Output length of the `Finalize` hash.
    const NH: usize;
    /// `Finalize` hash over `parts`; the first [`NH`](Self::NH) bytes are
    /// the output.
    fn finalize_hash(parts: &[&[u8]]) -> [u8; 64];
}

fn pad(h: [u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h);
    out
}

impl Suite for Ristretto255 {
    const ID: &'static [u8] = b"ristretto255-SHA512";
    const NH: usize = 64;
    fn finalize_hash(parts: &[&[u8]]) -> [u8; 64] {
        sha512(parts)
    }
}

impl Suite for P256 {
    const ID: &'static [u8] = b"P256-SHA256";
    const NH: usize = 32;
    fn finalize_hash(parts: &[&[u8]]) -> [u8; 64] {
        pad(sha256(parts))
    }
}

impl Suite for Sm2 {
    const ID: &'static [u8] = b"SM2-SM3";
    const NH: usize = 32;
    fn finalize_hash(parts: &[&[u8]]) -> [u8; 64] {
        pad(sm3(parts))
    }
}

impl Suite for FourQ {
    const ID: &'static [u8] = b"FourQ-SHA256";
    const NH: usize = 32;
    fn finalize_hash(parts: &[&[u8]]) -> [u8; 64] {
        pad(sha256(parts))
    }
}

/// RFC 9497 `HashToGroup`.
pub(crate) fn hash_to_group<S: Suite>(x: &[u8]) -> S::Point {
    S::hash_to_group(x, &[DST_H2G, CONTEXT_PREFIX, S::ID])
}

/// RFC 9497 `Finalize` given the unblinded element `p = H(x)^k`. The
/// output is the first [`Suite::NH`] bytes; the rest is zero. `x` must be
/// at most [`MAX_INPUT_LEN`] bytes.
pub(crate) fn finalize<S: Suite>(x: &[u8], p: &S::Point) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let enc = &mut buf[..S::POINT_LEN];
    S::encode(p, enc);
    let len = u16::try_from(x.len()).expect("input length checked by the caller");
    let ne = u16::try_from(S::POINT_LEN).expect("small");
    let out = S::finalize_hash(&[&len.to_be_bytes(), x, &ne.to_be_bytes(), enc, FINALIZE]);
    debug_assert!(out[S::NH..].iter().all(|&b| b == 0));
    out
}

/// `F_k(x)` evaluated directly with the key (the server's own inputs).
pub(crate) fn evaluate<S: Suite>(x: &[u8], k: &S::Scalar) -> [u8; 64] {
    finalize::<S>(x, &S::mul(&hash_to_group::<S>(x), k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::rand::csprng;
    use crate::primitives::test_util::hex;

    /// Blind, BlindEvaluate and Finalize against one RFC 9497 Appendix A
    /// OPRF-mode vector (skS, input, blind → blinded, evaluated, output).
    fn check_vector<S: Suite>(sk: S::Scalar, blind: S::Scalar, v: [&str; 4]) {
        let [input, blinded, evaluated, output] = v.map(hex);
        let enc = |p: &S::Point| {
            let mut b = vec![0u8; S::POINT_LEN];
            S::encode(p, &mut b);
            b
        };
        let q = S::mul(&hash_to_group::<S>(&input), &blind);
        assert_eq!(enc(&q), blinded, "BlindedElement");
        let e = S::mul(&S::decode(&blinded).unwrap(), &sk);
        assert_eq!(enc(&e), evaluated, "EvaluationElement");
        let p = S::mul(&e, &S::invert(&blind));
        assert_eq!(
            &finalize::<S>(&input, &p)[..S::NH],
            output.as_slice(),
            "Output"
        );
        assert_eq!(evaluate::<S>(&input, &sk), finalize::<S>(&input, &p));
    }

    #[test]
    fn rfc9497_ristretto255_sha512() {
        use curve25519_dalek::scalar::Scalar;
        let scalar = |s: &str| Scalar::from_canonical_bytes(hex(s).try_into().unwrap()).unwrap();
        let sk = || scalar("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e");
        let blind = || scalar("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");
        check_vector::<Ristretto255>(
            sk(),
            blind(),
            [
                "00",
                "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
                "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
                "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3\
             ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
            ],
        );
        check_vector::<Ristretto255>(
            sk(),
            blind(),
            [
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
                "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
                "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4\
             f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73",
            ],
        );
    }

    #[test]
    fn rfc9497_p256_sha256() {
        use p256::elliptic_curve::ff::PrimeField;
        use p256::Scalar;
        let scalar = |s: &str| {
            let b: [u8; 32] = hex(s).try_into().unwrap();
            Option::<Scalar>::from(Scalar::from_repr(b.into())).unwrap()
        };
        let sk = || scalar("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf");
        let blind = || scalar("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");
        check_vector::<P256>(
            sk(),
            blind(),
            [
                "00",
                "03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d",
                "030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832",
                "a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd",
            ],
        );
        check_vector::<P256>(
            sk(),
            blind(),
            [
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838",
                "03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c",
                "c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce",
            ],
        );
    }

    /// The OPRF output does not depend on the blind, only on the key.
    #[test]
    fn output_independent_of_blind() {
        fn check<S: Suite>() {
            let mut rng = csprng().unwrap();
            let k = S::random_scalar(&mut rng);
            for x in [&b"a"[..], b"", b"longer item"] {
                let direct = evaluate::<S>(x, &k);
                for _ in 0..3 {
                    let r = S::random_scalar(&mut rng);
                    let q = S::mul(&hash_to_group::<S>(x), &r);
                    let e = S::mul(&q, &k);
                    let p = S::mul(&e, &S::invert(&r));
                    assert_eq!(finalize::<S>(x, &p), direct);
                }
            }
        }
        check::<Ristretto255>();
        check::<P256>();
        check::<Sm2>();
        check::<FourQ>();
    }
}
