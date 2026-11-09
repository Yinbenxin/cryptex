//! Elliptic curve groups used by ECDH-PSI and base OT.

pub(crate) mod curve25519;
pub(crate) mod fourq;
pub(crate) mod fourq_group;
pub(crate) mod hash_to_curve;
pub(crate) mod p256;
pub(crate) mod sm2;

use primeorder::elliptic_curve::group::{Group as _, GroupEncoding};
use primeorder::{PrimeCurveParams, ProjectivePoint};
use rand::CryptoRng;
use zeroize::Zeroize;

use crate::{Error, Result};

pub(crate) use self::curve25519::Ristretto255;
pub(crate) use self::fourq_group::FourQ;
pub(crate) use self::p256::P256;
pub(crate) use self::sm2::Sm2;

/// A prime-order group with hash-to-group, as needed by DH-style protocols.
pub(crate) trait Group: 'static {
    /// Secret exponent.
    type Scalar: Clone + Zeroize + Send + Sync + 'static;
    /// Group element.
    type Point: Copy + Send + Sync + 'static;

    /// Length of an encoded point in bytes.
    const POINT_LEN: usize;
    /// RFC 9380 style suite ID, appended to protocol DSTs.
    const SUITE_ID: &'static [u8];

    /// Uniformly random non-zero scalar.
    fn random_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Self::Scalar;

    /// Hash to the group, uniform (random oracle) encoding. The DST is the
    /// concatenation of `dst`.
    fn hash_to_group(msg: &[u8], dst: &[&[u8]]) -> Self::Point;

    /// Scalar multiplication, constant time.
    fn mul(p: &Self::Point, k: &Self::Scalar) -> Self::Point;

    /// `k^-1` modulo the group order, constant time. `k` must be non-zero
    /// (as every scalar from [`random_scalar`](Self::random_scalar) is).
    fn invert(k: &Self::Scalar) -> Self::Scalar;

    /// Canonical compressed encoding into `out` (`POINT_LEN` bytes).
    fn encode(p: &Self::Point, out: &mut [u8]);

    /// Decode a point, rejecting invalid encodings, the identity and points
    /// outside the prime-order group.
    fn decode(bytes: &[u8]) -> Result<Self::Point>;

    /// Decode a peer's point and multiply it by `k`.
    ///
    /// Groups with a cofactor `h` may instead return `k·h·P` after a cheaper
    /// validity check: multiplying by `h` maps every curve point into the
    /// prime-order subgroup. Callers must then apply this to every peer point
    /// in the same way, so that both parties pick up the same factor `h`.
    fn decode_mul(bytes: &[u8], k: &Self::Scalar) -> Result<Self::Point> {
        Ok(Self::mul(&Self::decode(bytes)?, k))
    }

    /// The suite's companion hash (SHA-256, or SM3 for SM2) over `parts`.
    fn hash(parts: &[&[u8]]) -> [u8; 32];
}

/// SEC1 compressed encoding for curves from the `primeorder` family.
fn encode_sec1<C: PrimeCurveParams>(p: &ProjectivePoint<C>, out: &mut [u8]) {
    let repr = p.to_bytes();
    let bytes: &[u8] = repr.as_ref();
    out.copy_from_slice(bytes);
}

/// SEC1 compressed decoding with on-curve check; rejects the identity.
fn decode_sec1<C: PrimeCurveParams>(bytes: &[u8]) -> Result<ProjectivePoint<C>> {
    let mut repr = <ProjectivePoint<C> as GroupEncoding>::Repr::default();
    let buf: &mut [u8] = repr.as_mut();
    if bytes.len() != buf.len() {
        return Err(Error::InvalidInput("invalid point length".into()));
    }
    buf.copy_from_slice(bytes);
    Option::<ProjectivePoint<C>>::from(ProjectivePoint::<C>::from_bytes(&repr))
        .filter(|p| !bool::from(p.is_identity()))
        .ok_or_else(|| Error::InvalidInput("invalid curve point".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::rand::csprng;

    const DST: &[&[u8]] = &[b"CRYPTEX-TEST-", b"group"];

    fn check_group<G: Group>()
    where
        G::Point: PartialEq + core::fmt::Debug,
    {
        let mut rng = csprng().unwrap();
        let a = G::random_scalar(&mut rng);
        let b = G::random_scalar(&mut rng);

        // Hashing is deterministic and input-sensitive.
        let h = G::hash_to_group(b"alice", DST);
        assert_eq!(h, G::hash_to_group(b"alice", DST));
        assert_ne!(h, G::hash_to_group(b"alicf", DST));
        assert_ne!(h, G::hash_to_group(b"alice", &[b"other"]));

        // (h^a)^b == (h^b)^a
        assert_eq!(G::mul(&G::mul(&h, &a), &b), G::mul(&G::mul(&h, &b), &a));

        // (h^a)^(a^-1) == h, and inversion is an involution.
        let ai = G::invert(&a);
        assert_eq!(G::mul(&G::mul(&h, &a), &ai), h);
        assert_eq!(G::mul(&h, &G::invert(&ai)), G::mul(&h, &a));

        // Encoding round-trips.
        let mut buf = vec![0u8; G::POINT_LEN];
        G::encode(&h, &mut buf);
        assert_eq!(G::decode(&buf).unwrap(), h);

        // Malformed encodings are rejected.
        assert!(G::decode(&buf[1..]).is_err());
        assert!(G::decode(&vec![0u8; G::POINT_LEN]).is_err()); // identity
        assert!(G::decode(&vec![0xffu8; G::POINT_LEN]).is_err());
    }

    #[test]
    fn ristretto255() {
        check_group::<Ristretto255>();
    }

    /// Single-thread timings of the hot operations, for comparison.
    /// `cargo test --release group_timing -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn group_timing() {
        fn time<G: Group>(name: &str) {
            use std::time::Instant;
            let n = 20_000u32;
            let mut rng = csprng().unwrap();
            let k = G::random_scalar(&mut rng);
            let t = Instant::now();
            let pts: Vec<G::Point> = (0..n)
                .map(|i| G::hash_to_group(&i.to_le_bytes(), DST))
                .collect();
            let h = t.elapsed() / n;
            let t = Instant::now();
            let ms: Vec<G::Point> = pts.iter().map(|p| G::mul(p, &k)).collect();
            let m = t.elapsed() / n;
            let mut buf = vec![0u8; G::POINT_LEN];
            let t = Instant::now();
            let es: Vec<Vec<u8>> = ms
                .iter()
                .map(|p| {
                    G::encode(p, &mut buf);
                    buf.clone()
                })
                .collect();
            let e = t.elapsed() / n;
            let t = Instant::now();
            for b in &es {
                G::decode(b).unwrap();
            }
            let d = t.elapsed() / n;
            println!("{name:<13} hash_to_group {h:>9.1?}  mul {m:>9.1?}  encode {e:>9.1?}  decode {d:>9.1?}");
        }
        time::<Ristretto255>("Ristretto255");
        time::<FourQ>("FourQ");
        time::<P256>("P-256");
        time::<Sm2>("SM2");
    }

    #[test]
    fn fourq() {
        check_group::<FourQ>();
    }

    #[test]
    fn p256() {
        check_group::<P256>();
    }

    #[test]
    fn sm2() {
        check_group::<Sm2>();
    }
}
