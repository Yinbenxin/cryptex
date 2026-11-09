//! Random band OKVS over GF(2) (Bienstock, Patel, Seo, Yeo, USENIX Security
//! 2023). Values are byte arrays of any fixed size `N`; the matrix is binary,
//! so encoding and decoding only XOR values.
//!
//! Each key maps to a row of an `m`-column binary matrix that is zero except
//! for a random 128-bit band starting at a random column. `encode` solves
//! `row(k_i) · P = v_i` for the table `P` (`m` values of 64 bytes);
//! `decode(P, k) = row(k) · P` is the XOR of the table entries under the
//! band. Decoding is linear: `decode(A ⊕ B, k) = decode(A, k) ⊕ decode(B, k)`.
//!
//! Encoding sorts rows by start column and runs Gaussian elimination, which
//! stays inside the band, so it costs O(n · band) word operations. It fails
//! when the rows are linearly dependent; callers retry with a fresh seed
//! (see `docs/algorithm/psi.md` for the parameters and observed failure
//! rate).

use rand::CryptoRng;
use rayon::prelude::*;

use crate::primitives::hash::sha256;

/// Band width in bits.
pub(crate) const BAND_BITS: usize = 128;

const DST: &[u8] = b"CRYPTEX-RB-OKVS-V1";

/// Table size for `n` keys: `(1 + ε) n + band` with ε = 0.1, rounded up to a
/// multiple of 128 (whole AES blocks per column in the OT extension).
pub(crate) fn size(n: usize) -> usize {
    let m = n + n.div_ceil(10) + BAND_BITS;
    m.div_ceil(128) * 128
}

/// A key's row: band bits (bit 0 always set) starting at column `start`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    start: usize,
    band: u128,
}

/// Row for `key` in a table of `m` columns under hash `seed`.
pub(crate) fn row(m: usize, seed: &[u8; 16], key: &[u8; 32]) -> Row {
    debug_assert!(m >= BAND_BITS);
    let h = sha256(&[DST, seed, key]);
    let range = (m - BAND_BITS + 1) as u64;
    // Bias at most range / 2^64, negligible.
    let start = (u64::from_le_bytes(h[..8].try_into().expect("8 bytes")) % range) as usize;
    let band = u128::from_le_bytes(h[8..24].try_into().expect("16 bytes")) | 1;
    Row { start, band }
}

#[inline]
fn xor_into<const N: usize>(dst: &mut [u8; N], src: &[u8; N]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// XOR of `table[start + k]` for every set bit `k` of `band`.
#[inline]
fn band_sum<const N: usize>(table: &[[u8; N]], start: usize, mut band: u128) -> [u8; N] {
    let mut v = [0u8; N];
    while band != 0 {
        xor_into(&mut v, &table[start + band.trailing_zeros() as usize]);
        band &= band - 1;
    }
    v
}

/// Solve for a table of `m` entries such that `decode(table, rows[i]) ==
/// values[i]`. Unconstrained entries are uniformly random. Returns `None`
/// if the rows are linearly dependent.
pub(crate) fn encode<const N: usize, R: CryptoRng + ?Sized>(
    m: usize,
    rows: &[Row],
    values: &[[u8; N]],
    rng: &mut R,
) -> Option<Vec<[u8; N]>> {
    assert_eq!(rows.len(), values.len());
    let mut order: Vec<u32> = (0..rows.len() as u32).collect();
    order.par_sort_unstable_by_key(|&i| rows[i as usize].start);

    // After elimination, `table[p]` holds the value of the pivot row whose
    // leading one is column `p`, and `pivot[p]` its band aligned at `p`
    // (bit 0 set), or 0 if column `p` has no pivot.
    let mut table = vec![[0u8; N]; m];
    let mut pivot = vec![0u128; m];
    for &i in &order {
        let Row {
            mut start,
            mut band,
        } = rows[i as usize];
        let mut value = values[i as usize];
        loop {
            if band == 0 {
                // Dependent row: consistent only if the value reduced to 0,
                // which for random values happens with probability 2^-512.
                if value != [0u8; N] {
                    return None;
                }
                break;
            }
            let tz = band.trailing_zeros();
            start += tz as usize;
            band >>= tz;
            if pivot[start] == 0 {
                pivot[start] = band;
                table[start] = value;
                break;
            }
            band ^= pivot[start];
            xor_into(&mut value, &table[start]);
        }
    }

    // Back substitution, highest column first, so every entry a pivot row
    // refers to is final. Free columns get random values.
    for p in (0..m).rev() {
        let band = pivot[p];
        if band == 0 {
            rng.fill_bytes(&mut table[p]);
        } else {
            let rest = band_sum(&table, p, band & !1);
            xor_into(&mut table[p], &rest);
        }
    }
    Some(table)
}

/// `row · table`.
pub(crate) fn decode<const N: usize>(table: &[[u8; N]], row: Row) -> [u8; N] {
    band_sum(table, row.start, row.band)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::rand::csprng;
    use rand::Rng;

    fn keys(n: usize, salt: u8) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| sha256(&[&[salt], &(i as u64).to_le_bytes()]))
            .collect()
    }

    type Value = [u8; 16];

    fn values(n: usize) -> Vec<Value> {
        let mut rng = csprng().unwrap();
        (0..n)
            .map(|_| {
                let mut v = [0u8; 16];
                rng.fill_bytes(&mut v);
                v
            })
            .collect()
    }

    #[test]
    fn sizes() {
        assert_eq!(size(0), 128);
        assert_eq!(size(1), 256);
        assert_eq!(size(1000), 1280);
        assert!(size(1_000_000) >= 1_100_128);
        for n in [0, 1, 7, 1000, 123_457] {
            assert_eq!(size(n) % 128, 0);
        }
    }

    #[test]
    fn roundtrip() {
        let mut rng = csprng().unwrap();
        for n in [0, 1, 2, 100, 10_000] {
            let m = size(n);
            let seed = [n as u8; 16];
            let rows: Vec<Row> = keys(n, 0).iter().map(|k| row(m, &seed, k)).collect();
            let vals = values(n);
            let table = encode(m, &rows, &vals, &mut rng).expect("encode");
            assert_eq!(table.len(), m);
            for (r, v) in rows.iter().zip(&vals) {
                assert_eq!(&decode(&table, *r), v);
            }
            // Rows stay inside the table.
            assert!(rows.iter().all(|r| r.start + BAND_BITS <= m));
        }
    }

    #[test]
    fn linear() {
        let mut rng = csprng().unwrap();
        let m = size(500);
        let seed = [1u8; 16];
        let rows: Vec<Row> = keys(500, 1).iter().map(|k| row(m, &seed, k)).collect();
        let a = encode(m, &rows, &values(500), &mut rng).unwrap();
        let b = encode(m, &rows, &values(500), &mut rng).unwrap();
        let ab: Vec<Value> = a
            .iter()
            .zip(&b)
            .map(|(x, y)| {
                let mut z = *x;
                xor_into(&mut z, y);
                z
            })
            .collect();
        for k in keys(50, 9) {
            let r = row(m, &seed, &k);
            let mut expected = decode(&a, r);
            xor_into(&mut expected, &decode(&b, r));
            assert_eq!(decode(&ab, r), expected);
        }
    }

    #[test]
    fn duplicate_key_is_dependent() {
        let mut rng = csprng().unwrap();
        let m = size(3);
        let k = keys(2, 2);
        let rows = vec![
            row(m, &[0; 16], &k[0]),
            row(m, &[0; 16], &k[1]),
            row(m, &[0; 16], &k[0]),
        ];
        assert!(encode(m, &rows, &values(3), &mut rng).is_none());
    }

    /// Failure rate at our parameters. Run with
    /// `cargo test --release okvs_failure_rate -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn okvs_failure_rate() {
        let mut rng = csprng().unwrap();
        for (n, trials) in [(1_000usize, 20_000u32), (100_000, 500), (1_000_000, 50)] {
            let m = size(n);
            let k = keys(n, 3);
            let vals = values(n);
            let mut failures = 0;
            for t in 0..trials {
                let mut seed = [0u8; 16];
                seed[..4].copy_from_slice(&t.to_le_bytes());
                let rows: Vec<Row> = k.iter().map(|x| row(m, &seed, x)).collect();
                if encode(m, &rows, &vals, &mut rng).is_none() {
                    failures += 1;
                }
            }
            println!("n = {n:>9}  m = {m:>9}  trials = {trials:>6}  failures = {failures}");
        }
    }
}
