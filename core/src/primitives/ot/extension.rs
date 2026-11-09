//! IKNP-style OT extension producing a correlation over `GF(2)^W`, where
//! `W = 8 · B` and `B` is the row size in bytes (a const parameter).
//!
//! Roles follow the extension, which are the reverse of the base OTs:
//!
//! - The **sender** (holds `Δ ∈ {0,1}^W`) was the *receiver* of the `W`
//!   base OTs, with choice bits `Δ`, and knows `k_c^{Δ_c}` for each column.
//! - The **receiver** (holds `m` rows `P_j ∈ {0,1}^W`) was the base-OT
//!   *sender* and knows both `k_c^0, k_c^1`.
//!
//! With `t_c = PRG(k_c^0)`, `t'_c = PRG(k_c^1)` (`m` bits each), and `T`, `T'`
//! their transposes, the receiver sends `U_j = T_j ⊕ T'_j ⊕ P_j` and keeps
//! `T`. The sender computes `G` = transpose of `PRG(k_c^{Δ_c})` and
//!
//! ```text
//!     Q_j = G_j ⊕ (U_j ∧ Δ) = T_j ⊕ (P_j ∧ Δ)
//! ```
//!
//! a subfield VOLE: for every row, the sender's `Q_j` and the receiver's
//! `T_j` differ by `P_j ∧ Δ`. `U` is sent row-wise, so neither party
//! transposes `P` or `U`.
//!
//! Work is split into blocks of rows processed in parallel; each block reads
//! its own slice of every column's AES-CTR keystream.

use aes::cipher::{Array, KeyInit};
use aes::Aes128;
use rayon::prelude::*;

use super::transpose::transpose;
use super::Block;
use crate::primitives::prg::expand_at;

/// Rows per parallel block; a multiple of 128 so blocks start on AES-block
/// boundaries of every column stream.
const BLOCK_ROWS: usize = 1 << 13;

fn ciphers(keys: impl Iterator<Item = Block>) -> Vec<Aes128> {
    keys.map(|k| Aes128::new(&Array::from(k))).collect()
}

/// Rows `[first, first + out.len())` of the transpose of the column streams
/// `PRG(ciphers[c])`.
fn transposed_block<const B: usize>(
    ciphers: &[Aes128],
    first: usize,
    cols: &mut [u8],
    out: &mut [[u8; B]],
) {
    let n_bytes = out.len() / 8;
    let cols = &mut cols[..8 * B * n_bytes];
    for (c, col) in cols.chunks_mut(n_bytes).enumerate() {
        expand_at(&ciphers[c], (first / 128) as u128, col);
    }
    let cols: Vec<&[u8]> = cols.chunks(n_bytes).collect();
    transpose(&cols, n_bytes, out.as_flattened_mut());
}

/// Receiver side. `keys[c] = (k_c^0, k_c^1)` for `8 · B` columns; `rows`
/// holds `P` on input and `U` on return. Returns `T`. `rows.len()` must be a
/// multiple of 128.
pub(crate) fn receive<const B: usize>(keys: &[[Block; 2]], rows: &mut [[u8; B]]) -> Vec<[u8; B]> {
    assert_eq!(keys.len(), 8 * B);
    assert!(rows.len().is_multiple_of(128));
    let c0 = ciphers(keys.iter().map(|k| k[0]));
    let c1 = ciphers(keys.iter().map(|k| k[1]));
    let mut t = vec![[0u8; B]; rows.len()];
    t.par_chunks_mut(BLOCK_ROWS)
        .zip(rows.par_chunks_mut(BLOCK_ROWS))
        .enumerate()
        .for_each_init(
            || (vec![0u8; B * BLOCK_ROWS], vec![[0u8; B]; BLOCK_ROWS]),
            |(cols, t1), (i, (t_blk, p_blk))| {
                let first = i * BLOCK_ROWS;
                let t1 = &mut t1[..t_blk.len()];
                transposed_block(&c0, first, cols, t_blk);
                transposed_block(&c1, first, cols, t1);
                for ((p, a), b) in p_blk.iter_mut().zip(t_blk.iter()).zip(t1.iter()) {
                    for k in 0..B {
                        p[k] ^= a[k] ^ b[k];
                    }
                }
            },
        );
    t
}

/// Sender side. `keys[c] = k_c^{Δ_c}`, `u` the receiver's rows. Returns `Q`.
pub(crate) fn send<const B: usize>(keys: &[Block], delta: &[u8; B], u: &[[u8; B]]) -> Vec<[u8; B]> {
    assert_eq!(keys.len(), 8 * B);
    assert!(u.len().is_multiple_of(128));
    let cs = ciphers(keys.iter().copied());
    let mut q = vec![[0u8; B]; u.len()];
    q.par_chunks_mut(BLOCK_ROWS)
        .zip(u.par_chunks(BLOCK_ROWS))
        .enumerate()
        .for_each_init(
            || vec![0u8; B * BLOCK_ROWS],
            |cols, (i, (q_blk, u_blk))| {
                transposed_block(&cs, i * BLOCK_ROWS, cols, q_blk);
                for (q, u) in q_blk.iter_mut().zip(u_blk) {
                    for k in 0..B {
                        q[k] ^= u[k] & delta[k];
                    }
                }
            },
        );
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    use crate::primitives::rand::csprng;

    fn check<const B: usize>() {
        let mut rng = csprng().unwrap();
        let keys: Vec<[Block; 2]> = (0..8 * B)
            .map(|_| {
                let mut k = [[0u8; 16]; 2];
                rng.fill_bytes(&mut k[0]);
                rng.fill_bytes(&mut k[1]);
                k
            })
            .collect();
        let mut delta = [0u8; B];
        rng.fill_bytes(&mut delta);
        let bit = |c: usize| delta[c / 8] >> (c % 8) & 1 == 1;
        let chosen: Vec<Block> = (0..8 * B).map(|c| keys[c][usize::from(bit(c))]).collect();

        // Spans several blocks plus a partial one.
        for m in [128, BLOCK_ROWS * 2 + 384] {
            let p: Vec<[u8; B]> = (0..m)
                .map(|_| {
                    let mut r = [0u8; B];
                    rng.fill_bytes(&mut r);
                    r
                })
                .collect();
            let mut u = p.clone();
            let t = receive(&keys, &mut u);
            let q = send(&chosen, &delta, &u);
            for j in 0..m {
                for k in 0..B {
                    assert_eq!(q[j][k], t[j][k] ^ (p[j][k] & delta[k]), "row {j} byte {k}");
                }
            }
            // U is masked: not equal to P.
            assert_ne!(u, p);
        }
    }

    #[test]
    fn correlation_holds() {
        check::<16>();
        check::<64>();
    }
}
