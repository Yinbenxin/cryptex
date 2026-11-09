//! Bit-matrix transpose for OT extension.
//!
//! The extension produces `W` column vectors of `n` bits each (one per base
//! OT); the protocol needs them as `n` row vectors of `W` bits. Columns are
//! stored as `n / 8` bytes, little-endian bit order within each byte (bit
//! `r` of a column is bit `r % 8` of byte `r / 8`). Rows come out as `W / 8`
//! bytes with the same convention: bit `c` of a row is column `c`.

/// Transpose `cols` (`w` columns, each `n_bytes` long) into `out`
/// (`n_bytes * 8` rows of `w / 8` bytes). `w` must be a multiple of 8.
///
/// Works in 8×8 bit tiles: gather 8 column bytes, transpose the tile with
/// the classic three-step bit swap, scatter 8 row bytes.
pub(crate) fn transpose(cols: &[&[u8]], n_bytes: usize, out: &mut [u8]) {
    let w = cols.len();
    assert!(w.is_multiple_of(8), "column count must be a multiple of 8");
    let row_bytes = w / 8;
    assert_eq!(out.len(), n_bytes * 8 * row_bytes);
    assert!(cols.iter().all(|c| c.len() == n_bytes));

    // Each chunk of 8 output rows corresponds to one input byte index.
    // Sequential: callers parallelize over independent blocks of rows.
    out.chunks_mut(8 * row_bytes)
        .enumerate()
        .for_each(|(byte_idx, rows)| {
            for cb in 0..row_bytes {
                // Tile: input bytes cols[8cb + j][byte_idx], j = 0..8.
                let mut x: u64 = 0;
                for j in 0..8 {
                    x |= u64::from(cols[8 * cb + j][byte_idx]) << (8 * j);
                }
                let t = transpose8x8(x);
                for i in 0..8 {
                    rows[i * row_bytes + cb] = (t >> (8 * i)) as u8;
                }
            }
        });
}

/// Transpose an 8×8 bit matrix packed as 8 bytes (byte `j` = row `j`,
/// bit `i` of byte `j` = column `i`).
fn transpose8x8(mut x: u64) -> u64 {
    let mut t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^ t ^ (t << 28)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bit(buf: &[u8], i: usize) -> bool {
        buf[i / 8] >> (i % 8) & 1 == 1
    }

    #[test]
    fn tile_transpose() {
        for x in [0u64, u64::MAX, 0x0123_4567_89ab_cdef, 1, 1 << 63] {
            let t = transpose8x8(x);
            for r in 0..8 {
                for c in 0..8 {
                    assert_eq!(x >> (8 * r + c) & 1, t >> (8 * c + r) & 1);
                }
            }
            assert_eq!(transpose8x8(t), x);
        }
    }

    #[test]
    fn matches_naive() {
        let (w, n_bytes) = (24, 5);
        let owned: Vec<Vec<u8>> = (0..w)
            .map(|c| {
                (0..n_bytes)
                    .map(|b| (c * 37 + b * 11 + 5) as u8 ^ 0x5a)
                    .collect()
            })
            .collect();
        let cols: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let mut out = vec![0u8; n_bytes * 8 * w / 8];
        transpose(&cols, n_bytes, &mut out);
        for r in 0..n_bytes * 8 {
            let row = &out[r * w / 8..(r + 1) * w / 8];
            for (c, col) in cols.iter().enumerate() {
                assert_eq!(bit(row, c), bit(col, r), "row {r} col {c}");
            }
        }
    }
}
