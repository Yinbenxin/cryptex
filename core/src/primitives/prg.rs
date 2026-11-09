//! AES-128-CTR pseudorandom generator.
//!
//! `expand(seed, out)` fills `out` with `AES_seed(0) ‖ AES_seed(1) ‖ …`.
//! Uses AES-NI / ARMv8 Crypto when the CPU has them (detected at runtime by
//! the `aes` crate), with a constant-time software fallback.

#[cfg(test)]
use aes::cipher::KeyInit;
use aes::cipher::{Array, BlockCipherEncrypt};
use aes::Aes128;

/// Blocks encrypted per call into the cipher; lets the backend pipeline.
const CHUNK: usize = 64;

/// Fill `out` with the AES-CTR keystream for `seed`, counter starting at 0.
#[cfg(test)]
pub(crate) fn expand(seed: &[u8; 16], out: &mut [u8]) {
    expand_at(&Aes128::new(&Array::from(*seed)), 0, out);
}

/// Fill `out` with the keystream of `cipher` starting at block `first`.
pub(crate) fn expand_at(cipher: &Aes128, first: u128, out: &mut [u8]) {
    let mut counter = first;
    for chunk in out.chunks_mut(16 * CHUNK) {
        let n = chunk.len().div_ceil(16);
        let mut blocks = [Array::<u8, _>::default(); CHUNK];
        for b in &mut blocks[..n] {
            *b = Array::from(counter.to_le_bytes());
            counter += 1;
        }
        cipher.encrypt_blocks(&mut blocks[..n]);
        for (dst, src) in chunk.chunks_mut(16).zip(&blocks) {
            dst.copy_from_slice(&src[..dst.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;
    use aes::cipher::KeyInit;

    /// FIPS-197 Appendix C.1 (AES-128): key 00..0f, plaintext 00112233..ff.
    #[test]
    fn aes128_known_answer() {
        let cipher = Aes128::new(&Array::from(
            <[u8; 16]>::try_from(hex("000102030405060708090a0b0c0d0e0f")).unwrap(),
        ));
        let mut block =
            Array::from(<[u8; 16]>::try_from(hex("00112233445566778899aabbccddeeff")).unwrap());
        cipher.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    #[test]
    fn expand_is_ctr_mode_and_prefix_stable() {
        let seed = [7u8; 16];
        let mut long = vec![0u8; 16 * 200 + 5];
        expand(&seed, &mut long);
        let mut tail = vec![0u8; 16 * 70];
        expand_at(&Aes128::new(&Array::from(seed)), 100, &mut tail);
        assert_eq!(tail, long[16 * 100..16 * 170]);
        let mut short = vec![0u8; 37];
        expand(&seed, &mut short);
        assert_eq!(short, long[..37]);

        // Block i is AES_seed(i) with i as a little-endian 128-bit counter.
        let cipher = Aes128::new(&Array::from(seed));
        let mut b = Array::from(130u128.to_le_bytes());
        cipher.encrypt_block(&mut b);
        assert_eq!(&long[16 * 130..16 * 131], b.as_slice());

        let mut other = vec![0u8; 37];
        expand(&[8u8; 16], &mut other);
        assert_ne!(other, short);
    }
}
