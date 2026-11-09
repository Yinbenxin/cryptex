//! CTR mode (NIST SP 800-38A, 128-bit big-endian counter) over AES-128 or
//! SM4, from the `ctr` crate.
//!
//! Unauthenticated: callers must ensure a key is never used for two
//! different messages under the same IV, and that integrity is not needed
//! or is provided elsewhere.

use ctr::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroize;

use super::sm4::Sm4;

/// Block cipher under CTR mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    /// AES-128 (FIPS 197).
    Aes128,
    /// SM4 (GB/T 32907).
    Sm4,
}

/// XOR `buf` with the CTR keystream of `key`, initial counter block `iv`.
/// Encryption and decryption are the same operation.
pub(crate) fn apply(cipher: Cipher, key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let (mut k, iv) = ((*key).into(), (*iv).into());
    match cipher {
        Cipher::Aes128 => ctr::Ctr128BE::<aes::Aes128>::new(&k, &iv).apply_keystream(buf),
        Cipher::Sm4 => ctr::Ctr128BE::<Sm4>::new(&k, &iv).apply_keystream(buf),
    }
    k.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;

    /// NIST SP 800-38A F.5.1 (CTR-AES128.Encrypt), first two blocks.
    #[test]
    fn sp800_38a_aes128() {
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let iv: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let mut buf = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        apply(Cipher::Aes128, &key, &iv, &mut buf);
        assert_eq!(
            buf,
            hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff")
        );
        apply(Cipher::Aes128, &key, &iv, &mut buf);
        assert_eq!(
            buf,
            hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        );
    }

    /// SM4-CTR keystream block i is SM4_k(iv + i), big-endian counter.
    #[test]
    fn sm4_ctr_is_counter_mode() {
        use sm4::cipher::{Array, BlockCipherEncrypt, KeyInit};
        let key = [3u8; 16];
        let mut iv = [0u8; 16];
        iv[15] = 0xff; // carries into byte 14
        let mut buf = vec![0u8; 40];
        apply(Cipher::Sm4, &key, &iv, &mut buf);
        let sm4 = Sm4::new(&Array::from(key));
        for (i, chunk) in buf.chunks(16).enumerate() {
            let mut b = Array::from((u128::from_be_bytes(iv) + i as u128).to_be_bytes());
            sm4.encrypt_block(&mut b);
            assert_eq!(chunk, &b[..chunk.len()]);
        }
    }
}
