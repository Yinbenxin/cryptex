//! SM4 block cipher (GB/T 32907-2016).
//!
//! Software implementation from the `sm4` crate, table-based S-box (not
//! constant time with respect to cache timing).

pub(crate) use sm4::Sm4;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;
    use sm4::cipher::{Array, BlockCipherEncrypt, KeyInit};

    /// GB/T 32907-2016 Appendix A, example 1: key = plaintext =
    /// 0123456789abcdeffedcba9876543210.
    #[test]
    fn gbt32907_example1() {
        let k: [u8; 16] = hex("0123456789abcdeffedcba9876543210").try_into().unwrap();
        let cipher = Sm4::new(&Array::from(k));
        let mut block = Array::from(k);
        cipher.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), hex("681edf34d206965e86b3e94f536e4246"));
    }
}
