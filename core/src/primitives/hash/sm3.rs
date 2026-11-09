//! SM3 hash (GB/T 32905-2016).

use ::sm3::{Digest, Sm3};

/// SM3 over the concatenation of `parts`.
pub(crate) fn sm3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sm3::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;

    // GB/T 32905-2016 Appendix A.1
    #[test]
    fn gbt_32905_abc() {
        assert_eq!(
            sm3(&[b"abc"]).to_vec(),
            hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        );
    }
}
