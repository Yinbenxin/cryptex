//! SHA-256 (FIPS 180-4).

use sha2::{Digest, Sha256};

/// SHA-256 over the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_util::hex;

    #[test]
    fn fips_180_4_abc() {
        assert_eq!(
            sha256(&[b"a", b"bc"]).to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }
}
