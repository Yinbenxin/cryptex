//! SHA-512 (FIPS 180-4).

use sha2::{Digest, Sha512};

/// SHA-512 over the concatenation of `parts`.
pub(crate) fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
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
            sha512(&[b"a", b"bc"]).to_vec(),
            hex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }
}
