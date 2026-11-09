//! Building-block primitives used internally by the exposed algorithms.
//!
//! Everything here is `pub(crate)` and not part of the stable API. FFI and
//! language bindings must only wrap `crate::algorithms`.

pub(crate) mod cipher;
pub(crate) mod ec;
pub(crate) mod field;
pub(crate) mod hash;
pub(crate) mod okvs;
pub(crate) mod oprf;
pub(crate) mod ot;
pub(crate) mod prg;
pub(crate) mod rand;

#[cfg(test)]
pub(crate) mod test_util {
    /// Decode a hex string, panicking on malformed input.
    pub(crate) fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }
}
