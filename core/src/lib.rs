//! Cryptex - Cross-platform cryptographic library
//!
//! - `primitives`: internal building blocks (hash, cipher, EC, OT, VOLE, OKVS).
//! - `algorithms`: exposed algorithms (PSI, crypto tools), the stable API.
//! - `ffi`: C ABI over `algorithms`, consumed by Python/Go/Java bindings.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod algorithms;
pub mod error;
pub(crate) mod exec;
// FFI is the only module allowed to use `unsafe`.
#[allow(unsafe_code)]
pub mod ffi;
pub(crate) mod primitives;
pub mod protocol;

pub use error::{Error, Result};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
