//! Oblivious transfer.
//!
//! - [`base`]: 128 public-key OTs to seed the extension.
//! - [`extension`]: IKNP-style extension of those seeds into correlated OT
//!   (COT) with offset `Δ ∈ GF(2)^128`.
//! - [`ferret`]: silent COT: turns a reserve of COTs into ~10^7 new ones
//!   with little communication, bootstrapping itself from its own output.
//! - [`transpose`]: bit-matrix transpose used by the extension.

pub(crate) mod base;
pub(crate) mod extension;
pub(crate) mod ferret;
pub(crate) mod transpose;

/// 128-bit key or seed.
pub(crate) type Block = [u8; 16];
