//! FourQ (Costello, Longa, ASIACRYPT 2015), pure Rust.
//!
//! - [`fp`], [`fp2`]: GF(p) and GF(p^2) for p = 2^127 - 1, constant time.
//! - [`curve`]: twisted Edwards point arithmetic (FourQlib formulas).
//! - [`endo`]: endomorphisms and 4-dimensional scalar multiplication.
//! - [`h2c`]: hash-to-curve, cryptex-defined suite (see `docs/algorithm/psi.md`).
//!
//! Only the order-N subgroup is used: hash-to-curve clears the cofactor, and
//! decoding rejects points outside the subgroup.

pub(crate) mod curve;
pub(crate) mod endo;
pub(crate) mod fp;
pub(crate) mod fp2;
pub(crate) mod h2c;
