//! Private set intersection (semi-honest security).
//!
//! Two roles per protocol: the sender learns nothing, the receiver learns
//! which of its own items are in the intersection. Both roles implement
//! [`Party`](crate::protocol::Party); the receiver is the initiator.

pub mod bucket;
pub(crate) mod common;
pub mod ecdh;
pub mod oprf;
pub(crate) mod store;
pub mod vole;

/// Receiver output: indices into the receiver's items that are in the
/// intersection.
pub type Intersection = Vec<usize>;
