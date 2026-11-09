//! OPRF-PSI for unbalanced sets (a small receiver set against a large
//! sender set), without a client-side cache.
//!
//! The receiver blinds its items and obtains their OPRF values from the
//! sender; the sender sends the OPRF values of its own items truncated and
//! sorted, so the receiver does `O(n)` group operations instead of the
//! `O(n + m)` of ECDH-PSI and receives `t` bytes per sender item instead of
//! a full point. The OPRF is 2HashDH in the shape of RFC 9497's OPRF mode
//! (see [`protocol`]).

mod protocol;
pub mod receiver;
pub mod sender;

pub use super::ecdh::Curve;
pub use receiver::Receiver;
pub use sender::Sender;
