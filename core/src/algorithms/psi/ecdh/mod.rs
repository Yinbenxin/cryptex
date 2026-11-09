//! ECDH-PSI.

mod protocol;
pub mod receiver;
pub mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

/// Elliptic curve used to blind the hashed items. Both parties must use the
/// same curve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Curve {
    /// Ristretto255 over Curve25519, hash-to-group per RFC 9496 with
    /// `expand_message_xmd` (SHA-512).
    #[default]
    Ristretto255,
    /// NIST P-256, RFC 9380 suite `P256_XMD:SHA-256_SSWU_RO_`.
    P256,
    /// SM2 (GB/T 32918) with the cryptex-defined suite
    /// `SM2_XMD:SM3_SSWU_RO_`; only interoperates with cryptex.
    Sm2,
    /// FourQ (Costello–Longa) with the cryptex-defined suite
    /// `FourQ_XMD:SHA-256_ELL2_RO_`; only interoperates with cryptex.
    FourQ,
}
