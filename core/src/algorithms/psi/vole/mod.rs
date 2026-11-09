//! VOLE-PSI: OPRF from VOLE over GF(2^128) and a binary OKVS. VOLE comes
//! from silent OT (Ferret); one job covers all buckets with a single setup.
//! Fixed to AES-128 and SHA-256; there is no SM4 variant.
//!
//! The job is a full-duplex state machine (see [`job`]): unlike ECDH-PSI it
//! does not alternate strictly, so it is driven with
//! `receive` / `next_send` rather than [`crate::protocol::Party`].

pub(crate) mod job;
