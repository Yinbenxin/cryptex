//! Keyword PIR (anonymous query): the client looks up its keywords in the
//! server's key–label database; the server does not learn which keywords,
//! the client learns the labels of its own keywords. Semi-honest, with
//! bucket-level leakage (see below).
//!
//! The server keeps the database under a long-term OPRF key `k` (2HashDH,
//! [`crate::primitives::oprf`]); every record is
//!
//! ```text
//! id = F_k(key)[0..16]  ‖  CTR_{F_k(key)[16..32]}(IV = 0, len ‖ label)
//! ```
//!
//! stored with its real label length, in segments sorted by id. Writes
//! (upsert, delete) add a segment; [`Database::compact`] merges them. The
//! bucket of a record is the top `j` bits of its id, `2^j` buckets chosen
//! when the database is served, so nothing about buckets is stored.
//!
//! A query takes two round trips:
//!
//! ```text
//! Client (keywords x_i)                                Server (database, k)
//!            ◀── params: curve, 2^j buckets, records, padding, snapshot ──
//!   r ← random scalar, q_i = H(x_i)^r
//!            ── query: [q_i] ──▶
//!                                                      e_i = q_i^k
//!            ◀── eval: [e_i] ──
//!   F_k(x_i) = Fin(x_i, e_i^(1/r)) → (id_i, key_i)
//!            ── fetch: { top j bits of id_i } ──▶
//!            ◀── chunk … chunk (last): the live records of those buckets ──
//!   find id_i, decrypt
//! ```
//!
//! Leakage: the server learns the number of distinct keywords and the
//! buckets they fall in (each keyword hides among the ~`records / 2^j` keys
//! of its bucket); the client learns the public parameters and the sizes
//! of the buckets it fetched, and, unless the server pads to the longest
//! label, the length of every label in them. The IV is fixed, so a key
//! updated between two downloads of its bucket reveals `old ⊕ new` label
//! to the client.

mod client;
mod db;
mod segment;
mod server;
mod suite;
#[cfg(test)]
mod tests;

pub use super::psi::ecdh::Curve;
pub use client::Client;
pub use db::Database;
pub use server::{Padding, Server, Session};

use super::psi::common::{Reader, Writer};
use crate::primitives::oprf::MAX_INPUT_LEN;
use crate::{Error, Result};

/// Largest keyword: the OPRF frames its input with a 2-byte length.
pub const MAX_KEY_LEN: usize = MAX_INPUT_LEN;
/// Largest label: not a policy limit, only what the 32-bit length fields
/// of the record and wire formats can carry (about 4 GiB).
pub const MAX_LABEL_LEN: usize = u32::MAX as usize - LEN_PREFIX;
/// Largest metadata blob stored with a database.
pub const MAX_METADATA_LEN: usize = 1 << 16;
/// Largest bucket count is `2^MAX_LOG2_BUCKETS`.
pub const MAX_LOG2_BUCKETS: u8 = 20;

/// Bytes of a record id.
const ID_LEN: usize = 16;
/// Bytes of the label length inside the encrypted body.
const LEN_PREFIX: usize = 4;

/// State of a database, as the writer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbInfo {
    /// OPRF suite; also selects the cipher (SM4 for SM2, else AES-128) and
    /// the hash (SM3 for SM2, else SHA-256).
    pub curve: Curve,
    /// Live records: exact after [`Database::compact`], otherwise an
    /// estimate (updates count twice, deleting a missing key once).
    pub records: u64,
    /// Number of segments.
    pub segments: u32,
    /// Longest label written since the last compaction.
    pub max_label_len: u32,
    /// Increases with every commit and compaction.
    pub generation: u64,
    /// Opaque bytes stored with the database (e.g. a label schema).
    pub metadata: Vec<u8>,
}

/// Public parameters of a served snapshot, sent to every client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// OPRF suite.
    pub curve: Curve,
    /// `2^log2_buckets` buckets: a record's bucket is the top bits of its id.
    pub log2_buckets: u8,
    /// Live records (see [`DbInfo::records`]).
    pub records: u64,
    /// Bodies in the reply are padded to this many bytes (0 = not padded).
    pub padded_len: u32,
    /// Snapshot the parameters belong to.
    pub generation: u64,
    /// Metadata stored with the database.
    pub metadata: Vec<u8>,
}

impl Params {
    /// Number of buckets.
    pub fn buckets(&self) -> u32 {
        1 << self.log2_buckets
    }
}

/// `2^j` buckets for `records` records at about `bucket_size` per bucket:
/// the smallest `j` with `records / 2^j <= bucket_size`, at most
/// [`MAX_LOG2_BUCKETS`]. Powers of two nest, so a keyword queried under two
/// bucket counts is still hidden in the finer of the two buckets.
pub fn log2_buckets(records: u64, bucket_size: u64) -> Result<u8> {
    if bucket_size == 0 {
        return Err(Error::InvalidInput("bucket size must be positive".into()));
    }
    let mut j = 0;
    while j < MAX_LOG2_BUCKETS && records.div_ceil(1 << j) > bucket_size {
        j += 1;
    }
    Ok(j)
}

// Wire format (integers big-endian, points compressed):
//
// - params: 0x31 ‖ version (u8) ‖ curve (u8) ‖ log2_buckets (u8) ‖
//   records (u64) ‖ padded_len (u32) ‖ generation (u64) ‖
//   metadata_len (u32) ‖ metadata
// - query:  0x32 ‖ generation (u64) ‖ n (u64) ‖ q_1 … q_n
// - eval:   0x33 ‖ n (u64) ‖ e_1 … e_n
// - fetch:  0x35 ‖ generation (u64) ‖ k (u64) ‖ b_1 … b_k (u32, strictly
//   increasing)
// - chunk:  0x34 ‖ last (u8) ‖ count (u64) ‖ count × (id (16) ‖
//   body_len (u32) ‖ body)
const MSG_PARAMS: u8 = 0x31;
const MSG_QUERY: u8 = 0x32;
const MSG_EVAL: u8 = 0x33;
const MSG_CHUNK: u8 = 0x34;
const MSG_FETCH: u8 = 0x35;
const WIRE_VERSION: u8 = 2;

impl Params {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(MSG_PARAMS, 32 + self.metadata.len());
        w.u8(WIRE_VERSION);
        w.u8(db::curve_code(self.curve));
        w.u8(self.log2_buckets);
        w.u64(self.records as usize);
        w.u32(self.padded_len);
        w.u64(self.generation as usize);
        w.u32(self.metadata.len() as u32);
        w.bytes(&self.metadata);
        w.finish()
    }

    /// Parse a params message.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let mut r = Reader::new(msg, MSG_PARAMS)?;
        let version = r.u8()?;
        if version != WIRE_VERSION {
            return Err(malformed(&format!(
                "PIR version {version}, expected {WIRE_VERSION}"
            )));
        }
        let curve = db::curve_from_code(r.u8()?)?;
        let log2_buckets = r.u8()?;
        let records = r.u64()? as u64;
        let padded_len = r.u32()?;
        let generation = r.u64()? as u64;
        let meta_len = r.u32()? as usize;
        if log2_buckets > MAX_LOG2_BUCKETS || meta_len > MAX_METADATA_LEN {
            return Err(malformed("parameters out of range"));
        }
        let metadata = r.take(meta_len)?.to_vec();
        r.finish()?;
        Ok(Self {
            curve,
            log2_buckets,
            records,
            padded_len,
            generation,
            metadata,
        })
    }
}

fn check_key(key: &[u8]) -> Result<()> {
    if key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidInput(format!(
            "PIR: keyword longer than {MAX_KEY_LEN} bytes"
        )));
    }
    Ok(())
}

fn malformed(what: &str) -> Error {
    Error::InvalidInput(format!("malformed PIR message: {what}"))
}
