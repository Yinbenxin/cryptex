//! PIR server: answers queries against a snapshot of a database.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rand::rngs::ChaCha20Rng;
use rand::seq::SliceRandom;
use rand::Rng;
use rayon::prelude::*;

use super::db::{checked_key, open_segments, Manifest};
use super::segment::{prefix, Record, Segment, KIND_RECORD};
use super::suite::ServerKey;
use super::{
    log2_buckets, malformed, Params, ID_LEN, LEN_PREFIX, MSG_CHUNK, MSG_EVAL, MSG_FETCH, MSG_QUERY,
};
use crate::algorithms::psi::common::{Reader, Writer};
use crate::exec::Executor;
use crate::primitives::rand::csprng;
use crate::{Error, Result};

/// Target size of one chunk message.
const CHUNK_BYTES: usize = 4 << 20;

/// How record bodies are padded in replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Padding {
    /// Pad every body to the longest label written since the last
    /// compaction: the client learns no label lengths.
    #[default]
    Max,
    /// Send bodies at their real length: the client learns the length of
    /// every label in the buckets it fetches.
    None,
}

/// One consistent view of the database.
struct Snapshot {
    segments: Vec<Segment>,
    params: Params,
    encoded: Vec<u8>,
}

struct Inner {
    dir: PathBuf,
    key: Box<dyn ServerKey>,
    exec: Executor,
    bucket_size: u64,
    padding: Padding,
    current: RwLock<Arc<Snapshot>>,
}

/// A database opened for queries. Cheap to clone; sessions may run on
/// several threads at once. Writes made with [`Database`](super::Database)
/// become visible after [`reload`](Self::reload).
#[derive(Clone)]
pub struct Server(Arc<Inner>);

impl Server {
    /// Open the database in `dir` with the seed it was created with.
    /// `bucket_size`: about this many records per bucket (the bucket count
    /// is the next power of two). `threads` as in PSI.
    pub fn open(
        dir: &Path,
        seed: &[u8; 32],
        bucket_size: u64,
        padding: Padding,
        threads: usize,
    ) -> Result<Self> {
        Self::open_with(dir, seed, bucket_size, padding, Executor::new(threads)?)
    }

    pub(crate) fn open_with(
        dir: &Path,
        seed: &[u8; 32],
        bucket_size: u64,
        padding: Padding,
        exec: Executor,
    ) -> Result<Self> {
        log2_buckets(0, bucket_size)?; // validates
        let manifest = Manifest::read(dir)?;
        let key = checked_key(dir, &manifest, seed)?;
        let snapshot = load(dir, bucket_size, padding)?;
        Ok(Self(Arc::new(Inner {
            dir: dir.to_path_buf(),
            key,
            exec,
            bucket_size,
            padding,
            current: RwLock::new(Arc::new(snapshot)),
        })))
    }

    /// Switch to the latest committed state; `true` if it changed. Running
    /// sessions keep their snapshot.
    pub fn reload(&self) -> Result<bool> {
        let inner = &*self.0;
        let latest = Manifest::read(&inner.dir)?.generation;
        if latest == self.params().generation {
            return Ok(false);
        }
        let snapshot = load(&inner.dir, inner.bucket_size, inner.padding)?;
        *inner.current.write().expect("lock poisoned") = Arc::new(snapshot);
        Ok(true)
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        self.0.current.read().expect("lock poisoned").clone()
    }

    /// Public parameters of the current snapshot.
    pub fn params(&self) -> Params {
        self.snapshot().params.clone()
    }

    /// Start answering one client, pinned to the current snapshot.
    pub fn session(&self) -> Result<Session> {
        Ok(Session {
            server: self.clone(),
            snapshot: self.snapshot(),
            state: State::Query,
            keywords: 0,
            buckets: Vec::new(),
            next: 0,
            pending: Vec::new(),
            rng: rand::SeedableRng::try_from_rng(&mut csprng()?)
                .map_err(|_| Error::OperationFailed("random source failed".into()))?,
        })
    }
}

/// Read the manifest and open its segments. A compaction may remove a
/// segment between the two steps; then try again.
fn load(dir: &Path, bucket_size: u64, padding: Padding) -> Result<Snapshot> {
    let mut last = None;
    for _ in 0..3 {
        let m = Manifest::read(dir)?;
        match open_segments(dir, &m) {
            Ok(segments) => {
                let params = Params {
                    curve: m.curve,
                    log2_buckets: log2_buckets(m.records, bucket_size)?,
                    records: m.records,
                    padded_len: match padding {
                        Padding::Max => LEN_PREFIX as u32 + m.max_label_len,
                        Padding::None => 0,
                    },
                    generation: m.generation,
                    metadata: m.metadata,
                };
                let encoded = params.encode();
                return Ok(Snapshot {
                    segments,
                    params,
                    encoded,
                });
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("at least one attempt"))
}

enum State {
    Query,
    Fetch,
    Send,
    Done,
}

/// One client's exchange: [`params`](Self::params) →
/// [`query`](Self::query) → [`fetch`](Self::fetch) →
/// [`next_chunk`](Self::next_chunk) until `None`.
pub struct Session {
    server: Server,
    snapshot: Arc<Snapshot>,
    state: State,
    keywords: usize,
    buckets: Vec<u32>,
    next: usize,
    /// Records of the current bucket not yet sent (consumed from the back).
    pending: Vec<Record>,
    rng: ChaCha20Rng,
}

impl Session {
    /// Parameters of the pinned snapshot.
    pub fn info(&self) -> &Params {
        &self.snapshot.params
    }

    /// The params message: send it to the client first.
    pub fn params(&self) -> &[u8] {
        &self.snapshot.encoded
    }

    /// Distinct keywords in the query.
    pub fn keywords(&self) -> usize {
        self.keywords
    }

    /// Buckets the client fetches, ascending.
    pub fn buckets(&self) -> &[u32] {
        &self.buckets
    }

    fn check_generation(&self, r: &mut Reader<'_>) -> Result<()> {
        if r.u64()? as u64 != self.snapshot.params.generation {
            return Err(Error::InvalidInput(
                "PIR: message is for another snapshot of the database".into(),
            ));
        }
        Ok(())
    }

    /// Evaluate the client's blinded keywords; returns the eval message.
    /// Fails on more than `max_keywords` keywords (0 = no limit).
    pub fn query(&mut self, msg: &[u8], max_keywords: usize) -> Result<Vec<u8>> {
        if !matches!(self.state, State::Query) {
            return Err(state_error("query already answered"));
        }
        self.state = State::Done;
        let key = &*self.server.0.key;
        let plen = key.point_len();
        let mut r = Reader::new(msg, MSG_QUERY)?;
        self.check_generation(&mut r)?;
        let n = r.u64()?;
        if max_keywords != 0 && n > max_keywords {
            return Err(Error::InvalidInput(format!(
                "PIR: query has {n} keywords, more than the limit {max_keywords}"
            )));
        }
        let points = r.array(n, plen)?;
        r.finish()?;
        let mut e = vec![0u8; n * plen];
        self.server.0.exec.install(|| {
            e.par_chunks_mut(plen)
                .zip(points.par_chunks_exact(plen))
                .try_for_each(|(dst, src)| key.evaluate(src, dst))
        })?;
        let mut w = Writer::new(MSG_EVAL, 8 + e.len());
        w.u64(n);
        w.bytes(&e);
        self.keywords = n;
        self.state = State::Fetch;
        Ok(w.finish())
    }

    /// Accept the client's bucket list. Fails if it asks for more buckets
    /// than it has keywords.
    pub fn fetch(&mut self, msg: &[u8]) -> Result<()> {
        if !matches!(self.state, State::Fetch) {
            return Err(state_error("fetch out of order"));
        }
        self.state = State::Done;
        let total = self.snapshot.params.buckets();
        let mut r = Reader::new(msg, MSG_FETCH)?;
        self.check_generation(&mut r)?;
        let k = r.u64()?;
        if k > self.keywords || k > total as usize {
            return Err(malformed("more buckets than keywords"));
        }
        let raw = r.array(k, 4)?;
        r.finish()?;
        let mut buckets = Vec::with_capacity(k);
        for c in raw.as_chunks::<4>().0 {
            let b = u32::from_be_bytes(*c);
            if b >= total || buckets.last().is_some_and(|&p| b <= p) {
                return Err(malformed("buckets out of range or not increasing"));
            }
            buckets.push(b);
        }
        self.buckets = buckets;
        self.state = State::Send;
        Ok(())
    }

    /// Live records of bucket `b`, newest version per id, shuffled.
    fn bucket_records(&mut self, b: u32) -> Result<Vec<Record>> {
        let j = self.snapshot.params.log2_buckets;
        let (lo, hi) = if j == 0 {
            (0, u32::MAX)
        } else {
            let width = 32 - u32::from(j);
            let lo = b << width;
            (lo, lo | (((1u64 << width) - 1) as u32))
        };
        // Newest segment first: the first version seen of an id wins.
        let mut all: Vec<(usize, Record)> = Vec::new();
        for (age, seg) in self.snapshot.segments.iter().rev().enumerate() {
            all.extend(seg.range(lo, hi)?.into_iter().map(|r| (age, r)));
        }
        all.sort_by(|a, b| a.1.id.cmp(&b.1.id).then(a.0.cmp(&b.0)));
        let mut out = Vec::with_capacity(all.len());
        let mut prev: Option<[u8; ID_LEN]> = None;
        for (_, rec) in all {
            if prev == Some(rec.id) {
                continue;
            }
            prev = Some(rec.id);
            if rec.kind == KIND_RECORD {
                debug_assert!(prefix(&rec.id) >= lo && prefix(&rec.id) <= hi);
                out.push(rec);
            }
        }
        // The stored order is by id; shuffle so the order says nothing.
        out.shuffle(&mut self.rng);
        Ok(out)
    }

    /// Next chunk of records for the client, `None` once the reply is
    /// complete. A chunk holds records up to about [`CHUNK_BYTES`], at least
    /// one, so a very large label gets a chunk of its own. One bucket is in
    /// memory at a time. The last chunk carries a flag, so the client knows
    /// it is done without knowing the total in advance.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if !matches!(self.state, State::Send) {
            return match self.state {
                State::Done => Ok(None),
                _ => Err(state_error("call fetch first")),
            };
        }
        let padded = self.snapshot.params.padded_len as usize;
        let mut body = Vec::new();
        let mut count = 0usize;
        loop {
            if self.pending.is_empty() {
                if self.next == self.buckets.len() {
                    break;
                }
                let b = self.buckets[self.next];
                self.next += 1;
                self.pending = self.bucket_records(b)?;
                continue;
            }
            let len = self
                .pending
                .last()
                .expect("non-empty")
                .body
                .len()
                .max(padded);
            if count > 0 && body.len() + ID_LEN + 4 + len > CHUNK_BYTES {
                break;
            }
            let rec = self.pending.pop().expect("non-empty");
            body.reserve(ID_LEN + 4 + len);
            body.extend_from_slice(&rec.id);
            body.extend_from_slice(&(len as u32).to_be_bytes());
            body.extend_from_slice(&rec.body);
            let start = body.len();
            body.resize(start + len - rec.body.len(), 0);
            self.rng.fill_bytes(&mut body[start..]);
            count += 1;
        }
        let last = self.pending.is_empty() && self.next == self.buckets.len();
        let mut w = Writer::new(MSG_CHUNK, 9 + body.len());
        w.u8(u8::from(last));
        w.u64(count);
        w.bytes(&body);
        if last {
            self.state = State::Done;
        }
        Ok(Some(w.finish()))
    }
}

fn state_error(what: &str) -> Error {
    Error::InvalidState(format!("PIR server: {what}"))
}
