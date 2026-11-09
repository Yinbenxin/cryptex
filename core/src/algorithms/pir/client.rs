//! PIR client: one query of a batch of keywords.

use std::collections::HashMap;

use rand::seq::SliceRandom;
use rayon::prelude::*;

use super::suite::{self, Blinder, RecordKey};
use super::{check_key, malformed, Params, ID_LEN, MSG_CHUNK, MSG_EVAL, MSG_FETCH, MSG_QUERY};
use crate::algorithms::psi::common::{Reader, Writer};
use crate::exec::Executor;
use crate::primitives::rand::csprng;
use crate::{Error, Result};

enum State {
    Start,
    WaitEval,
    /// Receiving chunks: id → distinct keyword.
    Records {
        ids: HashMap<[u8; ID_LEN], usize>,
        keys: Vec<RecordKey>,
    },
    Done,
}

/// One query: send [`query`](Self::query), then feed every server message
/// to [`receive`](Self::receive), sending back what it returns, until
/// [`is_done`](Self::is_done); then read [`results`](Self::results).
pub struct Client {
    params: Params,
    /// Distinct keywords, in a random order (the order of the query).
    distinct: Vec<Vec<u8>>,
    /// Position in `distinct` of each input keyword.
    of_input: Vec<usize>,
    blind: Box<dyn Blinder>,
    found: Vec<Option<Vec<u8>>>,
    state: State,
    complete: bool,
    exec: Executor,
}

impl Client {
    /// Client for `keywords` against the database described by the
    /// server's params message. Duplicate keywords are queried once.
    pub fn new(params: &[u8], keywords: Vec<Vec<u8>>, threads: usize) -> Result<Self> {
        Self::with_executor(params, keywords, Executor::new(threads)?)
    }

    pub(crate) fn with_executor(
        params: &[u8],
        keywords: Vec<Vec<u8>>,
        exec: Executor,
    ) -> Result<Self> {
        let params = Params::decode(params)?;
        for k in &keywords {
            check_key(k)?;
        }
        // Dedupe, then shuffle: the server sees neither repeats nor order.
        let mut first: HashMap<&[u8], usize> = HashMap::with_capacity(keywords.len());
        let mut unique: Vec<usize> = Vec::new();
        let mut slot = Vec::with_capacity(keywords.len());
        for (i, k) in keywords.iter().enumerate() {
            let next = unique.len();
            let s = *first.entry(k).or_insert(next);
            if s == next {
                unique.push(i);
            }
            slot.push(s);
        }
        drop(first);
        let mut perm: Vec<usize> = (0..unique.len()).collect();
        perm.shuffle(&mut csprng()?);
        // perm[j] = old slot placed at j; invert it to remap `slot`.
        let mut new_pos = vec![0; perm.len()];
        for (j, &old) in perm.iter().enumerate() {
            new_pos[old] = j;
        }
        let of_input = slot.into_iter().map(|s| new_pos[s]).collect();
        let mut taken: Vec<Option<Vec<u8>>> = keywords.into_iter().map(Some).collect();
        let distinct = perm
            .iter()
            .map(|&old| {
                taken[unique[old]]
                    .take()
                    .expect("each distinct keyword once")
            })
            .collect::<Vec<_>>();
        Ok(Self {
            blind: suite::blinder(params.curve)?,
            found: vec![None; distinct.len()],
            params,
            distinct,
            of_input,
            state: State::Start,
            complete: false,
            exec,
        })
    }

    /// Public parameters of the server's snapshot.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Distinct keywords queried.
    pub fn distinct(&self) -> usize {
        self.found.len()
    }

    /// The query message. Call once, first.
    pub fn query(&mut self) -> Result<Vec<u8>> {
        if !matches!(self.state, State::Start) {
            return Err(state_error("query already made"));
        }
        self.state = State::Done;
        let blind = &*self.blind;
        let plen = blind.point_len();
        let mut q = vec![0u8; self.distinct.len() * plen];
        self.exec.install(|| {
            q.par_chunks_mut(plen)
                .zip(self.distinct.par_iter())
                .for_each(|(out, x)| blind.blind(x, out));
        });
        let mut w = Writer::new(MSG_QUERY, 16 + q.len());
        w.u64(self.params.generation as usize);
        w.u64(self.distinct.len());
        w.bytes(&q);
        self.state = State::WaitEval;
        Ok(w.finish())
    }

    /// Process one server message. After the eval message it returns the
    /// fetch message to send back; otherwise `None`.
    pub fn receive(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.state {
            State::Start => return Err(state_error("call query first")),
            State::Done => return Err(state_error("reply already complete")),
            _ => {}
        }
        match std::mem::replace(&mut self.state, State::Done) {
            State::WaitEval => {
                let n = self.distinct.len();
                let plen = self.blind.point_len();
                let mut r = Reader::new(msg, MSG_EVAL)?;
                if r.u64()? != n {
                    return Err(malformed("evaluation count does not match the query"));
                }
                let e = r.array(n, plen)?;
                r.finish()?;
                let blind = &*self.blind;
                let keys: Vec<RecordKey> = self.exec.install(|| {
                    e.par_chunks_exact(plen)
                        .zip(self.distinct.par_iter())
                        .map(|(enc, x)| blind.unblind(x, enc))
                        .collect::<Result<_>>()
                })?;
                // The keywords are no longer needed.
                self.distinct = Vec::new();
                let j = self.params.log2_buckets;
                let mut buckets: Vec<u32> =
                    keys.iter().map(|k| suite::bucket_of(&k.id, j)).collect();
                buckets.sort_unstable();
                buckets.dedup();
                let mut w = Writer::new(MSG_FETCH, 16 + 4 * buckets.len());
                w.u64(self.params.generation as usize);
                w.u64(buckets.len());
                for b in buckets {
                    w.u32(b);
                }
                let ids = keys.iter().enumerate().map(|(i, k)| (k.id, i)).collect();
                self.state = State::Records { ids, keys };
                Ok(Some(w.finish()))
            }
            State::Records { ids, keys } => {
                let mut r = Reader::new(msg, MSG_CHUNK)?;
                let last = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(malformed("bad last flag")),
                };
                let count = r.u64()?;
                let mut hits = Vec::new();
                for _ in 0..count {
                    let id: [u8; ID_LEN] = r.take(ID_LEN)?.try_into().expect("16 bytes");
                    let len = r.u32()? as usize;
                    let body = r.take(len)?;
                    if let Some(&i) = ids.get(&id) {
                        hits.push((i, body));
                    }
                }
                r.finish()?;
                let curve = self.params.curve;
                let opened: Vec<(usize, Vec<u8>)> = self.exec.install(|| {
                    hits.par_iter()
                        .map(|&(i, body)| suite::open(curve, &keys[i], body).map(|l| (i, l)))
                        .collect::<Result<_>>()
                })?;
                for (i, label) in opened {
                    self.found[i] = Some(label);
                }
                if last {
                    self.complete = true;
                } else {
                    self.state = State::Records { ids, keys };
                }
                Ok(None)
            }
            State::Start | State::Done => unreachable!("checked above"),
        }
    }

    /// Whether the reply is complete.
    pub fn is_done(&self) -> bool {
        self.complete
    }

    /// Label of each input keyword (in input order), `None` if the
    /// database has no such key. Fails until the reply is complete.
    pub fn results(&self) -> Result<Vec<Option<&[u8]>>> {
        if !self.is_done() {
            return Err(state_error("reply not complete"));
        }
        Ok(self
            .of_input
            .iter()
            .map(|&i| self.found[i].as_deref())
            .collect())
    }
}

fn state_error(what: &str) -> Error {
    Error::InvalidState(format!("PIR client: {what}"))
}
