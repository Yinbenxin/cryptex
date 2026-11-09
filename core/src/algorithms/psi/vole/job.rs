//! A VOLE-PSI job: one setup shared by all buckets, then one request and
//! one reply per bucket, pipelined over a full-duplex channel.
//!
//! # Correlations
//!
//! - 128 base OTs (Chou–Orlandi), the sender choosing `Δ`.
//! - IKNP extends them to the COT reserve of Ferret's setup iteration.
//! - Ferret ([`ferret`]) then streams silent COTs from the sender, which
//!   both sides turn into VOLE over GF(2^128): 128 COTs give the receiver
//!   `(a, c)` and the sender `b = c ⊕ a ⊗ Δ` ([`field::combine`]).
//!
//! # Per bucket (OPRF from VOLE + OKVS, as in VOLE-PSI / RR22)
//!
//! For items with `d = H("…-ITEM" ‖ x)` and `h(x) = H("…-CODE" ‖ d)`:
//!
//! - the receiver encodes `P = Encode({x_i → h(x_i)})` over `M` rows, sends
//!   `a' = a ⊕ P`, and evaluates `F(x) = H("…-OUT" ‖ b ‖ d ‖ Decode(c, x))`;
//! - the sender sets `K = b ⊕ a' ⊗ Δ = c ⊕ P ⊗ Δ` and replies, shuffled,
//!   `F(y) = H("…-OUT" ‖ b ‖ d ‖ Decode(K, y) ⊕ h(y) ⊗ Δ)` for its items.
//!
//! Both agree on encoded items; for any other `y`, `Decode(P, y) ⊕ h(y)` is
//! nonzero (except with probability 2^-128) and `F(y)` depends on the
//! unknown `Δ`.
//!
//! # Messages
//!
//! | tag    | dir   | content |
//! | ------ | ----- | ------- |
//! | `0x21` | R → S | seed_R (16), B (u32), n_0 … n_{B-1} (u64), A (32) |
//! | `0x22` | S → R | seed_S (16), B, m_0 … m_{B-1}, B_1 … B_128 (32 each) |
//! | `0x23` | R → S | IKNP rows U (16 each) |
//! | `0x24` | S → R | iteration (u64), Ferret message |
//! | `0x25` | R → S | bucket (u32), OKVS seed (16), M (u64), a' (16 each) |
//! | `0x26` | S → R | bucket (u32), t (u8), m (u64), outputs (t each) |
//! | `0x27` | R → S | bucket (u32), k (u64), positions (u32 or u64 each) |
//!
//! `0x27` is only sent when the receiver shares the result (`share`, a
//! byte after seed_R in `0x21`; the sender rejects a value different from
//! its own): the ascending positions in the bucket's shuffled reply that
//! matched, which the sender maps back to its own items. The sender trusts
//! them (semi-honest).
//!
//! Buckets where either side is empty are skipped by both parties. The
//! sender produces Ferret iterations only as far ahead as the receiver's
//! next [`WINDOW`] buckets need, and the receiver keeps at most `WINDOW`
//! requests outstanding, so memory stays bounded by a few buckets.

use std::collections::VecDeque;

use rand::seq::SliceRandom;
use rand::{Rng, RngExt};
use rayon::prelude::*;
use zeroize::Zeroize;

use crate::algorithms::psi::common::{
    intersect, intersect_both, read_positions, truncation_len, write_positions, Reader, Writer,
};
use crate::algorithms::psi::Intersection;
use crate::exec::Executor;
use crate::primitives::field::{self, Gf128};
use crate::primitives::hash::sha256;
use crate::primitives::okvs::band as okvs;
use crate::primitives::ot::base::{self, BaseOtSender};
use crate::primitives::ot::extension;
use crate::primitives::ot::ferret::{self, FerretReceiver, FerretSender, Params, ReceiverCots};
use crate::primitives::ot::Block;
use crate::primitives::rand::csprng;
use crate::{Error, Result};

const J1: u8 = 0x21;
const J2: u8 = 0x22;
const J3: u8 = 0x23;
const ITERATION: u8 = 0x24;
const REQUEST: u8 = 0x25;
const REPLY: u8 = 0x26;
const RESULT: u8 = 0x27;

const DST_ITEM: &[u8] = b"CRYPTEX-VOLE-PSI-V2-ITEM";
const DST_CODE: &[u8] = b"CRYPTEX-VOLE-PSI-V2-CODE";
const DST_OUT: &[u8] = b"CRYPTEX-VOLE-PSI-V2-OUT";
const DST_SESSION: &[u8] = b"CRYPTEX-VOLE-PSI-V2-SESSION";

/// Buckets in flight (requests sent but not answered).
pub(crate) const WINDOW: usize = 2;
const OKVS_ATTEMPTS: usize = 8;
const POINT_LEN: usize = 32;
const BASE_OTS: usize = 128;

/// Largest number of buckets accepted from the peer.
const MAX_BUCKETS: usize = 1 << 20;

/// Ferret parameters: setup iteration, then main iterations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FerretConfig {
    pub pre: Params,
    pub main: Params,
}

/// Production parameters (emp-ot's).
pub(crate) const PRODUCTION: FerretConfig = FerretConfig {
    pre: ferret::PRE,
    main: ferret::MAIN,
};

impl FerretConfig {
    /// VOLE elements usable from an iteration with `p`, followed by `next`.
    fn usable(p: Params, next: Params) -> usize {
        (p.n - next.reserve()) / 128
    }

    /// Iterations needed to produce `elements` VOLE elements.
    fn iterations_for(&self, elements: usize) -> usize {
        if elements == 0 {
            return 0;
        }
        let first = Self::usable(self.pre, self.main);
        if elements <= first {
            return 1;
        }
        1 + (elements - first).div_ceil(Self::usable(self.main, self.main))
    }

    /// IKNP COTs needed for the setup reserve, rounded up to 128.
    fn base_cots(&self) -> usize {
        self.pre.reserve().div_ceil(128) * 128
    }
}

fn digest(x: &[u8]) -> [u8; 32] {
    sha256(&[DST_ITEM, x])
}

fn code(d: &[u8; 32]) -> Gf128 {
    sha256(&[DST_CODE, d])[..16].try_into().expect("16")
}

fn output(bucket: u32, d: &[u8; 32], v: &Gf128, t: usize, out: &mut [u8]) {
    out.copy_from_slice(&sha256(&[DST_OUT, &bucket.to_le_bytes(), d, v])[..t]);
}

fn session_seed(r: &[u8], s: &[u8]) -> [u8; 32] {
    sha256(&[DST_SESSION, r, s])
}

fn state_error(what: &str) -> Error {
    Error::InvalidState(format!("VOLE-PSI job: {what}"))
}

fn read_sizes(r: &mut Reader<'_>, expected: usize) -> Result<Vec<usize>> {
    let b = r.u32()? as usize;
    if b != expected {
        return Err(Error::InvalidInput(format!(
            "VOLE-PSI job: peer has {b} buckets, we have {expected}"
        )));
    }
    (0..b).map(|_| r.u64()).collect()
}

fn write_sizes(w: &mut Writer, sizes: &[usize]) {
    w.u32(sizes.len() as u32);
    for &s in sizes {
        w.u64(s);
    }
}

/// Per-bucket bookkeeping shared by both roles, known after J1/J2.
struct Plan {
    /// Receiver's and sender's set sizes per bucket.
    n: Vec<usize>,
    m: Vec<usize>,
    /// Buckets that run, in order.
    active: Vec<u32>,
    /// VOLE elements (OKVS rows) per active bucket, same order.
    rows: Vec<usize>,
    iterations: usize,
}

impl Plan {
    fn new(n: Vec<usize>, m: Vec<usize>, cfg: &FerretConfig) -> Self {
        let active: Vec<u32> = (0..n.len() as u32)
            .filter(|&b| n[b as usize] > 0 && m[b as usize] > 0)
            .collect();
        let rows: Vec<usize> = active.iter().map(|&b| okvs::size(n[b as usize])).collect();
        let iterations = cfg.iterations_for(rows.iter().sum());
        Self {
            n,
            m,
            active,
            rows,
            iterations,
        }
    }

    fn truncation(&self, b: u32) -> usize {
        truncation_len(self.n[b as usize], self.m[b as usize], self.n.len() as u32)
    }

    /// Elements needed to serve active buckets `[0, upto)`.
    fn demand(&self, upto: usize) -> usize {
        self.rows[..upto.min(self.rows.len())].iter().sum()
    }
}

/// What a party needs from the driver next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    /// Items of this bucket (buckets are requested in increasing order;
    /// every bucket is requested, including skipped ones).
    Items(u32),
    /// Nothing right now.
    Nothing,
}

// ---------------------------------------------------------------- receiver

enum RecvPhase {
    /// Not started: J1 to send.
    Start,
    /// Waiting for J2.
    WaitJ2(BaseOtSender),
    /// Setup done on our side; Ferret messages and replies flow.
    Running(Box<RecvRun>),
    Done,
}

struct RecvRun {
    plan: Plan,
    ferret: Option<FerretReceiver>,
    iterations_done: usize,
    /// VOLE elements `(a, c)` not yet assigned to a bucket.
    vole: VecDeque<(Gf128, Gf128)>,
    /// Next active-bucket position to request, and outstanding requests:
    /// (bucket, truncated outputs of our items).
    next_request: usize,
    outstanding: VecDeque<(u32, usize, Vec<u8>)>,
    replies: usize,
}

/// PSI receiver of a job: initiates and learns the intersection per bucket.
pub(crate) struct VoleJobReceiver {
    exec: Executor,
    cfg: FerretConfig,
    sizes: Vec<usize>,
    seed: [u8; 16],
    /// Items provided by the driver, by bucket, until consumed.
    items: VecDeque<(u32, Vec<Vec<u8>>)>,
    provided: u32,
    phase: RecvPhase,
    out: VecDeque<Vec<u8>>,
    results: VecDeque<(u32, Intersection)>,
    /// Send each bucket's matches back to the sender.
    share: bool,
}

impl VoleJobReceiver {
    /// `sizes[b]`: number of (distinct) items this party will provide for
    /// bucket `b`. `share`: also give the sender the result; must match
    /// the sender's setting.
    pub(crate) fn new(
        sizes: Vec<usize>,
        exec: Executor,
        cfg: FerretConfig,
        share: bool,
    ) -> Result<Self> {
        if sizes.is_empty() || sizes.len() > MAX_BUCKETS {
            return Err(Error::InvalidInput("bucket count out of range".into()));
        }
        let mut seed = [0u8; 16];
        csprng()?.fill_bytes(&mut seed);
        Ok(Self {
            exec,
            cfg,
            sizes,
            seed,
            items: VecDeque::new(),
            provided: 0,
            phase: RecvPhase::Start,
            out: VecDeque::new(),
            results: VecDeque::new(),
            share,
        })
    }

    pub(crate) fn need(&self) -> Need {
        // Keep up to WINDOW + 1 buckets of items ahead of the next request.
        let next = match &self.phase {
            RecvPhase::Running(run) => run.plan.active.get(run.next_request).copied(),
            RecvPhase::Done => None,
            _ => Some(0),
        };
        let horizon = next.map_or(self.sizes.len() as u32, |b| b + 1 + WINDOW as u32);
        if (self.provided as usize) < self.sizes.len() && self.provided < horizon {
            Need::Items(self.provided)
        } else {
            Need::Nothing
        }
    }

    pub(crate) fn provide(&mut self, bucket: u32, items: Vec<Vec<u8>>) -> Result<()> {
        if bucket != self.provided {
            return Err(state_error(&format!(
                "items for bucket {bucket} given, expected bucket {}",
                self.provided
            )));
        }
        if items.len() != self.sizes[bucket as usize] {
            return Err(Error::InvalidInput(format!(
                "bucket {bucket}: {} items given, {} announced",
                items.len(),
                self.sizes[bucket as usize]
            )));
        }
        self.provided += 1;
        self.items.push_back((bucket, items));
        Ok(())
    }

    pub(crate) fn take_result(&mut self) -> Option<(u32, Intersection)> {
        self.results.pop_front()
    }

    pub(crate) fn is_done(&self) -> bool {
        matches!(self.phase, RecvPhase::Done) && self.out.is_empty()
    }

    /// Whether more messages from the peer are expected.
    pub(crate) fn expects_messages(&self) -> bool {
        !matches!(self.phase, RecvPhase::Done)
    }

    pub(crate) fn next_send(&mut self) -> Result<Option<Vec<u8>>> {
        if let RecvPhase::Start = self.phase {
            let (ot, a) = BaseOtSender::new(&mut csprng()?);
            let mut w = Writer::new(J1, 16 + 1 + 4 + 8 * self.sizes.len() + POINT_LEN);
            w.bytes(&self.seed);
            w.u8(u8::from(self.share));
            write_sizes(&mut w, &self.sizes);
            w.bytes(&a);
            self.out.push_back(w.finish());
            self.phase = RecvPhase::WaitJ2(ot);
        }
        if let Some(m) = self.out.pop_front() {
            return Ok(Some(m));
        }
        self.try_request()
    }

    /// Send the next bucket request if its VOLE and items are ready.
    fn try_request(&mut self) -> Result<Option<Vec<u8>>> {
        let RecvPhase::Running(run) = &mut self.phase else {
            return Ok(None);
        };
        if run.outstanding.len() >= WINDOW || run.next_request >= run.plan.active.len() {
            return Ok(None);
        }
        let pos = run.next_request;
        let bucket = run.plan.active[pos];
        let rows = run.plan.rows[pos];
        if run.vole.len() < rows {
            return Ok(None);
        }
        // Drop items of skipped buckets before this one.
        while let Some((b, _)) = self.items.front() {
            if *b < bucket {
                self.items.pop_front();
            } else {
                break;
            }
        }
        let Some((b, _)) = self.items.front() else {
            return Ok(None);
        };
        if *b != bucket {
            return Ok(None);
        }
        let (_, items) = self.items.pop_front().expect("checked");
        let vole: Vec<(Gf128, Gf128)> = run.vole.drain(..rows).collect();
        let t = run.plan.truncation(bucket);
        let (msg, outputs) = self
            .exec
            .install(|| bucket_request(bucket, &items, vole, t))?;
        run.outstanding.push_back((bucket, t, outputs));
        run.next_request += 1;
        Ok(Some(msg))
    }

    pub(crate) fn receive(&mut self, msg: &[u8]) -> Result<()> {
        let tag = *msg
            .first()
            .ok_or_else(|| Error::InvalidInput("empty message".into()))?;
        match (std::mem::replace(&mut self.phase, RecvPhase::Done), tag) {
            (RecvPhase::WaitJ2(ot), J2) => self.on_j2(ot, msg),
            (RecvPhase::Running(mut run), ITERATION) => {
                self.on_ferret(&mut run, msg)?;
                self.phase = RecvPhase::Running(run);
                self.finish_if_done();
                Ok(())
            }
            (RecvPhase::Running(mut run), REPLY) => {
                self.on_reply(&mut run, msg)?;
                self.phase = RecvPhase::Running(run);
                self.finish_if_done();
                Ok(())
            }
            (_, tag) => Err(state_error(&format!("unexpected message type {tag:#x}"))),
        }
    }

    fn finish_if_done(&mut self) {
        if let RecvPhase::Running(run) = &self.phase {
            if run.replies == run.plan.active.len() && run.iterations_done == run.plan.iterations {
                self.phase = RecvPhase::Done;
            }
        }
    }

    fn on_j2(&mut self, ot: BaseOtSender, msg: &[u8]) -> Result<()> {
        let mut r = Reader::new(msg, J2)?;
        let seed_s = r.take(16)?;
        let m = read_sizes(&mut r, self.sizes.len())?;
        let reply = r.array(BASE_OTS, POINT_LEN)?;
        r.finish()?;
        let plan = Plan::new(self.sizes.clone(), m, &self.cfg);
        let session = session_seed(&self.seed, seed_s);
        let mut keys = ot.finish(reply, BASE_OTS)?;

        let ferret = if plan.iterations > 0 {
            // IKNP: random choice bits, rows U to the sender.
            let count = self.cfg.base_cots();
            let mut rng = csprng()?;
            let bits: Vec<bool> = (0..count).map(|_| rng.random::<bool>()).collect();
            let mut rows: Vec<[u8; 16]> = bits
                .iter()
                .map(|&x| if x { [0xff; 16] } else { [0; 16] })
                .collect();
            let t = self.exec.install(|| extension::receive(&keys, &mut rows));
            let mut w = Writer::new(J3, 16 * count);
            w.bytes(rows.as_flattened());
            self.out.push_back(w.finish());
            let reserve = self.cfg.pre.reserve();
            Some(FerretReceiver::new(
                self.cfg.pre,
                ReceiverCots {
                    bits: bits[..reserve].to_vec(),
                    blocks: t[..reserve].to_vec(),
                },
                session,
            ))
        } else {
            None
        };
        keys.zeroize();
        self.phase = RecvPhase::Running(Box::new(RecvRun {
            plan,
            ferret,
            iterations_done: 0,
            vole: VecDeque::new(),
            next_request: 0,
            outstanding: VecDeque::new(),
            replies: 0,
        }));
        self.finish_if_done();
        Ok(())
    }

    fn on_ferret(&mut self, run: &mut RecvRun, msg: &[u8]) -> Result<()> {
        let mut r = Reader::new(msg, ITERATION)?;
        let it = r.u64()?;
        if it != run.iterations_done || it >= run.plan.iterations {
            return Err(Error::InvalidInput(format!(
                "VOLE-PSI job: unexpected iteration {it}"
            )));
        }
        let body = r.take(msg.len() - 9)?;
        r.finish()?;
        let f = run
            .ferret
            .as_mut()
            .ok_or_else(|| state_error("no Ferret state"))?;
        let main = self.cfg.main;
        // 128 COTs → one VOLE element (a, c), folded as they are produced.
        let fresh = self.exec.install(|| {
            f.iterate(body, main, |bits, blocks| {
                (field::pack_bits(bits), field::combine(blocks))
            })
        })?;
        run.vole.extend(fresh);
        run.iterations_done += 1;
        Ok(())
    }

    fn on_reply(&mut self, run: &mut RecvRun, msg: &[u8]) -> Result<()> {
        let mut r = Reader::new(msg, REPLY)?;
        let bucket = r.u32()?;
        let (expected, t, outputs) = run
            .outstanding
            .pop_front()
            .ok_or_else(|| Error::InvalidInput("VOLE-PSI job: unsolicited reply".into()))?;
        if bucket != expected {
            return Err(Error::InvalidInput(format!(
                "VOLE-PSI job: reply for bucket {bucket}, expected {expected}"
            )));
        }
        let got_t = usize::from(r.u8()?);
        let m = r.u64()?;
        if got_t != t || m != run.plan.m[bucket as usize] {
            return Err(Error::InvalidInput(format!(
                "VOLE-PSI job: bucket {bucket} reply has t = {got_t}, m = {m}"
            )));
        }
        let f = r.array(m, t)?;
        r.finish()?;
        let found = if self.share {
            let (found, positions) = self.exec.install(|| intersect_both(&outputs, f, t));
            let mut w = Writer::new(RESULT, 4 + 8 + 4 * positions.len());
            w.u32(bucket);
            write_positions(&mut w, &positions, m);
            self.out.push_back(w.finish());
            found
        } else {
            self.exec.install(|| intersect(&outputs, f, t))
        };
        self.results.push_back((bucket, found));
        run.replies += 1;
        Ok(())
    }
}

/// Receiver's work for one bucket: OKVS-encode, mask with `a`, evaluate the
/// OPRF on our items with `c`.
fn bucket_request(
    bucket: u32,
    items: &[Vec<u8>],
    vole: Vec<(Gf128, Gf128)>,
    t: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let size = vole.len();
    let digests: Vec<[u8; 32]> = items.par_iter().map(|x| digest(x)).collect();
    let values: Vec<Gf128> = digests.par_iter().map(code).collect();
    let mut rng = csprng()?;
    let (seed, rows, table) = (0..OKVS_ATTEMPTS)
        .find_map(|_| {
            let mut seed = [0u8; 16];
            rng.fill_bytes(&mut seed);
            let rows: Vec<okvs::Row> = digests
                .par_iter()
                .map(|d| okvs::row(size, &seed, d))
                .collect();
            okvs::encode(size, &rows, &values, &mut rng).map(|tbl| (seed, rows, tbl))
        })
        .ok_or_else(|| Error::OperationFailed("VOLE-PSI: OKVS encoding failed".into()))?;

    let (a, c): (Vec<Gf128>, Vec<Gf128>) = vole.into_iter().unzip();
    let mut w = Writer::new(REQUEST, 4 + 16 + 8 + 16 * size);
    w.u32(bucket);
    w.bytes(&seed);
    w.u64(size);
    let masked: Vec<u8> = table
        .par_iter()
        .zip(a.par_iter())
        .flat_map_iter(|(p, a)| field::add(p, a))
        .collect();
    w.bytes(&masked);

    let mut outputs = vec![0u8; items.len() * t];
    outputs
        .par_chunks_mut(t)
        .zip(digests.par_iter().zip(rows.par_iter()))
        .for_each(|(out, (d, row))| output(bucket, d, &okvs::decode(&c, *row), t, out));
    Ok((w.finish(), outputs))
}

// ------------------------------------------------------------------ sender

enum SendPhase {
    WaitJ1,
    WaitJ3(Box<SendSetup>),
    Running(Box<SendRun>),
    Done,
}

struct SendSetup {
    plan: Plan,
    session: [u8; 32],
    keys: Vec<Block>,
}

struct SendRun {
    plan: Plan,
    ferret: Option<FerretSender>,
    iterations_sent: usize,
    /// VOLE elements `b` not yet assigned to a bucket.
    vole: VecDeque<Gf128>,
    /// Requests received, not yet answered, in order.
    requests: VecDeque<Vec<u8>>,
    answered: usize,
    /// Sharing: shuffle of each answered bucket whose result has not come
    /// back yet, and how many results arrived.
    perms: VecDeque<(u32, Vec<usize>)>,
    results_in: usize,
}

impl SendRun {
    /// Every bucket answered and, when sharing, every result received.
    fn finished(&self) -> bool {
        self.answered == self.plan.active.len()
            && self.iterations_sent == self.plan.iterations
            && self.perms.is_empty()
    }
}

/// PSI sender of a job: holds `Δ`. Learns nothing, or the intersection per
/// bucket when the receiver shares it.
pub(crate) struct VoleJobSender {
    exec: Executor,
    cfg: FerretConfig,
    sizes: Vec<usize>,
    delta: Block,
    items: VecDeque<(u32, Vec<Vec<u8>>)>,
    provided: u32,
    phase: SendPhase,
    out: VecDeque<Vec<u8>>,
    share: bool,
    results: VecDeque<(u32, Intersection)>,
}

impl Drop for VoleJobSender {
    fn drop(&mut self) {
        self.delta.zeroize();
    }
}

impl VoleJobSender {
    /// `share`: expect each bucket's result from the receiver; must match
    /// the receiver's setting.
    pub(crate) fn new(
        sizes: Vec<usize>,
        exec: Executor,
        cfg: FerretConfig,
        share: bool,
    ) -> Result<Self> {
        if sizes.is_empty() || sizes.len() > MAX_BUCKETS {
            return Err(Error::InvalidInput("bucket count out of range".into()));
        }
        let mut delta = [0u8; 16];
        csprng()?.fill_bytes(&mut delta);
        Ok(Self {
            exec,
            cfg,
            sizes,
            delta,
            items: VecDeque::new(),
            provided: 0,
            phase: SendPhase::WaitJ1,
            out: VecDeque::new(),
            share,
            results: VecDeque::new(),
        })
    }

    /// Sharing: the next bucket whose result arrived, as indices into the
    /// items provided for it.
    pub(crate) fn take_result(&mut self) -> Option<(u32, Intersection)> {
        self.results.pop_front()
    }

    pub(crate) fn need(&self) -> Need {
        let next = match &self.phase {
            SendPhase::Running(run) => run.plan.active.get(run.answered).copied(),
            SendPhase::Done => None,
            _ => Some(0),
        };
        let horizon = next.map_or(self.sizes.len() as u32, |b| b + 1 + WINDOW as u32);
        if (self.provided as usize) < self.sizes.len() && self.provided < horizon {
            Need::Items(self.provided)
        } else {
            Need::Nothing
        }
    }

    pub(crate) fn provide(&mut self, bucket: u32, items: Vec<Vec<u8>>) -> Result<()> {
        if bucket != self.provided {
            return Err(state_error(&format!(
                "items for bucket {bucket} given, expected bucket {}",
                self.provided
            )));
        }
        if items.len() != self.sizes[bucket as usize] {
            return Err(Error::InvalidInput(format!(
                "bucket {bucket}: {} items given, {} announced",
                items.len(),
                self.sizes[bucket as usize]
            )));
        }
        self.provided += 1;
        self.items.push_back((bucket, items));
        Ok(())
    }

    pub(crate) fn is_done(&self) -> bool {
        matches!(self.phase, SendPhase::Done) && self.out.is_empty()
    }

    pub(crate) fn expects_messages(&self) -> bool {
        match &self.phase {
            SendPhase::Running(run) => {
                let n = run.plan.active.len();
                run.answered + run.requests.len() < n || (self.share && run.results_in < n)
            }
            SendPhase::Done => false,
            _ => true,
        }
    }

    pub(crate) fn receive(&mut self, msg: &[u8]) -> Result<()> {
        let tag = *msg
            .first()
            .ok_or_else(|| Error::InvalidInput("empty message".into()))?;
        match (std::mem::replace(&mut self.phase, SendPhase::Done), tag) {
            (SendPhase::WaitJ1, J1) => self.on_j1(msg),
            (SendPhase::WaitJ3(setup), J3) => self.on_j3(*setup, msg),
            (SendPhase::Running(mut run), REQUEST) => {
                if run.answered + run.requests.len() >= run.plan.active.len() {
                    return Err(Error::InvalidInput(
                        "VOLE-PSI job: too many requests".into(),
                    ));
                }
                run.requests.push_back(msg.to_vec());
                self.phase = SendPhase::Running(run);
                Ok(())
            }
            (SendPhase::Running(mut run), RESULT) if self.share => {
                self.on_result(&mut run, msg)?;
                self.phase = if run.finished() {
                    SendPhase::Done
                } else {
                    SendPhase::Running(run)
                };
                Ok(())
            }
            (_, tag) => Err(state_error(&format!("unexpected message type {tag:#x}"))),
        }
    }

    fn on_j1(&mut self, msg: &[u8]) -> Result<()> {
        let mut r = Reader::new(msg, J1)?;
        let seed_r = r.take(16)?;
        let share = match r.u8()? {
            0 => false,
            1 => true,
            f => {
                return Err(Error::InvalidInput(format!(
                    "VOLE-PSI job: bad share flag {f}"
                )))
            }
        };
        if share != self.share {
            return Err(Error::InvalidInput(format!(
                "VOLE-PSI job: receiver {} the result, sender expects {}",
                if share { "shares" } else { "does not share" },
                if self.share { "it" } else { "nothing" },
            )));
        }
        let n = read_sizes(&mut r, self.sizes.len())?;
        let a = r.take(POINT_LEN)?;
        r.finish()?;
        let mut seed_s = [0u8; 16];
        let mut rng = csprng()?;
        rng.fill_bytes(&mut seed_s);
        let choices: Vec<bool> = (0..BASE_OTS)
            .map(|c| self.delta[c / 8] >> (c % 8) & 1 == 1)
            .collect();
        let (reply, keys) = base::receive(&mut rng, a, &choices)?;
        let plan = Plan::new(n, self.sizes.clone(), &self.cfg);

        let mut w = Writer::new(J2, 16 + 4 + 8 * self.sizes.len() + reply.len());
        w.bytes(&seed_s);
        write_sizes(&mut w, &self.sizes);
        w.bytes(&reply);
        self.out.push_back(w.finish());

        let session = session_seed(seed_r, &seed_s);
        if plan.iterations == 0 {
            self.phase = if plan.active.is_empty() {
                SendPhase::Done
            } else {
                unreachable!("active buckets need VOLE")
            };
            return Ok(());
        }
        self.phase = SendPhase::WaitJ3(Box::new(SendSetup {
            plan,
            session,
            keys,
        }));
        Ok(())
    }

    fn on_j3(&mut self, setup: SendSetup, msg: &[u8]) -> Result<()> {
        let count = self.cfg.base_cots();
        let mut r = Reader::new(msg, J3)?;
        let u = r.array(count, 16)?;
        r.finish()?;
        let u: Vec<[u8; 16]> = u.as_chunks::<16>().0.to_vec();
        let delta = self.delta;
        let q = self
            .exec
            .install(|| extension::send(&setup.keys, &delta, &u));
        let reserve = q[..self.cfg.pre.reserve()].to_vec();
        let SendSetup { plan, session, .. } = setup;
        self.phase = SendPhase::Running(Box::new(SendRun {
            plan,
            ferret: Some(FerretSender::new(
                self.cfg.pre,
                self.delta,
                reserve,
                session,
            )),
            iterations_sent: 0,
            vole: VecDeque::new(),
            requests: VecDeque::new(),
            answered: 0,
            perms: VecDeque::new(),
            results_in: 0,
        }));
        Ok(())
    }

    /// RESULT for the oldest answered bucket: matching positions in our
    /// shuffled reply, mapped back through the shuffle.
    fn on_result(&mut self, run: &mut SendRun, msg: &[u8]) -> Result<()> {
        let mut r = Reader::new(msg, RESULT)?;
        let bucket = r.u32()?;
        let (expected, perm) = run
            .perms
            .pop_front()
            .ok_or_else(|| Error::InvalidInput("VOLE-PSI job: unsolicited result".into()))?;
        if bucket != expected {
            return Err(Error::InvalidInput(format!(
                "VOLE-PSI job: result for bucket {bucket}, expected {expected}"
            )));
        }
        let positions = read_positions(&mut r, perm.len())?;
        r.finish()?;
        let mut own: Vec<usize> = positions.iter().map(|&p| perm[p]).collect();
        own.sort_unstable();
        self.results.push_back((bucket, own));
        run.results_in += 1;
        Ok(())
    }

    pub(crate) fn next_send(&mut self) -> Result<Option<Vec<u8>>> {
        if let Some(m) = self.out.pop_front() {
            return Ok(Some(m));
        }
        let SendPhase::Running(run) = &mut self.phase else {
            return Ok(None);
        };

        // 1. Answer the oldest request if we have its VOLE and items.
        if let Some(msg) = run.requests.front() {
            let pos = run.answered;
            let bucket = run.plan.active[pos];
            let rows = run.plan.rows[pos];
            while let Some((b, _)) = self.items.front() {
                if *b < bucket {
                    self.items.pop_front();
                } else {
                    break;
                }
            }
            let ready_items = matches!(self.items.front(), Some((b, _)) if *b == bucket);
            if ready_items && run.vole.len() >= rows {
                let msg = msg.clone();
                run.requests.pop_front();
                let (_, items) = self.items.pop_front().expect("checked");
                let b: Vec<Gf128> = run.vole.drain(..rows).collect();
                let t = run.plan.truncation(bucket);
                let delta = self.delta;
                let (reply, perm) = self
                    .exec
                    .install(|| bucket_reply(bucket, &items, &b, &delta, &msg, t))?;
                run.answered += 1;
                if self.share {
                    run.perms.push_back((bucket, perm));
                }
                if run.finished() {
                    self.phase = SendPhase::Done;
                }
                return Ok(Some(reply));
            }
        }

        // 2. Produce a Ferret iteration if the receiver's window needs it.
        let horizon = run.answered + WINDOW + 1;
        let needed = run.plan.demand(horizon);
        let produced_ahead = run.vole.len() + run.plan.demand(run.answered);
        if run.iterations_sent < run.plan.iterations && produced_ahead < needed {
            let it = run.iterations_sent as u64;
            let main = self.cfg.main;
            let f = run
                .ferret
                .as_mut()
                .expect("ferret runs while iterations remain");
            // 128 COTs → one VOLE element b, folded as they are produced.
            let (body, fresh) = self
                .exec
                .install(|| -> Result<_> { Ok(f.iterate(&mut csprng()?, main, field::combine)) })?;
            run.vole.extend(fresh);
            run.iterations_sent += 1;
            let mut w = Writer::new(ITERATION, 8 + body.len());
            w.u64(it as usize);
            w.bytes(&body);
            if run.iterations_sent == run.plan.iterations {
                run.ferret = None;
            }
            return Ok(Some(w.finish()));
        }
        Ok(None)
    }
}

/// Sender's work for one bucket: the reply, and the shuffle (`perm[k]` =
/// index of the item behind the `k`-th output).
fn bucket_reply(
    bucket: u32,
    items: &[Vec<u8>],
    b: &[Gf128],
    delta: &Gf128,
    msg: &[u8],
    t: usize,
) -> Result<(Vec<u8>, Vec<usize>)> {
    let mut r = Reader::new(msg, REQUEST)?;
    let got = r.u32()?;
    if got != bucket {
        return Err(Error::InvalidInput(format!(
            "VOLE-PSI job: request for bucket {got}, expected {bucket}"
        )));
    }
    let seed: [u8; 16] = r.take(16)?.try_into().expect("16");
    let size = r.u64()?;
    if size != b.len() {
        return Err(Error::InvalidInput(format!(
            "VOLE-PSI job: bucket {bucket} table has {size} rows, expected {}",
            b.len()
        )));
    }
    let masked = r.array(size, 16)?;
    r.finish()?;

    // K = b ⊕ a' ⊗ Δ = c ⊕ P ⊗ Δ.
    let k: Vec<Gf128> = masked
        .as_chunks::<16>()
        .0
        .par_iter()
        .zip(b.par_iter())
        .map(|(a, b)| field::add(b, &field::mul(a, delta)))
        .collect();
    let mut f = vec![0u8; items.len() * t];
    f.par_chunks_mut(t)
        .zip(items.par_iter())
        .for_each(|(out, y)| {
            let d = digest(y);
            let mut v = okvs::decode(&k, okvs::row(size, &seed, &d));
            field::add_assign(&mut v, &field::mul(&code(&d), delta));
            output(bucket, &d, &v, t, out);
            v.zeroize();
        });
    drop(k);
    let mut perm: Vec<usize> = (0..items.len()).collect();
    perm.shuffle(&mut csprng()?);
    let f: Vec<u8> = perm
        .iter()
        .flat_map(|&i| &f[i * t..(i + 1) * t])
        .copied()
        .collect();

    let mut w = Writer::new(REPLY, 4 + 1 + 8 + f.len());
    w.u32(bucket);
    w.u8(u8::try_from(t).expect("truncation length <= 32"));
    w.u64(items.len());
    w.bytes(&f);
    Ok((w.finish(), perm))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small (insecure) parameters so tests run in milliseconds.
    const TEST: FerretConfig = FerretConfig {
        pre: Params {
            n: 64 * 64,
            k: 300,
            t: 64,
            h: 6,
        },
        main: Params {
            n: 128 * 128,
            k: 1200,
            t: 128,
            h: 7,
        },
    };

    fn items(xs: impl IntoIterator<Item = String>) -> Vec<Vec<u8>> {
        xs.into_iter().map(String::into_bytes).collect()
    }

    /// Drive both parties in memory, delivering messages in a random
    /// interleaving to exercise the pipelining. Returns results by bucket.
    fn run(
        rx: Vec<Vec<Vec<u8>>>,
        sx: Vec<Vec<Vec<u8>>>,
        cfg: FerretConfig,
        seed: u64,
    ) -> Vec<Intersection> {
        run_with(rx, sx, cfg, seed, false).0
    }

    /// Like [`run`]; with `share`, also returns the sender's results.
    fn run_with(
        rx: Vec<Vec<Vec<u8>>>,
        sx: Vec<Vec<Vec<u8>>>,
        cfg: FerretConfig,
        seed: u64,
        share: bool,
    ) -> (Vec<Intersection>, Vec<Intersection>) {
        use rand::SeedableRng;
        let mut rng = rand::rngs::ChaCha20Rng::seed_from_u64(seed);
        let exec = Executor::default();
        let sizes = |x: &Vec<Vec<Vec<u8>>>| x.iter().map(Vec::len).collect();
        let mut r = VoleJobReceiver::new(sizes(&rx), exec.clone(), cfg, share).unwrap();
        let mut s = VoleJobSender::new(sizes(&sx), exec, cfg, share).unwrap();
        let (mut to_s, mut to_r) = (VecDeque::new(), VecDeque::new());
        let mut results = vec![None; rx.len()];
        let mut sender_results = vec![None; sx.len()];
        for _ in 0..100_000 {
            while let Need::Items(b) = r.need() {
                r.provide(b, rx[b as usize].clone()).unwrap();
            }
            while let Need::Items(b) = s.need() {
                s.provide(b, sx[b as usize].clone()).unwrap();
            }
            match rng.random_range(0..4) {
                0 => {
                    if let Some(m) = r.next_send().unwrap() {
                        to_s.push_back(m)
                    }
                }
                1 => {
                    if let Some(m) = s.next_send().unwrap() {
                        to_r.push_back(m)
                    }
                }
                2 => {
                    if let Some(m) = to_s.pop_front() {
                        s.receive(&m).unwrap()
                    }
                }
                _ => {
                    if let Some(m) = to_r.pop_front() {
                        r.receive(&m).unwrap()
                    }
                }
            }
            while let Some((b, res)) = r.take_result() {
                results[b as usize] = Some(res);
            }
            while let Some((b, res)) = s.take_result() {
                assert!(share, "sender result without sharing");
                sender_results[b as usize] = Some(res);
            }
            if r.is_done() && s.is_done() && to_s.is_empty() && to_r.is_empty() {
                assert!(!r.expects_messages() && !s.expects_messages());
                let flat = |v: Vec<Option<Intersection>>| {
                    v.into_iter().map(Option::unwrap_or_default).collect()
                };
                return (flat(results), flat(sender_results));
            }
        }
        panic!("job did not finish");
    }

    /// Sender-side indices of the intersection, per bucket.
    fn expected_sender(rx: &[Vec<Vec<u8>>], sx: &[Vec<Vec<u8>>]) -> Vec<Intersection> {
        expected(sx, rx)
    }

    #[test]
    fn shared_result() {
        let rx: Vec<_> = (0..5)
            .map(|b| items((0..300).map(|i| format!("{b}-{i}"))))
            .collect();
        let mut sx: Vec<_> = (0..5)
            .map(|b| items((150..500).map(|i| format!("{b}-{i}"))))
            .collect();
        sx[2].clear(); // a skipped bucket produces no result on either side
        for seed in 0..3 {
            let (r, s) = run_with(rx.clone(), sx.clone(), TEST, seed, true);
            assert_eq!(r, expected(&rx, &sx));
            assert_eq!(s, expected_sender(&rx, &sx));
        }
    }

    #[test]
    fn share_mismatch_is_rejected() {
        for (rs, ss) in [(true, false), (false, true)] {
            let mut r = VoleJobReceiver::new(vec![1], Executor::default(), TEST, rs).unwrap();
            let mut s = VoleJobSender::new(vec![1], Executor::default(), TEST, ss).unwrap();
            let j1 = r.next_send().unwrap().unwrap();
            assert!(matches!(s.receive(&j1), Err(Error::InvalidInput(_))));
        }
        // A RESULT the sender did not ask for is a protocol error.
        let mut s = VoleJobSender::new(vec![1], Executor::default(), TEST, false).unwrap();
        assert!(s.receive(&[RESULT, 0, 0, 0, 0]).is_err());
    }

    fn expected(rx: &[Vec<Vec<u8>>], sx: &[Vec<Vec<u8>>]) -> Vec<Intersection> {
        rx.iter()
            .zip(sx)
            .map(|(r, s)| (0..r.len()).filter(|&i| s.contains(&r[i])).collect())
            .collect()
    }

    #[test]
    fn single_bucket() {
        let rx = vec![items((0..300).map(|i| format!("id-{i}")))];
        let sx = vec![items((150..600).map(|i| format!("id-{i}")))];
        for seed in 0..5 {
            assert_eq!(run(rx.clone(), sx.clone(), TEST, seed), expected(&rx, &sx));
        }
    }

    #[test]
    fn many_buckets_spanning_iterations() {
        // Each bucket needs several iterations' worth of VOLE.
        let rx: Vec<_> = (0..7)
            .map(|b| items((0..400).map(|i| format!("{b}-{i}"))))
            .collect();
        let sx: Vec<_> = (0..7)
            .map(|b| items((200..700).map(|i| format!("{b}-{i}"))))
            .collect();
        for seed in 0..3 {
            assert_eq!(run(rx.clone(), sx.clone(), TEST, seed), expected(&rx, &sx));
        }
    }

    #[test]
    fn empty_buckets_are_skipped() {
        let rx = vec![
            vec![],
            items(["a".into(), "b".into()]),
            items(["c".into()]),
            vec![],
        ];
        let sx = vec![items(["a".into()]), items(["b".into()]), vec![], vec![]];
        assert_eq!(
            run(rx.clone(), sx.clone(), TEST, 1),
            vec![vec![], vec![1], vec![], vec![]]
        );
        // Nothing active at all: no Ferret, just the size exchange.
        let none = vec![vec![], vec![]];
        assert_eq!(run(none.clone(), none, TEST, 2), vec![vec![], vec![]]);
    }

    /// Step timings for one 10^6-item bucket with production parameters.
    /// `cargo test --release vole_job_timing -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn vole_job_timing() {
        let n = 1_000_000;
        let rx = items((0..n).map(|i| format!("1{i:010}")));
        let sx = items((n / 2..n / 2 + n).map(|i| format!("1{i:010}")));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(5)
            .build()
            .unwrap();
        pool.install(|| {
            let exec = Executor::default();
            let mut r = VoleJobReceiver::new(vec![n], exec.clone(), PRODUCTION, false).unwrap();
            let mut s = VoleJobSender::new(vec![n], exec, PRODUCTION, false).unwrap();
            r.provide(0, rx).unwrap();
            s.provide(0, sx).unwrap();
            let t = std::time::Instant::now();
            let lap = |what: &str, t: &mut std::time::Instant| {
                println!("{what:<28} {:>8.1?}", t.elapsed());
                *t = std::time::Instant::now();
            };
            let mut t = t;
            let j1 = r.next_send().unwrap().unwrap();
            s.receive(&j1).unwrap();
            let j2 = s.next_send().unwrap().unwrap();
            r.receive(&j2).unwrap();
            let j3 = r.next_send().unwrap().unwrap();
            s.receive(&j3).unwrap();
            lap("setup (base OT + IKNP)", &mut t);
            let mut its = 0;
            loop {
                match s.next_send().unwrap() {
                    Some(m) if m[0] == ITERATION => {
                        r.receive(&m).unwrap();
                        its += 1;
                    }
                    Some(_) => unreachable!(),
                    None => break,
                }
            }
            lap(&format!("ferret x{its} (both sides)"), &mut t);
            let req = r.next_send().unwrap().unwrap();
            lap("receiver request (OKVS)", &mut t);
            s.receive(&req).unwrap();
            let rep = s.next_send().unwrap().unwrap();
            lap("sender reply", &mut t);
            r.receive(&rep).unwrap();
            lap("receiver intersect", &mut t);
            assert_eq!(r.take_result().unwrap().1.len(), n / 2);
        });
    }

    #[test]
    fn plan_matches_on_both_sides() {
        let cfg = PRODUCTION;
        let elements = 10_000_000;
        let its = cfg.iterations_for(elements);
        let usable = FerretConfig::usable(cfg.pre, cfg.main)
            + (its - 1) * FerretConfig::usable(cfg.main, cfg.main);
        assert!(usable >= elements);
        assert!(usable - FerretConfig::usable(cfg.main, cfg.main) < elements);
        assert_eq!(cfg.iterations_for(0), 0);
        assert_eq!(cfg.iterations_for(1), 1);
    }

    #[test]
    fn rejects_bad_driver_calls() {
        let mut r = VoleJobReceiver::new(vec![2, 1], Executor::default(), TEST, false).unwrap();
        assert!(r.provide(1, vec![]).is_err()); // out of order
        assert!(r.provide(0, items(["a".into()])).is_err()); // wrong size
        assert!(VoleJobReceiver::new(vec![], Executor::default(), TEST, false).is_err());
        let mut s = VoleJobSender::new(vec![1], Executor::default(), TEST, false).unwrap();
        assert!(s.receive(&[REQUEST, 0]).is_err()); // before setup
        assert!(s.receive(&[]).is_err());
    }

    #[test]
    fn bucket_count_mismatch_is_rejected() {
        let mut r = VoleJobReceiver::new(vec![1, 1], Executor::default(), TEST, false).unwrap();
        let mut s = VoleJobSender::new(vec![1], Executor::default(), TEST, false).unwrap();
        let j1 = r.next_send().unwrap().unwrap();
        assert!(matches!(s.receive(&j1), Err(Error::InvalidInput(_))));
    }
}
