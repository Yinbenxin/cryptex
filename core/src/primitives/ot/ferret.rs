//! Silent correlated OT, following Ferret (Yang, Weng, Lan, Zhang, Wang,
//! CCS 2020) as implemented in emp-ot: regular-noise primal LPN over GF(2)
//! with a local linear code, single-point COT from GGM trees, and
//! bootstrapping (each iteration reserves part of its output to seed the
//! next one).
//!
//! A COT with offset `Δ ∈ {0,1}^128` (held by the sender) gives the receiver
//! a choice bit `x` and a block `t`, and the sender `q = t ⊕ x·Δ`.
//!
//! One iteration with parameters `(n, k, t, h)` (`n = t · 2^h`) consumes a
//! reserve of `k + t·h` COTs and produces `n` new ones:
//!
//! 1. **SPCOT.** For each of the `t` blocks the sender expands a random GGM
//!    tree with `2^h` leaves `v_l`. The receiver's punctured index `α` is
//!    given by the choice bits of `h` reserved COTs (`α`'s bit at level `ℓ`
//!    is the *negated* choice bit), so no message flows from the receiver.
//!    For every level the sender sends the XOR of all left / right
//!    children, each masked with `H(q)` / `H(q ⊕ Δ)` of that level's COT;
//!    the receiver unmasks the off-path one and rebuilds every leaf but
//!    `v_α`. The sender also sends `Δ ⊕ ⊕_l v_l`, from which the receiver
//!    gets `v_α ⊕ Δ`. Result: the sender holds `v`, the receiver holds `v`
//!    with `v_α ⊕ Δ` at `α`, i.e. a COT whose choice vector is the unit
//!    vector `e_α`.
//! 2. **LPN.** With `u, r` the choice bits / blocks of the first `k` reserved
//!    COTs and a public matrix `A` with `D = 10` ones per column, output `i`
//!    is `x_i = e_i ⊕ ⊕_j u[A_j(i)]`, `t_i = spcot_i ⊕ ⊕_j r[A_j(i)]` (and
//!    the same XOR of `q`s on the sender's side). The choice bits `x` are
//!    pseudorandom to the sender under the LPN assumption.
//!
//! Only the sender sends during an iteration (`t · (32·h + 16)` bytes), so
//! iterations stream one way.
//!
//! Outputs are produced in work units of whole trees (about [`CHUNK`]
//! leaves): each unit expands its trees, applies LPN and hands every group
//! of 128 outputs to a caller-supplied map (for VOLE-PSI: fold into one
//! GF(2^128) element) while still in cache. The `n` raw COTs of an
//! iteration (170 MB for the main parameters) are never held at once; only
//! the next reserve is kept.

use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use rand::CryptoRng;
use rayon::prelude::*;
use zeroize::Zeroize;

use super::Block;
use crate::primitives::hash::sha256;
use crate::primitives::prg::expand_at;
use crate::{Error, Result};

/// Ones per column of the LPN matrix.
const D: usize = 10;

/// LPN and tree parameters of one iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Params {
    /// Outputs per iteration, `t · 2^h`.
    pub n: usize,
    /// LPN secret length.
    pub k: usize,
    /// Noise weight = number of trees.
    pub t: usize,
    /// Tree depth, `log2` of the block length.
    pub h: usize,
}

impl Params {
    /// COTs an iteration consumes.
    pub(crate) const fn reserve(&self) -> usize {
        self.k + self.t * self.h
    }

    /// Bytes the sender sends per iteration.
    pub(crate) const fn message_len(&self) -> usize {
        self.t * (32 * self.h + 16)
    }
}

/// emp-ot's setup iteration (`N_PRE_REG`, `K_PRE_REG`, `T_PRE_REG`,
/// `BIN_SZ_PRE_REG`), run once on COTs from IKNP.
pub(crate) const PRE: Params = Params {
    n: 649_728,
    k: 36_288,
    t: 1_269,
    h: 9,
};

/// emp-ot's main iteration (`N_REG`, `K_REG`, `T_REG`, `BIN_SZ_REG`).
pub(crate) const MAIN: Params = Params {
    n: 10_608_640,
    k: 588_160,
    t: 1_295,
    h: 13,
};

/// A batch of COTs on the receiver's side: choice bits and blocks.
#[derive(Default)]
pub(crate) struct ReceiverCots {
    pub bits: Vec<bool>,
    pub blocks: Vec<Block>,
}

impl Drop for ReceiverCots {
    fn drop(&mut self) {
        self.blocks.zeroize();
    }
}

/// The two fixed-key AES permutations used as the GGM length-doubling PRG:
/// `G(s) = (AES_k0(s) ⊕ s, AES_k1(s) ⊕ s)`.
struct Ggm([Aes128; 2]);

impl Ggm {
    fn new() -> Self {
        let k = sha256(&[b"CRYPTEX-FERRET-GGM-V1"]);
        let k0: [u8; 16] = k[..16].try_into().expect("16");
        let k1: [u8; 16] = k[16..].try_into().expect("16");
        Self([Aes128::new(&Array::from(k0)), Aes128::new(&Array::from(k1))])
    }

    /// Children of every node in `level` into `next` (`2 × level.len()`),
    /// left child of node `i` at `2i`. `aes` is scratch space of at least
    /// `level.len()` blocks.
    fn expand(&self, level: &[Block], next: &mut [Block], aes: &mut [AesBlock]) {
        let aes = &mut aes[..level.len()];
        for (side, cipher) in self.0.iter().enumerate() {
            for (a, s) in aes.iter_mut().zip(level) {
                *a = Array::from(*s);
            }
            cipher.encrypt_blocks(aes);
            for (i, (b, s)) in aes.iter().zip(level).enumerate() {
                let mut c: Block = (*b).into();
                xor(&mut c, s);
                next[2 * i + side] = c;
            }
        }
    }
}

type AesBlock = aes::Block;

#[inline]
fn xor(a: &mut Block, b: &Block) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

#[inline]
fn xored(a: &Block, b: &Block) -> Block {
    let mut c = *a;
    xor(&mut c, b);
    c
}

/// Correlation-robust hash for derandomizing COT number `index` of the job.
fn crh(index: u64, x: &Block) -> Block {
    let h = sha256(&[b"CRYPTEX-FERRET-CRH-V1", &index.to_le_bytes(), x]);
    h[..16].try_into().expect("16")
}

/// LPN matrix rows for outputs `[first, first + out.len())`: `D` indices in
/// `[0, k)` per output, from AES-CTR under the iteration's public seed.
fn lpn_indices(cipher: &Aes128, k: usize, first: usize, out: &mut [[u32; D]]) {
    // 40 bytes per output; 3 AES blocks (48 bytes) each to keep alignment.
    let mut buf = vec![0u8; out.len() * 48];
    expand_at(cipher, (first * 3) as u128, &mut buf);
    for (idx, chunk) in out.iter_mut().zip(buf.as_chunks::<48>().0) {
        for (j, w) in idx.iter_mut().enumerate() {
            let v = u32::from_le_bytes(chunk[4 * j..4 * j + 4].try_into().expect("4"));
            // Bias at most k / 2^32 (< 2^-12 for k ≤ 2^20), as in emp-ot.
            *w = v % k as u32;
        }
    }
}

/// Outputs per work unit: whole trees, about this many leaves, so a unit's
/// trees, LPN rows and outputs stay in cache and the full `n`-output
/// intermediate is never materialized.
const CHUNK: usize = 1 << 14;

/// Output layout of one iteration split into work units of whole trees.
#[derive(Clone, Copy)]
struct Layout {
    p: Params,
    /// Trees per unit.
    trees: usize,
    /// Outputs in 128-groups handed to the caller: `[0, usable)`.
    usable: usize,
    /// Start of the outputs kept as the next reserve: `[keep, n)`.
    keep: usize,
}

impl Layout {
    fn new(p: Params, next: Params) -> Self {
        let leaves = 1usize << p.h;
        let keep = p.n - next.reserve();
        Self {
            p,
            trees: (CHUNK / leaves).max(1),
            usable: keep / 128 * 128,
            keep,
        }
    }

    fn units(&self) -> usize {
        self.p.t.div_ceil(self.trees)
    }

    /// Trees `[first, end)` of unit `u`.
    fn trees_of(&self, u: usize) -> (usize, usize) {
        let first = u * self.trees;
        (first, (first + self.trees).min(self.p.t))
    }

    /// Output offset of unit `u`.
    fn offset(&self, u: usize) -> usize {
        (u * self.trees) << self.p.h
    }

    /// For a unit covering outputs `[off, off + len)`: the length of its
    /// prefix inside `[0, usable)` (a multiple of 128, since `off` is) and
    /// the range of its outputs inside `[keep, n)`, relative to `off`.
    fn split(&self, off: usize, len: usize) -> (usize, std::ops::Range<usize>) {
        let end = off + len;
        let groups = self.usable.clamp(off, end) - off;
        let tail = self.keep.clamp(off, end) - off..len;
        (groups, tail)
    }
}

/// Per-worker scratch: two tree levels, AES blocks and LPN rows.
struct Scratch {
    cur: Vec<Block>,
    next: Vec<Block>,
    aes: Vec<AesBlock>,
    idx: Vec<[u32; D]>,
    out: Vec<Block>,
}

impl Scratch {
    fn new(l: &Layout) -> Self {
        let leaves = 1usize << l.p.h;
        let len = l.trees * leaves;
        Self {
            cur: vec![[0u8; 16]; leaves],
            next: vec![[0u8; 16]; leaves],
            aes: vec![AesBlock::default(); leaves / 2],
            idx: vec![[0u32; D]; len],
            out: vec![[0u8; 16]; len],
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.cur.zeroize();
        self.next.zeroize();
        self.out.zeroize();
        for a in &mut self.aes {
            a.fill(0);
        }
    }
}

/// Public seed of the LPN matrix for `iteration`.
fn lpn_cipher(session: &[u8; 32], iteration: u64) -> Aes128 {
    let h = sha256(&[b"CRYPTEX-FERRET-LPN-V1", session, &iteration.to_le_bytes()]);
    Aes128::new(&Array::from(<[u8; 16]>::try_from(&h[..16]).expect("16")))
}

/// Sender of the silent COT: holds `Δ` and produces the stream.
pub(crate) struct FerretSender {
    params: Params,
    delta: Block,
    /// Reserve for the next iteration (`params.reserve()` blocks).
    reserve: Vec<Block>,
    session: [u8; 32],
    iteration: u64,
    /// Global COT counter, for CRH domain separation.
    counter: u64,
    ggm: Ggm,
}

impl Drop for FerretSender {
    fn drop(&mut self) {
        self.delta.zeroize();
        self.reserve.zeroize();
    }
}

/// Receiver of the silent COT.
pub(crate) struct FerretReceiver {
    params: Params,
    reserve: ReceiverCots,
    session: [u8; 32],
    iteration: u64,
    counter: u64,
    ggm: Ggm,
}

impl FerretSender {
    /// `reserve` must hold `params.reserve()` COTs.
    pub(crate) fn new(
        params: Params,
        delta: Block,
        reserve: Vec<Block>,
        session: [u8; 32],
    ) -> Self {
        assert_eq!(reserve.len(), params.reserve());
        Self {
            params,
            delta,
            reserve,
            session,
            iteration: 0,
            counter: 0,
            ggm: Ggm::new(),
        }
    }

    /// Run one iteration and switch to `next` for the following one.
    /// Returns the message for the receiver and `map` applied to every
    /// usable group of 128 consecutive new COT blocks `q`, in order; the
    /// last `next.reserve()` outputs become the next reserve.
    pub(crate) fn iterate<T: Send, R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        next: Params,
        map: impl Fn(&[Block; 128]) -> T + Sync,
    ) -> (Vec<u8>, Vec<T>) {
        let p = self.params;
        let l = Layout::new(p, next);
        let mut roots = vec![[0u8; 16]; p.t];
        for r in &mut roots {
            rng.fill_bytes(r);
        }
        let (r, tree_cots) = self.reserve.split_at(p.k);
        let delta = self.delta;
        let base = self.counter + p.k as u64;
        let ggm = &self.ggm;
        let cipher = lpn_cipher(&self.session, self.iteration);
        let tree_msg = 32 * p.h + 16;
        let leaves = 1usize << p.h;

        let parts: Vec<(Vec<u8>, Vec<T>, Vec<Block>)> = (0..l.units())
            .into_par_iter()
            .map_init(
                || Scratch::new(&l),
                |s, u| {
                    let (first, end) = l.trees_of(u);
                    let len = (end - first) * leaves;
                    let mut msg = vec![0u8; (end - first) * tree_msg];
                    for (i, j) in (first..end).enumerate() {
                        let cots = &tree_cots[j * p.h..(j + 1) * p.h];
                        let m = &mut msg[i * tree_msg..(i + 1) * tree_msg];
                        let index = base + (j * p.h) as u64;
                        sender_tree(ggm, p.h, roots[j], cots, &delta, index, m, s);
                        s.out[i * leaves..(i + 1) * leaves].copy_from_slice(&s.cur);
                    }
                    // LPN: q_i ^= XOR of D reserved blocks.
                    let off = l.offset(u);
                    let (out, idx) = (&mut s.out[..len], &mut s.idx[..len]);
                    lpn_indices(&cipher, p.k, off, idx);
                    for (v, ix) in out.iter_mut().zip(idx.iter()) {
                        for &a in ix {
                            xor(v, &r[a as usize]);
                        }
                    }
                    let (groups, tail) = l.split(off, len);
                    let mapped = out[..groups]
                        .as_chunks::<128>()
                        .0
                        .iter()
                        .map(&map)
                        .collect();
                    (msg, mapped, out[tail].to_vec())
                },
            )
            .collect();
        roots.zeroize();

        let mut msg = Vec::with_capacity(p.message_len());
        let mut mapped = Vec::with_capacity(l.usable / 128);
        let mut reserve = Vec::with_capacity(next.reserve());
        for (m, g, mut tail) in parts {
            msg.extend_from_slice(&m);
            mapped.extend(g);
            reserve.extend_from_slice(&tail);
            tail.zeroize();
        }
        debug_assert_eq!(reserve.len(), next.reserve());
        self.reserve.zeroize();
        self.reserve = reserve;
        self.counter += p.reserve() as u64;
        self.iteration += 1;
        self.params = next;
        (msg, mapped)
    }
}

/// Sender's GGM tree from `root`: leaves end up in `s.cur`; writes the
/// tree's message (`32·h + 16` bytes) to `m`. `cots` are the tree's `h`
/// reserved COTs, numbered from `index` for the CRH.
#[allow(clippy::too_many_arguments)]
fn sender_tree(
    ggm: &Ggm,
    h: usize,
    root: Block,
    cots: &[Block],
    delta: &Block,
    index: u64,
    m: &mut [u8],
    s: &mut Scratch,
) {
    s.cur[0] = root;
    for (l, cq) in cots.iter().enumerate().take(h) {
        let width = 1usize << l;
        ggm.expand(&s.cur[..width], &mut s.next[..2 * width], &mut s.aes);
        let mut sums = [[0u8; 16]; 2];
        for (i, c) in s.next[..2 * width].iter().enumerate() {
            xor(&mut sums[i & 1], c);
        }
        let idx = index + l as u64;
        let m0 = xored(&sums[0], &crh(idx, cq));
        let m1 = xored(&sums[1], &crh(idx, &xored(cq, delta)));
        m[32 * l..32 * l + 16].copy_from_slice(&m0);
        m[32 * l + 16..32 * l + 32].copy_from_slice(&m1);
        std::mem::swap(&mut s.cur, &mut s.next);
    }
    let mut corr = *delta;
    for v in &s.cur {
        xor(&mut corr, v);
    }
    m[32 * h..].copy_from_slice(&corr);
}

impl FerretReceiver {
    /// `reserve` must hold `params.reserve()` COTs.
    pub(crate) fn new(params: Params, reserve: ReceiverCots, session: [u8; 32]) -> Self {
        assert_eq!(reserve.bits.len(), params.reserve());
        assert_eq!(reserve.blocks.len(), params.reserve());
        Self {
            params,
            reserve,
            session,
            iteration: 0,
            counter: 0,
            ggm: Ggm::new(),
        }
    }

    /// Process one iteration's message and switch to `next`. Returns `map`
    /// applied to every usable group of 128 consecutive new COTs (choice
    /// bits, blocks), in order; the last `next.reserve()` outputs become
    /// the next reserve.
    pub(crate) fn iterate<T: Send>(
        &mut self,
        msg: &[u8],
        next: Params,
        map: impl Fn(&[bool], &[Block; 128]) -> T + Sync,
    ) -> Result<Vec<T>> {
        let p = self.params;
        if msg.len() != p.message_len() {
            return Err(Error::InvalidInput(
                "Ferret: wrong iteration message length".into(),
            ));
        }
        let l = Layout::new(p, next);
        let (ru, tree_bits) = self.reserve.bits.split_at(p.k);
        let (rb, tree_blocks) = self.reserve.blocks.split_at(p.k);
        let base = self.counter + p.k as u64;
        let ggm = &self.ggm;
        let cipher = lpn_cipher(&self.session, self.iteration);
        let tree_msg = 32 * p.h + 16;
        let leaves = 1usize << p.h;

        let parts: Vec<(Vec<T>, Vec<bool>, Vec<Block>)> = (0..l.units())
            .into_par_iter()
            .map_init(
                || (Scratch::new(&l), vec![false; l.trees * leaves]),
                |(s, x), u| {
                    let (first, end) = l.trees_of(u);
                    let len = (end - first) * leaves;
                    let x = &mut x[..len];
                    x.fill(false);
                    for (i, j) in (first..end).enumerate() {
                        let r = j * p.h..(j + 1) * p.h;
                        let m = &msg[j * tree_msg..(j + 1) * tree_msg];
                        let a = receiver_tree(
                            ggm,
                            p.h,
                            &tree_bits[r.clone()],
                            &tree_blocks[r],
                            base + (j * p.h) as u64,
                            m,
                            s,
                        );
                        s.out[i * leaves..(i + 1) * leaves].copy_from_slice(&s.cur);
                        x[i * leaves + a] = true;
                    }
                    // LPN: x_i ^= XOR of D reserved bits, t_i likewise.
                    let off = l.offset(u);
                    let (out, idx) = (&mut s.out[..len], &mut s.idx[..len]);
                    lpn_indices(&cipher, p.k, off, idx);
                    for ((v, b), ix) in out.iter_mut().zip(x.iter_mut()).zip(idx.iter()) {
                        for &a in ix {
                            xor(v, &rb[a as usize]);
                            *b ^= ru[a as usize];
                        }
                    }
                    let (groups, tail) = l.split(off, len);
                    let mapped = out[..groups]
                        .as_chunks::<128>()
                        .0
                        .iter()
                        .zip(x[..groups].as_chunks::<128>().0)
                        .map(|(t, b)| map(b, t))
                        .collect();
                    (mapped, x[tail.clone()].to_vec(), out[tail].to_vec())
                },
            )
            .collect();

        let mut mapped = Vec::with_capacity(l.usable / 128);
        let mut reserve = ReceiverCots {
            bits: Vec::with_capacity(next.reserve()),
            blocks: Vec::with_capacity(next.reserve()),
        };
        for (g, bits, mut blocks) in parts {
            mapped.extend(g);
            reserve.bits.extend_from_slice(&bits);
            reserve.blocks.extend_from_slice(&blocks);
            blocks.zeroize();
        }
        debug_assert_eq!(reserve.blocks.len(), next.reserve());
        self.reserve = reserve;
        self.counter += p.reserve() as u64;
        self.iteration += 1;
        self.params = next;
        Ok(mapped)
    }
}

/// Receiver's punctured GGM tree: leaves end up in `s.cur`, with
/// `v_α ⊕ Δ` at the punctured index `α`, which is returned. `bits` and
/// `blocks` are the tree's `h` reserved COTs, numbered from `index`.
fn receiver_tree(
    ggm: &Ggm,
    h: usize,
    bits: &[bool],
    blocks: &[Block],
    index: u64,
    m: &[u8],
    s: &mut Scratch,
) -> usize {
    // Path bits, most significant first: α_ℓ = ¬x_ℓ.
    let mut a = 0usize;
    s.cur[0] = [0u8; 16];
    for l in 0..h {
        let x = bits[l];
        let path = usize::from(!x);
        let width = 1usize << l;
        let next = &mut s.next[..2 * width];
        // Children of all known nodes; the unknown parent at index `a`
        // gives two garbage children, fixed below.
        ggm.expand(&s.cur[..width], next, &mut s.aes);
        let off = 2 * a + (1 - path);
        let on = 2 * a + path;
        let side = usize::from(x); // = 1 - path
        let mo: Block = m[32 * l + 16 * side..32 * l + 16 * side + 16]
            .try_into()
            .expect("16");
        let mut sibling = xored(&mo, &crh(index + l as u64, &blocks[l]));
        for (i, c) in next.iter().enumerate() {
            if i & 1 == side && i != off {
                xor(&mut sibling, c);
            }
        }
        next[off] = sibling;
        next[on] = [0u8; 16];
        a = on;
        std::mem::swap(&mut s.cur, &mut s.next);
    }
    let mut va: Block = m[32 * h..].try_into().expect("16");
    for (i, v) in s.cur.iter().enumerate() {
        if i != a {
            xor(&mut va, v);
        }
    }
    s.cur[a] = va; // = v_α ⊕ Δ
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::rand::csprng;
    use rand::{Rng, RngExt};

    /// Tiny parameter sets for tests (not secure): setup, then main.
    const TINY: Params = Params {
        n: 16 * 32,
        k: 60,
        t: 16,
        h: 5,
    };
    const TINY_MAIN: Params = Params {
        n: 32 * 64,
        k: 200,
        t: 32,
        h: 6,
    };

    /// Random COTs with offset `delta`, as a trusted dealer would give.
    fn dealer(rng: &mut impl Rng, delta: &Block, n: usize) -> (ReceiverCots, Vec<Block>) {
        let mut r = ReceiverCots::default();
        let mut s = Vec::new();
        for _ in 0..n {
            let mut t = [0u8; 16];
            rng.fill_bytes(&mut t);
            let x = rng.random::<bool>();
            r.bits.push(x);
            r.blocks.push(t);
            s.push(if x { xored(&t, delta) } else { t });
        }
        (r, s)
    }

    fn check_cots(delta: &Block, r: &ReceiverCots, q: &[Block]) {
        assert_eq!(r.bits.len(), q.len());
        for (i, qi) in q.iter().enumerate() {
            let expect = if r.bits[i] {
                xored(&r.blocks[i], delta)
            } else {
                r.blocks[i]
            };
            assert_eq!(*qi, expect, "COT {i}");
        }
    }

    fn run(params: [Params; 3], iterations: usize) {
        let mut rng = csprng().unwrap();
        let mut delta = [0u8; 16];
        rng.fill_bytes(&mut delta);
        let (rr, sr) = dealer(&mut rng, &delta, params[0].reserve());
        let session = [7u8; 32];
        let mut s = FerretSender::new(params[0], delta, sr, session);
        let mut r = FerretReceiver::new(params[0], rr, session);
        let mut ones = 0usize;
        let mut total = 0usize;
        for it in 0..iterations {
            let cur = params[it.min(2)];
            let next = params[(it + 1).min(2)];
            let (msg, q) = s.iterate(&mut rng, next, |g| g.to_vec());
            assert_eq!(msg.len(), cur.message_len());
            let groups = r
                .iterate(&msg, next, |b, t| (b.to_vec(), t.to_vec()))
                .unwrap();
            // Usable outputs: whole 128-groups before the next reserve.
            assert_eq!(groups.len(), (cur.n - next.reserve()) / 128);
            let q: Vec<Block> = q.concat();
            let cots = ReceiverCots {
                bits: groups.iter().flat_map(|g| g.0.clone()).collect(),
                blocks: groups.iter().flat_map(|g| g.1.clone()).collect(),
            };
            check_cots(&delta, &cots, &q);
            // The next reserve is a valid COT batch as well.
            check_cots(&delta, &r.reserve, &s.reserve);
            assert_eq!(s.reserve.len(), next.reserve());
            ones += cots.bits.iter().filter(|&&b| b).count();
            total += cots.bits.len();
        }
        // Choice bits look balanced.
        let ratio = ones as f64 / total as f64;
        assert!((0.4..0.6).contains(&ratio), "ratio {ratio}");
    }

    #[test]
    fn tiny_iterations_bootstrap() {
        // Each iteration's output must cover the next reserve.
        assert!(TINY.n >= TINY_MAIN.reserve());
        assert!(TINY_MAIN.n > TINY_MAIN.reserve());
        run([TINY, TINY_MAIN, TINY_MAIN], 6);
    }

    #[test]
    fn rejects_bad_message_length() {
        let mut rng = csprng().unwrap();
        let delta = [3u8; 16];
        let (rr, _) = dealer(&mut rng, &delta, TINY.reserve());
        let mut r = FerretReceiver::new(TINY, rr, [0; 32]);
        assert!(r
            .iterate(&vec![0u8; TINY.message_len() - 1], TINY_MAIN, |_, _| ())
            .is_err());
    }

    #[test]
    fn production_params_are_consistent() {
        for p in [PRE, MAIN] {
            assert_eq!(p.n, p.t << p.h);
            assert!(p.k < 1 << 20);
        }
        // Setup output covers the main reserve; main output covers itself.
        assert!(PRE.n >= MAIN.reserve());
        assert!(MAIN.n > MAIN.reserve());
        assert_eq!(MAIN.message_len(), 1295 * (32 * 13 + 16));
    }

    /// Time per main iteration on 5 threads. Run with
    /// `cargo test --release ferret_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn ferret_timing() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(5)
            .build()
            .unwrap();
        pool.install(|| {
            let mut rng = csprng().unwrap();
            let delta = [9u8; 16];
            let (rr, sr) = dealer(&mut rng, &delta, MAIN.reserve());
            let mut s = FerretSender::new(MAIN, delta, sr, [1; 32]);
            let mut r = FerretReceiver::new(MAIN, rr, [1; 32]);
            for _ in 0..3 {
                // Same output folding as VOLE-PSI: 128 COTs per element.
                let t = std::time::Instant::now();
                let (msg, q) = s.iterate(&mut rng, MAIN, crate::primitives::field::combine);
                let ts = t.elapsed();
                let t = std::time::Instant::now();
                let v = r
                    .iterate(&msg, MAIN, |b, t| {
                        (
                            crate::primitives::field::pack_bits(b),
                            crate::primitives::field::combine(t),
                        )
                    })
                    .unwrap();
                let tr = t.elapsed();
                let cots = 128 * q.len();
                println!(
                    "sender {ts:?}  receiver {tr:?}  ({cots} COTs, {:.1} M COT/s per side)",
                    cots as f64 / ts.as_secs_f64().max(tr.as_secs_f64()) / 1e6
                );
                drop(v);
            }
        });
    }

    /// One real setup + main iteration; slow in debug builds. Run with
    /// `cargo test --release ferret_production -- --ignored`.
    #[test]
    #[ignore]
    fn ferret_production() {
        run([PRE, MAIN, MAIN], 2);
    }

    /// Pins the messages and outputs of two iterations from a fixed seed,
    /// so that refactorings cannot silently change the wire format.
    /// Digest of (message, sender groups, receiver groups, choice bits) per
    /// iteration; the values were recorded with the original, unchunked
    /// implementation.
    #[test]
    fn known_answer() {
        use rand::SeedableRng;
        let cases = [
            (PRE, MAIN, [0xdb, 0xb5, 0xa7, 0x51, 0xe1, 0xc5, 0x8d, 0x08]),
            (
                TINY,
                TINY_MAIN,
                [0xec, 0x68, 0x09, 0x4b, 0x95, 0x21, 0xa4, 0xd2],
            ),
        ];
        for (p0, p1, expected) in cases {
            let mut rng = rand::rngs::ChaCha20Rng::seed_from_u64(42);
            let delta: Block = rng.random();
            let mut rr = ReceiverCots::default();
            let mut sr = Vec::new();
            for _ in 0..p0.reserve() {
                let t: Block = rng.random();
                let x = rng.random::<bool>();
                rr.bits.push(x);
                rr.blocks.push(t);
                sr.push(if x { xored(&t, &delta) } else { t });
            }
            let mut s = FerretSender::new(p0, delta, sr, [5; 32]);
            let mut r = FerretReceiver::new(p0, rr, [5; 32]);
            let mut acc = Vec::new();
            for _ in 0..2 {
                let (msg, q) = s.iterate(&mut rng, p1, |g| g.to_vec());
                let g = r
                    .iterate(&msg, p1, |b, t| (b.to_vec(), t.to_vec()))
                    .unwrap();
                let q: Vec<Block> = q.concat();
                let c = ReceiverCots {
                    bits: g.iter().flat_map(|x| x.0.clone()).collect(),
                    blocks: g.iter().flat_map(|x| x.1.clone()).collect(),
                };
                acc.extend(sha256(&[&msg]));
                acc.extend(sha256(&[q.as_flattened()]));
                acc.extend(sha256(&[c.blocks.as_flattened()]));
                let bits: Vec<u8> = c.bits.iter().map(|&b| b as u8).collect();
                acc.extend(sha256(&[&bits]));
                let _ = rng.next_u32();
            }
            assert_eq!(sha256(&[&acc])[..8], expected, "{p0:?}");
        }
    }
}
