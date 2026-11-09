//! Curve-generic OPRF-PSI parties.
//!
//! ```text
//! Receiver (X, small)                          Sender (Y, large; key k)
//!   r ← random scalar
//!   q_i = H(x_i)^r
//!            ── msg1: [q_1 .. q_n] ──▶
//!                                              e_i = q_i^k          (order kept)
//!                                              f_j = T(F_k(y_j))    (sorted)
//!            ◀── msg2: [e_i], [f_j] ──
//!   F_k(x_i) = Fin(x_i, e_i^(1/r))
//!   x_i ∈ X ∩ Y  ⟺  T(F_k(x_i)) ∈ { f_j }
//! ```
//!
//! `F_k` is the 2HashDH OPRF of [`crate::primitives::oprf`] (exactly RFC
//! 9497's OPRF mode for Ristretto255 and P-256). Unlike the RFC, one blind
//! `r` covers a whole batch, so the receiver inverts once; the OPRF output
//! does not depend on the blind.
//!
//! `T` keeps the first `t` bytes, `t` as in ECDH-PSI
//! (`λ + log2 n + log2 m + log2 B` bits). The key `k` is fresh per session,
//! so the bound only has to cover this session's comparisons.
//!
//! Wire format (counts u64 big-endian, points compressed):
//!
//! - msg1: `0x11 ‖ n ‖ q_1 … q_n`
//! - msg2: `0x12 ‖ t (u8) ‖ n ‖ e_1 … e_n ‖ m ‖ f_1 … f_m`, the `f_j` in
//!   ascending byte order
//!
//! Sorted pseudorandom values carry no information about `Y`'s order, so
//! no shuffle is needed, and the receiver matches by one merge pass with
//! `O(n)` extra memory. The sender's `f_j` do not depend on msg1: it
//! computes them in the background from the moment it is created.
//!
//! Peer points are fully validated (`Group::decode`: on the curve, in the
//! prime-order subgroup, not the identity) on both sides. For FourQ this
//! costs a subgroup check per received point, i.e. on the `n` small-side
//! items only.

use std::sync::mpsc;

use rayon::prelude::*;
use zeroize::Zeroize;

use crate::algorithms::psi::common::{truncation_len, Reader, Writer};
use crate::algorithms::psi::Intersection;
use crate::exec::Executor;
use crate::primitives::oprf::{evaluate, finalize, hash_to_group, Suite, MAX_INPUT_LEN};
use crate::primitives::rand::csprng;
use crate::protocol::{Party, Step};
use crate::{Error, Result};

const MSG1: u8 = 0x11;
const MSG2: u8 = 0x12;

/// Largest item accepted: `Finalize` frames the input with a 2-byte length.
const MAX_ITEM_LEN: usize = MAX_INPUT_LEN;

fn check_items(items: &[Vec<u8>]) -> Result<()> {
    match items.iter().position(|x| x.len() > MAX_ITEM_LEN) {
        Some(i) => Err(Error::InvalidInput(format!(
            "OPRF-PSI: item {i} is longer than {MAX_ITEM_LEN} bytes"
        ))),
        None => Ok(()),
    }
}

fn state_error(what: &str) -> Error {
    Error::InvalidState(format!("OPRF-PSI: {what}"))
}

/// Bytes of each sender output kept before `t` is known. Prefixes of a
/// sorted list are still sorted, so the list is cut to `t` bytes once
/// msg1 arrives. Enough for `t` up to 128 bits, i.e. `n · m · B < 2^88`.
const TAG: usize = 16;

/// The sender's OPRF outputs `F_k(y_j)`, cut to [`TAG`] bytes and sorted.
/// Runs on an executor worker; must not block.
fn sender_tags<S: Suite>(items: Vec<Vec<u8>>, mut key: S::Scalar) -> Vec<[u8; TAG]> {
    let mut tags: Vec<[u8; TAG]> = items
        .par_iter()
        .map(|y| {
            let out = evaluate::<S>(y, &key);
            out[..TAG].try_into().expect("TAG <= NH")
        })
        .collect();
    key.zeroize();
    drop(items);
    tags.par_sort_unstable();
    tags
}

/// Indices `i` (ascending) whose tag in `ours` (unsorted, `t` bytes each)
/// occurs in `theirs` (sorted, `t` bytes each), by sorting `ours` and one
/// merge pass. Fails if `theirs` is not sorted.
fn merge_matches(ours: &[u8], theirs: &[u8], t: usize) -> Result<Intersection> {
    let mut mine: Vec<(&[u8], usize)> = ours.chunks_exact(t).zip(0..).collect();
    mine.par_sort_unstable();
    let mut out = Vec::new();
    let mut prev: Option<&[u8]> = None;
    let mut k = 0;
    for f in theirs.chunks_exact(t) {
        if prev.is_some_and(|p| p > f) {
            return Err(Error::InvalidInput(
                "OPRF-PSI: sender outputs are not sorted".into(),
            ));
        }
        prev = Some(f);
        while k < mine.len() && mine[k].0 < f {
            k += 1;
        }
        // Equal own tags (a hash collision between own items) all match.
        let mut j = k;
        while j < mine.len() && mine[j].0 == f {
            out.push(mine[j].1);
            j += 1;
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

enum ReceiverState {
    Start,
    WaitReply,
    Done,
}

/// Receiver: initiates and learns the intersection.
pub(crate) struct OprfReceiver<S: Suite> {
    items: Vec<Vec<u8>>,
    blind: S::Scalar,
    state: ReceiverState,
    exec: Executor,
    sessions: u32,
}

impl<S: Suite> OprfReceiver<S> {
    /// `sessions`: number of sessions (buckets) the job is split into; must
    /// match the sender's.
    pub(crate) fn new(items: Vec<Vec<u8>>, exec: Executor, sessions: u32) -> Result<Self> {
        check_items(&items)?;
        Ok(Self {
            blind: S::random_scalar(&mut csprng()?),
            items,
            state: ReceiverState::Start,
            exec,
            sessions,
        })
    }
}

impl<S: Suite> Drop for OprfReceiver<S> {
    fn drop(&mut self) {
        self.blind.zeroize();
    }
}

impl<S: Suite> Party for OprfReceiver<S> {
    type Output = Intersection;

    fn is_initiator(&self) -> bool {
        true
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<Intersection>> {
        match (
            std::mem::replace(&mut self.state, ReceiverState::Done),
            incoming,
        ) {
            (ReceiverState::Start, None) => {
                let (items, r) = (&self.items, &self.blind);
                let mut q = vec![0u8; items.len() * S::POINT_LEN];
                self.exec.install(|| {
                    q.par_chunks_mut(S::POINT_LEN)
                        .zip(items.par_iter())
                        .for_each(|(out, x)| S::encode(&S::mul(&hash_to_group::<S>(x), r), out));
                });
                let mut w = Writer::new(MSG1, 8 + q.len());
                w.u64(items.len());
                w.bytes(&q);
                self.state = ReceiverState::WaitReply;
                Ok(Step::Send(w.finish()))
            }
            (ReceiverState::WaitReply, Some(msg)) => {
                let n = self.items.len();
                let mut rd = Reader::new(msg, MSG2)?;
                let t = usize::from(rd.u8()?);
                if rd.u64()? != n {
                    return Err(Error::InvalidInput(
                        "OPRF-PSI: reply does not match our set size".into(),
                    ));
                }
                let e = rd.array(n, S::POINT_LEN)?;
                let m = rd.u64()?;
                let f = rd.array(m, t)?;
                rd.finish()?;
                let expected = truncation_len(n, m, self.sessions);
                if t != expected {
                    return Err(Error::InvalidInput(format!(
                        "OPRF-PSI: truncation length {t}, expected {expected} \
                         (do both parties use the same bucket count?)"
                    )));
                }
                let mut r_inv = S::invert(&self.blind);
                self.blind.zeroize();
                let items = &self.items;
                let result = self.exec.install(|| -> Result<Intersection> {
                    let mut ours = vec![0u8; n * t];
                    ours.par_chunks_mut(t)
                        .zip(e.par_chunks_exact(S::POINT_LEN))
                        .zip(items.par_iter())
                        .try_for_each(|((out, enc), x)| -> Result<()> {
                            let p = S::mul(&S::decode(enc)?, &r_inv);
                            out.copy_from_slice(&finalize::<S>(x, &p)[..t]);
                            Ok(())
                        })?;
                    merge_matches(&ours, f, t)
                });
                r_inv.zeroize();
                Ok(Step::Done {
                    send: None,
                    output: result?,
                })
            }
            (ReceiverState::Start, Some(_)) => Err(state_error("receiver speaks first")),
            (ReceiverState::WaitReply, None) => Err(state_error("waiting for the sender's reply")),
            (ReceiverState::Done, _) => Err(state_error("protocol already finished")),
        }
    }
}

enum SenderState {
    /// Own outputs being computed in the background.
    Start(mpsc::Receiver<Result<Vec<[u8; TAG]>>>),
    Done,
}

/// Sender: evaluates the OPRF for the receiver and learns nothing.
pub(crate) struct OprfSender<S: Suite> {
    key: S::Scalar,
    m: usize,
    state: SenderState,
    exec: Executor,
    sessions: u32,
}

impl<S: Suite> OprfSender<S> {
    /// Create the sender with a fresh key and start computing the OPRF
    /// outputs of its own items on `exec`.
    pub(crate) fn new(items: Vec<Vec<u8>>, exec: Executor, sessions: u32) -> Result<Self> {
        check_items(&items)?;
        let key = S::random_scalar(&mut csprng()?);
        let m = items.len();
        let bg_key = key.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        exec.spawn(move || {
            // The session may have been dropped; then nobody waits.
            let _ = tx.send(Ok(sender_tags::<S>(items, bg_key)));
        });
        Ok(Self {
            key,
            m,
            state: SenderState::Start(rx),
            exec,
            sessions,
        })
    }
}

impl<S: Suite> Drop for OprfSender<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<S: Suite> Party for OprfSender<S> {
    type Output = ();

    fn is_initiator(&self) -> bool {
        false
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<()>> {
        let (pending, msg) = match (
            std::mem::replace(&mut self.state, SenderState::Done),
            incoming,
        ) {
            (SenderState::Start(pending), Some(msg)) => (pending, msg),
            (state @ SenderState::Start(_), None) => {
                self.state = state;
                return Err(state_error("sender waits for the receiver's message"));
            }
            (SenderState::Done, _) => return Err(state_error("protocol already finished")),
        };
        let mut r = Reader::new(msg, MSG1)?;
        let n = r.u64()?;
        let q = r.array(n, S::POINT_LEN)?;
        r.finish()?;
        let t = truncation_len(n, self.m, self.sessions);
        if t > TAG {
            return Err(Error::InvalidInput(format!(
                "OPRF-PSI: sets too large for one session ({n} x {}), use buckets",
                self.m
            )));
        }

        // Evaluate first: if the background job is still running, the two
        // share the executor's workers.
        let key = &self.key;
        let mut out = Writer::new(MSG2, 1 + 16 + n * S::POINT_LEN + self.m * t);
        out.u8(u8::try_from(t).expect("t <= TAG"));
        out.u64(n);
        let mut e = vec![0u8; n * S::POINT_LEN];
        self.exec.install(|| {
            e.par_chunks_mut(S::POINT_LEN)
                .zip(q.par_chunks_exact(S::POINT_LEN))
                .try_for_each(|(dst, src)| -> Result<()> {
                    S::encode(&S::mul(&S::decode(src)?, key), dst);
                    Ok(())
                })
        })?;
        self.key.zeroize();
        out.bytes(&e);
        drop(e);

        // Blocking wait on the caller's thread, never on a worker (see
        // crate::exec).
        let tags = pending
            .recv()
            .map_err(|_| Error::OperationFailed("OPRF-PSI: precomputation aborted".into()))??;
        debug_assert_eq!(tags.len(), self.m);
        out.u64(tags.len());
        for tag in &tags {
            out.bytes(&tag[..t]);
        }
        Ok(Step::Done {
            send: Some(out.finish()),
            output: (),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ec::{FourQ, Ristretto255, Sm2, P256};

    fn items(xs: &[&str]) -> Vec<Vec<u8>> {
        xs.iter().map(|x| x.as_bytes().to_vec()).collect()
    }

    /// Both parties in memory: (receiver output, msg1, msg2).
    fn run<S: Suite>(rx: Vec<Vec<u8>>, sx: Vec<Vec<u8>>) -> (Intersection, Vec<u8>, Vec<u8>) {
        let mut r = OprfReceiver::<S>::new(rx, Executor::default(), 1).unwrap();
        let mut s = OprfSender::<S>::new(sx, Executor::default(), 1).unwrap();
        let Step::Send(m1) = r.step(None).unwrap() else {
            panic!("receiver sends msg1")
        };
        let Step::Done { send: Some(m2), .. } = s.step(Some(&m1)).unwrap() else {
            panic!("sender replies")
        };
        let Step::Done { send: None, output } = r.step(Some(&m2)).unwrap() else {
            panic!("receiver finishes")
        };
        (output, m1, m2)
    }

    fn check<S: Suite>() {
        let (out, m1, m2) = run::<S>(
            items(&["a", "b", "c", "d"]),
            items(&["x", "d", "b", "y", "z"]),
        );
        assert_eq!(out, vec![1, 3]);
        let t = truncation_len(4, 5, 1);
        assert_eq!(m1.len(), 1 + 8 + 4 * S::POINT_LEN);
        assert_eq!(m2.len(), 1 + 1 + 8 + 4 * S::POINT_LEN + 8 + 5 * t);
        // Sender outputs are sorted.
        let f = &m2[m2.len() - 5 * t..];
        let tags: Vec<&[u8]> = f.chunks_exact(t).collect();
        assert!(tags.windows(2).all(|w| w[0] <= w[1]));

        assert!(run::<S>(vec![], items(&["a"])).0.is_empty());
        assert!(run::<S>(items(&["a"]), vec![]).0.is_empty());
        assert!(run::<S>(vec![], vec![]).0.is_empty());
        assert_eq!(
            run::<S>(items(&["a", "b"]), items(&["b", "a"])).0,
            vec![0, 1]
        );
        assert_eq!(
            run::<S>(vec![vec![], vec![0, 255]], vec![vec![0, 255]]).0,
            vec![1]
        );
    }

    #[test]
    fn ristretto255() {
        check::<Ristretto255>();
    }

    #[test]
    fn p256() {
        check::<P256>();
    }

    #[test]
    fn sm2() {
        check::<Sm2>();
    }

    #[test]
    fn fourq() {
        check::<FourQ>();
    }

    /// The unbalanced shape: a few receiver items against many sender items.
    #[test]
    fn unbalanced_sets() {
        let rx: Vec<Vec<u8>> = (0..50)
            .map(|i| format!("id-{}", i * 97).into_bytes())
            .collect();
        let sx: Vec<Vec<u8>> = (0..20_000)
            .map(|i| format!("id-{i}").into_bytes())
            .collect();
        let (out, _, m2) = run::<Ristretto255>(rx, sx);
        // id-(97 i) < 20000  ⟺  i ≤ 206: all 50.
        assert_eq!(out, (0..50).collect::<Vec<_>>());
        // Sender side costs t bytes per item, not a point.
        let t = truncation_len(50, 20_000, 1);
        assert_eq!(m2.len(), 1 + 1 + 8 + 50 * 32 + 8 + 20_000 * t);
    }

    #[test]
    fn merge_matches_cases() {
        // Own tags unsorted, with a duplicate; theirs sorted.
        let ours = b"dd\0aa\0zz\0aa\0";
        let theirs = b"aa\0bb\0dd\0";
        assert_eq!(merge_matches(ours, theirs, 3).unwrap(), vec![0, 1, 3]);
        assert!(merge_matches(ours, b"", 3).unwrap().is_empty());
        assert!(merge_matches(b"", theirs, 3).unwrap().is_empty());
        // Unsorted sender list is rejected.
        assert!(merge_matches(ours, b"dd\0aa\0", 3).is_err());
    }

    #[test]
    fn single_thread_pool() {
        for wait_first in [false, true] {
            let exec = Executor::new(1).unwrap();
            let mut r = OprfReceiver::<Sm2>::new(items(&["a", "b"]), exec.clone(), 1).unwrap();
            let mut s = OprfSender::<Sm2>::new(items(&["b", "c"]), exec, 1).unwrap();
            if wait_first {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let Step::Send(m1) = r.step(None).unwrap() else {
                panic!()
            };
            let Step::Done { send: Some(m2), .. } = s.step(Some(&m1)).unwrap() else {
                panic!()
            };
            let Step::Done { output, .. } = r.step(Some(&m2)).unwrap() else {
                panic!()
            };
            assert_eq!(output, vec![1]);
        }
    }

    #[test]
    fn rejects_out_of_order_calls() {
        let mut r = OprfReceiver::<P256>::new(items(&["a"]), Executor::default(), 1).unwrap();
        assert!(matches!(r.step(Some(b"x")), Err(Error::InvalidState(_))));
        let mut r = OprfReceiver::<P256>::new(items(&["a"]), Executor::default(), 1).unwrap();
        r.step(None).unwrap();
        assert!(matches!(r.step(None), Err(Error::InvalidState(_))));
        let mut s = OprfSender::<P256>::new(items(&["a"]), Executor::default(), 1).unwrap();
        assert!(matches!(s.step(None), Err(Error::InvalidState(_))));
    }

    #[test]
    fn rejects_malformed_messages() {
        let new_s = || OprfSender::<P256>::new(items(&["a"]), Executor::default(), 1).unwrap();
        assert!(matches!(
            new_s().step(Some(b"")),
            Err(Error::InvalidInput(_))
        ));
        // An ECDH-PSI msg1 (tag 0x01) is not accepted.
        assert!(matches!(
            new_s().step(Some(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0])),
            Err(Error::InvalidInput(_))
        ));
        // Invalid point.
        let mut w = Writer::new(MSG1, 0);
        w.u64(1);
        w.bytes(&[0xff; 33]);
        assert!(matches!(
            new_s().step(Some(&w.finish())),
            Err(Error::InvalidInput(_))
        ));
        // Count overflow.
        let mut w = Writer::new(MSG1, 0);
        w.u64(usize::MAX);
        assert!(matches!(
            new_s().step(Some(&w.finish())),
            Err(Error::InvalidInput(_))
        ));

        // Reply tampering: wrong t, invalid point, unsorted outputs.
        let reply = || {
            let mut r =
                OprfReceiver::<P256>::new(items(&["a", "b"]), Executor::default(), 1).unwrap();
            let mut s =
                OprfSender::<P256>::new(items(&["a", "c", "d"]), Executor::default(), 1).unwrap();
            let Step::Send(m1) = r.step(None).unwrap() else {
                panic!()
            };
            let Step::Done { send: Some(m2), .. } = s.step(Some(&m1)).unwrap() else {
                panic!()
            };
            (r, m2)
        };
        let (mut r, mut m2) = reply();
        m2[1] += 1;
        assert!(matches!(r.step(Some(&m2)), Err(Error::InvalidInput(_))));
        let (mut r, mut m2) = reply();
        m2[1 + 1 + 8..1 + 1 + 8 + 33].fill(0xff);
        assert!(matches!(r.step(Some(&m2)), Err(Error::InvalidInput(_))));
        let (mut r, mut m2) = reply();
        let t = usize::from(m2[1]);
        let f = m2.len() - 3 * t;
        let (a, b) = m2[f..].split_at_mut(t);
        a.swap_with_slice(&mut b[..t]);
        if m2[f..f + t] != m2[f + t..f + 2 * t] {
            assert!(matches!(r.step(Some(&m2)), Err(Error::InvalidInput(_))));
        }
    }

    #[test]
    fn rejects_long_items() {
        let long = vec![vec![0u8; MAX_ITEM_LEN + 1]];
        assert!(OprfReceiver::<P256>::new(long.clone(), Executor::default(), 1).is_err());
        assert!(OprfSender::<P256>::new(long, Executor::default(), 1).is_err());
        let ok = vec![vec![7u8; MAX_ITEM_LEN]];
        assert_eq!(run::<P256>(ok.clone(), ok).0, vec![0]);
    }

    /// A session count mismatch changes `t` and is rejected.
    #[test]
    fn session_count_mismatch_is_rejected() {
        let xs: Vec<Vec<u8>> = (0..300).map(|i| format!("{i}").into_bytes()).collect();
        let mut r = OprfReceiver::<Ristretto255>::new(xs.clone(), Executor::default(), 1).unwrap();
        let mut s = OprfSender::<Ristretto255>::new(xs, Executor::default(), 1 << 16).unwrap();
        let Step::Send(m1) = r.step(None).unwrap() else {
            panic!()
        };
        let Step::Done { send: Some(m2), .. } = s.step(Some(&m1)).unwrap() else {
            panic!()
        };
        assert!(matches!(r.step(Some(&m2)), Err(Error::InvalidInput(_))));
    }
}
