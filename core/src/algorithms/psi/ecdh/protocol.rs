//! Curve-generic ECDH-PSI parties.
//!
//! ```text
//! Receiver (X, a)                              Sender (Y, b)
//!   u_i = H(x_i)^a
//!            ── msg1: [u_1 .. u_n] ──▶
//!                                              v_i = u_i^b        (order kept)
//!                                              w_j = H(y_j)^b     (shuffled)
//!            ◀── msg2: [T(v_i)], [w_j] ──
//!   x_i ∈ X ∩ Y  ⟺  T(v_i) ∈ { T(w_j^a) }
//!            ── msg3: positions k of matching w_k ──▶  (only when sharing)
//! ```
//!
//! Wire format (counts are u64 big-endian, points use the group's
//! compressed encoding):
//!
//! - msg1: `0x01 ‖ share ‖ n ‖ u_1 … u_n`, where `share` (u8) is 1 when the
//!   receiver will share the result with the sender
//! - msg2: `0x02 ‖ t ‖ n ‖ T(v_1) … T(v_n) ‖ m ‖ w_1 … w_m`, where `t` (u8)
//!   is the truncation length in bytes
//! - msg3 (sharing only): `0x03 ‖ k ‖ p_1 … p_k`, the ascending positions
//!   in the `w` block that matched, u32 each (u64 if `m` ≥ 2^32). The
//!   sender maps them back through its shuffle to its own item indices.
//!
//! Sharing is a semi-honest feature: the sender trusts the receiver to
//! report the matches correctly. Both parties must choose the same
//! setting; the sender rejects a msg1 whose flag differs from its own.
//!
//! The sender's `w_j` do not depend on msg1, so the sender starts computing
//! them in the background as soon as it is created. With the parties on
//! separate machines this overlaps with the receiver's first step and the
//! transfer of msg1; on receipt of msg1 only the `v_i` are left to compute.

use std::sync::mpsc;

use rand::seq::SliceRandom;
use rayon::prelude::*;
use zeroize::Zeroize;

use crate::algorithms::psi::common::{
    intersect, intersect_both, read_positions, truncation_len, write_positions, Reader, Writer,
};
use crate::algorithms::psi::Intersection;
use crate::exec::Executor;
use crate::primitives::ec::Group;
use crate::primitives::rand::csprng;
use crate::protocol::{Party, Step};
use crate::{Error, Result};

const MSG1: u8 = 0x01;
const MSG2: u8 = 0x02;
const MSG3: u8 = 0x03;

/// Protocol-level domain separation: hash-to-curve DST is
/// `DST_PREFIX ‖ suite ID`, the truncation hash is keyed with `DST_T`.
const DST_PREFIX: &[u8] = b"CRYPTEX-ECDH-PSI-V1-";
const DST_T: &[u8] = b"CRYPTEX-ECDH-PSI-V1-T";

fn hash_items<G: Group>(items: &[Vec<u8>]) -> Vec<G::Point> {
    items.par_iter().map(|x| hash_item::<G>(x)).collect()
}

fn hash_item<G: Group>(x: &[u8]) -> G::Point {
    G::hash_to_group(x, &[DST_PREFIX, G::SUITE_ID])
}

/// `p_i^k` for each point, encoded into one buffer.
fn mul_encode<G: Group>(points: &[G::Point], k: &G::Scalar) -> Vec<u8> {
    let mut out = vec![0u8; points.len() * G::POINT_LEN];
    out.par_chunks_mut(G::POINT_LEN)
        .zip(points.par_iter())
        .for_each(|(buf, p)| G::encode(&G::mul(p, k), buf));
    out
}

/// Decode every point in `buf`, then `T(p^k)` for each, into one buffer.
fn mul_truncate<G: Group>(buf: &[u8], k: &G::Scalar, t: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; buf.len() / G::POINT_LEN * t];
    out.par_chunks_mut(t)
        .zip(buf.par_chunks_exact(G::POINT_LEN))
        .try_for_each(|(dst, src)| -> Result<()> {
            // For groups with a cofactor this is k·h·P (see Group::decode_mul);
            // every comparison value passes through exactly one decode_mul on
            // each side, so both parties get the same factor.
            let p = G::decode_mul(src, k)?;
            let mut enc = [0u8; 64];
            let enc = &mut enc[..G::POINT_LEN];
            G::encode(&p, enc);
            dst.copy_from_slice(&G::hash(&[DST_T, enc])[..t]);
            Ok(())
        })?;
    Ok(out)
}

fn state_error(what: &str) -> Error {
    Error::InvalidState(format!("ECDH-PSI: {what}"))
}

enum ReceiverState {
    Start(Vec<Vec<u8>>),
    WaitReply { n: usize },
    Done,
}

/// Receiver: initiates and learns the intersection.
pub(crate) struct EcdhReceiver<G: Group> {
    key: G::Scalar,
    state: ReceiverState,
    exec: Executor,
    sessions: u32,
    /// Send the matching positions back to the sender (msg3).
    share: bool,
}

impl<G: Group> EcdhReceiver<G> {
    /// `sessions`: how many sessions (buckets) share the false-positive
    /// budget; must match the sender's. `share`: also give the sender the
    /// result; must match the sender's setting.
    pub(crate) fn new(
        items: Vec<Vec<u8>>,
        exec: Executor,
        sessions: u32,
        share: bool,
    ) -> Result<Self> {
        let key = G::random_scalar(&mut csprng()?);
        Ok(Self {
            key,
            state: ReceiverState::Start(items),
            exec,
            sessions,
            share,
        })
    }
}

impl<G: Group> Drop for EcdhReceiver<G> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<G: Group> Party for EcdhReceiver<G> {
    type Output = Intersection;

    fn is_initiator(&self) -> bool {
        true
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<Intersection>> {
        match (
            std::mem::replace(&mut self.state, ReceiverState::Done),
            incoming,
        ) {
            (ReceiverState::Start(items), None) => {
                let n = items.len();
                let key = &self.key;
                let points = self
                    .exec
                    .install(|| mul_encode::<G>(&hash_items::<G>(&items), key));
                let mut w = Writer::new(MSG1, 1 + 8 + points.len());
                w.u8(u8::from(self.share));
                w.u64(n);
                w.bytes(&points);
                self.state = ReceiverState::WaitReply { n };
                Ok(Step::Send(w.finish()))
            }
            (ReceiverState::WaitReply { n }, Some(msg)) => {
                let mut r = Reader::new(msg, MSG2)?;
                let t = usize::from(r.u8()?);
                if r.u64()? != n {
                    return Err(Error::InvalidInput(
                        "ECDH-PSI: reply does not match our set size".into(),
                    ));
                }
                let v = r.array(n, t)?;
                let m = r.u64()?;
                let w = r.array(m, G::POINT_LEN)?;
                r.finish()?;
                let expected = truncation_len(n, m, self.sessions);
                if t != expected {
                    return Err(Error::InvalidInput(format!(
                        "ECDH-PSI: truncation length {t}, expected {expected} \
                         (do both parties use the same bucket count?)"
                    )));
                }
                let key = &self.key;
                let t_w = self.exec.install(|| mul_truncate::<G>(w, key, t))?;
                self.key.zeroize();
                if !self.share {
                    return Ok(Step::Done {
                        send: None,
                        output: intersect(v, &t_w, t),
                    });
                }
                let (output, positions) = intersect_both(v, &t_w, t);
                let mut w3 = Writer::new(MSG3, 8 + 4 * positions.len());
                write_positions(&mut w3, &positions, m);
                Ok(Step::Done {
                    send: Some(w3.finish()),
                    output,
                })
            }
            (ReceiverState::Start(_), Some(_)) => Err(state_error("receiver speaks first")),
            (ReceiverState::WaitReply { .. }, None) => {
                Err(state_error("waiting for the sender's reply"))
            }
            (ReceiverState::Done, _) => Err(state_error("protocol already finished")),
        }
    }
}

/// The sender's own encoded, shuffled points `w_j = H(y_j)^b`.
struct Precomputed {
    m: usize,
    w: Vec<u8>,
    /// `perm[j]`: index of the item behind `w_j`; kept only when sharing.
    perm: Option<Vec<usize>>,
}

/// Compute `w_j`: hash, shuffle, blind. Runs on an executor worker; must not
/// block.
fn precompute<G: Group>(
    items: Vec<Vec<u8>>,
    mut key: G::Scalar,
    share: bool,
) -> Result<Precomputed> {
    let m = items.len();
    // Shuffle so the receiver cannot tell which of our items matched.
    let mut perm: Vec<usize> = (0..m).collect();
    perm.shuffle(&mut csprng()?);
    let hashed: Vec<G::Point> = perm
        .par_iter()
        .map(|&i| hash_item::<G>(&items[i]))
        .collect();
    drop(items);
    let w = mul_encode::<G>(&hashed, &key);
    key.zeroize();
    Ok(Precomputed {
        m,
        w,
        perm: share.then_some(perm),
    })
}

enum SenderState {
    /// Background precomputation running; its result arrives on the channel.
    Start(mpsc::Receiver<Result<Precomputed>>),
    /// msg2 sent; waiting for the matching positions (sharing only).
    WaitResult {
        perm: Vec<usize>,
    },
    Done,
}

/// Sender: answers the receiver's message. Learns nothing, or the
/// intersection when the receiver shares it.
pub(crate) struct EcdhSender<G: Group> {
    key: G::Scalar,
    /// Own set size, known before the precomputation finishes.
    m: usize,
    state: SenderState,
    exec: Executor,
    sessions: u32,
    share: bool,
}

impl<G: Group> EcdhSender<G> {
    /// Create the sender and immediately start precomputing its own points
    /// on `exec`. `share`: expect the result from the receiver; must match
    /// the receiver's setting.
    pub(crate) fn new(
        items: Vec<Vec<u8>>,
        exec: Executor,
        sessions: u32,
        share: bool,
    ) -> Result<Self> {
        let key = G::random_scalar(&mut csprng()?);
        let m = items.len();
        let bg_key = key.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        exec.spawn(move || {
            // The receiver is gone if the session was dropped; nothing to do.
            let _ = tx.send(precompute::<G>(items, bg_key, share));
        });
        Ok(Self {
            key,
            m,
            state: SenderState::Start(rx),
            exec,
            sessions,
            share,
        })
    }

    /// msg3: matching positions in the shuffled `w` block → own indices.
    fn on_result(&self, perm: &[usize], msg: &[u8]) -> Result<Intersection> {
        let mut r = Reader::new(msg, MSG3)?;
        let positions = read_positions(&mut r, perm.len())?;
        r.finish()?;
        let mut out: Vec<usize> = positions.iter().map(|&p| perm[p]).collect();
        out.sort_unstable();
        Ok(out)
    }
}

impl<G: Group> Drop for EcdhSender<G> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<G: Group> Party for EcdhSender<G> {
    /// The intersection as indices into own items when the receiver shares
    /// it, else `None`.
    type Output = Option<Intersection>;

    fn is_initiator(&self) -> bool {
        false
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<Self::Output>> {
        let (pending, msg) = match (
            std::mem::replace(&mut self.state, SenderState::Done),
            incoming,
        ) {
            (SenderState::Start(pending), Some(msg)) => (pending, msg),
            (SenderState::WaitResult { perm }, Some(msg)) => {
                return Ok(Step::Done {
                    send: None,
                    output: Some(self.on_result(&perm, msg)?),
                });
            }
            (state @ (SenderState::Start(_) | SenderState::WaitResult { .. }), None) => {
                self.state = state;
                return Err(state_error("sender waits for the receiver's message"));
            }
            (SenderState::Done, _) => return Err(state_error("protocol already finished")),
        };
        let mut r = Reader::new(msg, MSG1)?;
        let share = match r.u8()? {
            0 => false,
            1 => true,
            f => return Err(Error::InvalidInput(format!("ECDH-PSI: bad share flag {f}"))),
        };
        if share != self.share {
            return Err(Error::InvalidInput(format!(
                "ECDH-PSI: receiver {} the result, sender expects {}",
                if share { "shares" } else { "does not share" },
                if self.share { "it" } else { "nothing" },
            )));
        }
        let n = r.u64()?;
        let u = r.array(n, G::POINT_LEN)?;
        r.finish()?;

        // v_i first: if the precomputation is still running, the two share
        // the executor's workers.
        let t = truncation_len(n, self.m, self.sessions);
        let key = &self.key;
        let v = self.exec.install(|| mul_truncate::<G>(u, key, t))?;
        self.key.zeroize();

        // Blocking wait on the caller's thread, never on a worker (see
        // crate::exec).
        let Precomputed { m, w, perm } = pending
            .recv()
            .map_err(|_| Error::OperationFailed("ECDH-PSI: precomputation aborted".into()))??;
        debug_assert_eq!(m, self.m);

        let mut out = Writer::new(MSG2, 1 + 16 + v.len() + w.len());
        out.u8(u8::try_from(t).expect("truncation length <= 32"));
        out.u64(n);
        out.bytes(&v);
        out.u64(m);
        out.bytes(&w);
        match perm {
            Some(perm) => {
                self.state = SenderState::WaitResult { perm };
                Ok(Step::Send(out.finish()))
            }
            None => Ok(Step::Done {
                send: Some(out.finish()),
                output: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ec::{FourQ, Ristretto255, Sm2, P256};

    fn items(xs: &[&str]) -> Vec<Vec<u8>> {
        xs.iter().map(|x| x.as_bytes().to_vec()).collect()
    }

    /// Run both parties in memory, returning the receiver's output and the
    /// two messages.
    fn run<G: Group>(rx: &[&str], sx: &[&str]) -> (Intersection, Vec<u8>, Vec<u8>) {
        let mut r = EcdhReceiver::<G>::new(items(rx), Executor::default(), 1, false).unwrap();
        let mut s = EcdhSender::<G>::new(items(sx), Executor::default(), 1, false).unwrap();
        let Step::Send(m1) = r.step(None).unwrap() else {
            panic!("receiver must send msg1")
        };
        let Step::Done {
            send: Some(m2),
            output: None,
        } = s.step(Some(&m1)).unwrap()
        else {
            panic!("sender must finish with msg2")
        };
        let Step::Done { send: None, output } = r.step(Some(&m2)).unwrap() else {
            panic!("receiver must finish")
        };
        (output, m1, m2)
    }

    fn check<G: Group>() {
        let (out, m1, m2) = run::<G>(&["a", "b", "c", "d"], &["x", "d", "b", "y", "z"]);
        assert_eq!(out, vec![1, 3]);
        let t = truncation_len(4, 5, 1);
        assert_eq!(m1.len(), 1 + 1 + 8 + 4 * G::POINT_LEN);
        assert_eq!(m2.len(), 1 + 1 + 8 + 4 * t + 8 + 5 * G::POINT_LEN);

        // Edge cases: empty sets and full overlap.
        assert!(run::<G>(&[], &["a"]).0.is_empty());
        assert!(run::<G>(&["a"], &[]).0.is_empty());
        assert!(run::<G>(&[], &[]).0.is_empty());
        assert_eq!(run::<G>(&["a", "b"], &["b", "a"]).0, vec![0, 1]);
        // Binary and empty items are fine.
        let mut r =
            EcdhReceiver::<G>::new(vec![vec![], vec![0, 255]], Executor::default(), 1, false)
                .unwrap();
        let mut s =
            EcdhSender::<G>::new(vec![vec![0, 255]], Executor::default(), 1, false).unwrap();
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

    #[test]
    fn larger_sets() {
        let rx: Vec<String> = (0..2000).map(|i| format!("id-{i}")).collect();
        let sx: Vec<String> = (1000..5000).map(|i| format!("id-{i}")).collect();
        let rx: Vec<&str> = rx.iter().map(String::as_str).collect();
        let sx: Vec<&str> = sx.iter().map(String::as_str).collect();
        let (out, _, _) = run::<Ristretto255>(&rx, &sx);
        assert_eq!(out, (1000..2000).collect::<Vec<_>>());
    }

    /// Precomputation must not deadlock even on a single worker thread, with
    /// msg1 arriving before or after it finishes.
    #[test]
    fn single_thread_pool() {
        for wait_first in [false, true] {
            let exec = Executor::new(1).unwrap();
            let mut r =
                EcdhReceiver::<Sm2>::new(items(&["a", "b"]), exec.clone(), 1, false).unwrap();
            let mut s = EcdhSender::<Sm2>::new(items(&["b", "c"]), exec, 1, false).unwrap();
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

    /// Dropping a sender before msg1 arrives leaves the background job to
    /// finish on its own.
    #[test]
    fn drop_sender_during_precompute() {
        let big: Vec<Vec<u8>> = (0..2000).map(|i| format!("{i}").into_bytes()).collect();
        let s = EcdhSender::<P256>::new(big, Executor::new(2).unwrap(), 1, false).unwrap();
        drop(s);
    }

    /// Both parties must agree on the session count; a mismatch changes the
    /// truncation length and is rejected instead of yielding a wrong result.
    #[test]
    fn session_count_mismatch_is_rejected() {
        let rx: Vec<Vec<u8>> = (0..300).map(|i| format!("{i}").into_bytes()).collect();
        let mut r =
            EcdhReceiver::<Ristretto255>::new(rx.clone(), Executor::default(), 1, false).unwrap();
        let mut s =
            EcdhSender::<Ristretto255>::new(rx, Executor::default(), 1 << 16, false).unwrap();
        let Step::Send(m1) = r.step(None).unwrap() else {
            panic!()
        };
        let Step::Done { send: Some(m2), .. } = s.step(Some(&m1)).unwrap() else {
            panic!()
        };
        assert!(matches!(r.step(Some(&m2)), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn sender_output_is_shuffled() {
        // The w_j block is a random permutation, so two runs over the same
        // set produce different orders (with overwhelming probability).
        let sx: Vec<String> = (0..32).map(|i| i.to_string()).collect();
        let sx: Vec<&str> = sx.iter().map(String::as_str).collect();
        let (_, _, a) = run::<Ristretto255>(&["0"], &sx);
        let (_, _, b) = run::<Ristretto255>(&["0"], &sx);
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_out_of_order_calls() {
        let mut r = EcdhReceiver::<Sm2>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        assert!(matches!(r.step(Some(b"x")), Err(Error::InvalidState(_))));
        let mut r = EcdhReceiver::<Sm2>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        r.step(None).unwrap();
        assert!(matches!(r.step(None), Err(Error::InvalidState(_))));

        let mut s = EcdhSender::<Sm2>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        assert!(matches!(s.step(None), Err(Error::InvalidState(_))));
    }

    #[test]
    fn rejects_malformed_messages() {
        let mut s = EcdhSender::<P256>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        assert!(matches!(s.step(Some(b"")), Err(Error::InvalidInput(_))));

        // msg1 claiming one point but carrying an invalid encoding.
        let mut w = Writer::new(MSG1, 0);
        w.u8(0);
        w.u64(1);
        w.bytes(&[0xff; 33]);
        let mut s = EcdhSender::<P256>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        assert!(matches!(
            s.step(Some(&w.finish())),
            Err(Error::InvalidInput(_))
        ));

        // msg1 with a count that overflows the length computation.
        let mut w = Writer::new(MSG1, 0);
        w.u8(0);
        w.u64(usize::MAX);
        let mut s = EcdhSender::<P256>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        assert!(matches!(
            s.step(Some(&w.finish())),
            Err(Error::InvalidInput(_))
        ));

        // Reply whose set size does not match the receiver's.
        let mut r =
            EcdhReceiver::<P256>::new(items(&["a", "b"]), Executor::default(), 1, false).unwrap();
        let Step::Send(m1) = r.step(None).unwrap() else {
            panic!()
        };
        let mut s = EcdhSender::<P256>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        let Step::Done {
            send: Some(mut m2), ..
        } = s.step(Some(&m1)).unwrap()
        else {
            panic!()
        };
        m2[1] += 1; // wrong truncation length
        assert!(matches!(r.step(Some(&m2)), Err(Error::InvalidInput(_))));
    }

    /// Run with the result shared: (receiver output, sender output).
    fn run_shared<G: Group>(rx: &[&str], sx: &[&str]) -> (Intersection, Intersection) {
        let mut r = EcdhReceiver::<G>::new(items(rx), Executor::default(), 1, true).unwrap();
        let mut s = EcdhSender::<G>::new(items(sx), Executor::default(), 1, true).unwrap();
        let Step::Send(m1) = r.step(None).unwrap() else {
            panic!("receiver sends msg1")
        };
        let Step::Send(m2) = s.step(Some(&m1)).unwrap() else {
            panic!("sharing sender waits for msg3")
        };
        let Step::Done {
            send: Some(m3),
            output: ro,
        } = r.step(Some(&m2)).unwrap()
        else {
            panic!("receiver finishes with msg3")
        };
        let Step::Done {
            send: None,
            output: Some(so),
        } = s.step(Some(&m3)).unwrap()
        else {
            panic!("sender finishes with its result")
        };
        (ro, so)
    }

    /// Both parties get the intersection as indices into their own items.
    #[test]
    fn shared_result() {
        fn check<G: Group>() {
            let (r, s) = run_shared::<G>(&["a", "b", "c", "d"], &["x", "d", "b", "y", "z"]);
            assert_eq!(r, vec![1, 3]);
            assert_eq!(s, vec![1, 2]);
            assert_eq!(run_shared::<G>(&[], &["a"]), (vec![], vec![]));
            assert_eq!(run_shared::<G>(&["a"], &[]), (vec![], vec![]));
        }
        check::<Ristretto255>();
        check::<P256>();
        check::<Sm2>();
        check::<FourQ>();

        let rx: Vec<String> = (0..3000).map(|i| format!("id-{i}")).collect();
        let sx: Vec<String> = (2000..6000).map(|i| format!("id-{i}")).collect();
        let rx: Vec<&str> = rx.iter().map(String::as_str).collect();
        let sx: Vec<&str> = sx.iter().map(String::as_str).collect();
        let (r, s) = run_shared::<Ristretto255>(&rx, &sx);
        assert_eq!(r, (2000..3000).collect::<Vec<_>>());
        assert_eq!(s, (0..1000).collect::<Vec<_>>());
    }

    /// A mismatch in the share setting is rejected by the sender, in both
    /// directions.
    #[test]
    fn share_mismatch_is_rejected() {
        for (rs, ss) in [(true, false), (false, true)] {
            let mut r =
                EcdhReceiver::<Sm2>::new(items(&["a"]), Executor::default(), 1, rs).unwrap();
            let mut s = EcdhSender::<Sm2>::new(items(&["a"]), Executor::default(), 1, ss).unwrap();
            let Step::Send(m1) = r.step(None).unwrap() else {
                panic!()
            };
            assert!(matches!(s.step(Some(&m1)), Err(Error::InvalidInput(_))));
        }
    }

    /// msg3 positions are validated against the sender's set size.
    #[test]
    fn rejects_malformed_result() {
        let new = || {
            let mut s =
                EcdhSender::<P256>::new(items(&["a", "b"]), Executor::default(), 1, true).unwrap();
            let mut w = Writer::new(MSG1, 0);
            w.u8(1);
            w.u64(0);
            let Step::Send(_) = s.step(Some(&w.finish())).unwrap() else {
                panic!()
            };
            s
        };
        for positions in [&[2usize][..], &[1, 0], &[0, 0]] {
            let mut w = Writer::new(MSG3, 0);
            write_positions(&mut w, positions, 2);
            assert!(new().step(Some(&w.finish())).is_err(), "{positions:?}");
        }
        assert!(new().step(None).is_err());
        // Unknown flag value.
        let mut s = EcdhSender::<P256>::new(items(&["a"]), Executor::default(), 1, false).unwrap();
        let mut w = Writer::new(MSG1, 0);
        w.u8(2);
        w.u64(0);
        assert!(s.step(Some(&w.finish())).is_err());
    }
}
