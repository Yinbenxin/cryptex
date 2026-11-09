//! ECDH-PSI sender.

use super::protocol::EcdhSender;
use super::Curve;
use crate::algorithms::psi::Intersection;
use crate::exec::Executor;
use crate::primitives::ec::{FourQ, Ristretto255, Sm2, P256};
use crate::protocol::{Party, Step};
use crate::Result;

enum Inner {
    Ristretto255(EcdhSender<Ristretto255>),
    P256(EcdhSender<P256>),
    Sm2(EcdhSender<Sm2>),
    FourQ(EcdhSender<FourQ>),
}

/// ECDH-PSI sender. Learns nothing about the receiver's set, unless the
/// receiver shares the result (see [`with_executor`](Self::with_executor)).
///
/// Starts computing its own blinded points in the background on creation,
/// so create it as early as possible (before waiting for the receiver).
pub struct Sender(Inner);

impl Sender {
    /// Create a party holding `items`, computing on rayon's global pool.
    /// Items must be distinct.
    pub fn new(curve: Curve, items: Vec<Vec<u8>>) -> Result<Self> {
        Self::with_threads(curve, items, 0)
    }

    /// Like [`new`](Self::new), computing on a dedicated pool of `threads`
    /// workers (0 = rayon's global pool).
    pub fn with_threads(curve: Curve, items: Vec<Vec<u8>>, threads: usize) -> Result<Self> {
        Self::with_executor(curve, items, Executor::new(threads)?, 1, false)
    }

    /// `sessions`: number of sessions (buckets) the job is split into; both
    /// parties must pass the same value. `share`: the receiver sends the
    /// result back, so the protocol ends with the sender's
    /// [`Step::Done`] carrying `Some(indices)` into its own items; both
    /// parties must pass the same value.
    pub(crate) fn with_executor(
        curve: Curve,
        items: Vec<Vec<u8>>,
        exec: Executor,
        sessions: u32,
        share: bool,
    ) -> Result<Self> {
        Ok(Self(match curve {
            Curve::Ristretto255 => {
                Inner::Ristretto255(EcdhSender::new(items, exec, sessions, share)?)
            }
            Curve::P256 => Inner::P256(EcdhSender::new(items, exec, sessions, share)?),
            Curve::Sm2 => Inner::Sm2(EcdhSender::new(items, exec, sessions, share)?),
            Curve::FourQ => Inner::FourQ(EcdhSender::new(items, exec, sessions, share)?),
        }))
    }
}

impl Party for Sender {
    /// Own indices in the intersection when the receiver shares it.
    type Output = Option<Intersection>;

    fn is_initiator(&self) -> bool {
        false
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<Self::Output>> {
        match &mut self.0 {
            Inner::Ristretto255(p) => p.step(incoming),
            Inner::P256(p) => p.step(incoming),
            Inner::Sm2(p) => p.step(incoming),
            Inner::FourQ(p) => p.step(incoming),
        }
    }
}
