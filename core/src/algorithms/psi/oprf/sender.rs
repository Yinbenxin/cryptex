//! OPRF-PSI sender (the large set).

use super::protocol::OprfSender;
use super::Curve;
use crate::exec::Executor;
use crate::primitives::ec::{FourQ, Ristretto255, Sm2, P256};
use crate::protocol::{Party, Step};
use crate::Result;

enum Inner {
    Ristretto255(OprfSender<Ristretto255>),
    P256(OprfSender<P256>),
    Sm2(OprfSender<Sm2>),
    FourQ(OprfSender<FourQ>),
}

/// OPRF-PSI sender. Learns nothing about the receiver's set; meant to hold
/// the larger set.
///
/// Starts computing the OPRF outputs of its own items in the background on
/// creation, so create it as early as possible.
pub struct Sender(Inner);

impl Sender {
    /// Create a party holding `items`, computing on rayon's global pool.
    /// Items must be distinct and at most 65535 bytes long.
    pub fn new(curve: Curve, items: Vec<Vec<u8>>) -> Result<Self> {
        Self::with_threads(curve, items, 0)
    }

    /// Like [`new`](Self::new), computing on a dedicated pool of `threads`
    /// workers (0 = rayon's global pool).
    pub fn with_threads(curve: Curve, items: Vec<Vec<u8>>, threads: usize) -> Result<Self> {
        Self::with_executor(curve, items, Executor::new(threads)?, 1)
    }

    /// `sessions`: number of sessions (buckets) the job is split into; both
    /// parties must pass the same value.
    pub(crate) fn with_executor(
        curve: Curve,
        items: Vec<Vec<u8>>,
        exec: Executor,
        sessions: u32,
    ) -> Result<Self> {
        Ok(Self(match curve {
            Curve::Ristretto255 => Inner::Ristretto255(OprfSender::new(items, exec, sessions)?),
            Curve::P256 => Inner::P256(OprfSender::new(items, exec, sessions)?),
            Curve::Sm2 => Inner::Sm2(OprfSender::new(items, exec, sessions)?),
            Curve::FourQ => Inner::FourQ(OprfSender::new(items, exec, sessions)?),
        }))
    }
}

impl Party for Sender {
    type Output = ();

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
