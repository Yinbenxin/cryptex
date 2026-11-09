//! OPRF-PSI receiver (the small set).

use super::protocol::OprfReceiver;
use super::Curve;
use crate::algorithms::psi::Intersection;
use crate::exec::Executor;
use crate::primitives::ec::{FourQ, Ristretto255, Sm2, P256};
use crate::protocol::{Party, Step};
use crate::Result;

enum Inner {
    Ristretto255(OprfReceiver<Ristretto255>),
    P256(OprfReceiver<P256>),
    Sm2(OprfReceiver<Sm2>),
    FourQ(OprfReceiver<FourQ>),
}

/// OPRF-PSI receiver. Initiates the protocol and learns the intersection;
/// meant to hold the smaller set.
pub struct Receiver(Inner);

impl Receiver {
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
            Curve::Ristretto255 => Inner::Ristretto255(OprfReceiver::new(items, exec, sessions)?),
            Curve::P256 => Inner::P256(OprfReceiver::new(items, exec, sessions)?),
            Curve::Sm2 => Inner::Sm2(OprfReceiver::new(items, exec, sessions)?),
            Curve::FourQ => Inner::FourQ(OprfReceiver::new(items, exec, sessions)?),
        }))
    }
}

impl Party for Receiver {
    type Output = Intersection;

    fn is_initiator(&self) -> bool {
        true
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

#[cfg(test)]
mod tests {
    use super::super::Sender;
    use super::*;

    #[test]
    fn all_curves() {
        for curve in [Curve::Ristretto255, Curve::P256, Curve::Sm2, Curve::FourQ] {
            let rx = vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()];
            let sx = vec![b"carol".to_vec(), b"dave".to_vec(), b"alice".to_vec()];
            let mut r = Receiver::new(curve, rx).unwrap();
            let mut s = Sender::new(curve, sx).unwrap();
            let Step::Send(m1) = r.step(None).unwrap() else {
                panic!("{curve:?}: receiver sends msg1")
            };
            let Step::Done { send: Some(m2), .. } = s.step(Some(&m1)).unwrap() else {
                panic!("{curve:?}: sender replies")
            };
            let Step::Done { output, .. } = r.step(Some(&m2)).unwrap() else {
                panic!("{curve:?}: receiver finishes")
            };
            assert_eq!(output, vec![0, 2], "{curve:?}");
        }
    }

    /// Mismatched curves fail or give an empty (never a wrong) result.
    #[test]
    fn curve_mismatch() {
        let items = || vec![b"a".to_vec()];
        for (rc, sc) in [
            (Curve::P256, Curve::Ristretto255),
            (Curve::Sm2, Curve::P256),
        ] {
            let mut r = Receiver::new(rc, items()).unwrap();
            let mut s = Sender::new(sc, items()).unwrap();
            let Step::Send(m1) = r.step(None).unwrap() else {
                panic!()
            };
            if let Ok(Step::Done { send: Some(m2), .. }) = s.step(Some(&m1)) {
                if let Ok(Step::Done { output, .. }) = r.step(Some(&m2)) {
                    assert!(output.is_empty());
                }
            }
        }
    }
}
