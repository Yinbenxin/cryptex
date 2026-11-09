//! ECDH-PSI receiver.

use super::protocol::EcdhReceiver;
use super::Curve;
use crate::algorithms::psi::Intersection;
use crate::exec::Executor;
use crate::primitives::ec::{FourQ, Ristretto255, Sm2, P256};
use crate::protocol::{Party, Step};
use crate::Result;

enum Inner {
    Ristretto255(EcdhReceiver<Ristretto255>),
    P256(EcdhReceiver<P256>),
    Sm2(EcdhReceiver<Sm2>),
    FourQ(EcdhReceiver<FourQ>),
}

/// ECDH-PSI receiver. Initiates the protocol and learns the intersection.
pub struct Receiver(Inner);

impl Receiver {
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
    /// parties must pass the same value. `share`: also send the result to
    /// the sender (the last step then has a message for it); both parties
    /// must pass the same value.
    pub(crate) fn with_executor(
        curve: Curve,
        items: Vec<Vec<u8>>,
        exec: Executor,
        sessions: u32,
        share: bool,
    ) -> Result<Self> {
        Ok(Self(match curve {
            Curve::Ristretto255 => {
                Inner::Ristretto255(EcdhReceiver::new(items, exec, sessions, share)?)
            }
            Curve::P256 => Inner::P256(EcdhReceiver::new(items, exec, sessions, share)?),
            Curve::Sm2 => Inner::Sm2(EcdhReceiver::new(items, exec, sessions, share)?),
            Curve::FourQ => Inner::FourQ(EcdhReceiver::new(items, exec, sessions, share)?),
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

    /// Public API end to end for every curve.
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
            let Step::Done { send, output } = r.step(Some(&m2)).unwrap() else {
                panic!("{curve:?}: receiver finishes")
            };
            assert!(send.is_none());
            assert_eq!(output, vec![0, 2], "{curve:?}");
        }
    }

    /// Mismatched curves must not produce a (wrong) result silently.
    #[test]
    fn curve_mismatch_fails() {
        let items = || vec![b"a".to_vec()];
        let mut r = Receiver::new(Curve::P256, items()).unwrap();
        let mut s = Sender::new(Curve::Ristretto255, items()).unwrap();
        let Step::Send(m1) = r.step(None).unwrap() else {
            panic!()
        };
        assert!(s.step(Some(&m1)).is_err());

        // P-256 and SM2 share the point length; the encoding check catches it
        // unless the x-coordinate happens to be valid on both curves, in which
        // case the result is still an empty (not wrong) intersection.
        let mut r = Receiver::new(Curve::Sm2, items()).unwrap();
        let mut s = Sender::new(Curve::P256, items()).unwrap();
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
