//! Message-driven interface for two-party protocols (OT, VOLE, PSI).
//!
//! The library does no network IO. Each party is a state machine: feed it the
//! bytes received from the peer, and it returns the bytes to send back. The
//! caller (Python/Go/Java) owns the transport.
//!
//! Exactly one party is the initiator: it calls `step(None)` first. The other
//! party starts by waiting for the initiator's first message.

use crate::Result;

/// Outcome of a single protocol step.
#[derive(Debug)]
pub enum Step<T> {
    /// Send this message to the peer and wait for its reply.
    Send(Vec<u8>),
    /// Protocol finished; `send` is an optional last message for the peer.
    Done {
        /// Final message to deliver to the peer, if any.
        send: Option<Vec<u8>>,
        /// Protocol output for this party.
        output: T,
    },
}

impl<T> Step<T> {
    /// Map the protocol output, leaving the message untouched.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Step<U> {
        match self {
            Step::Send(msg) => Step::Send(msg),
            Step::Done { send, output } => Step::Done {
                send,
                output: f(output),
            },
        }
    }
}

/// One party of a two-party protocol.
pub trait Party {
    /// Output produced when the protocol completes.
    type Output;

    /// Whether this party sends the first message.
    fn is_initiator(&self) -> bool;

    /// Advance the protocol. `incoming` is `None` only on the initiator's
    /// first call.
    fn step(&mut self, incoming: Option<&[u8]>) -> Result<Step<Self::Output>>;
}
