//! Error types for cryptex

use std::fmt;

/// Result type for cryptex operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Invalid input parameter
    InvalidInput(String),
    /// Invalid key size
    InvalidKeySize,
    /// Operation failed
    OperationFailed(String),
    /// Not implemented
    NotImplemented,
    /// Call not allowed in the current protocol state
    InvalidState(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Error::InvalidKeySize => write!(f, "Invalid key size"),
            Error::OperationFailed(msg) => write!(f, "Operation failed: {}", msg),
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
        }
    }
}

impl std::error::Error for Error {}
