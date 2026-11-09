//! Cryptographically secure random number generation.

use rand::rngs::{ChaCha20Rng, SysRng};
use rand::SeedableRng;

use crate::{Error, Result};

/// A ChaCha20 CSPRNG freshly seeded from the operating system.
///
/// Seed one per protocol session; do not share across threads.
pub(crate) fn csprng() -> Result<ChaCha20Rng> {
    ChaCha20Rng::try_from_rng(&mut SysRng)
        .map_err(|e| Error::OperationFailed(format!("OS random source failed: {e}")))
}
