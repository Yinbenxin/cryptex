//! Where a session's parallel work runs.
//!
//! Every PSI session computes on an [`Executor`]: either rayon's global pool
//! (one thread per CPU, shared by all sessions) or a dedicated pool.
//!
//! Rule for protocol code: only ever block (on a channel, a lock, …) from
//! the thread that called `step`, never from inside [`Executor::install`] or
//! [`Executor::spawn`]. A worker that blocks can stall work queued behind it
//! on the same pool, which deadlocks small pools.

use std::sync::Arc;

use crate::{Error, Result};

/// Upper bound on per-session worker threads, guards against typos such as
/// passing a set size instead of a thread count.
pub(crate) const MAX_THREADS: usize = 1024;

/// Thread pool handle for one session. Cheap to clone.
#[derive(Clone, Default)]
pub(crate) struct Executor(Option<Arc<rayon::ThreadPool>>);

impl Executor {
    /// `0` = rayon's global pool, `n` = a dedicated pool of `n` threads.
    pub(crate) fn new(threads: usize) -> Result<Self> {
        match threads {
            0 => Ok(Self(None)),
            n if n > MAX_THREADS => Err(Error::InvalidInput(format!(
                "threads must be at most {MAX_THREADS}, got {n}"
            ))),
            n => rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("cryptex-psi-{i}"))
                .build()
                .map(|pool| Self(Some(Arc::new(pool))))
                .map_err(|e| Error::OperationFailed(format!("cannot start worker threads: {e}"))),
        }
    }

    /// Run `f` with this executor as the current pool, so `par_iter` inside
    /// it uses these threads. Blocks the caller until `f` returns.
    pub(crate) fn install<R: Send>(&self, f: impl FnOnce() -> R + Send) -> R {
        match &self.0 {
            Some(pool) => pool.install(f),
            None => f(),
        }
    }

    /// Run `f` in the background on this executor.
    pub(crate) fn spawn(&self, f: impl FnOnce() + Send + 'static) {
        match &self.0 {
            Some(pool) => pool.spawn(f),
            None => rayon::spawn(f),
        }
    }

    /// Worker threads available to this executor.
    #[cfg(test)]
    pub(crate) fn threads(&self) -> usize {
        self.install(rayon::current_num_threads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_count_is_validated() {
        assert_eq!(
            Executor::new(0).unwrap().threads(),
            rayon::current_num_threads()
        );
        assert_eq!(Executor::new(3).unwrap().threads(), 3);
        assert!(Executor::new(MAX_THREADS).is_ok());
        assert!(matches!(
            Executor::new(MAX_THREADS + 1),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn spawn_runs_on_the_pool() {
        let exec = Executor::new(2).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        exec.spawn(move || tx.send(rayon::current_num_threads()).unwrap());
        assert_eq!(rx.recv().unwrap(), 2);
    }
}
