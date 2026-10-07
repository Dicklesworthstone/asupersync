//! Filesystem work that remains owned until its blocking operation retires.
//!
//! The ordinary `fs` helpers have a soft-cancellation host boundary: dropping
//! their wait need not stop a blocking operation already running. [`ScopedFs`]
//! instead uses [`Cx::spawn_blocking_drained`]. Its real child task retains
//! region ownership through the operation and destruction of abandoned results.
//! It never substitutes an inline operation or an unowned fallback thread.
//!
//! Cancellation of the calling context is forwarded to the operation's own
//! context, then the caller waits for retirement. Dropping the calling future
//! requests cancellation; closing its region remains the drain backstop.
//! A queued operation can be cancelled before execution. A running OS call is
//! not preemptible: it must return before graceful close can finish. Hard
//! runtime teardown and cleanup escalation retain their existing boundaries.
//!
//! These are ordinary path-based host filesystem operations, not a filesystem
//! sandbox or deterministic lab effects. Both I/O and spawn authority, a live
//! runtime gateway, and a blocking pool (a `RuntimeBuilder` default) are required.
//! No path confinement, atomic replacement, rollback, or fsync is implied.

use crate::cx::cap::{All, CapSetRuntimeMask, HasIo, HasSpawn};
use crate::cx::Cx;
use crate::runtime::{JoinError, SpawnError};
use crate::types::CancelReason;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::path::PathBuf;
use std::pin::pin;
use std::task::Poll;

#[path = "scoped/bounded.rs"]
mod bounded;

/// Failure of region-owned filesystem work.
#[derive(Debug)]
pub enum ScopedFsError {
    /// The explicit context's runtime mask refuses I/O authority.
    CapabilityDenied,
    /// The caller's cancellation or budget checkpoint refused dispatch.
    Checkpoint(crate::error::Error),
    /// No operation was admitted through the runtime's blocking gateway.
    Admission(SpawnError),
    /// The child was refused, cancelled before execution, or panicked.
    Join(JoinError),
    /// The operation returned an actual filesystem error.
    Io(io::Error),
}

impl fmt::Display for ScopedFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityDenied => write!(f, "scoped filesystem I/O capability denied"),
            Self::Checkpoint(error) => write!(f, "scoped filesystem checkpoint: {error}"),
            Self::Admission(error) => write!(f, "scoped filesystem admission: {error}"),
            Self::Join(error) => write!(f, "scoped filesystem retirement: {error}"),
            Self::Io(error) => write!(f, "scoped filesystem operation: {error}"),
        }
    }
}

impl std::error::Error for ScopedFsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// A capability-bound filesystem execution surface, not a new region.
///
/// Clones retain the same context and ownership target. Construct it from a
/// child region's context to give filesystem work a separate close boundary.
/// Creating this value performs no I/O and admits no work.
pub struct ScopedFs<Caps = All> {
    cx: Cx<Caps>,
}

impl<Caps> Clone for ScopedFs<Caps> {
    fn clone(&self) -> Self {
        Self { cx: self.cx.clone() }
    }
}

impl<Caps> fmt::Debug for ScopedFs<Caps> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedFs")
            .field("region", &self.cx.region_id())
            .finish_non_exhaustive()
    }
}

impl<Caps> Cx<Caps>
where
    Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
{
    /// Bind filesystem operations to this context's region and capabilities.
    ///
    /// Both the static capability row and the runtime mask are respected.
    /// Missing blocking-pool or region wiring refuses at dispatch; the lab's
    /// inline blocking fallback is deliberately not used by this API.
    ///
    /// ```compile_fail
    /// use asupersync::cx::{Cx, NoCaps};
    /// fn cannot_gain_io_or_spawn(cx: &Cx<NoCaps>) {
    ///     let _ = cx.scoped_fs();
    /// }
    /// ```
    #[must_use]
    pub fn scoped_fs(&self) -> ScopedFs<Caps> {
        ScopedFs { cx: self.clone() }
    }
}

impl<Caps> ScopedFs<Caps>
where
    Caps: HasIo + HasSpawn + CapSetRuntimeMask + Send + Sync + 'static,
{
    /// Run a custom blocking filesystem operation under actual region ownership.
    ///
    /// The operation receives its own child context, installed as the ambient
    /// context for this synchronous call. It can checkpoint between individual
    /// OS operations. Captures and results must be owned and `Send`; do not
    /// block waiting for another job on the same potentially saturated pool.
    ///
    /// A cancellation request starts the drain even when the calling context
    /// is masked. Once work is running, its exact `io::Result` is preserved:
    /// cancellation does not imply that filesystem effects were rolled back.
    /// If this future is dropped, region close still waits for the child.
    ///
    /// # Errors
    ///
    /// Returns a typed authority, checkpoint, admission, retirement, or I/O
    /// failure. A child panic is captured as `ScopedFsError::Join`.
    pub async fn run_io<F, T>(&self, operation: F) -> Result<T, ScopedFsError>
    where
        F: FnOnce(Cx<Caps>) -> io::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if !self.cx.capabilities().io {
            return Err(ScopedFsError::CapabilityDenied);
        }
        self.cx.checkpoint().map_err(ScopedFsError::Checkpoint)?;
        let mut handle = self
            .cx
            .spawn_blocking_drained(move |child| {
                let _ambient = child.clone().set_current_restricted();
                // Recheck at the execution boundary, after queueing and any
                // admission-time attenuation of the child's capabilities.
                crate::cx::io_gate::require_ambient_io("scoped_fs")?;
                child.checkpoint().map_err(|error| {
                    io::Error::new(io::ErrorKind::Interrupted, error)
                })?;
                operation(child)
            })
            .map_err(ScopedFsError::Admission)?;

        let completed = {
            let mut cancelled = pin!(self.cx.cancelled());
            let mut joining = pin!(handle.join());
            poll_fn(|task| {
                // A result already retired is real information. Prefer it to
                // a concurrent cancellation instead of erasing completed I/O.
                if let Poll::Ready(result) = joining.as_mut().poll(task) {
                    return Poll::Ready(Some(result));
                }
                if cancelled.as_mut().poll(task).is_ready() {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        let result = match completed {
            Some(result) => result,
            None => {
                handle.abort_with_reason(self.cx.cancel_reason().unwrap_or_else(|| {
                    CancelReason::user("scoped filesystem caller cancelled")
                }));
                // Acknowledge where masking permits it. Retirement itself is
                // uninterruptible and a running operation keeps its result.
                let _ = self.cx.checkpoint();
                handle.join().await
            }
        };
        result.map_err(ScopedFsError::Join)?.map_err(ScopedFsError::Io)
    }

    /// Read a whole file, waiting for the worker and file handle to retire.
    ///
    /// Allocation follows the file's size; use [`Self::read_bounded`] for
    /// untrusted files. This is not a point-in-time snapshot of a file being
    /// modified concurrently.
    pub async fn read(&self, path: impl Into<PathBuf>) -> Result<Vec<u8>, ScopedFsError> {
        let path = path.into();
        self.run_io(move |_| std::fs::read(path)).await
    }

    /// Read a UTF-8 file. Invalid UTF-8 is an ordinary I/O error.
    pub async fn read_to_string(&self, path: impl Into<PathBuf>) -> Result<String, ScopedFsError> {
        let path = path.into();
        self.run_io(move |_| std::fs::read_to_string(path)).await
    }

    /// Create or truncate a file and write owned bytes, then retire its handle.
    ///
    /// This is not atomic replacement or a durability barrier. An error may
    /// leave a partially written file. Cancellation after execution starts
    /// waits for the actual result rather than claiming the write did not occur.
    pub async fn write(
        &self,
        path: impl Into<PathBuf>,
        contents: Vec<u8>,
    ) -> Result<(), ScopedFsError> {
        let path = path.into();
        self.run_io(move |_| std::fs::write(path, contents)).await
    }

    /// Create a directory and its missing ancestors.
    pub async fn create_dir_all(&self, path: impl Into<PathBuf>) -> Result<(), ScopedFsError> {
        let path = path.into();
        self.run_io(move |_| std::fs::create_dir_all(path)).await
    }

    /// Copy file bytes and permissions using the platform's normal copy semantics.
    ///
    /// The destination can be truncated and an error can leave a partial copy.
    /// The returned byte count is the worker's actual result, not a prediction.
    pub async fn copy(
        &self,
        from: impl Into<PathBuf>,
        to: impl Into<PathBuf>,
    ) -> Result<u64, ScopedFsError> {
        let from = from.into();
        let to = to.into();
        self.run_io(move |_| std::fs::copy(from, to)).await
    }

    /// Rename a path with the platform's ordinary replacement semantics.
    ///
    /// Cross-filesystem renames may fail. This does not fsync the directory.
    pub async fn rename(
        &self,
        from: impl Into<PathBuf>,
        to: impl Into<PathBuf>,
    ) -> Result<(), ScopedFsError> {
        let from = from.into();
        let to = to.into();
        self.run_io(move |_| std::fs::rename(from, to)).await
    }

    /// Read metadata, following symlinks like `std::fs::metadata`.
    pub async fn metadata(
        &self,
        path: impl Into<PathBuf>,
    ) -> Result<std::fs::Metadata, ScopedFsError> {
        let path = path.into();
        self.run_io(move |_| std::fs::metadata(path)).await
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn runtime_io_attenuation_refuses_before_dispatch() {
        let cx = {
            let _restricted = Cx::for_testing()
                .restrict::<crate::cx::NoCaps>()
                .set_current_restricted();
            Cx::current().expect("restricted ambient context")
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = futures_lite::future::block_on(cx.scoped_fs().run_io(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(result, Err(ScopedFsError::CapabilityDenied)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_runtime_wiring_refuses_instead_of_running_inline() {
        let cx = Cx::for_testing();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = futures_lite::future::block_on(cx.scoped_fs().run_io(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(result, Err(ScopedFsError::Admission(SpawnError::RuntimeUnavailable))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
