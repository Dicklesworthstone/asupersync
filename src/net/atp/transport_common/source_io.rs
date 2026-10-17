//! Cancellation/authority boundary for bounded ATP source filesystem jobs.
//!
//! Register for the initiating context's cancellation while a job is pending,
//! and acknowledge only through checkpoint(), preserving cancellation masking.
//! Check the current caller's I/O authority on every poll. A submitted blocking
//! job is still soft-cancelled: it may finish and discard its owned result.
//! This does not certify syscall preemption or region-drained retirement.

use std::future::{Future, poll_fn};
use std::io;
use std::path::Path;
use std::pin::{Pin, pin};
use std::task::Poll;

use crate::cx::Cx;

use super::streaming::StreamingError;

fn source_error(path: &Path, error: impl std::fmt::Display) -> StreamingError {
    StreamingError::new(format!("{}: {error}", path.display()))
}

fn cancelled(path: &Path) -> StreamingError {
    source_error(path, io::Error::new(io::ErrorKind::Interrupted, "source operation cancelled"))
}

async fn guard<T>(
    path: &Path,
    operation: &'static str,
    future: impl Future<Output = io::Result<T>>,
) -> Result<T, StreamingError> {
    // Captured on first poll, not future construction. The observer borrows an
    // owned context inside this async frame, so it remains registered between
    // polls and unregisters on success, error, panic or abandonment.
    let owner = Cx::with_current(Clone::clone);
    let mut cancellation = owner.as_ref().map(Cx::cancelled);
    let mut future = pin!(future);
    poll_fn(|task| {
        if let Err(error) = crate::cx::io_gate::require_ambient_io(operation) {
            return Poll::Ready(Err(source_error(path, error)));
        }
        if owner.as_ref().is_some_and(|cx| cx.checkpoint().is_err()) {
            return Poll::Ready(Err(cancelled(path)));
        }
        match future.as_mut().poll(task) {
            Poll::Ready(result) => Poll::Ready(result.map_err(|e| source_error(path, e))),
            Poll::Pending => {
                // The observer closes the check/register race. A masked
                // request may be observed, but it neither aborts this job nor
                // causes a self-wake loop while the filesystem is parked.
                if let Some(wait) = cancellation.as_mut() {
                    if Pin::new(wait).poll(task).is_ready()
                        && owner.as_ref().is_some_and(|cx| cx.checkpoint().is_err())
                    {
                        return Poll::Ready(Err(cancelled(path)));
                    }
                }
                Poll::Pending
            }
        }
    })
    .await
}

pub(super) async fn run<T, F>(
    path: &Path,
    operation: &'static str,
    job: F,
) -> Result<T, StreamingError>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    // spawn_blocking_io is lazy: guard checks before its first poll dispatches
    // the closure. Calling run for each batch also checks between ready jobs.
    guard(path, operation, crate::runtime::spawn_blocking_io(job)).await
}

#[cfg(test)]
#[path = "source_io_inline_tests.rs"]
mod tests;
