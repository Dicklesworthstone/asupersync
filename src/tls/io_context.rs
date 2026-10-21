//! Wake-driven, explicit-context waits over a borrowed TLS stream.

use super::{TlsError, TlsStream};
use crate::cx::{Cx, io_gate::require_ambient_io};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::Poll;

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Read plaintext while observing `cx`, including while I/O is parked.
    ///
    /// Unlike handshake establishment, this wait borrows the stream. Cancelling
    /// or dropping a pending wait does not drop the connection, consume unread
    /// plaintext, or discard partially received TLS records. After an established
    /// connection's wait is cancelled, another permitted context can resume it.
    /// Drop the stream instead when cancellation should abort the TLS session.
    ///
    /// Both the polling caller and `cx` must permit I/O, checked on every poll.
    /// The supplied context is installed only while polling or destroying the
    /// inner wait. Cancellation masks are respected. No detached task or timer
    /// is created; the wait owns and retires its own cancellation observer.
    ///
    /// # Completion and Cancellation
    ///
    /// A completed read wins over cancellation racing that poll: bytes already
    /// consumed into `buf` are reported, never hidden behind a cancellation
    /// error. Cancellation before a poll or after `Pending` returns
    /// [`io::ErrorKind::Interrupted`]. The adapter does not invalidate channel
    /// binding merely because a wait was cancelled; actual TLS/transport errors
    /// retain the stream's existing failure behavior.
    ///
    /// Use an established stream. An implicit handshake remains not cancel-safe;
    /// discard the connection if this wait ends before that handshake completes.
    /// An empty buffer returns zero without polling the transport, subject to
    /// the same capability and cancellation checks.
    ///
    /// # Errors
    ///
    /// Preserves the TLS read's I/O error. Context cancellation returns
    /// `Interrupted`; I/O capability refusal returns `PermissionDenied`.
    pub async fn read_with_cx(&mut self, cx: &Cx, buf: &mut [u8]) -> io::Result<usize> {
        wait_with_context(cx, "tls::read_with_cx", self.read(buf)).await
    }

    /// Accept a plaintext prefix while observing `cx` independently of I/O.
    ///
    /// Reports exactly the prefix accepted by TLS, not delivery to the peer.
    /// A completed write wins over concurrent cancellation: replacing its byte
    /// count with an error could cause a caller to resend accepted plaintext.
    /// Flush separately with [`Self::flush_with_cx`] to drive all queued records.
    /// This is a single write, not `write_all`; callers must retain their offset
    /// across multiple writes (see also [`crate::io::WriteAllSession`]).
    ///
    /// Cancelling or dropping a pending wait leaves the established stream and
    /// its queued records intact. No new plaintext is accepted on a `Pending`
    /// result. Capability, masking, observer ownership, and implicit-handshake
    /// restrictions are the same as [`Self::read_with_cx`].
    ///
    /// # Errors
    ///
    /// Preserves write errors. Context cancellation before acceptance returns
    /// `Interrupted`; I/O capability refusal returns `PermissionDenied`.
    pub async fn write_with_cx(&mut self, cx: &Cx, buf: &[u8]) -> io::Result<usize> {
        wait_with_context(cx, "tls::write_with_cx", self.write(buf)).await
    }

    /// Flush accepted TLS records while observing `cx` independently of I/O.
    ///
    /// Cancellation of this wait is not rollback: some bytes may already have
    /// reached the peer. Partial TLS/transport flush progress remains in the
    /// stream, so resume flushing rather than resubmitting accepted plaintext.
    /// Dropping the wait retires its observer but does not drop the stream.
    /// A completed flush, including an error, is not replaced by cancellation.
    /// Capability and masking rules are the same as [`Self::read_with_cx`].
    ///
    /// # Errors
    ///
    /// Preserves flush errors, including their existing retry/terminal semantics.
    /// Context cancellation returns `Interrupted`; capability refusal returns
    /// `PermissionDenied`.
    pub async fn flush_with_cx(&mut self, cx: &Cx) -> io::Result<()> {
        wait_with_context(cx, "tls::flush_with_cx", self.flush()).await
    }

    /// Flush `close_notify` and shut down the transport while observing `cx`.
    ///
    /// Cancellation or drop ends only the wait. Once shutdown has started, the
    /// stream stays write-closed; it cannot be reopened by cancelling this
    /// future. Resume shutdown with a permitted context (or under an appropriate
    /// cancellation mask), or drop the stream to abandon graceful shutdown.
    /// Reads may continue under the existing half-close rules. Completed results
    /// are preserved. Capability and masking rules match [`Self::read_with_cx`].
    ///
    /// # Errors
    ///
    /// Preserves shutdown errors. Context cancellation returns `Interrupted`;
    /// I/O capability refusal returns `PermissionDenied`.
    pub async fn shutdown_with_cx(&mut self, cx: &Cx) -> io::Result<()> {
        wait_with_context(cx, "tls::shutdown_with_cx", self.shutdown()).await
    }

    /// Flush TLS `close_notify` without shutting down the underlying transport.
    ///
    /// Observes `cx` while parked, with the same retained-progress and masking
    /// rules as [`Self::shutdown_with_cx`]. Delegates the actual TLS half-close
    /// to [`Self::poll_shutdown_tls`]; it does not create a second shutdown path.
    ///
    /// # Errors
    ///
    /// Preserves [`Self::poll_shutdown_tls`] errors. Context cancellation returns
    /// [`TlsError::Io`] with `Interrupted`; capability refusal returns
    /// [`TlsError::Io`] with `PermissionDenied`.
    pub async fn shutdown_tls_with_cx(&mut self, cx: &Cx) -> Result<(), TlsError> {
        wait_with_context(
            cx,
            "tls::shutdown_tls_with_cx",
            poll_fn(|task| self.poll_shutdown_tls(task)),
        )
        .await
    }
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "TLS I/O wait cancelled")
}

async fn wait_with_context<T, E>(
    cx: &Cx,
    name: &'static str,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    E: From<io::Error>,
{
    let mut stopped = pin!(cx.cancelled());
    let mut operation = pin!(cx.with_ambient(async move {
        let mut operation = pin!(operation);
        poll_fn(|task| {
            // Check the owner even for transports that have no gate themselves.
            if let Err(error) = require_ambient_io(name) {
                return Poll::Ready(Err(E::from(error)));
            }
            operation.as_mut().poll(task)
        })
        .await
    }));
    poll_fn(|task| {
        // A restricted caller must not borrow the owner's stronger capability.
        if let Err(error) = require_ambient_io(name) {
            return Poll::Ready(Err(E::from(error)));
        }
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(E::from(cancelled())));
        }
        match operation.as_mut().poll(task) {
            // This is the byte-commit boundary. Never mask a completed read or
            // accepted write with a cancellation that arrived during its poll.
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                // Register-and-recheck covers cancellation inside the first
                // poll, refreshes migrated wakers, and respects masking.
                if stopped.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                    return Poll::Ready(Err(E::from(cancelled())));
                }
                Poll::Pending
            }
        }
    })
    .await
}

#[cfg(all(test, feature = "tls-ring"))]
#[path = "io_context_tests.rs"]
mod tests;
