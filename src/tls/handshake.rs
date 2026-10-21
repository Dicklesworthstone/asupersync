//! Owned, wake-driven cancellation of public TLS connection establishment.

use super::{TlsAcceptor, TlsConnector, TlsError, TlsStream};
use crate::cx::{Cx, io_gate::require_ambient_io};
use crate::io::{AsyncRead, AsyncWrite};
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::Poll;

impl TlsConnector {
    /// Establish TLS while observing `cx`, even when the transport is parked.
    ///
    /// Delegates negotiation, certificate verification, pinning, ALPN and the
    /// configured handshake timeout to [`Self::connect`]. A successful result
    /// is the same established stream, including its channel-binding APIs.
    ///
    /// The supplied context is installed for each handshake poll and for
    /// destruction of the unfinished handshake, including a future dropped
    /// before its first poll. Creating the future attaches this ownership guard
    /// but does not poll the transport, start negotiation, or register a waiter.
    /// Both the polling caller and the supplied context must permit I/O;
    /// resuming under a restricted caller
    /// cannot borrow stronger authority from an earlier poll.
    ///
    /// # Cancellation
    ///
    /// Cancellation wakes this wait independently of transport readiness.
    /// Checkpoints respect cancellation masks. An unmasked request observed
    /// before polling, while parked, or before publishing a successful stream
    /// returns [`TlsError::Io`] with [`io::ErrorKind::Interrupted`]. The owned
    /// transport is dropped before the result is returned; no partially
    /// authenticated stream or binding material escapes. Dropping this future
    /// also drops the transport and retires its cancellation registration.
    ///
    /// This cannot preempt a synchronous poll or provide asynchronous cleanup
    /// for a transport's destructor. After success the returned stream does not
    /// retain this cancellation observer. Existing `connect` is unchanged.
    ///
    /// # Errors
    ///
    /// Preserves errors from [`Self::connect`], including timeout and pinning
    /// failures. I/O capability refusal returns `PermissionDenied`.
    pub fn connect_with_cx<IO>(
        &self,
        cx: &Cx,
        domain: &str,
        io: IO,
    ) -> impl Future<Output = Result<TlsStream<IO>, TlsError>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        with_cancellation(cx, self.connect(domain, io))
    }
}

impl TlsAcceptor {
    /// Accept TLS while observing `cx`, even when the transport is parked.
    ///
    /// Uses [`Self::accept`] without bypassing client authentication, ALPN,
    /// early-data rejection or the configured handshake timeout. Cancellation,
    /// ownership and capability checks are identical to
    /// [`TlsConnector::connect_with_cx`]. An unfinished connection is dropped,
    /// never returned for reuse; a successful stream no longer owns an observer.
    ///
    /// # Errors
    ///
    /// Preserves [`Self::accept`] errors. Acknowledged cancellation returns
    /// [`TlsError::Io`] with [`io::ErrorKind::Interrupted`]; I/O capability
    /// refusal returns `PermissionDenied`. Cancellation masks are respected.
    pub fn accept_with_cx<IO>(
        &self,
        cx: &Cx,
        io: IO,
    ) -> impl Future<Output = Result<TlsStream<IO>, TlsError>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        with_cancellation(cx, self.accept(io))
    }
}

fn cancelled() -> TlsError {
    TlsError::Io(io::Error::new(
        io::ErrorKind::Interrupted,
        "TLS handshake cancelled",
    ))
}

fn with_cancellation<T>(
    cx: &Cx,
    operation: impl Future<Output = Result<T, TlsError>>,
) -> impl Future<Output = Result<T, TlsError>> {
    // Attach destruction authority now, not in an async body that may never
    // be polled. The public entry points must return this future directly:
    // an outer async fn would capture and drop IO before this guard exists.
    // This constructs a wrapper only; the handshake itself stays lazy.
    let operation = cx.with_ambient(async move {
        let mut operation = pin!(operation);
        poll_fn(|task| {
            if let Err(error) = require_ambient_io("tls::handshake") {
                return Poll::Ready(Err(TlsError::Io(error)));
            }
            match operation.as_mut().poll(task) {
                Poll::Ready(Ok(value)) if cx.checkpoint().is_err() => {
                    drop(value);
                    Poll::Ready(Err(cancelled()))
                }
                result => result,
            }
        })
        .await
    });
    async move {
        let mut stopped = pin!(cx.cancelled());
        let mut operation = pin!(operation);
        poll_fn(|task| {
            // Check the caller before installing the explicit owner's context.
            if let Err(error) = require_ambient_io("tls::handshake") {
                return Poll::Ready(Err(TlsError::Io(error)));
            }
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(cancelled()));
            }
            match operation.as_mut().poll(task) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => {
                    // Register-and-recheck closes cancellation racing the first
                    // Pending. The observer refreshes the current task's waker and
                    // unregisters on drop. A masked request does not self-wake.
                    if stopped.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                        return Poll::Ready(Err(cancelled()));
                    }
                    Poll::Pending
                }
            }
        })
        .await
    }
}

#[cfg(all(test, feature = "tls-ring"))]
#[path = "handshake_tests.rs"]
mod tests;

#[cfg(all(test, feature = "tls-ring"))]
#[path = "handshake_ownership_tests.rs"]
mod ownership_tests;
