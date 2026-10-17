//! QUIC stream types.
//!
//! Provides cancel-correct stream handling for QUIC connections.

use super::error::QuicError;
use crate::cx::Cx;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

/// Tracks active streams for cleanup on cancellation.
#[derive(Debug, Default)]
pub struct StreamTracker {
    /// Whether the connection is being closed.
    closing: AtomicBool,
}

impl StreamTracker {
    /// Create a new stream tracker.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            closing: AtomicBool::new(false),
        })
    }

    /// Mark the connection as closing.
    pub fn mark_closing(&self) {
        self.closing.store(true, Ordering::Release);
    }

    /// Check if the connection is closing.
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }
}

/// A QUIC send stream with cancel-correct semantics.
///
/// On connection shutdown, the stream is reset with an error code on drop.
#[derive(Debug)]
pub struct SendStream {
    inner: quinn::SendStream,
    tracker: Arc<StreamTracker>,
    /// Error code to use when resetting on cancel/drop.
    reset_code: u32,
}

impl SendStream {
    /// Create a new send stream.
    pub(crate) fn new(inner: quinn::SendStream, tracker: &Arc<StreamTracker>) -> Self {
        Self {
            inner,
            tracker: Arc::clone(tracker),
            reset_code: 0,
        }
    }

    /// Get the stream ID.
    #[must_use]
    pub fn id(&self) -> quinn::StreamId {
        self.inner.id()
    }

    /// Set the error code to use when resetting on cancel/drop.
    pub fn set_reset_code(&mut self, code: u32) {
        self.reset_code = code;
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written.
    pub async fn write(&mut self, cx: &Cx, data: &[u8]) -> Result<usize, QuicError> {
        check_stream_operation(cx, &self.tracker)?;

        wait_result_with_cx(cx, self.inner.write(data)).await
    }

    /// Write all data to the stream.
    pub async fn write_all(&mut self, cx: &Cx, data: &[u8]) -> Result<(), QuicError> {
        check_stream_operation(cx, &self.tracker)?;

        wait_result_with_cx(cx, self.inner.write_all(data)).await
    }

    /// Finish sending on this stream (half-close).
    ///
    /// This signals to the peer that no more data will be sent.
    pub async fn finish(&mut self, cx: &Cx) -> Result<(), QuicError> {
        check_stream_operation(cx, &self.tracker)?;
        self.inner.finish().map_err(QuicError::from)
    }

    /// Reset the stream with an error code.
    ///
    /// This abruptly terminates sending on this stream.
    pub fn reset(&mut self, code: u32) {
        self.inner.reset(code.into()).ok();
    }

    /// Get a reference to the inner quinn stream.
    #[must_use]
    pub fn inner(&self) -> &quinn::SendStream {
        &self.inner
    }

    /// Get a mutable reference to the inner quinn stream.
    pub fn inner_mut(&mut self) -> &mut quinn::SendStream {
        &mut self.inner
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        // Reset stream on drop if connection is closing (cancellation path)
        if self.tracker.is_closing() {
            self.inner.reset(self.reset_code.into()).ok();
        }
    }
}

/// A QUIC receive stream with cancel-correct semantics.
///
/// On connection shutdown, the stream is stopped with an error code on drop.
#[derive(Debug)]
pub struct RecvStream {
    inner: quinn::RecvStream,
    tracker: Arc<StreamTracker>,
    /// Error code to use when stopping on cancel/drop.
    stop_code: u32,
}

impl RecvStream {
    /// Create a new receive stream.
    pub(crate) fn new(inner: quinn::RecvStream, tracker: &Arc<StreamTracker>) -> Self {
        Self {
            inner,
            tracker: Arc::clone(tracker),
            stop_code: 0,
        }
    }

    /// Get the stream ID.
    #[must_use]
    pub fn id(&self) -> quinn::StreamId {
        self.inner.id()
    }

    /// Set the error code to use when stopping on cancel/drop.
    pub fn set_stop_code(&mut self, code: u32) {
        self.stop_code = code;
    }

    /// Read data from the stream.
    ///
    /// Returns `None` if the stream has been fully received.
    pub async fn read(&mut self, cx: &Cx, buf: &mut [u8]) -> Result<Option<usize>, QuicError> {
        check_stream_operation(cx, &self.tracker)?;

        wait_result_with_cx(cx, self.inner.read(buf)).await
    }

    /// Read exactly the requested number of bytes.
    pub async fn read_exact(&mut self, cx: &Cx, buf: &mut [u8]) -> Result<(), QuicError> {
        check_stream_operation(cx, &self.tracker)?;

        wait_result_with_cx(cx, self.inner.read_exact(buf)).await
    }

    /// Read all remaining data up to a limit.
    pub async fn read_to_end(&mut self, cx: &Cx, limit: usize) -> Result<Vec<u8>, QuicError> {
        check_stream_operation(cx, &self.tracker)?;

        wait_result_with_cx(cx, self.inner.read_to_end(limit)).await
    }

    /// Stop reading from this stream with an error code.
    ///
    /// This signals to the peer that we're done receiving.
    pub fn stop(&mut self, code: u32) {
        self.inner.stop(code.into()).ok();
    }

    /// Get a reference to the inner quinn stream.
    #[must_use]
    pub fn inner(&self) -> &quinn::RecvStream {
        &self.inner
    }

    /// Get a mutable reference to the inner quinn stream.
    pub fn inner_mut(&mut self) -> &mut quinn::RecvStream {
        &mut self.inner
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        // Stop stream on drop if connection is closing (cancellation path)
        if self.tracker.is_closing() {
            self.inner.stop(self.stop_code.into()).ok();
        }
    }
}

fn check_stream_operation(cx: &Cx, tracker: &StreamTracker) -> Result<(), QuicError> {
    cx.checkpoint()?;

    if tracker.is_closing() {
        return Err(QuicError::StreamClosed);
    }

    Ok(())
}

async fn wait_result_with_cx<T, E, F>(cx: &Cx, future: F) -> Result<T, QuicError>
where
    E: Into<QuicError>,
    F: Future<Output = Result<T, E>>,
{
    let mut future = std::pin::pin!(future);
    poll_fn(|poll_cx| {
        if let Err(err) = cx.checkpoint() {
            return Poll::Ready(Err(QuicError::from(err)));
        }
        future
            .as_mut()
            .poll(poll_cx)
            .map(|result| result.map_err(Into::into))
    })
    .await
}

#[cfg(test)]
#[path = "stream_inline_tests.rs"]
mod tests;
