//! Async framed writer combining `AsyncWrite` with an `Encoder`.

use crate::bytes::BytesMut;
use crate::codec::Encoder;
use crate::io::AsyncWrite;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default write buffer capacity.
const DEFAULT_CAPACITY: usize = 8192;
/// Default soft boundary for readiness-driven write backpressure.
const DEFAULT_BACKPRESSURE_BOUNDARY: usize = DEFAULT_CAPACITY;
/// Cooperative cap on repeated write passes inside one `poll_flush`.
///
/// Without this bound, a writer that always accepts tiny chunks can monopolize
/// a single executor turn while draining a large encoded frame.
const MAX_WRITE_PASSES_PER_POLL: usize = 32;

/// Async framed writer that applies an `Encoder` to an `AsyncWrite` sink.
///
/// Items are encoded into an internal buffer, then flushed to the underlying
/// writer. Repeated producers should call [`FramedWrite::poll_ready`] before
/// each [`FramedWrite::start_send`]. Readiness flushes once the configured soft
/// boundary is reached, so at most one encoded frame can take the buffer over
/// that boundary. Call `poll_flush` to ensure all buffered data reaches the
/// writer.
///
/// # Cancel Safety
///
/// `start_send` completes synchronously with either success or an encoder
/// error. `poll_ready` and `poll_flush` are cancel-safe: partial writes are
/// tracked and resumed on the next call.
pub struct FramedWrite<W, E> {
    inner: W,
    encoder: E,
    buffer: BytesMut,
    backpressure_boundary: usize,
}

impl<W, E> FramedWrite<W, E> {
    /// Creates a new `FramedWrite` with default buffer capacity.
    #[inline]
    pub fn new(inner: W, encoder: E) -> Self {
        Self::with_capacity(inner, encoder, DEFAULT_BACKPRESSURE_BOUNDARY)
    }

    /// Creates a new `FramedWrite` with the specified buffer capacity.
    ///
    /// The initial backpressure boundary matches `capacity` and can be changed
    /// independently with [`FramedWrite::set_backpressure_boundary`].
    pub fn with_capacity(inner: W, encoder: E, capacity: usize) -> Self {
        Self {
            inner,
            encoder,
            buffer: BytesMut::with_capacity(capacity),
            backpressure_boundary: capacity,
        }
    }

    /// Returns a reference to the underlying writer.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Returns a reference to the encoder.
    #[inline]
    #[must_use]
    pub fn encoder(&self) -> &E {
        &self.encoder
    }

    /// Returns a mutable reference to the encoder.
    pub fn encoder_mut(&mut self) -> &mut E {
        &mut self.encoder
    }

    /// Returns a reference to the write buffer.
    #[inline]
    #[must_use]
    pub fn write_buffer(&self) -> &BytesMut {
        &self.buffer
    }

    /// Sets the soft write-buffer boundary used by [`FramedWrite::poll_ready`].
    ///
    /// The boundary is checked before encoding the next frame. One frame may
    /// therefore take the buffer over the configured value; readiness will not
    /// be reported again until that buffered frame has drained. A boundary of
    /// zero flushes before every frame.
    #[inline]
    pub fn set_backpressure_boundary(&mut self, boundary: usize) {
        self.backpressure_boundary = boundary;
    }

    /// Configures the soft write-buffer boundary used by
    /// [`FramedWrite::poll_ready`].
    #[inline]
    #[must_use]
    pub fn with_backpressure_boundary(mut self, boundary: usize) -> Self {
        self.set_backpressure_boundary(boundary);
        self
    }

    /// Returns the soft write-buffer boundary used by
    /// [`FramedWrite::poll_ready`].
    #[inline]
    #[must_use]
    pub fn backpressure_boundary(&self) -> usize {
        self.backpressure_boundary
    }

    /// Consumes `self` and returns the inner writer.
    #[inline]
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Consumes `self` and returns the inner writer, encoder, and buffer.
    pub fn into_parts(self) -> (W, E, BytesMut) {
        (self.inner, self.encoder, self.buffer)
    }
}

impl<W, E> FramedWrite<W, E> {
    /// Encodes an item into the write buffer without polling readiness.
    ///
    /// This convenience method is appropriate when the caller immediately
    /// flushes one frame. Repeated producers should use the bounded
    /// [`FramedWrite::poll_ready`] / [`FramedWrite::start_send`] protocol.
    pub fn send<I>(&mut self, item: I) -> Result<(), <E as Encoder<I>>::Error>
    where
        E: Encoder<I>,
    {
        self.start_send(item)
    }

    /// Encodes one item after [`FramedWrite::poll_ready`] reports readiness.
    ///
    /// The boundary is soft: this one encoded frame may exceed it. The caller
    /// must poll readiness again before encoding another frame.
    pub fn start_send<I>(&mut self, item: I) -> Result<(), <E as Encoder<I>>::Error>
    where
        E: Encoder<I>,
    {
        self.encoder.encode(item, &mut self.buffer)
    }
}

impl<W, E> FramedWrite<W, E>
where
    W: AsyncWrite + Unpin,
{
    /// Polls whether another frame may be encoded without bypassing the
    /// configured backpressure boundary.
    ///
    /// Once the current buffer reaches the boundary this flushes it before
    /// returning readiness. A pending writer therefore prevents further
    /// readiness-driven buffer growth.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.buffer.len() < self.backpressure_boundary {
            Poll::Ready(Ok(()))
        } else {
            self.poll_flush(cx)
        }
    }

    /// Flush all buffered data to the underlying writer.
    ///
    /// Returns `Poll::Ready(Ok(()))` when the buffer is empty and the
    /// underlying writer has been flushed.
    ///
    /// If the writer reports more bytes written than it was given, returns
    /// `InvalidData` without advancing the buffer for that write.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write_passes = 0usize;
        while !self.buffer.is_empty() {
            if write_passes >= MAX_WRITE_PASSES_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let remaining = self.buffer.len();
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) if n > remaining => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("writer reported {n} bytes written for {remaining}-byte buffer"),
                    )));
                }
                Poll::Ready(Ok(n)) => n,
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write frame to transport",
                )));
            }
            // Discard the just-written bytes without the alloc + memcpy of a
            // throwaway `split_to` head; `advance` bumps the front offset.
            self.buffer.advance(n);
            write_passes += 1;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// Flush all buffered data and shut down the underlying writer.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<W: std::fmt::Debug, E: std::fmt::Debug> std::fmt::Debug for FramedWrite<W, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedWrite")
            .field("inner", &self.inner)
            .field("encoder", &self.encoder)
            .field("buffer_len", &self.buffer.len())
            .field("backpressure_boundary", &self.backpressure_boundary)
            .finish()
    }
}

#[cfg(test)]
#[path = "framed_write_inline_tests.rs"]
mod tests;
