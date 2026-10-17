//! Full-duplex framed transport combining `AsyncRead` + `AsyncWrite` with a codec.

use crate::bytes::BytesMut;
use crate::codec::framed_read::ReadState;
use crate::codec::{Decoder, Encoder};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::stream::Stream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default buffer capacity for both read and write.
const DEFAULT_CAPACITY: usize = 8192;
/// Default soft boundary for readiness-driven write backpressure.
const DEFAULT_BACKPRESSURE_BOUNDARY: usize = DEFAULT_CAPACITY;

/// Stack buffer size for reads.
const READ_BUF_SIZE: usize = 8192;
/// Cooperative cap on repeated read/decode passes inside one `poll_next`.
///
/// Without this bound, an always-ready transport that never completes a frame
/// can monopolize a single executor turn indefinitely.
const MAX_READ_PASSES_PER_POLL: usize = 32;
/// Cooperative cap on repeated write passes inside one `poll_flush`.
///
/// Without this bound, a transport that always accepts tiny writes can
/// monopolize a single executor turn while draining a large frame buffer.
const MAX_WRITE_PASSES_PER_POLL: usize = 32;

/// Full-duplex framed transport.
///
/// Combines an `AsyncRead + AsyncWrite` transport with a codec that
/// implements both `Decoder` and `Encoder`. The read half implements
/// `Stream` for receiving decoded frames. The write half provides
/// `poll_ready`/`start_send`/`poll_flush`/`poll_close` for sending encoded
/// frames with bounded producer backpressure.
///
/// # Cancel Safety
///
/// - Reading (`poll_next`): cancel-safe. Partial data stays in the read buffer.
/// - Writing (`start_send`): completes synchronously with success or an
///   encoder error.
/// - Readiness/flushing (`poll_ready`, `poll_flush`): cancel-safe. Partial
///   writes resume on the next call.
pub struct Framed<T, U> {
    inner: T,
    codec: U,
    read_buf: BytesMut,
    write_buf: BytesMut,
    backpressure_boundary: usize,
    eof: bool,
    read_state: ReadState,
    /// Upper bound on the read buffer before a frame completes.
    ///
    /// Mirrors [`FramedRead`](crate::codec::FramedRead)'s cap (default
    /// [`DEFAULT_MAX_BUFFER_LEN`](crate::codec::framed_read::DEFAULT_MAX_BUFFER_LEN)
    /// = an 8 MiB payload plus four-byte length prefix); `0` disables
    /// enforcement (br-asupersync-bj427s).
    max_buffer_len: usize,
    /// Set once the read half surfaces an `Err` (decode, `decode_eof`, or IO).
    ///
    /// Subsequent `poll_next` calls return `Ready(None)` instead of re-running
    /// the decoder over the same bytes, which would re-produce the same error
    /// forever and hang `collect`/`for_each` consumers (br-asupersync-3asq77).
    poisoned: bool,
}

impl<T, U> Framed<T, U> {
    /// Creates a new `Framed` with default buffer capacity.
    #[inline]
    pub fn new(inner: T, codec: U) -> Self {
        Self::with_capacity(inner, codec, DEFAULT_BACKPRESSURE_BOUNDARY)
    }

    /// Creates a new `Framed` with the specified buffer capacity for both
    /// read and write buffers.
    ///
    /// The initial write backpressure boundary matches `capacity` and can be
    /// changed independently with [`Framed::set_backpressure_boundary`].
    pub fn with_capacity(inner: T, codec: U, capacity: usize) -> Self {
        Self {
            inner,
            codec,
            read_buf: BytesMut::with_capacity(capacity),
            write_buf: BytesMut::with_capacity(capacity),
            backpressure_boundary: capacity,
            eof: false,
            read_state: ReadState::NeedsRead,
            max_buffer_len: crate::codec::framed_read::DEFAULT_MAX_BUFFER_LEN,
            poisoned: false,
        }
    }

    /// Sets the maximum read-buffer length before a frame completes.
    ///
    /// A peer that streams bytes without ever closing a frame would otherwise
    /// grow this buffer without bound (slowloris-style). A value of `0`
    /// disables enforcement. Mirrors
    /// [`FramedRead::with_max_buffer_len`](crate::codec::FramedRead::with_max_buffer_len).
    #[inline]
    #[must_use]
    pub fn with_max_buffer_len(mut self, max: usize) -> Self {
        self.max_buffer_len = max;
        self
    }

    /// Returns the configured maximum read-buffer length.
    #[inline]
    #[must_use]
    pub fn max_buffer_len(&self) -> usize {
        self.max_buffer_len
    }

    /// Returns a reference to the underlying transport.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns a reference to the codec.
    #[inline]
    #[must_use]
    pub fn codec(&self) -> &U {
        &self.codec
    }

    /// Returns a mutable reference to the codec.
    pub fn codec_mut(&mut self) -> &mut U {
        self.read_state = ReadState::NeedsDecode;
        &mut self.codec
    }

    /// Returns a reference to the read buffer.
    #[inline]
    #[must_use]
    pub fn read_buffer(&self) -> &BytesMut {
        &self.read_buf
    }

    /// Returns a reference to the write buffer.
    #[inline]
    #[must_use]
    pub fn write_buffer(&self) -> &BytesMut {
        &self.write_buf
    }

    /// Sets the soft write-buffer boundary used by [`Framed::poll_ready`].
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
    /// [`Framed::poll_ready`].
    #[inline]
    #[must_use]
    pub fn with_backpressure_boundary(mut self, boundary: usize) -> Self {
        self.set_backpressure_boundary(boundary);
        self
    }

    /// Returns the soft write-buffer boundary used by [`Framed::poll_ready`].
    #[inline]
    #[must_use]
    pub fn backpressure_boundary(&self) -> usize {
        self.backpressure_boundary
    }

    /// Consumes `self` and returns the transport.
    #[inline]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Consumes `self` and returns all parts.
    pub fn into_parts(self) -> FramedParts<T, U> {
        FramedParts {
            inner: self.inner,
            codec: self.codec,
            read_buf: self.read_buf,
            write_buf: self.write_buf,
        }
    }
}

/// Parts of a deconstructed `Framed`.
pub struct FramedParts<T, U> {
    /// The underlying transport.
    pub inner: T,
    /// The codec.
    pub codec: U,
    /// Unprocessed read data.
    pub read_buf: BytesMut,
    /// Unsent write data.
    pub write_buf: BytesMut,
}

// --- Stream (read) implementation ---

impl<T, U> Stream for Framed<T, U>
where
    T: AsyncRead + Unpin,
    U: Decoder + Unpin,
{
    type Item = Result<<U as Decoder>::Item, <U as Decoder>::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // br-asupersync-3asq77: once the read half has surfaced an error the
        // stream is terminally poisoned. Re-polling must NOT re-run the
        // decoder over the same buffered bytes (which re-produces the same
        // error in a tight loop, hanging `collect`/`for_each` consumers).
        if this.poisoned {
            return Poll::Ready(None);
        }

        let mut read_passes = 0usize;
        let mut should_yield = false;

        loop {
            // Try to decode only when bytes or explicit codec mutation could
            // have changed the previous result.
            if !this.eof && this.read_state == ReadState::NeedsDecode {
                match this.codec.decode(&mut this.read_buf) {
                    Ok(Some(item)) => return Poll::Ready(Some(Ok(item))),
                    Ok(None) => {
                        this.read_state = ReadState::NeedsRead;
                        if should_yield {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Err(e) => {
                        this.poisoned = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                }
            }

            // EOF: give decoder one last chance.
            if this.eof {
                return match this.codec.decode_eof(&mut this.read_buf) {
                    Ok(Some(item)) => {
                        // EOF decoders may drain multiple final frames across
                        // polls. Keep decoding eligible until decode_eof says
                        // the buffer is exhausted.
                        this.read_state = ReadState::NeedsDecode;
                        Poll::Ready(Some(Ok(item)))
                    }
                    Ok(None) => Poll::Ready(None),
                    Err(e) => {
                        this.poisoned = true;
                        Poll::Ready(Some(Err(e)))
                    }
                };
            }

            // br-asupersync-yf1bg1: cap each ordinary read at the remaining
            // buffer capacity so transport batching cannot turn several
            // legal frames into one apparent oversized partial frame. At
            // exact capacity, a one-byte probe distinguishes EOF and IO
            // errors from actual over-cap growth without using a zero-length
            // ReadBuf (which would report zero progress even with data ready).
            let read_len = if this.max_buffer_len == 0 {
                READ_BUF_SIZE
            } else {
                this.max_buffer_len
                    .saturating_sub(this.read_buf.len())
                    .clamp(1, READ_BUF_SIZE)
            };
            let mut tmp = [0u8; READ_BUF_SIZE];
            let mut read_buf = ReadBuf::new(&mut tmp[..read_len]);

            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.poisoned = true;
                    return Poll::Ready(Some(Err(e.into())));
                }
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                        this.read_state = ReadState::NeedsDecode;
                    } else {
                        // br-asupersync-bj427s: bound the partial-frame buffer
                        // BEFORE appending so a peer that never completes a
                        // frame cannot drive unbounded per-connection memory
                        // growth. PRE-append so the buffer never crosses the
                        // cap; `0` disables enforcement.
                        if this.max_buffer_len > 0 {
                            let projected = this.read_buf.len().saturating_add(filled.len());
                            if projected > this.max_buffer_len {
                                let cap = this.max_buffer_len;
                                let buffered = this.read_buf.len();
                                let added = filled.len();
                                let err = io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "Framed buffer would exceed max_buffer_len: \
                                         {buffered} + {added} = {projected} > {cap} bytes \
                                         (slowloris-style partial-frame attack? \
                                         see br-asupersync-bj427s)"
                                    ),
                                );
                                this.poisoned = true;
                                return Poll::Ready(Some(Err(err.into())));
                            }
                        }
                        this.read_buf.put_slice(filled);
                        this.read_state = ReadState::NeedsDecode;
                        read_passes += 1;
                        if read_passes >= MAX_READ_PASSES_PER_POLL {
                            should_yield = true;
                        }
                    }
                }
            }
        }
    }
}

// --- Write (sink) methods ---

impl<T, U> Framed<T, U> {
    /// Encodes an item into the write buffer without polling readiness.
    ///
    /// This convenience method is appropriate when the caller immediately
    /// flushes one frame. Repeated producers should use the bounded
    /// [`Framed::poll_ready`] / [`Framed::start_send`] protocol.
    pub fn send<I>(&mut self, item: I) -> Result<(), <U as Encoder<I>>::Error>
    where
        U: Encoder<I>,
    {
        self.start_send(item)
    }

    /// Encodes one item after [`Framed::poll_ready`] reports readiness.
    ///
    /// The boundary is soft: this one encoded frame may exceed it. The caller
    /// must poll readiness again before encoding another frame.
    pub fn start_send<I>(&mut self, item: I) -> Result<(), <U as Encoder<I>>::Error>
    where
        U: Encoder<I>,
    {
        self.read_state = ReadState::NeedsDecode;
        self.codec.encode(item, &mut self.write_buf)
    }
}

impl<T, U> Framed<T, U>
where
    T: AsyncWrite + Unpin,
{
    /// Polls whether another frame may be encoded without bypassing the
    /// configured backpressure boundary.
    ///
    /// Once the current buffer reaches the boundary this flushes it before
    /// returning readiness. A pending transport therefore prevents further
    /// readiness-driven buffer growth.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.len() < self.backpressure_boundary {
            Poll::Ready(Ok(()))
        } else {
            self.poll_flush(cx)
        }
    }

    /// Flush all buffered write data to the underlying transport.
    ///
    /// If the transport reports more bytes written than it was given, returns
    /// `InvalidData` without advancing the buffer for that write.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write_passes = 0usize;
        while !self.write_buf.is_empty() {
            if write_passes >= MAX_WRITE_PASSES_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let remaining = self.write_buf.len();
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
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
            // Discard the just-written bytes. `advance` bumps the front offset
            // in place — no alloc + memcpy of a throwaway `split_to` head per
            // write pass (up to MAX_WRITE_PASSES_PER_POLL passes per flush).
            self.write_buf.advance(n);
            write_passes += 1;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// Flush all buffered data and shut down the transport.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: std::fmt::Debug, U: std::fmt::Debug> std::fmt::Debug for Framed<T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framed")
            .field("inner", &self.inner)
            .field("codec", &self.codec)
            .field("read_buf_len", &self.read_buf.len())
            .field("write_buf_len", &self.write_buf.len())
            .field("backpressure_boundary", &self.backpressure_boundary)
            .field("eof", &self.eof)
            .finish()
    }
}

#[cfg(test)]
#[path = "framed_inline_tests.rs"]
mod tests;
