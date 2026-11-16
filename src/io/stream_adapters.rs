//! Bridges between byte streams, sinks, and async I/O.
//!
//! These adapters cover the common bridge patterns used by middleware and
//! protocol glue:
//!
//! - [`ReaderStream`]: `AsyncRead` -> `Stream<Item = io::Result<Vec<u8>>>`
//! - [`StreamReader`]: `Stream<Item = io::Result<Vec<u8>>>` -> `AsyncRead` / `AsyncBufRead`
//! - [`SinkWriter`]: `Sink<Vec<u8>>` -> `AsyncWrite`

use super::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use crate::stream::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFAULT_CHUNK_SIZE: usize = 8 * 1024;

/// Adapts an [`AsyncRead`] into a stream of byte chunks.
///
/// Any in-place read progress is yielded exactly once, including bytes filled
/// before a provider returns `Pending`. If a read fills bytes and returns an
/// error, those bytes are yielded first and the original error on the next
/// poll. An error or clean EOF then fuses the stream without polling the reader
/// again. Empty pending reads are not EOF.
///
/// A reader panic propagates and fences this adapter if the caller catches the
/// unwind; a substituted destination buffer also terminates it with
/// `InvalidData`. Neither case retries an input position with unknown effects.
#[derive(Debug)]
pub struct ReaderStream<R> {
    reader: R,
    chunk_size: usize,
    done: bool,
    scratch: Vec<u8>,
    pending_error: Option<io::Error>,
    poisoned: bool,
}

impl<R> ReaderStream<R> {
    /// Creates a new `ReaderStream` with the default chunk size (8 KiB).
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, DEFAULT_CHUNK_SIZE)
    }

    /// Creates a new `ReaderStream` with a custom chunk size.
    #[must_use]
    pub fn with_capacity(reader: R, chunk_size: usize) -> Self {
        let chunk_size = chunk_size.max(1);
        Self {
            reader,
            chunk_size,
            done: false,
            scratch: vec![0; chunk_size],
            pending_error: None,
            poisoned: false,
        }
    }

    /// Returns a reference to the inner reader.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Returns a mutable reference to the inner reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consumes the adapter and returns the inner reader.
    ///
    /// Any deferred error is discarded; chunks already yielded remain owned
    /// by their recipients. A pending operation inside the reader retains that
    /// reader's own resume/drop contract.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: AsyncRead + Unpin> Stream for ReaderStream<R> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if let Some(error) = this.pending_error.take() {
            this.done = true;
            return Poll::Ready(Some(Err(error)));
        }
        if this.poisoned {
            this.done = true;
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream reader has unknown effects after a provider failure",
            ))));
        }

        if this.scratch.len() != this.chunk_size {
            this.scratch.resize(this.chunk_size, 0);
        }

        let start = this.scratch.as_ptr();
        let offered = this.scratch.len();
        // Arm before invoking provider code: a caught unwind must not re-read
        // a source whose position may have changed without a usable count.
        this.poisoned = true;
        let (result, filled) = {
            let mut read_buf = ReadBuf::new(&mut this.scratch);
            let result = Pin::new(&mut this.reader).poll_read(cx, &mut read_buf);
            if !super::transfer_session::filled_in_place(read_buf.filled(), start, offered) {
                this.done = true;
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream reader replaced its destination buffer",
                ))));
            }
            (result, read_buf.filled().len())
        };
        this.poisoned = false;

        if filled != 0 {
            if let Poll::Ready(Err(error)) = result {
                this.pending_error = Some(error);
            }
            return Poll::Ready(Some(Ok(this.scratch[..filled].to_vec())));
        }

        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.done = true;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Ok(())) => {
                this.done = true;
                Poll::Ready(None)
            }
        }
    }
}

/// Adapts a byte stream into [`AsyncRead`] and [`AsyncBufRead`] implementations.
///
/// Buffered reads borrow the current chunk without copying or consuming it.
/// [`super::copy_buf`] consumes those bytes only after a successful write, so a
/// dropped copy future leaves unwritten data in this adapter for a later retry.
/// Keep the adapter itself alive: dropping it or calling `into_inner` discards
/// any buffered remainder and deferred error. Empty chunks are not EOF; only
/// the underlying stream's `None` ends the byte stream.
#[derive(Debug)]
pub struct StreamReader<S> {
    stream: S,
    current: Vec<u8>,
    offset: usize,
    pending_error: Option<io::Error>,
    done: bool,
}

impl<S> StreamReader<S> {
    /// Creates a new `StreamReader`.
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            current: Vec::new(),
            offset: 0,
            pending_error: None,
            done: false,
        }
    }

    /// Returns a reference to the inner stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the adapter and returns the inner stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> AsyncRead for StreamReader<S>
where
    S: Stream<Item = io::Result<Vec<u8>>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let mut steps = 0;

        loop {
            if steps > 32 {
                cx.waker().wake_by_ref();
                if buf.filled().len() == filled_before {
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(()));
            }
            steps += 1;

            if this.offset < this.current.len() {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                let remaining = &this.current[this.offset..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                this.offset += to_copy;
                if this.offset == this.current.len() {
                    this.current.clear();
                    this.offset = 0;
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            if let Some(err) = this.pending_error.take() {
                if buf.filled().len() == filled_before {
                    return Poll::Ready(Err(err));
                }
                this.pending_error = Some(err);
                return Poll::Ready(Ok(()));
            }

            if this.done {
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut this.stream).poll_next(cx) {
                Poll::Pending => {
                    if buf.filled().len() == filled_before {
                        return Poll::Pending;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    this.done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    this.current = chunk;
                    this.offset = 0;
                }
                Poll::Ready(Some(Err(err))) => {
                    if buf.filled().len() == filled_before {
                        return Poll::Ready(Err(err));
                    }
                    this.pending_error = Some(err);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S> AsyncBufRead for StreamReader<S>
where
    S: Stream<Item = io::Result<Vec<u8>>> + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.offset < this.current.len() {
            return Poll::Ready(Ok(&this.current[this.offset..]));
        }
        // AsyncRead can observe an error after copying a prefix into its caller's
        // buffer. Switching interfaces must not skip or reorder that error.
        if let Some(error) = this.pending_error.take() {
            return Poll::Ready(Err(error));
        }
        if this.done {
            return Poll::Ready(Ok(&[]));
        }

        // A producer of immediately-ready empty chunks must not monopolize a
        // worker. We have no bytes to report, so yield with a registered wake
        // rather than returning an empty slice (which would falsely signal EOF).
        for _ in 0..32 {
            match Pin::new(&mut this.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.done = true;
                    return Poll::Ready(Ok(&[]));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    this.current = chunk;
                    this.offset = 0;
                    return Poll::Ready(Ok(&this.current));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        // Clamp before addition to avoid overflow or consuming a future chunk.
        this.offset += amount.min(this.current.len() - this.offset);
        if this.offset == this.current.len() {
            this.current.clear();
            this.offset = 0;
        }
    }
}

/// Adapts a sink of owned byte chunks into [`AsyncWrite`].
///
/// Each nonempty write waits for [`Sink::poll_ready`] before copying at most
/// [`Self::max_chunk_size`] bytes into one owned chunk. A successful write
/// reports only that accepted prefix; [`super::AsyncWriteExt::write_all`] can
/// send the rest. The default maximum is 8 KiB. This bounds each adapter-owned
/// allocation; the total retained queue depends on the sink's readiness policy.
///
/// A write does not flush the sink. Flush explicitly before waiting for a peer
/// that needs the bytes, or call shutdown to flush and close the sending side.
///
/// # Cancellation and errors
///
/// A pending write has not submitted any of that call's bytes. A successful
/// write has transferred them to the sink, which must be kept alive to finish
/// its buffered work. Dropping a flush or shutdown future keeps the sink here
/// for another attempt. Dropping this adapter instead drops the sink; its own
/// cleanup contract applies. Inner errors do not imply rollback or durability.
/// After shutdown succeeds, later nonempty writes return `BrokenPipe`; empty
/// writes, flush, and repeated shutdown complete without polling the sink.
///
/// [`crate::codec::FramedWrite`] with [`crate::codec::BytesCodec`] is one native
/// sink that can be used here without a foreign runtime or sink dependency.
#[derive(Debug)]
pub struct SinkWriter<S> {
    sink: S,
    max_chunk_size: usize,
    closed: bool,
}

impl<S> SinkWriter<S> {
    /// Creates a byte writer with a maximum chunk size of 8 KiB.
    #[must_use]
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            max_chunk_size: DEFAULT_CHUNK_SIZE,
            closed: false,
        }
    }

    /// Sets the maximum number of bytes accepted by a single write.
    ///
    /// Zero is raised to one so a nonempty write can always make progress once
    /// the sink becomes ready. This does not alter items already accepted.
    #[must_use]
    pub fn with_max_chunk_size(mut self, max_chunk_size: usize) -> Self {
        self.max_chunk_size = max_chunk_size.max(1);
        self
    }

    /// Returns the maximum size of an owned chunk submitted to the sink.
    #[must_use]
    pub fn max_chunk_size(&self) -> usize {
        self.max_chunk_size
    }

    /// Returns a reference to the underlying sink.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.sink
    }

    /// Returns a mutable reference to the underlying sink.
    ///
    /// Preserve the sink's readiness and ordering protocol when using it
    /// directly. Successful adapter shutdown remains terminal even if the
    /// sink is subsequently changed through this reference.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Returns the underlying sink, including any work it retains.
    ///
    /// This does not flush or close the sink.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.sink
    }
}

impl<S> AsyncWrite for SinkWriter<S>
where
    S: Sink<Vec<u8>> + Unpin,
    S::Error: Into<io::Error>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "cannot write after the byte sink has closed",
            )));
        }
        match Pin::new(&mut this.sink).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(())) => {}
        }

        // Do not allocate or transfer the caller's bytes until admission
        // succeeds. There is no suspension between acceptance and its count.
        let count = buf.len().min(this.max_chunk_size);
        match Pin::new(&mut this.sink).start_send(buf[..count].to_vec()) {
            Ok(()) => Poll::Ready(Ok(count)),
            Err(error) => Poll::Ready(Err(error.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.sink).poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut this.sink).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(())) => {
                this.closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
#[path = "stream_reader_buf_tests.rs"]
mod buffered_tests;

#[cfg(test)]
#[path = "stream_adapters_inline_tests.rs"]
mod tests;
