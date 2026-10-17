//! Stream/AsyncRead bridge adapters.
//!
//! These adapters cover the common bridge patterns used by middleware and
//! protocol glue:
//!
//! - [`ReaderStream`]: `AsyncRead` -> `Stream<Item = io::Result<Vec<u8>>>`
//! - [`StreamReader`]: `Stream<Item = io::Result<Vec<u8>>>` -> `AsyncRead` / `AsyncBufRead`

use super::{AsyncBufRead, AsyncRead, ReadBuf};
use crate::stream::Stream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFAULT_CHUNK_SIZE: usize = 8 * 1024;

/// Adapts an [`AsyncRead`] into a stream of byte chunks.
#[derive(Debug)]
pub struct ReaderStream<R> {
    reader: R,
    chunk_size: usize,
    done: bool,
    scratch: Vec<u8>,
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

        if this.scratch.len() != this.chunk_size {
            this.scratch.resize(this.chunk_size, 0);
        }

        let mut read_buf = ReadBuf::new(&mut this.scratch);
        match Pin::new(&mut this.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.done = true;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    this.done = true;
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(filled.to_vec())))
                }
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

#[cfg(test)]
#[path = "stream_reader_buf_tests.rs"]
mod buffered_tests;

#[cfg(test)]
#[path = "stream_adapters_inline_tests.rs"]
mod tests;
