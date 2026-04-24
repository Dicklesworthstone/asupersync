//! Stream/AsyncRead bridge adapters.
//!
//! These adapters cover the common bridge patterns used by middleware and
//! protocol glue:
//!
//! - [`ReaderStream`]: `AsyncRead` -> `Stream<Item = io::Result<Vec<u8>>>`
//! - [`StreamReader`]: `Stream<Item = io::Result<Vec<u8>>>` -> `AsyncRead`

use super::{AsyncRead, ReadBuf};
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

/// Adapts a byte stream into an [`AsyncRead`] implementation.
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
                    this.done = true;
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
                        this.done = true;
                        return Poll::Ready(Err(err));
                    }
                    this.pending_error = Some(err);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream;

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn poll_read<R: AsyncRead + Unpin>(reader: &mut R, out: &mut [u8]) -> Poll<io::Result<usize>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut read_buf = ReadBuf::new(out);
        match Pin::new(reader).poll_read(&mut cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    #[test]
    fn reader_stream_yields_chunks() {
        init_test("reader_stream_yields_chunks");
        let input: &[u8] = b"abcdef";
        let mut stream = ReaderStream::with_capacity(input, 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(first, Poll::Ready(Some(Ok(chunk))) if chunk == b"ab");
        crate::assert_with_log!(ok, "first chunk", true, ok);

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(second, Poll::Ready(Some(Ok(chunk))) if chunk == b"cd");
        crate::assert_with_log!(ok, "second chunk", true, ok);

        let third = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(third, Poll::Ready(Some(Ok(chunk))) if chunk == b"ef");
        crate::assert_with_log!(ok, "third chunk", true, ok);

        let done = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(done, Poll::Ready(None));
        crate::assert_with_log!(ok, "terminal none", true, ok);
        crate::test_complete!("reader_stream_yields_chunks");
    }

    #[test]
    fn stream_reader_reads_across_multiple_chunks() {
        init_test("stream_reader_reads_across_multiple_chunks");
        let chunks = vec![Ok(vec![1_u8, 2]), Ok(vec![3]), Ok(vec![4, 5])];
        let stream = stream::iter(chunks);
        let mut reader = StreamReader::new(stream);

        let mut out = [0_u8; 5];
        let read = poll_read(&mut reader, &mut out);
        let ok = matches!(read, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ok, "read length", true, ok);
        crate::assert_with_log!(out == [1, 2, 3, 4, 5], "content", [1, 2, 3, 4, 5], out);

        let mut eof = [0_u8; 4];
        let read = poll_read(&mut reader, &mut eof);
        let ok = matches!(read, Poll::Ready(Ok(0)));
        crate::assert_with_log!(ok, "eof", true, ok);
        crate::test_complete!("stream_reader_reads_across_multiple_chunks");
    }

    #[test]
    fn stream_reader_defers_error_until_partial_data_consumed() {
        init_test("stream_reader_defers_error_until_partial_data_consumed");
        let chunks = vec![
            Ok(vec![10_u8, 11]),
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream failed")),
        ];
        let stream = stream::iter(chunks);
        let mut reader = StreamReader::new(stream);

        let mut out = [0_u8; 8];
        let read = poll_read(&mut reader, &mut out);
        let ok = matches!(read, Poll::Ready(Ok(2)));
        crate::assert_with_log!(ok, "partial read before error", true, ok);
        crate::assert_with_log!(out[..2] == [10, 11], "partial content", [10, 11], &out[..2]);

        let mut second = [0_u8; 8];
        let read = poll_read(&mut reader, &mut second);
        let ok = matches!(read, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe);
        crate::assert_with_log!(ok, "error surfaced on next read", true, ok);
        crate::test_complete!("stream_reader_defers_error_until_partial_data_consumed");
    }

    struct PendingThenDataStream {
        state: u8,
    }

    impl PendingThenDataStream {
        fn new() -> Self {
            Self { state: 0 }
        }
    }

    impl Stream for PendingThenDataStream {
        type Item = io::Result<Vec<u8>>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.state {
                0 => {
                    self.state = 1;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                1 => {
                    self.state = 2;
                    Poll::Ready(Some(Ok(vec![7, 8, 9])))
                }
                _ => Poll::Ready(None),
            }
        }
    }

    #[test]
    fn stream_reader_pending_without_buffered_data() {
        init_test("stream_reader_pending_without_buffered_data");
        let mut reader = StreamReader::new(PendingThenDataStream::new());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = [0_u8; 3];
        let mut read_buf = ReadBuf::new(&mut out);
        let first = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ok = first.is_pending();
        crate::assert_with_log!(ok, "first poll pending", true, ok);

        let mut out = [0_u8; 3];
        let mut read_buf = ReadBuf::new(&mut out);
        let second = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ok = matches!(second, Poll::Ready(Ok(()))) && read_buf.filled() == [7, 8, 9];
        crate::assert_with_log!(ok, "second poll reads data", true, ok);
        crate::test_complete!("stream_reader_pending_without_buffered_data");
    }
}
