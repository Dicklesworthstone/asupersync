//! Async copy operations between readers and writers.
//!
//! This module provides efficient async copy operations with progress tracking.
//!
//! # Cancel Safety
//!
//! - [`Copy`]: Cancel-safe. Bytes already written to the destination remain committed.
//! - [`CopyBuf`]: Cancel-safe. Bytes already written remain committed.
//! - [`CopyWithProgress`]: Cancel-safe. Progress callback receives accurate byte counts.
//! - [`CopyBidirectional`]: Cancel-safe. Both directions can be partially complete.

use super::{AsyncRead, AsyncWrite, ReadBuf};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default buffer size for copy operations.
const DEFAULT_BUF_SIZE: usize = 8192;

/// Copy all data from a reader to a writer.
///
/// Returns the total number of bytes copied.
///
/// # Cancel Safety
///
/// This future is cancel-safe. Bytes already written to the writer remain
/// committed. If cancelled, the returned byte count reflects all data that
/// was successfully written before cancellation.
///
/// # Example
///
/// ```ignore
/// let mut reader: &[u8] = b"hello world";
/// let mut writer = Vec::new();
/// let n = copy(&mut reader, &mut writer).await?;
/// assert_eq!(n, 11);
/// assert_eq!(writer, b"hello world");
/// ```
pub fn copy<'a, R, W>(reader: &'a mut R, writer: &'a mut W) -> Copy<'a, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    Copy {
        reader,
        writer,
        buf: [0u8; DEFAULT_BUF_SIZE],
        read_done: false,
        pos: 0,
        cap: 0,
        total: 0,
        yield_counter: 0,
    }
}

/// Future for the [`copy`] function.
pub struct Copy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    buf: [u8; DEFAULT_BUF_SIZE],
    read_done: bool,
    pos: usize,
    cap: usize,
    total: u64,
    yield_counter: u8,
}

impl<R, W> Future for Copy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            // If we have buffered data, write it
            if this.pos < this.cap {
                match Pin::new(&mut *this.writer).poll_write(cx, &this.buf[this.pos..this.cap]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(n)) => {
                        this.pos += n;
                        this.total += n as u64;
                        continue;
                    }
                }
            }

            // If read is done and buffer is empty, we're finished
            if this.read_done {
                return Poll::Ready(Ok(this.total));
            }

            // Read more data
            let mut read_buf = ReadBuf::new(&mut this.buf);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.read_done = true;
                    } else {
                        this.pos = 0;
                        this.cap = n;
                    }
                }
            }
        }
    }
}

/// Buffered read trait for efficient copy operations.
///
/// This is a minimal version of `BufRead` for async contexts.
pub trait AsyncBufRead: AsyncRead {
    /// Returns the contents of the internal buffer, filling it if empty.
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>>;

    /// Tells the buffer that `amt` bytes have been consumed.
    fn consume(self: Pin<&mut Self>, amt: usize);
}

impl AsyncBufRead for &[u8] {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        Poll::Ready(Ok(this))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        let to_consume = std::cmp::min(amt, this.len());
        *this = &this[to_consume..];
    }
}

impl<T> AsyncBufRead for std::io::Cursor<T>
where
    T: AsRef<[u8]> + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        let data = this.get_ref().as_ref();
        let pos = std::cmp::min(this.position() as usize, data.len());
        Poll::Ready(Ok(&data[pos..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        let data_len = this.get_ref().as_ref().len() as u64;
        let pos = this.position();
        let advance = std::cmp::min(amt as u64, data_len.saturating_sub(pos));
        this.set_position(pos.saturating_add(advance));
    }
}

/// Copy all data from a buffered reader to a writer.
///
/// More efficient than [`copy`] when the reader is already buffered.
///
/// # Cancel Safety
///
/// This future is cancel-safe. Bytes already written remain committed.
pub fn copy_buf<'a, R, W>(reader: &'a mut R, writer: &'a mut W) -> CopyBuf<'a, R, W>
where
    R: AsyncBufRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    CopyBuf {
        reader,
        writer,
        total: 0,
        yield_counter: 0,
    }
}

/// Future for the [`copy_buf`] function.
pub struct CopyBuf<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    total: u64,
    yield_counter: u8,
}

impl<R, W> Future for CopyBuf<'_, R, W>
where
    R: AsyncBufRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            let buf = match Pin::new(&mut *this.reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(buf)) => buf,
            };

            if buf.is_empty() {
                return Poll::Ready(Ok(this.total));
            }

            let n = match Pin::new(&mut *this.writer).poll_write(cx, buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => n,
            };

            Pin::new(&mut *this.reader).consume(n);
            this.total += n as u64;
        }
    }
}

/// Copy all data from a reader to a writer with progress reporting.
///
/// The callback `on_progress` is called after each successful write with
/// the cumulative total bytes written so far.
///
/// # Cancel Safety
///
/// This future is cancel-safe. The progress callback receives accurate
/// cumulative byte counts.
///
/// # Example
///
/// ```ignore
/// let mut reader: &[u8] = b"hello world";
/// let mut writer = Vec::new();
/// let n = copy_with_progress(&mut reader, &mut writer, |total| {
///     println!("Copied {} bytes", total);
/// }).await?;
/// ```
pub fn copy_with_progress<'a, R, W, F>(
    reader: &'a mut R,
    writer: &'a mut W,
    on_progress: F,
) -> CopyWithProgress<'a, R, W, F>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
    F: FnMut(u64),
{
    CopyWithProgress {
        reader,
        writer,
        on_progress,
        buf: [0u8; DEFAULT_BUF_SIZE],
        read_done: false,
        pos: 0,
        cap: 0,
        total: 0,
        yield_counter: 0,
    }
}

/// Future for the [`copy_with_progress`] function.
pub struct CopyWithProgress<'a, R: ?Sized, W: ?Sized, F> {
    reader: &'a mut R,
    writer: &'a mut W,
    on_progress: F,
    buf: [u8; DEFAULT_BUF_SIZE],
    read_done: bool,
    pos: usize,
    cap: usize,
    total: u64,
    yield_counter: u8,
}

impl<R, W, F> Future for CopyWithProgress<'_, R, W, F>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
    F: FnMut(u64) + Unpin,
{
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            if this.yield_counter > 32 {
                this.yield_counter = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.yield_counter += 1;

            // If we have buffered data, write it
            if this.pos < this.cap {
                match Pin::new(&mut *this.writer).poll_write(cx, &this.buf[this.pos..this.cap]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(n)) => {
                        this.pos += n;
                        this.total += n as u64;
                        (this.on_progress)(this.total);
                        continue;
                    }
                }
            }

            // If read is done and buffer is empty, we're finished
            if this.read_done {
                return Poll::Ready(Ok(this.total));
            }

            // Read more data
            let mut read_buf = ReadBuf::new(&mut this.buf);
            match Pin::new(&mut *this.reader).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.read_done = true;
                    } else {
                        this.pos = 0;
                        this.cap = n;
                    }
                }
            }
        }
    }
}

/// Bidirectional copy between two streams.
///
/// Copies data in both directions simultaneously:
/// - From `a` to `b`
/// - From `b` to `a`
///
/// Returns the number of bytes copied in each direction: `(a_to_b, b_to_a)`.
///
/// This is useful for proxying, tunneling, and other bidirectional protocols.
///
/// # Cancel Safety
///
/// This future is cancel-safe. Both directions can be partially complete
/// upon cancellation. The returned byte counts reflect all data that was
/// successfully written in each direction.
///
/// # Example
///
/// ```ignore
/// let (a_to_b, b_to_a) = copy_bidirectional(&mut stream_a, &mut stream_b).await?;
/// println!("A->B: {} bytes, B->A: {} bytes", a_to_b, b_to_a);
/// ```
pub fn copy_bidirectional<'a, A, B>(a: &'a mut A, b: &'a mut B) -> CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b_buf: [0u8; DEFAULT_BUF_SIZE],
        b_to_a_buf: [0u8; DEFAULT_BUF_SIZE],
        a_to_b: TransferState::default(),
        b_to_a: TransferState::default(),
        a_to_b_total: 0,
        b_to_a_total: 0,
        steps: 0,
    }
}

/// State for one direction of bidirectional copy.
#[derive(Default)]
struct TransferState {
    read_done: bool,
    shutdown_done: bool,
    pos: usize,
    cap: usize,
}

/// Future for the [`copy_bidirectional`] function.
pub struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b_buf: [u8; DEFAULT_BUF_SIZE],
    b_to_a_buf: [u8; DEFAULT_BUF_SIZE],
    a_to_b: TransferState,
    b_to_a: TransferState,
    a_to_b_total: u64,
    b_to_a_total: u64,
    steps: usize,
}

const YIELD_BUDGET: usize = 64;

/// Result of a single transfer step.
enum TransferResult {
    /// Direction is fully complete (read done, buffer flushed, shutdown done).
    Done,
    /// Blocked on I/O.
    Pending,
    /// Made progress (read or wrote bytes, or shutdown).
    Progress,
    /// Encountered an error.
    Error(io::Error),
}

impl<A, B> CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    /// Perform one step of A->B transfer.
    fn step_a_to_b(&mut self, cx: &mut Context<'_>) -> TransferResult {
        let state = &mut self.a_to_b;

        // 1. Try to write buffered data to B
        if state.pos < state.cap {
            match Pin::new(&mut *self.b).poll_write(cx, &self.a_to_b_buf[state.pos..state.cap]) {
                Poll::Pending => return TransferResult::Pending,
                Poll::Ready(Err(err)) => return TransferResult::Error(err),
                Poll::Ready(Ok(0)) => {
                    return TransferResult::Error(io::Error::from(io::ErrorKind::WriteZero));
                }
                Poll::Ready(Ok(n)) => {
                    state.pos += n;
                    self.a_to_b_total += n as u64;
                    return TransferResult::Progress;
                }
            }
        }

        // 2. If read from A is done and buffer is empty, shutdown B and finish
        if state.read_done {
            if !state.shutdown_done {
                match Pin::new(&mut *self.b).poll_shutdown(cx) {
                    Poll::Pending => return TransferResult::Pending,
                    Poll::Ready(Err(err)) => return TransferResult::Error(err),
                    Poll::Ready(Ok(())) => {
                        state.shutdown_done = true;
                        return TransferResult::Progress;
                    }
                }
            }
            return TransferResult::Done;
        }

        // 3. Read more data from A
        // Reset buffer state if empty (it should be empty here due to check 1)
        state.pos = 0;
        state.cap = 0;

        let mut read_buf = ReadBuf::new(&mut self.a_to_b_buf);
        match Pin::new(&mut *self.a).poll_read(cx, &mut read_buf) {
            Poll::Pending => TransferResult::Pending,
            Poll::Ready(Err(err)) => TransferResult::Error(err),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    state.read_done = true;
                }
                state.cap = n;
                // We just learned we are done (or read data).
                // If done, next call will hit check 2 (buffer empty + read_done).
                TransferResult::Progress
            }
        }
    }

    /// Perform one step of B->A transfer.
    fn step_b_to_a(&mut self, cx: &mut Context<'_>) -> TransferResult {
        let state = &mut self.b_to_a;

        // 1. Try to write buffered data to A
        if state.pos < state.cap {
            match Pin::new(&mut *self.a).poll_write(cx, &self.b_to_a_buf[state.pos..state.cap]) {
                Poll::Pending => return TransferResult::Pending,
                Poll::Ready(Err(err)) => return TransferResult::Error(err),
                Poll::Ready(Ok(0)) => {
                    return TransferResult::Error(io::Error::from(io::ErrorKind::WriteZero));
                }
                Poll::Ready(Ok(n)) => {
                    state.pos += n;
                    self.b_to_a_total += n as u64;
                    return TransferResult::Progress;
                }
            }
        }

        // 2. If read from B is done and buffer is empty, shutdown A and finish
        if state.read_done {
            if !state.shutdown_done {
                match Pin::new(&mut *self.a).poll_shutdown(cx) {
                    Poll::Pending => return TransferResult::Pending,
                    Poll::Ready(Err(err)) => return TransferResult::Error(err),
                    Poll::Ready(Ok(())) => {
                        state.shutdown_done = true;
                        return TransferResult::Progress;
                    }
                }
            }
            return TransferResult::Done;
        }

        // 3. Read more data from B
        state.pos = 0;
        state.cap = 0;

        let mut read_buf = ReadBuf::new(&mut self.b_to_a_buf);
        match Pin::new(&mut *self.b).poll_read(cx, &mut read_buf) {
            Poll::Pending => TransferResult::Pending,
            Poll::Ready(Err(err)) => TransferResult::Error(err),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    state.read_done = true;
                }
                state.cap = n;
                TransferResult::Progress
            }
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Poll both directions, interleaved, until both block or are done
        loop {
            // Check yield budget to prevent starvation
            if this.steps >= YIELD_BUDGET {
                this.steps = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let mut made_progress = false;

            // Step A->B
            match this.step_a_to_b(cx) {
                TransferResult::Progress => made_progress = true,
                TransferResult::Error(e) => return Poll::Ready(Err(e)),
                TransferResult::Done | TransferResult::Pending => {}
            }

            // Step B->A
            match this.step_b_to_a(cx) {
                TransferResult::Progress => made_progress = true,
                TransferResult::Error(e) => return Poll::Ready(Err(e)),
                TransferResult::Done | TransferResult::Pending => {}
            }

            if made_progress {
                this.steps += 1;
            } else {
                // Check if both are done (read complete, buffer flushed, AND shutdown complete)
                let a_to_b_done = this.a_to_b.read_done
                    && this.a_to_b.pos >= this.a_to_b.cap
                    && this.a_to_b.shutdown_done;
                let b_to_a_done = this.b_to_a.read_done
                    && this.b_to_a.pos >= this.b_to_a.cap
                    && this.b_to_a.shutdown_done;

                if a_to_b_done && b_to_a_done {
                    return Poll::Ready(Ok((this.a_to_b_total, this.b_to_a_total)));
                }
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn poll_ready<F: Future>(fut: &mut Pin<&mut F>) -> Option<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..1024 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return Some(output);
            }
        }
        None
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn copy_small_data() {
        init_test("copy_small_data");
        let mut reader: &[u8] = b"hello world";
        let mut writer = Vec::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 11, "bytes", 11, n);
        crate::assert_with_log!(writer == b"hello world", "writer", b"hello world", writer);
        crate::test_complete!("copy_small_data");
    }

    #[test]
    fn copy_empty_data() {
        init_test("copy_empty_data");
        let mut reader: &[u8] = b"";
        let mut writer = Vec::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 0, "bytes", 0, n);
        let empty = writer.is_empty();
        crate::assert_with_log!(empty, "writer empty", true, empty);
        crate::test_complete!("copy_empty_data");
    }

    #[test]
    fn copy_large_data() {
        init_test("copy_large_data");
        let data: Vec<u8> = (0u32..32768).map(|i| (i % 256) as u8).collect();
        let mut reader: &[u8] = &data;
        let mut writer = Vec::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 32768, "bytes", 32768, n);
        crate::assert_with_log!(writer == data, "writer", data, writer);
        crate::test_complete!("copy_large_data");
    }

    #[test]
    fn copy_with_progress_tracks_bytes() {
        init_test("copy_with_progress_tracks_bytes");
        let mut reader: &[u8] = b"hello world";
        let mut writer = Vec::new();
        let mut progress_calls = Vec::new();
        let mut fut = copy_with_progress(&mut reader, &mut writer, |total| {
            progress_calls.push(total);
        });
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 11, "bytes", 11, n);
        crate::assert_with_log!(writer == b"hello world", "writer", b"hello world", writer);
        // Progress should be called with increasing values
        let empty = progress_calls.is_empty();
        crate::assert_with_log!(!empty, "progress calls", false, empty);
        let last = *progress_calls.last().unwrap();
        crate::assert_with_log!(last == 11, "last progress", 11, last);
        crate::test_complete!("copy_with_progress_tracks_bytes");
    }

    #[test]
    fn copy_buf_reads_from_slice() {
        init_test("copy_buf_reads_from_slice");
        let mut reader: &[u8] = b"hello buffer";
        let mut writer = Vec::new();
        let mut fut = copy_buf(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 12, "bytes", 12, n);
        crate::assert_with_log!(writer == b"hello buffer", "writer", b"hello buffer", writer);
        let empty = reader.is_empty();
        crate::assert_with_log!(empty, "reader empty", true, empty);
        crate::test_complete!("copy_buf_reads_from_slice");
    }

    #[test]
    fn copy_buf_reads_from_cursor() {
        init_test("copy_buf_reads_from_cursor");
        let data = b"cursor data";
        let mut reader = std::io::Cursor::new(data);
        let mut writer = Vec::new();
        let mut fut = copy_buf(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 11, "bytes", 11, n);
        crate::assert_with_log!(writer == data, "writer", data, writer);
        crate::test_complete!("copy_buf_reads_from_cursor");
    }

    /// A simple duplex stream for testing bidirectional copy.
    struct TestDuplex {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        shutdown_called: bool,
    }

    impl TestDuplex {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_data: read_data.to_vec(),
                read_pos: 0,
                written: Vec::new(),
                shutdown_called: false,
            }
        }
    }

    impl AsyncRead for TestDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.read_pos >= this.read_data.len() {
                return Poll::Ready(Ok(()));
            }
            let to_copy = std::cmp::min(this.read_data.len() - this.read_pos, buf.remaining());
            buf.put_slice(&this.read_data[this.read_pos..this.read_pos + to_copy]);
            this.read_pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().shutdown_called = true;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn copy_bidirectional_basic() {
        init_test("copy_bidirectional_basic");
        let mut a = TestDuplex::new(b"from A");
        let mut b = TestDuplex::new(b"from B");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 6, "a_to_b", 6, a_to_b);
        crate::assert_with_log!(b_to_a == 6, "b_to_a", 6, b_to_a);
        crate::assert_with_log!(b.written == b"from A", "b written", b"from A", b.written);
        crate::assert_with_log!(a.written == b"from B", "a written", b"from B", a.written);
        crate::test_complete!("copy_bidirectional_basic");
    }

    #[test]
    fn copy_bidirectional_propagates_shutdown() {
        init_test("copy_bidirectional_propagates_shutdown");
        let mut a = TestDuplex::new(b"from A");
        let mut b = TestDuplex::new(b"from B");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let _ = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();

        crate::assert_with_log!(a.shutdown_called, "a shutdown", true, a.shutdown_called);
        crate::assert_with_log!(b.shutdown_called, "b shutdown", true, b.shutdown_called);
        crate::test_complete!("copy_bidirectional_propagates_shutdown");
    }

    #[test]
    fn copy_bidirectional_asymmetric() {
        init_test("copy_bidirectional_asymmetric");
        let mut a = TestDuplex::new(b"short");
        let mut b = TestDuplex::new(b"this is a longer message");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 5, "a_to_b", 5, a_to_b);
        crate::assert_with_log!(b_to_a == 24, "b_to_a", 24, b_to_a);
        crate::assert_with_log!(b.written == b"short", "b written", b"short", b.written);
        crate::assert_with_log!(
            a.written == b"this is a longer message",
            "a written",
            b"this is a longer message",
            a.written
        );
        crate::test_complete!("copy_bidirectional_asymmetric");
    }

    #[test]
    fn copy_bidirectional_empty() {
        init_test("copy_bidirectional_empty");
        let mut a = TestDuplex::new(b"");
        let mut b = TestDuplex::new(b"");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 0, "a_to_b", 0, a_to_b);
        crate::assert_with_log!(b_to_a == 0, "b_to_a", 0, b_to_a);
        crate::test_complete!("copy_bidirectional_empty");
    }

    /// Duplex that defers shutdown by returning Pending on the first call.
    struct DeferredShutdownDuplex {
        inner: TestDuplex,
        shutdown_poll_count: usize,
    }

    impl DeferredShutdownDuplex {
        fn new(read_data: &[u8]) -> Self {
            Self {
                inner: TestDuplex::new(read_data),
                shutdown_poll_count: 0,
            }
        }
    }

    impl AsyncRead for DeferredShutdownDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DeferredShutdownDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.shutdown_poll_count += 1;
            if this.shutdown_poll_count <= 1 {
                // Defer: register waker and return Pending on first call.
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                this.inner.shutdown_called = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    #[test]
    fn copy_bidirectional_waits_for_shutdown_completion() {
        init_test("copy_bidirectional_waits_for_shutdown_completion");
        let mut a = DeferredShutdownDuplex::new(b"hello");
        let mut b = DeferredShutdownDuplex::new(b"world");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 5, "a_to_b", 5, a_to_b);
        crate::assert_with_log!(b_to_a == 5, "b_to_a", 5, b_to_a);
        // Both sides must have completed shutdown.
        let a_shut = a.inner.shutdown_called;
        let b_shut = b.inner.shutdown_called;
        crate::assert_with_log!(a_shut, "a shutdown done", true, a_shut);
        crate::assert_with_log!(b_shut, "b shutdown done", true, b_shut);
        crate::test_complete!("copy_bidirectional_waits_for_shutdown_completion");
    }

    #[test]
    fn copy_bidirectional_yields_on_fast_streams() {
        init_test("copy_bidirectional_yields_on_fast_streams");

        // Use an infinitely fast, infinite stream.
        struct InfiniteStream;
        impl AsyncRead for InfiniteStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let space = buf.remaining();
                let zeros = vec![0u8; space];
                buf.put_slice(&zeros);
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for InfiniteStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut a = InfiniteStream;
        let mut b = InfiniteStream;
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Run poll() in a thread with timeout to detect infinite loop
        let (tx, rx) = std::sync::mpsc::channel();

        // We need to move `fut` into the thread, but `Pin` makes it tricky.
        // Actually, since `InfiniteStream` is ZST and `CopyBidirectional` owns `&mut`,
        // passing `&mut a` across thread boundary is hard.
        // But we can just use `std::thread::scope` or rely on `poll` returning quickly.
        // Or construct the future inside the thread? But `copy_bidirectional` takes lifetimes.

        // Let's just construct everything inside the thread.
        std::thread::spawn(move || {
            let mut a = InfiniteStream;
            let mut b = InfiniteStream;
            let mut fut = copy_bidirectional(&mut a, &mut b);
            let mut fut = Pin::new(&mut fut);

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            // Should return Pending eventually due to yield
            let _ = fut.poll(&mut cx);
            tx.send(true).unwrap();
        });

        // Wait up to 100ms. If it loops forever, we timeout.
        let result = rx.recv_timeout(std::time::Duration::from_millis(100));

        if result.is_err() {
            panic!("copy_bidirectional failed to yield (infinite loop)");
        }

        crate::test_complete!("copy_bidirectional_yields_on_fast_streams");
    }
}
