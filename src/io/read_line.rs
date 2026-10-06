//! Async read-line convenience function.
//!
//! # Cancel Safety
//!
//! [`ReadLine`] is cancel-safe for bytes already appended to the output
//! `String`. If cancelled and then restarted with a fresh `ReadLine`, the
//! caller can observe the partial line already present in the buffer.
//!
//! Incomplete UTF-8 bytes buffered internally are preserved across polls, but
//! they cannot be committed to the `String` until the code point is complete.
//! Dropping the [`read_line`] free-function future before that happens loses
//! the trailing partial code point — the underlying reader has already been
//! `consume()`d for those bytes, and the prefix lives only on the future.
//! For a multi-byte UTF-8 sequence (e.g. an emoji) that straddles a cancel
//! boundary, the *next* call to `read_line` re-reads from the byte AFTER
//! the dropped prefix and decodes the trailing continuation as a leading
//! byte → returns `InvalidData` on a stream that contained valid UTF-8.
//!
//! For cancel-safety across the partial-UTF-8 boundary, use
//! [`LineReader`] — a small wrapper that holds the pending prefix in the
//! reader-owned state instead of in the future. (br-asupersync-ghv5u1)

use super::AsyncBufRead;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Read bytes from `reader` until a newline (`\n`) is found, appending them
/// (including the newline) to `buf`.
///
/// Returns the number of bytes read (including the newline). If the reader
/// reaches EOF without a newline, the remaining bytes are still appended and
/// counted. Returns `Ok(0)` only when the reader is at EOF and no bytes remain.
///
/// A line that is not valid UTF-8 is skipped through its `\n` and returns an
/// `InvalidData` error, leaving `buf` as it was, as std and tokio do.
///
/// `\r\n` line endings are normalised: the `\r` before `\n` is stripped from
/// `buf`, but it **is** counted in the returned byte count (matching
/// `std::io::BufRead::read_line` semantics for the return value).
///
/// If `buf` is reused after a cancelled `ReadLine`, any trailing `\r` already
/// present in `buf` is treated as part of the in-flight line and will be
/// normalised if the resumed read later completes with `\n`. Clear `buf`
/// before starting an unrelated line if you do not want prior contents to
/// participate in that normalization.
///
/// # Cancel Safety
///
/// This future is cancel-safe for bytes already appended to `buf`. The caller
/// should be aware that `buf` may contain a partial line if the future is
/// dropped before completion. As with `read_to_string`, a trailing partial
/// UTF-8 code point buffered internally cannot be committed until it is
/// complete and may be lost if the future is dropped first.
///
/// # Example
///
/// ```ignore
/// use asupersync::io::{BufReader, read_line};
///
/// let mut reader = BufReader::new(&b"hello\nworld\n"[..]);
/// let mut line = String::new();
/// let n = read_line(&mut reader, &mut line).await?;
/// assert_eq!(line, "hello\n");
/// assert_eq!(n, 6);
/// ```
pub fn read_line<'a, R>(reader: &'a mut R, buf: &'a mut String) -> ReadLine<'a, R>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    ReadLine {
        reader,
        start_len: buf.len(),
        buf,
        bytes_read: 0,
        pending: Vec::new(),
        discarding: None,
        completed: false,
    }
}

/// Future for the [`read_line`] function.
pub struct ReadLine<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut String,
    /// `buf`'s length when the call started; a line that is not UTF-8 leaves
    /// `buf` at this length.
    start_len: usize,
    bytes_read: usize,
    /// Holds incomplete UTF-8 bytes that were consumed from the reader
    /// but not yet appended to `buf`.
    pending: Vec<u8>,
    /// Set after invalid UTF-8 in a line whose `\n` has not been read yet:
    /// the rest of the line is skipped before the error is reported.
    discarding: Option<std::str::Utf8Error>,
    completed: bool,
}

fn strip_cr_before_nl(buf: &mut String) {
    let buf_bytes = buf.as_bytes();
    let len = buf_bytes.len();
    if len >= 2 && buf_bytes[len - 2] == b'\r' && buf_bytes[len - 1] == b'\n' {
        let cr_pos = len - 2;
        buf.remove(cr_pos);
    }
}

enum ChunkAction {
    Consume,
    Finish(io::Result<usize>),
    ConsumeAndFinish(io::Result<usize>),
    /// Invalid UTF-8 before this line's `\n`: consume the window and skip
    /// the rest of the line, then report the error.
    ConsumeAndDiscardLine(std::str::Utf8Error),
}

fn invalid_data_result(err: std::str::Utf8Error) -> io::Result<usize> {
    Err(io::Error::new(io::ErrorKind::InvalidData, err))
}

/// An invalid line ends at its `\n` (or at EOF): skip what remains of it, as
/// std and tokio do, so its tail never comes back as the next line. Returns
/// the error once the line is gone, or `None` while more of it may follow.
fn discard_line<R: AsyncBufRead + Unpin + ?Sized>(
    reader: &mut R,
    available_len: usize,
    newline: Option<usize>,
    discarding: &mut Option<std::str::Utf8Error>,
) -> Option<io::Result<usize>> {
    let error = (*discarding)?;
    match newline {
        Some(pos) => {
            Pin::new(reader).consume(pos + 1);
            *discarding = None;
            Some(invalid_data_result(error))
        }
        None if available_len == 0 => {
            *discarding = None;
            Some(invalid_data_result(error))
        }
        None => {
            Pin::new(reader).consume(available_len);
            None
        }
    }
}

/// Only UTF-8 errors reach here (an I/O error from the reader returns earlier
/// and keeps what was read): a line that is not UTF-8 leaves `buf` as the
/// call found it, as std's and tokio's `read_line` do.
fn restore_unless_ok(
    buf: &mut String,
    start_len: usize,
    result: io::Result<usize>,
) -> io::Result<usize> {
    if result.is_err() {
        buf.truncate(start_len);
    }
    result
}

fn append_utf8(buf: &mut String, bytes_read: &mut usize, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let s = std::str::from_utf8(bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    buf.push_str(s);
    *bytes_read += bytes.len();
    Ok(())
}

fn finish_line(buf: &mut String, bytes_read: usize) -> ChunkAction {
    strip_cr_before_nl(buf);
    ChunkAction::ConsumeAndFinish(Ok(bytes_read))
}

fn process_fresh_chunk(
    buf: &mut String,
    pending: &mut Vec<u8>,
    bytes_read: &mut usize,
    chunk: &[u8],
    found_newline: bool,
) -> ChunkAction {
    match std::str::from_utf8(chunk) {
        Ok(s) => {
            buf.push_str(s);
            *bytes_read += chunk.len();
            if found_newline {
                finish_line(buf, *bytes_read)
            } else {
                ChunkAction::Consume
            }
        }
        Err(e) => {
            let valid_len = e.valid_up_to();
            if valid_len > 0 {
                if let Err(err) = append_utf8(buf, bytes_read, &chunk[..valid_len]) {
                    return ChunkAction::Finish(Err(err));
                }
                if found_newline {
                    ChunkAction::ConsumeAndFinish(invalid_data_result(e))
                } else if e.error_len().is_some() {
                    ChunkAction::ConsumeAndDiscardLine(e)
                } else {
                    pending.extend_from_slice(&chunk[valid_len..]);
                    ChunkAction::Consume
                }
            } else if found_newline {
                ChunkAction::ConsumeAndFinish(invalid_data_result(e))
            } else if e.error_len().is_some() {
                ChunkAction::ConsumeAndDiscardLine(e)
            } else {
                pending.extend_from_slice(chunk);
                ChunkAction::Consume
            }
        }
    }
}

fn process_pending_chunk(
    buf: &mut String,
    pending: &mut Vec<u8>,
    bytes_read: &mut usize,
    chunk: &[u8],
    found_newline: bool,
) -> ChunkAction {
    pending.extend_from_slice(chunk);
    match std::str::from_utf8(pending) {
        Ok(s) => {
            let pending_len = pending.len();
            buf.push_str(s);
            *bytes_read += pending_len;
            pending.clear();
            if found_newline {
                finish_line(buf, *bytes_read)
            } else {
                ChunkAction::Consume
            }
        }
        Err(e) => {
            let valid_len = e.valid_up_to();
            if valid_len > 0 {
                if let Err(err) = append_utf8(buf, bytes_read, &pending[..valid_len]) {
                    return ChunkAction::Finish(Err(err));
                }
                pending.drain(..valid_len);
                if found_newline {
                    pending.clear();
                    ChunkAction::ConsumeAndFinish(invalid_data_result(e))
                } else if e.error_len().is_some() {
                    pending.clear();
                    ChunkAction::ConsumeAndDiscardLine(e)
                } else {
                    ChunkAction::Consume
                }
            } else if found_newline {
                pending.clear();
                ChunkAction::ConsumeAndFinish(invalid_data_result(e))
            } else if e.error_len().is_some() {
                pending.clear();
                ChunkAction::ConsumeAndDiscardLine(e)
            } else {
                ChunkAction::Consume
            }
        }
    }
}

impl<R> Future for ReadLine<'_, R>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadLine future polled after completion",
            )));
        }
        let mut steps = 0;

        loop {
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            let available = match Pin::new(&mut *this.reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.completed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(buf)) => buf,
            };

            if this.discarding.is_some() {
                let newline = available.iter().position(|&b| b == b'\n');
                let available_len = available.len();
                if let Some(result) = discard_line(
                    &mut *this.reader,
                    available_len,
                    newline,
                    &mut this.discarding,
                ) {
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, result));
                }
                continue;
            }

            if available.is_empty() {
                if let Err(err) = append_utf8(this.buf, &mut this.bytes_read, &this.pending) {
                    this.pending.clear();
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, Err(err)));
                }
                this.pending.clear();
                this.completed = true;
                return Poll::Ready(Ok(this.bytes_read));
            }

            let (chunk, consume_len, found_newline) = available
                .iter()
                .position(|&b| b == b'\n')
                .map_or((available, available.len(), false), |pos| {
                    (&available[..=pos], pos + 1, true)
                });

            let action = if this.pending.is_empty() {
                process_fresh_chunk(
                    this.buf,
                    &mut this.pending,
                    &mut this.bytes_read,
                    chunk,
                    found_newline,
                )
            } else {
                process_pending_chunk(
                    this.buf,
                    &mut this.pending,
                    &mut this.bytes_read,
                    chunk,
                    found_newline,
                )
            };

            match action {
                ChunkAction::Consume => Pin::new(&mut *this.reader).consume(consume_len),
                ChunkAction::Finish(result) => {
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, result));
                }
                ChunkAction::ConsumeAndFinish(result) => {
                    Pin::new(&mut *this.reader).consume(consume_len);
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, result));
                }
                ChunkAction::ConsumeAndDiscardLine(error) => {
                    Pin::new(&mut *this.reader).consume(consume_len);
                    this.discarding = Some(error);
                }
            }
        }
    }
}

// ============================================================================
// br-asupersync-ghv5u1: cancel-safe LineReader wrapper.
//
// The free `read_line` function above stores the partial UTF-8 prefix on the
// future itself. If the future is dropped between consuming bytes from the
// underlying reader and appending the completed codepoint to the user's
// String, those bytes are lost — the reader has already been `consume()`d
// past them.
//
// `LineReader` solves this by hoisting the prefix `Vec<u8>` onto a wrapper
// struct that owns the underlying reader. Each `LineReader::read_line` call
// borrows the wrapper's `pending` field, so cancelling the future leaves
// the partial prefix in the wrapper for the next call. The user holds a
// `LineReader` and the same `String` across read_line invocations and gets
// bit-exact resumption on cancel: complete codepoints are already in the
// String, only the partial one waits in the wrapper.
// ============================================================================

/// Cancel-safe wrapper that holds the partial UTF-8 prefix for a sequence of
/// [`LineReader::read_line`] calls (br-asupersync-ghv5u1).
///
/// Use this in place of the bare `read_line` function whenever the calling
/// future may be cancelled between codepoints — for example a server loop
/// that reads lines from a TCP socket and times out the line read mid-emoji.
///
/// # Example
///
/// ```ignore
/// use asupersync::io::{BufReader, LineReader};
///
/// let mut reader = LineReader::new(BufReader::new(socket));
/// // Keep the String across calls. A read cancelled mid-line leaves the
/// // complete part of the line here and the partial codepoint in `reader`;
/// // a fresh String per call would drop the start of the line.
/// let mut line = String::new();
/// loop {
///     let n = reader.read_line(&mut line).await?;
///     if n == 0 { break; }
///     handle_line(&line);
///     line.clear();
/// }
/// ```
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    pending: Vec<u8>,
    /// Kept here, like `pending`, so a cancelled call still skips the rest
    /// of an invalid line before the next call reads a new one.
    discarding: Option<std::str::Utf8Error>,
}

impl<R> LineReader<R> {
    /// Wrap an `AsyncBufRead` for cancel-safe line reads.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            discarding: None,
        }
    }

    /// Get a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Get a mutable reference to the wrapped reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consume the wrapper and return the underlying reader plus any
    /// partial UTF-8 prefix that has not yet been committed.
    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.inner, self.pending)
    }
}

impl<R> LineReader<R>
where
    R: AsyncBufRead + Unpin,
{
    /// Cancel-safe equivalent of [`read_line`]. The partial UTF-8 prefix
    /// is held on `self.pending` so cancelling the returned future does
    /// not lose bytes that straddle the cancel boundary.
    pub fn read_line<'a>(&'a mut self, buf: &'a mut String) -> ReadLineCancelSafe<'a, R> {
        ReadLineCancelSafe {
            reader: &mut self.inner,
            start_len: buf.len(),
            buf,
            bytes_read: 0,
            pending: &mut self.pending,
            discarding: &mut self.discarding,
            completed: false,
        }
    }
}

/// Future for the cancel-safe [`LineReader::read_line`] method
/// (br-asupersync-ghv5u1). Mirrors [`ReadLine`] but borrows the partial-
/// prefix buffer from the parent [`LineReader`] so it survives cancel.
pub struct ReadLineCancelSafe<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut String,
    /// `buf`'s length when the call started, as on [`ReadLine`].
    start_len: usize,
    bytes_read: usize,
    pending: &'a mut Vec<u8>,
    discarding: &'a mut Option<std::str::Utf8Error>,
    completed: bool,
}

impl<R> Future for ReadLineCancelSafe<'_, R>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other(
                "ReadLineCancelSafe future polled after completion",
            )));
        }
        let mut steps = 0;

        loop {
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            let available = match Pin::new(&mut *this.reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.completed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(buf)) => buf,
            };

            if this.discarding.is_some() {
                let newline = available.iter().position(|&b| b == b'\n');
                let available_len = available.len();
                if let Some(result) =
                    discard_line(&mut *this.reader, available_len, newline, this.discarding)
                {
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, result));
                }
                continue;
            }

            if available.is_empty() {
                if let Err(err) = append_utf8(this.buf, &mut this.bytes_read, this.pending) {
                    // An incomplete code point at EOF is reported once; the
                    // next call then sees a plain EOF instead of this error
                    // again forever.
                    this.pending.clear();
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, Err(err)));
                }
                this.pending.clear();
                this.completed = true;
                return Poll::Ready(Ok(this.bytes_read));
            }

            let (chunk, consume_len, found_newline) = available
                .iter()
                .position(|&b| b == b'\n')
                .map_or((available, available.len(), false), |pos| {
                    (&available[..=pos], pos + 1, true)
                });

            let action = if this.pending.is_empty() {
                process_fresh_chunk(
                    this.buf,
                    this.pending,
                    &mut this.bytes_read,
                    chunk,
                    found_newline,
                )
            } else {
                process_pending_chunk(
                    this.buf,
                    this.pending,
                    &mut this.bytes_read,
                    chunk,
                    found_newline,
                )
            };

            match action {
                ChunkAction::Consume => Pin::new(&mut *this.reader).consume(consume_len),
                ChunkAction::Finish(result) => {
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, result));
                }
                ChunkAction::ConsumeAndFinish(result) => {
                    Pin::new(&mut *this.reader).consume(consume_len);
                    this.completed = true;
                    return Poll::Ready(restore_unless_ok(this.buf, this.start_len, result));
                }
                ChunkAction::ConsumeAndDiscardLine(error) => {
                    Pin::new(&mut *this.reader).consume(consume_len);
                    *this.discarding = Some(error);
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
    use crate::io::BufReader;
    use crate::io::{AsyncBufRead, AsyncRead, ReadBuf};

    use std::task::{Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
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

    struct SplitReader {
        chunks: Vec<Vec<u8>>,
    }

    impl AsyncRead for SplitReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            unreachable!("read_line should use poll_fill_buf for this test")
        }
    }

    impl AsyncBufRead for SplitReader {
        fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let this = self.get_mut();
            if this.chunks.is_empty() {
                Poll::Ready(Ok(&[]))
            } else {
                Poll::Ready(Ok(&this.chunks[0]))
            }
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            let this = self.get_mut();
            if this.chunks.is_empty() {
                return;
            }
            if amt >= this.chunks[0].len() {
                this.chunks.remove(0);
            } else {
                this.chunks[0] = this.chunks[0][amt..].to_vec();
            }
        }
    }

    struct PendingBetweenChunksReader {
        chunks: Vec<Vec<u8>>,
        pending_once: bool,
    }

    impl AsyncRead for PendingBetweenChunksReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            unreachable!("read_line should use poll_fill_buf for this test")
        }
    }

    impl AsyncBufRead for PendingBetweenChunksReader {
        fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let this = self.get_mut();
            if this.pending_once {
                this.pending_once = false;
                return Poll::Pending;
            }

            if this.chunks.is_empty() {
                Poll::Ready(Ok(&[]))
            } else {
                Poll::Ready(Ok(&this.chunks[0]))
            }
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            let this = self.get_mut();
            if this.chunks.is_empty() {
                return;
            }

            if amt >= this.chunks[0].len() {
                this.chunks.remove(0);
                this.pending_once = !this.chunks.is_empty();
            } else {
                this.chunks[0] = this.chunks[0][amt..].to_vec();
            }
        }
    }

    #[test]
    fn read_line_basic() {
        init_test("read_line_basic");
        let mut reader = BufReader::new(&b"hello\nworld\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 6, "bytes", 6, n);
        crate::assert_with_log!(line == "hello\n", "line", "hello\n", line);
        crate::test_complete!("read_line_basic");
    }

    #[test]
    fn read_line_crlf() {
        init_test("read_line_crlf");
        let mut reader = BufReader::new(&b"hello\r\nworld\r\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        // \r\n is 7 bytes read, but \r is stripped from the string
        crate::assert_with_log!(n == 7, "bytes", 7, n);
        crate::assert_with_log!(line == "hello\n", "line", "hello\n", line);
        crate::test_complete!("read_line_crlf");
    }

    #[test]
    fn read_line_eof_no_newline() {
        init_test("read_line_eof_no_newline");
        let mut reader = BufReader::new(&b"no newline"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 10, "bytes", 10, n);
        crate::assert_with_log!(line == "no newline", "line", "no newline", line);
        crate::test_complete!("read_line_eof_no_newline");
    }

    #[test]
    fn read_line_empty() {
        init_test("read_line_empty");
        let mut reader = BufReader::new(&b""[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 0, "bytes", 0, n);
        let empty = line.is_empty();
        crate::assert_with_log!(empty, "line empty", true, empty);
        crate::test_complete!("read_line_empty");
    }

    #[test]
    fn read_line_successive() {
        init_test("read_line_successive");
        let mut reader = BufReader::new(&b"first\nsecond\n"[..]);

        let mut line1 = String::new();
        let mut fut = read_line(&mut reader, &mut line1);
        let mut fut = Pin::new(&mut fut);
        let n1 = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n1 == 6, "bytes1", 6, n1);
        crate::assert_with_log!(line1 == "first\n", "line1", "first\n", line1);

        let mut line2 = String::new();
        let mut fut = read_line(&mut reader, &mut line2);
        let mut fut = Pin::new(&mut fut);
        let n2 = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n2 == 7, "bytes2", 7, n2);
        crate::assert_with_log!(line2 == "second\n", "line2", "second\n", line2);

        // EOF
        let mut line3 = String::new();
        let mut fut = read_line(&mut reader, &mut line3);
        let mut fut = Pin::new(&mut fut);
        let n3 = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n3 == 0, "bytes3", 0, n3);
        crate::test_complete!("read_line_successive");
    }

    #[test]
    fn read_line_only_newline() {
        init_test("read_line_only_newline");
        let mut reader = BufReader::new(&b"\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 1, "bytes", 1, n);
        crate::assert_with_log!(line == "\n", "line", "\n", line);
        crate::test_complete!("read_line_only_newline");
    }

    #[test]
    fn read_line_invalid_utf8() {
        init_test("read_line_invalid_utf8");
        let mut reader = BufReader::new(&[0xff, 0xfe, b'\n'][..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        crate::test_complete!("read_line_invalid_utf8");
    }

    #[test]
    fn read_line_split_utf8_across_chunks() {
        init_test("read_line_split_utf8_across_chunks");

        let mut reader = SplitReader {
            chunks: vec![vec![0xF0, 0x9F], vec![0x94, 0xA5, b'\n']],
        };
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let bytes = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect("split UTF-8 line should decode");
        crate::assert_with_log!(bytes == "🔥\n".len(), "bytes", "🔥\n".len(), bytes);
        crate::assert_with_log!(line == "🔥\n", "line", "🔥\n", line);
        crate::test_complete!("read_line_split_utf8_across_chunks");
    }

    #[test]
    fn read_line_crlf_is_normalized_after_cancel_and_restart() {
        init_test("read_line_crlf_is_normalized_after_cancel_and_restart");

        let mut reader = PendingBetweenChunksReader {
            chunks: vec![b"hello\r".to_vec(), b"\n".to_vec()],
            pending_once: false,
        };
        let mut line = String::new();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut first = read_line(&mut reader, &mut line);
            let first_poll = Pin::new(&mut first).poll(&mut cx);
            let first_pending = matches!(first_poll, Poll::Pending);
            crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);
        }
        crate::assert_with_log!(line == "hello\r", "partial line", "hello\r", line);

        let mut resumed = read_line(&mut reader, &mut line);
        let mut resumed = Pin::new(&mut resumed);
        let bytes = poll_ready(&mut resumed)
            .expect("future did not resolve")
            .expect("resumed read_line should succeed");

        crate::assert_with_log!(bytes == 1, "bytes", 1, bytes);
        crate::assert_with_log!(line == "hello\n", "line", "hello\n", line);
        crate::test_complete!("read_line_crlf_is_normalized_after_cancel_and_restart");
    }

    #[test]
    fn read_line_repoll_after_completion_fails_closed() {
        init_test("read_line_repoll_after_completion_fails_closed");
        let mut reader = BufReader::new(&b"hello\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut pinned = Pin::new(&mut fut);

        let first = poll_ready(&mut pinned).expect("future did not resolve");
        assert!(first.is_ok(), "first poll should succeed");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let second = pinned.as_mut().poll(&mut cx);
        match second {
            Poll::Ready(Err(e)) => {
                let msg = e.to_string();
                let ok = msg.contains("polled after completion");
                crate::assert_with_log!(ok, "error message", "polled after completion", msg);
            }
            other => panic!("expected Ready(Err), got {other:?}"), // ubs:ignore - test logic
        }
        crate::test_complete!("read_line_repoll_after_completion_fails_closed");
    }

    // ====================================================================
    // br-asupersync-ghv5u1: LineReader cancel-safety across multi-byte
    // UTF-8 boundary. The free read_line loses the prefix on cancel;
    // LineReader hoists it to the wrapper so the next read_line picks
    // up where the prior one left off.
    // ====================================================================

    #[test]
    fn ghv5u1_line_reader_resumes_partial_utf8_after_cancel() {
        // A 4-byte emoji split across two reads, with the reader pending in
        // between. The first read_line takes the partial prefix and parks;
        // it is dropped there. The prefix lives on the LineReader, so the
        // next read_line decodes the emoji. (This test used to complete its
        // first call through EOF, and passed only because an incomplete
        // code point at EOF stayed in `pending` forever.)
        let emoji = "\u{1F600}\n"; // U+1F600 = F0 9F 98 80, then a newline
        let bytes = emoji.as_bytes();
        let mut reader = LineReader::new(PendingBetweenChunksReader {
            chunks: vec![bytes[..2].to_vec(), bytes[2..].to_vec()],
            pending_once: false,
        });
        let mut buf = String::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut fut = reader.read_line(&mut buf);
            let poll = Pin::new(&mut fut).poll(&mut cx);
            assert!(poll.is_pending(), "the first call parks between chunks");
        }
        assert!(buf.is_empty());

        let mut fut = reader.read_line(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("the resumed call completes")
            .expect("the emoji decodes");
        assert_eq!(n, bytes.len());
        assert_eq!(buf, emoji);
    }

    /// Invalid UTF-8 before a line's `\n`, with the newline in a later
    /// buffer: the error used to consume only the current buffer, so the
    /// rest of the bad line came back as the next "line".
    #[test]
    fn read_line_skips_the_rest_of_an_invalid_line() {
        init_test("read_line_skips_the_rest_of_an_invalid_line");
        let chunks = || vec![b"ab\xFFcd".to_vec(), b"ef\nnext\n".to_vec()];

        let mut reader = SplitReader { chunks: chunks() };
        let mut line = String::new();
        let err = {
            let mut fut = read_line(&mut reader, &mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut)
                .expect("resolves")
                .expect_err("invalid line")
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        line.clear();
        let n = {
            let mut fut = read_line(&mut reader, &mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut).expect("resolves").expect("next line")
        };
        assert_eq!((n, line.as_str()), (5, "next\n"));

        let mut reader = LineReader::new(SplitReader { chunks: chunks() });
        let mut line = String::new();
        let err = {
            let mut fut = reader.read_line(&mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut)
                .expect("resolves")
                .expect_err("invalid line")
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        line.clear();
        let n = {
            let mut fut = reader.read_line(&mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut).expect("resolves").expect("next line")
        };
        assert_eq!((n, line.as_str()), (5, "next\n"));
    }

    /// A line that is not UTF-8 leaves the caller's buffer as it was, whether
    /// the bad byte arrives with the line's `\n`, before EOF, or as a code
    /// point that EOF cuts off.
    #[test]
    fn an_invalid_line_leaves_the_buffer_as_it_was() {
        init_test("an_invalid_line_leaves_the_buffer_as_it_was");
        for input in [&b"ab\xFFcd\n"[..], &b"ab\xFF"[..], &b"ab\xF0\x9F"[..]] {
            let mut reader = BufReader::new(input);
            let mut line = String::from("kept ");
            let err = {
                let mut fut = read_line(&mut reader, &mut line);
                let mut fut = Pin::new(&mut fut);
                poll_ready(&mut fut)
                    .expect("resolves")
                    .expect_err("invalid line")
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(line, "kept ", "read_line on {input:?}");

            let mut reader = LineReader::new(BufReader::new(input));
            let mut line = String::from("kept ");
            let err = {
                let mut fut = reader.read_line(&mut line);
                let mut fut = Pin::new(&mut fut);
                poll_ready(&mut fut)
                    .expect("resolves")
                    .expect_err("invalid line")
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(line, "kept ", "LineReader::read_line on {input:?}");
        }
    }

    /// A stream that ends inside a code point is an error once; the call
    /// after it used to fail the same way forever instead of seeing EOF.
    #[test]
    fn line_reader_reports_eof_after_an_incomplete_code_point() {
        init_test("line_reader_reports_eof_after_an_incomplete_code_point");
        let mut reader = LineReader::new(BufReader::new(&b"ok\n\xF0\x9F"[..]));
        let mut results = Vec::new();
        for _ in 0..3 {
            let mut line = String::new();
            let mut fut = reader.read_line(&mut line);
            let mut fut = Pin::new(&mut fut);
            let result = poll_ready(&mut fut).expect("resolves");
            results.push(result.map_err(|err| err.kind()));
        }
        assert_eq!(results, vec![Ok(3), Err(io::ErrorKind::InvalidData), Ok(0)]);
    }

    #[test]
    fn ghv5u1_line_reader_completes_full_utf8_in_one_call() {
        // Sanity: when the full codepoint is available in one read,
        // LineReader behaves identically to the free read_line.
        use crate::io::BufReader;
        let mut reader = LineReader::new(BufReader::new(&b"hello\n"[..]));
        let mut buf = String::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = reader.read_line(&mut buf);
        let mut pinned = std::pin::Pin::new(&mut fut);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(Ok(n)) => {
                    assert_eq!(n, 6);
                    assert_eq!(buf, "hello\n");
                    return;
                }
                Poll::Ready(Err(e)) => panic!("unexpected error: {e}"), // ubs:ignore
                Poll::Pending => {}                                     // drive again
            }
        }
    }
}
