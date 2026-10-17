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
// `LineReader` and the same `String` across read_line invocations, and no
// byte is lost on cancel: complete codepoints are already in the String,
// only the partial one waits in the wrapper. A resumed call returns only the
// count of bytes it read itself, so the caller must check the String, not
// just the count, for a line begun before the cancel (asupersync-6n35x5).
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
///     // `n` counts only the bytes this call read. After a cancelled call,
///     // `line` can hold the start of a last line that this call ends with
///     // EOF (n == 0), so the loop handles it before it stops.
///     let n = reader.read_line(&mut line).await?;
///     if n == 0 && line.is_empty() { break; }
///     handle_line(&line);
///     line.clear();
///     if n == 0 { break; }
/// }
/// ```
///
/// After an error (for example invalid UTF-8), `line` can still hold the
/// start of the bad line: clear it before reusing the `String`.
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
#[path = "read_line_inline_tests.rs"]
mod tests;
