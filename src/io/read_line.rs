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
//! Dropping the future before that happens may still lose that trailing partial
//! code point.

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
        buf,
        bytes_read: 0,
        pending: Vec::new(),
        completed: false,
    }
}

/// Future for the [`read_line`] function.
pub struct ReadLine<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut String,
    bytes_read: usize,
    /// Holds incomplete UTF-8 bytes that were consumed from the reader
    /// but not yet appended to `buf`.
    pending: Vec<u8>,
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
}

fn invalid_data_result(err: std::str::Utf8Error) -> io::Result<usize> {
    Err(io::Error::new(io::ErrorKind::InvalidData, err))
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
                if found_newline || e.error_len().is_some() {
                    ChunkAction::ConsumeAndFinish(invalid_data_result(e))
                } else {
                    pending.extend_from_slice(&chunk[valid_len..]);
                    ChunkAction::Consume
                }
            } else if e.error_len().is_some() || found_newline {
                ChunkAction::ConsumeAndFinish(invalid_data_result(e))
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
                if found_newline || e.error_len().is_some() {
                    ChunkAction::ConsumeAndFinish(invalid_data_result(e))
                } else {
                    ChunkAction::Consume
                }
            } else if e.error_len().is_some() || found_newline {
                ChunkAction::ConsumeAndFinish(invalid_data_result(e))
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

            if available.is_empty() {
                if let Err(err) = append_utf8(this.buf, &mut this.bytes_read, &this.pending) {
                    this.completed = true;
                    return Poll::Ready(Err(err));
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
                    return Poll::Ready(result);
                }
                ChunkAction::ConsumeAndFinish(result) => {
                    Pin::new(&mut *this.reader).consume(consume_len);
                    this.completed = true;
                    return Poll::Ready(result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::BufReader;
    use crate::io::{AsyncBufRead, AsyncRead, ReadBuf};
    use std::sync::Arc;
    use std::task::{Poll, Wake, Waker};

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
}
