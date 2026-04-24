//! Async line iterator.

use super::AsyncBufRead;
use crate::stream::Stream;
use std::io;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Iterator over the lines of an [`AsyncBufRead`].
#[derive(Debug)]
pub struct Lines<R> {
    reader: R,
    buf: Vec<u8>,
    completed: bool,
}

impl<R> Lines<R> {
    /// Creates a new `Lines` iterator.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            completed: false,
        }
    }
}

impl<R: AsyncBufRead + Unpin> Stream for Lines<R> {
    type Item = io::Result<String>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(None);
        }
        let mut steps = 0;

        loop {
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            // 1. Check if we already have a newline at the end of `this.buf`
            // We know it can only be at the end because of step 4.
            if this.buf.last() == Some(&b'\n') {
                // Remove \n
                this.buf.pop();

                // Handle \r\n
                if this.buf.last() == Some(&b'\r') {
                    this.buf.pop();
                }

                let s = String::from_utf8(mem::take(&mut this.buf))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));

                if s.is_err() {
                    this.completed = true;
                }

                return Poll::Ready(Some(s));
            }

            // 2. Poll the reader
            let available = match Pin::new(&mut this.reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.completed = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Ok(buf)) => buf,
            };

            // 3. EOF check
            if available.is_empty() {
                if this.buf.is_empty() {
                    this.completed = true;
                    return Poll::Ready(None);
                }
                let s = String::from_utf8(mem::take(&mut this.buf))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                this.completed = true;
                return Poll::Ready(Some(s));
            }

            // 4. Scan available for newline
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                this.buf.extend_from_slice(&available[..=pos]);
                Pin::new(&mut this.reader).consume(pos + 1);
                // Loop will catch it in step 1
            } else {
                this.buf.extend_from_slice(available);
                let len = available.len();
                Pin::new(&mut this.reader).consume(len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::io::{AsyncBufRead, AsyncRead, BufReader, ReadBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    struct CountWaker {
        wakes: AtomicUsize,
    }

    use std::task::Wake;
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_next<S: Stream + Unpin>(stream: &mut S) -> Poll<Option<S::Item>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(stream).poll_next(&mut cx)
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
            unreachable!("lines should use poll_fill_buf for this test")
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
            unreachable!("lines should use poll_fill_buf for this test")
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
    fn lines_basic() {
        init_test("lines_basic");
        let data: &[u8] = b"line 1\nline 2\nline 3";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        let first = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 1");
        crate::assert_with_log!(first, "line 1", true, first);
        let second = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 2");
        crate::assert_with_log!(second, "line 2", true, second);
        let third = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 3");
        crate::assert_with_log!(third, "line 3", true, third);
        // No newline at end of file logic check: "line 3" should return then None.
        let done = matches!(poll_next(&mut lines), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_basic");
    }

    #[test]
    fn lines_crlf() {
        init_test("lines_crlf");
        let data: &[u8] = b"line 1\r\nline 2\r\n";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        let first = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 1");
        crate::assert_with_log!(first, "line 1", true, first);
        let second = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 2");
        crate::assert_with_log!(second, "line 2", true, second);
        let done = matches!(poll_next(&mut lines), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_crlf");
    }

    #[test]
    fn lines_empty() {
        init_test("lines_empty");
        let data: &[u8] = b"";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);
        let done = matches!(poll_next(&mut lines), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_empty");
    }

    #[test]
    fn lines_incomplete_last() {
        init_test("lines_incomplete_last");
        let data: &[u8] = b"foo\nbar";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        let first = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "foo");
        crate::assert_with_log!(first, "foo", true, first);
        let second = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "bar");
        crate::assert_with_log!(second, "bar", true, second);
        let done = matches!(poll_next(&mut lines), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_incomplete_last");
    }

    #[test]
    fn lines_repoll_after_empty_completion_returns_none() {
        let data: &[u8] = b"";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));

        // Fail-closed: repoll after completion returns None instead of panicking
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));
        // Third poll also safe
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));
    }

    #[test]
    fn lines_repoll_after_exhausting_non_empty_input_returns_none() {
        let data: &[u8] = b"line 1\nline 2";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 1"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 2"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));

        // Fail-closed: repoll after completion returns None instead of panicking
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));
    }

    #[test]
    fn lines_split_utf8_across_chunks() {
        init_test("lines_split_utf8_across_chunks");
        let reader = SplitReader {
            chunks: vec![vec![0xF0, 0x9F], vec![0x94, 0xA5, b'\n']],
        };
        let mut lines = Lines::new(reader);

        let first = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "🔥");
        crate::assert_with_log!(first, "split utf8 line", true, first);
        let done = matches!(poll_next(&mut lines), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_split_utf8_across_chunks");
    }

    #[test]
    fn lines_crlf_after_pending_between_chunks() {
        init_test("lines_crlf_after_pending_between_chunks");
        let reader = PendingBetweenChunksReader {
            chunks: vec![b"hello\r".to_vec(), b"\n".to_vec()],
            pending_once: false,
        };
        let mut lines = Lines::new(reader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_pending = matches!(Pin::new(&mut lines).poll_next(&mut cx), Poll::Pending);
        crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);

        let second = matches!(Pin::new(&mut lines).poll_next(&mut cx), Poll::Ready(Some(Ok(s))) if s == "hello");
        crate::assert_with_log!(second, "normalized line", true, second);
        let done = matches!(Pin::new(&mut lines).poll_next(&mut cx), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_crlf_after_pending_between_chunks");
    }

    #[test]
    fn lines_bounded_self_wake_after_many_immediately_ready_chunks() {
        init_test("lines_bounded_self_wake_after_many_immediately_ready_chunks");
        let mut chunks = vec![vec![b'a']; 40];
        chunks.push(vec![b'\n']);
        let reader = SplitReader { chunks };
        let mut lines = Lines::new(reader);
        let wake_counter = Arc::new(CountWaker {
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(wake_counter.clone());
        let mut cx = Context::from_waker(&waker);

        let first_pending = matches!(Pin::new(&mut lines).poll_next(&mut cx), Poll::Pending);
        crate::assert_with_log!(
            first_pending,
            "bounded self-wake pending",
            true,
            first_pending
        );

        let woke_self = wake_counter.wakes.load(Ordering::SeqCst) > 0;
        crate::assert_with_log!(woke_self, "self wake recorded", true, woke_self);

        let expected = "a".repeat(40);
        let second = matches!(
            Pin::new(&mut lines).poll_next(&mut cx),
            Poll::Ready(Some(Ok(ref s))) if s == &expected
        );
        crate::assert_with_log!(second, "line after rewake", true, second);

        let done = matches!(Pin::new(&mut lines).poll_next(&mut cx), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_bounded_self_wake_after_many_immediately_ready_chunks");
    }

    #[test]
    fn lines_long_line_remains_unbounded() {
        init_test("lines_long_line_remains_unbounded");
        let long = "a".repeat(16 * 1024);
        let payload = format!("{long}\n");
        let reader = BufReader::new(payload.as_bytes());
        let mut lines = Lines::new(reader);

        let first = matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(ref s))) if s == &long);
        crate::assert_with_log!(first, "long line", true, first);
        let done = matches!(poll_next(&mut lines), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_long_line_remains_unbounded");
    }

    #[test]
    fn lines_invalid_utf8_repoll_after_error_returns_none() {
        init_test("lines_invalid_utf8_repoll_after_error_returns_none");
        let reader = SplitReader {
            chunks: vec![vec![0xF0, 0x9F], vec![b'\n']],
        };
        let mut lines = Lines::new(reader);

        let invalid_data = matches!(poll_next(&mut lines), Poll::Ready(Some(Err(err))) if err.kind() == io::ErrorKind::InvalidData);
        crate::assert_with_log!(invalid_data, "invalid-data line error", true, invalid_data);

        let done = matches!(poll_next(&mut lines), Poll::Ready(None));
        crate::assert_with_log!(done, "done", true, done);
        crate::test_complete!("lines_invalid_utf8_repoll_after_error_returns_none");
    }
}
