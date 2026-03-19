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
                if s.is_err() {
                    this.completed = true;
                }
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
    use super::*;
    use crate::io::BufReader;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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
}
