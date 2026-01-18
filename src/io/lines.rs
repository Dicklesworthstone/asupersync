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
    bytes_read: usize,
}

impl<R> Lines<R> {
    /// Creates a new `Lines` iterator.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            bytes_read: 0,
        }
    }
}

impl<R: AsyncBufRead + Unpin> Stream for Lines<R> {
    type Item = io::Result<String>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // 1. Check if we already have a newline in `this.buf`
            if let Some(pos) = this.buf[this.bytes_read..]
                .iter()
                .position(|&b| b == b'\n')
            {
                let newline_pos = this.bytes_read + pos;
                let rest = this.buf.split_off(newline_pos + 1);
                // this.buf now contains [line + \n]
                // rest contains [remainder]

                // Remove \n
                this.buf.pop();

                // Handle \r\n
                if this.buf.last() == Some(&b'\r') {
                    this.buf.pop();
                }

                let s = String::from_utf8(mem::take(&mut this.buf))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));

                // Restore remainder
                this.buf = rest;
                this.bytes_read = 0;

                return Poll::Ready(Some(s));
            }
            this.bytes_read = this.buf.len();

            // 2. Poll the reader
            let available = match Pin::new(&mut this.reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Ok(buf)) => buf,
            };

            // 3. EOF check
            if available.is_empty() {
                if this.buf.is_empty() {
                    return Poll::Ready(None);
                }
                let s = String::from_utf8(mem::take(&mut this.buf))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                this.bytes_read = 0;
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

    #[test]
    fn lines_basic() {
        let data: &[u8] = b"line 1\nline 2\nline 3";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 1"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 2"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 3"));
        // No newline at end of file logic check: "line 3" should return then None.
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));
    }

    #[test]
    fn lines_crlf() {
        let data: &[u8] = b"line 1\r\nline 2\r\n";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 1"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "line 2"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));
    }

    #[test]
    fn lines_empty() {
        let data: &[u8] = b"";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));
    }

    #[test]
    fn lines_incomplete_last() {
        let data: &[u8] = b"foo\nbar";
        let reader = BufReader::new(data);
        let mut lines = Lines::new(reader);

        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "foo"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(Some(Ok(s))) if s == "bar"));
        assert!(matches!(poll_next(&mut lines), Poll::Ready(None)));
    }
}
