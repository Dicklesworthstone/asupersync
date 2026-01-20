//! Buffered async reader for filesystem I/O.
//!
//! This is a thin wrapper around the core `io::BufReader` to provide
//! a convenient `fs`-scoped type for file operations.

use crate::fs::Lines;
use crate::io::{self, AsyncBufRead, AsyncRead, ReadBuf};
use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Buffered async reader.
#[derive(Debug)]
pub struct BufReader<R> {
    inner: io::BufReader<R>,
}

impl<R> BufReader<R> {
    /// Creates a new `BufReader` with the default buffer capacity.
    pub fn new(inner: R) -> Self {
        Self {
            inner: io::BufReader::new(inner),
        }
    }

    /// Creates a new `BufReader` with the specified buffer capacity.
    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner: io::BufReader::with_capacity(capacity, inner),
        }
    }

    /// Returns a reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        self.inner.get_ref()
    }

    /// Returns a mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        self.inner.get_mut()
    }

    /// Consumes the `BufReader` and returns the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }

    /// Returns the current buffer contents.
    pub fn buffer(&self) -> &[u8] {
        self.inner.buffer()
    }

    /// Returns an iterator over the lines of this reader.
    pub fn lines(self) -> Lines<R> {
        Lines {
            inner: crate::io::Lines::new(self),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BufReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for BufReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<&[u8]>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        Pin::new(&mut this.inner).consume(amt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::File;
    use crate::stream::StreamExt as _;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_buf_reader_basic() {
        init_test("test_buf_reader_basic");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test.txt");
            crate::fs::write(&path, b"hello\nworld\n").await.unwrap();

            let file = File::open(&path).await.unwrap();
            let reader = BufReader::new(file);

            let mut lines = reader.lines();
            let first = lines.next().await.unwrap().unwrap();
            crate::assert_with_log!(first == "hello", "first line", "hello", first);
            let second = lines.next().await.unwrap().unwrap();
            crate::assert_with_log!(second == "world", "second line", "world", second);
        });
        crate::test_complete!("test_buf_reader_basic");
    }

    #[test]
    fn test_buf_reader_lines() {
        init_test("test_buf_reader_lines");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test_lines.txt");
            crate::fs::write(&path, b"line1\nline2\nline3")
                .await
                .unwrap();

            let file = File::open(&path).await.unwrap();
            let reader = BufReader::new(file);
            let lines: Vec<_> = reader.lines().try_collect().await.unwrap();

            let expected = vec!["line1", "line2", "line3"];
            crate::assert_with_log!(lines == expected, "lines", expected, lines);
        });
        crate::test_complete!("test_buf_reader_lines");
    }
}
