//! Buffered async writer for files.

use crate::io::AsyncWrite;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Default buffer capacity.
const DEFAULT_BUF_CAPACITY: usize = 8192;

/// Buffered async file writer.
#[derive(Debug)]
pub struct BufWriter<W> {
    inner: W,
    buf: Vec<u8>,
    capacity: usize,
    written: usize,
}

impl<W> BufWriter<W> {
    /// Creates a new `BufWriter` with default capacity.
    pub fn new(inner: W) -> Self {
        Self::with_capacity(DEFAULT_BUF_CAPACITY, inner)
    }

    /// Creates a new `BufWriter` with specified capacity.
    pub fn with_capacity(capacity: usize, inner: W) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(capacity),
            capacity,
            written: 0,
        }
    }

    /// Gets a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Gets a mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Returns the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns the contents of the buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }
}

impl<W: AsyncWrite + Unpin> BufWriter<W> {
    fn poll_flush_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.buf.len() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, &self.buf[self.written..]) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write buffered data",
                )));
            }
            self.written += n;
        }
        self.buf.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for BufWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        // If buffer + new data <= capacity, just buffer it
        if this.buf.len() + buf.len() <= this.capacity {
            this.buf.extend_from_slice(buf);
            return Poll::Ready(Ok(buf.len()));
        }

        // Flush buffer first
        if !this.buf.is_empty() {
            match this.poll_flush_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // If larger than capacity, bypass buffer
        if buf.len() >= this.capacity {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        this.buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        match this.poll_flush_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        match this.poll_flush_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();

        if this.buf.len() + total_len <= this.capacity {
            for b in bufs {
                this.buf.extend_from_slice(b);
            }
            return Poll::Ready(Ok(total_len));
        }

        if !this.buf.is_empty() {
            match this.poll_flush_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if total_len >= this.capacity {
            return Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        }

        for b in bufs {
            this.buf.extend_from_slice(b);
        }
        Poll::Ready(Ok(total_len))
    }

    fn is_write_vectored(&self) -> bool {
        // We support vectored writing into buffer
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::File;
    use crate::io::AsyncWriteExt;
    use tempfile::tempdir;

    #[test]
    fn test_buf_writer_basic() {
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test_write.txt");

            let file = File::create(&path).await.unwrap();
            let mut writer = BufWriter::new(file);

            writer.write_all(b"hello ").await.unwrap();
            writer.write_all(b"world").await.unwrap();
            writer.flush().await.unwrap();

            let contents = crate::fs::read_to_string(&path).await.unwrap();
            assert_eq!(contents, "hello world");
        });
    }

    #[test]
    fn test_buf_writer_large() {
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test_large.txt");

            let file = File::create(&path).await.unwrap();
            let mut writer = BufWriter::with_capacity(1024, file);

            // Write more than buffer capacity
            let data = vec![b'x'; 10000];
            writer.write_all(&data).await.unwrap();
            writer.flush().await.unwrap();

            let contents = crate::fs::read(&path).await.unwrap();
            assert_eq!(contents.len(), 10000);
            assert!(contents.iter().all(|&b| b == b'x'));
        });
    }
}
