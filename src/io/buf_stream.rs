//! Independent read and write buffering for duplex byte streams.

use super::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, BufWriter, ReadBuf};
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A duplex stream with independent buffers for incoming and outgoing bytes.
///
/// This composes [BufReader] and [BufWriter] so both directions retain the
/// existing buffering, partial-progress, and error handling contracts. Reading
/// does not flush outgoing data: full-duplex protocols must be able to receive
/// while their writer is backpressured. Flush explicitly before awaiting a
/// response to a buffered request.
///
/// The read and write cursors are independent. For a shared-cursor file, manage
/// seeking and read/write ordering separately rather than treating it as a
/// duplex stream.
///
/// # Cancellation and shutdown
///
/// A dropped read or flush future leaves unconsumed read-ahead and unwritten
/// output in this adapter. Keep the adapter alive to resume. Bytes already
/// delivered to the caller are not rolled back; multi-read operations still
/// need their own progress tracking. Shutdown flushes
/// outgoing bytes before delegating to the underlying writer; incoming
/// read-ahead remains available after a successful write-side shutdown.
///
/// Dropping the adapter or calling [Self::into_inner] discards both buffers.
/// Neither operation can asynchronously flush.
///
/// # Example
///
/// ```no_run
/// use asupersync::io::{AsyncReadExt, AsyncWriteExt, BufStream};
/// use asupersync::net::TcpStream;
///
/// async fn exchange(socket: TcpStream) -> std::io::Result<[u8; 4]> {
///     let mut stream = BufStream::new(socket);
///     stream.write_all(b"ping").await?;
///     stream.flush().await?;
///     let mut reply = [0; 4];
///     stream.read_exact(&mut reply).await?;
///     Ok(reply)
/// }
/// ```
#[derive(Debug)]
pub struct BufStream<S> {
    inner: BufReader<BufWriter<S>>,
}

impl<S> BufStream<S> {
    /// Creates a stream with the default 8192-byte buffer in each direction.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner: BufReader::new(BufWriter::new(inner)),
        }
    }

    /// Creates a stream with independently sized read and write buffers.
    ///
    /// As with [BufReader::with_capacity], a zero read capacity becomes one
    /// byte. A zero write capacity bypasses write buffering.
    #[must_use]
    pub fn with_capacity(read_capacity: usize, write_capacity: usize, inner: S) -> Self {
        Self {
            inner: BufReader::with_capacity(
                read_capacity,
                BufWriter::with_capacity(write_capacity, inner),
            ),
        }
    }

    /// Returns the underlying stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref().get_ref()
    }

    /// Returns the underlying stream mutably.
    ///
    /// Direct reads bypass unread buffered data; direct writes can overtake
    /// buffered output. Use the adapter's I/O methods to preserve ordering.
    pub fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut().get_mut()
    }

    /// Returns the underlying stream, discarding unread and unflushed bytes.
    ///
    /// Flush output and consume any needed read-ahead before calling this.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner.into_inner().into_inner()
    }

    /// Incoming bytes already read from the stream but not yet consumed.
    #[must_use]
    pub fn read_buffer(&self) -> &[u8] {
        self.inner.buffer()
    }

    /// Outgoing bytes not yet accepted by the underlying stream.
    ///
    /// A prefix accepted during a partial flush is excluded.
    #[must_use]
    pub fn write_buffer(&self) -> &[u8] {
        self.inner.get_ref().buffer()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BufStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + Unpin> AsyncBufRead for BufStream<S> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        Pin::new(&mut self.get_mut().inner).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        Pin::new(&mut self.get_mut().inner).consume(amount);
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BufStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{AsyncWriteExt, duplex};
    use std::future::Future;
    use std::task::Waker;

    fn read_ready<R: AsyncRead + Unpin>(
        reader: &mut R,
        cx: &mut Context<'_>,
        capacity: usize,
    ) -> Vec<u8> {
        let mut storage = vec![0; capacity];
        let mut buf = ReadBuf::new(&mut storage);
        match Pin::new(reader).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => buf.filled().to_vec(),
            Poll::Ready(Err(error)) => panic!("read failed: {error}"),
            Poll::Pending => panic!("expected readable bytes or EOF"),
        }
    }

    #[test]
    fn buffered_request_response_and_half_close_preserve_read_ahead() {
        let (socket, mut peer) = duplex(8);
        let mut stream = BufStream::with_capacity(8, 8, socket);
        let mut cx = Context::from_waker(Waker::noop());

        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"ping"),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(stream.write_buffer(), b"ping");
        let mut waiting = [0; 4];
        assert!(Pin::new(&mut peer)
            .poll_read(&mut cx, &mut ReadBuf::new(&mut waiting))
            .is_pending());
        assert!(matches!(
            Pin::new(&mut stream).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_ready(&mut peer, &mut cx, 8), b"ping");

        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut cx, b"pong"),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(read_ready(&mut stream, &mut cx, 2), b"po");
        assert_eq!(stream.read_buffer(), b"ng");

        let parts = [IoSlice::new(b"ne"), IoSlice::new(b"xt")];
        assert!(stream.is_write_vectored());
        assert!(matches!(
            Pin::new(&mut stream).poll_write_vectored(&mut cx, &parts),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(stream.read_buffer(), b"ng");
        assert_eq!(stream.write_buffer(), b"next");
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(stream.write_buffer().is_empty());
        assert_eq!(read_ready(&mut peer, &mut cx, 8), b"next");
        assert!(read_ready(&mut peer, &mut cx, 8).is_empty());

        // Closing only the outgoing direction must not discard incoming bytes.
        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut cx, b"OK"),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(read_ready(&mut stream, &mut cx, 8), b"ng");
        assert_eq!(read_ready(&mut stream, &mut cx, 8), b"OK");
    }

    #[test]
    fn reads_progress_while_writes_are_backpressured_and_flush_can_resume() {
        let (socket, mut peer) = duplex(4);
        let mut stream = BufStream::with_capacity(8, 8, socket);
        let mut cx = Context::from_waker(Waker::noop());

        // Establish an actually full outgoing pipe, without timing assumptions.
        assert!(matches!(
            Pin::new(stream.get_mut()).poll_write(&mut cx, b"busy"),
            Poll::Ready(Ok(4))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"queued"),
            Poll::Ready(Ok(6))
        ));
        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut cx, b"data"),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(read_ready(&mut stream, &mut cx, 1), b"d");
        assert_eq!(stream.read_buffer(), b"ata");
        assert_eq!(stream.write_buffer(), b"queued");

        {
            let mut flush = std::pin::pin!(stream.flush());
            assert!(flush.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(stream.write_buffer(), b"queued");
        assert_eq!(read_ready(&mut peer, &mut cx, 4), b"busy");

        {
            let mut flush = std::pin::pin!(stream.flush());
            assert!(flush.as_mut().poll(&mut cx).is_pending());
        }
        // Four bytes were committed before this flush future was dropped.
        assert_eq!(stream.write_buffer(), b"ed");
        assert_eq!(read_ready(&mut peer, &mut cx, 4), b"queu");
        {
            let mut flush = std::pin::pin!(stream.flush());
            assert!(matches!(flush.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        }
        assert_eq!(read_ready(&mut peer, &mut cx, 4), b"ed");
        assert!(stream.write_buffer().is_empty());
        assert_eq!(read_ready(&mut stream, &mut cx, 4), b"ata");
    }

    #[test]
    fn write_failure_preserves_unsent_bytes_and_read_ahead() {
        let (socket, mut peer) = duplex(8);
        let mut stream = BufStream::with_capacity(8, 8, socket);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut cx, b"reply"),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(read_ready(&mut stream, &mut cx, 1), b"r");
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"request"),
            Poll::Ready(Ok(7))
        ));
        drop(peer);

        for shutdown in [false, true] {
            let result = if shutdown {
                Pin::new(&mut stream).poll_shutdown(&mut cx)
            } else {
                Pin::new(&mut stream).poll_flush(&mut cx)
            };
            assert!(matches!(
                result,
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
            ));
            assert_eq!(stream.write_buffer(), b"request");
            assert_eq!(stream.read_buffer(), b"eply");
        }
        assert_eq!(read_ready(&mut stream, &mut cx, 8), b"eply");
        assert!(read_ready(&mut stream, &mut cx, 8).is_empty());
    }

    #[test]
    fn buffered_read_consumption_keeps_independent_output() {
        let mut stream = BufStream::with_capacity(4, 8, &b"abcdef"[..]);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_fill_buf(&mut cx),
            Poll::Ready(Ok(b"abcd"))
        ));
        Pin::new(&mut stream).consume(2);
        assert_eq!(stream.read_buffer(), b"cd");
        assert_eq!(read_ready(&mut stream, &mut cx, 8), b"cd");
        assert_eq!(read_ready(&mut stream, &mut cx, 8), b"ef");
    }

    #[test]
    fn wrappers_forward_independent_directions_without_extra_trait_bounds() {
        let mut cx = Context::from_waker(Waker::noop());

        // Vec implements only the write direction; BufReader must not require
        // AsyncRead to forward it.
        let mut writer = BufReader::new(Vec::<u8>::new());
        assert!(matches!(
            Pin::new(&mut writer).poll_write_vectored(
                &mut cx,
                &[IoSlice::new(b"ab"), IoSlice::new(b"cd")],
            ),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(writer.get_ref(), b"abcd");
        assert!(matches!(
            Pin::new(&mut writer).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut writer).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));

        // The inverse nesting forwards both byte and buffered reads without
        // requiring an AsyncWrite implementation from the read-only slice.
        let reader = BufReader::with_capacity(4, &b"abcdef"[..]);
        let mut reader = BufWriter::new(reader);
        assert!(matches!(
            Pin::new(&mut reader).poll_fill_buf(&mut cx),
            Poll::Ready(Ok(b"abcd"))
        ));
        Pin::new(&mut reader).consume(1);
        assert_eq!(read_ready(&mut reader, &mut cx, 8), b"bcd");
        assert_eq!(read_ready(&mut reader, &mut cx, 8), b"ef");
    }

    #[test]
    fn zero_capacity_writes_through_and_buffered_stream_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<BufStream<crate::io::DuplexStream>>();
        let mut stream = BufStream::with_capacity(0, 0, Vec::<u8>::new());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"direct"),
            Poll::Ready(Ok(6))
        ));
        assert!(stream.write_buffer().is_empty());
        assert_eq!(stream.get_ref(), b"direct");
        assert_eq!(stream.into_inner(), b"direct");
    }
}
