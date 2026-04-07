//! Bidirectional I/O trait adapters.
//!
//! Provides type wrappers that bridge between Asupersync's `AsyncRead`/`AsyncWrite`
//! traits and their Tokio equivalents.
//!
//! # Adapters
//!
//! - [`TokioIo<T>`]: Wraps an Asupersync I/O type to implement hyper/tokio I/O traits.
//! - [`AsupersyncIo<T>`]: Wraps a Tokio I/O type to implement Asupersync's I/O traits.
//!
//! # Cancel Safety
//!
//! Both adapters preserve the cancel-safety properties of the underlying type:
//! - `poll_read` is cancel-safe (partial data is discarded by caller)
//! - `poll_write` is cancel-safe (partial writes are OK)
//! - `read_exact` and `write_all` are NOT cancel-safe through either adapter

use pin_project_lite::pin_project;
#[cfg(feature = "tokio-io")]
use std::io;
#[cfg(feature = "tokio-io")]
use std::pin::Pin;
#[cfg(feature = "tokio-io")]
use std::task::{Context, Poll};

pin_project! {
    /// Wraps an Asupersync I/O type to implement hyper/tokio-compatible I/O traits.
    ///
    /// Use this to pass Asupersync TCP streams, TLS streams, etc. to hyper
    /// and other Tokio-locked crates.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync_tokio_compat::io::TokioIo;
    ///
    /// let asupersync_stream = asupersync::net::TcpStream::connect(addr).await?;
    /// let hyper_io = TokioIo::new(asupersync_stream);
    /// // Now usable with hyper::server::conn::http1::Builder
    /// ```
    pub struct TokioIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> TokioIo<T> {
    /// Wrap an Asupersync I/O type for Tokio/hyper compatibility.
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Get a reference to the inner I/O type.
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner I/O type.
    pub const fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume the wrapper and return the inner I/O type.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

pin_project! {
    /// Wraps a Tokio I/O type to implement Asupersync's `AsyncRead`/`AsyncWrite`.
    ///
    /// Use this to pass Tokio-originated streams into Asupersync code.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync_tokio_compat::io::AsupersyncIo;
    ///
    /// let tokio_stream = tokio::net::TcpStream::connect(addr).await?;
    /// let stream = AsupersyncIo::new(tokio_stream);
    /// // Now usable with Asupersync's read/write extensions
    /// ```
    pub struct AsupersyncIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> AsupersyncIo<T> {
    /// Wrap a Tokio I/O type for Asupersync compatibility.
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Get a reference to the inner I/O type.
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner I/O type.
    pub const fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume the wrapper and return the inner I/O type.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// Direction 1: Asupersync → Tokio  (TokioIo<T>)
// ---------------------------------------------------------------------------

#[cfg(feature = "tokio-io")]
impl<T> tokio::io::AsyncRead for TokioIo<T>
where
    T: asupersync::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tokio_buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Get a mutable slice from Tokio's ReadBuf for Asupersync to write into.
        let unfilled = tokio_buf.initialize_unfilled();
        let mut asupersync_buf = asupersync::io::ReadBuf::new(unfilled);

        match self.project().inner.poll_read(cx, &mut asupersync_buf) {
            Poll::Ready(Ok(())) => {
                let n = asupersync_buf.filled().len();
                tokio_buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio-io")]
impl<T> tokio::io::AsyncWrite for TokioIo<T>
where
    T: asupersync::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Direction 2: Tokio → Asupersync  (AsupersyncIo<T>)
// ---------------------------------------------------------------------------

#[cfg(feature = "tokio-io")]
impl<T> asupersync::io::AsyncRead for AsupersyncIo<T>
where
    T: tokio::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        asupersync_buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Get the unfilled region from Asupersync's ReadBuf for Tokio to write into.
        let unfilled = asupersync_buf.unfilled();
        let mut tokio_buf = tokio::io::ReadBuf::new(unfilled);

        // Asupersync's ReadBuf guarantees that `unfilled()` returns a fully initialized slice.
        // We inform Tokio of this to prevent it from zeroing the buffer unnecessarily.
        let capacity = tokio_buf.capacity();
        // Safety: the slice was returned from `unfilled()` which is guaranteed to be initialized
        // up to its length by Asupersync's `ReadBuf` invariants.
        unsafe {
            tokio_buf.assume_init(capacity);
        }

        match self.project().inner.poll_read(cx, &mut tokio_buf) {
            Poll::Ready(Ok(())) => {
                let n = tokio_buf.filled().len();
                asupersync_buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio-io")]
impl<T> asupersync::io::AsyncWrite for AsupersyncIo<T>
where
    T: tokio::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Direction 3: Asupersync → hyper v1  (TokioIo<T>)
// ---------------------------------------------------------------------------

#[cfg(feature = "hyper-bridge")]
#[allow(unsafe_code)]
impl<T> hyper::rt::Read for TokioIo<T>
where
    T: asupersync::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut hyper_buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: We zero-initialize the cursor's uninitialized buffer before
        // reinterpreting it as &mut [u8]. Asupersync's ReadBuf requires
        // initialized memory. The advance() call is valid because
        // n <= buffer length (guaranteed by ReadBuf::filled().len()).
        let uninit = unsafe { hyper_buf.as_mut() };
        uninit.iter_mut().for_each(|b| {
            b.write(0);
        });
        let len = uninit.len();
        let buf = unsafe { std::slice::from_raw_parts_mut(uninit.as_mut_ptr().cast::<u8>(), len) };

        let mut read_buf = asupersync::io::ReadBuf::new(buf);
        match self.project().inner.poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                unsafe { hyper_buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "hyper-bridge")]
impl<T> hyper::rt::Write for TokioIo<T>
where
    T: asupersync::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokio_io_wraps_and_unwraps() {
        let data: Vec<u8> = Vec::new();
        let wrapped = TokioIo::new(data);
        assert!(wrapped.inner().is_empty());
        let unwrapped = wrapped.into_inner();
        assert!(unwrapped.is_empty());
    }

    #[test]
    fn asupersync_io_wraps_and_unwraps() {
        let data: Vec<u8> = Vec::new();
        let wrapped = AsupersyncIo::new(data);
        assert!(wrapped.inner().is_empty());
        let unwrapped = wrapped.into_inner();
        assert!(unwrapped.is_empty());
    }

    #[cfg(feature = "tokio-io")]
    mod tokio_io_tests {
        use super::*;
        use std::sync::Arc;
        use std::task::{Wake, Waker};
        use tokio::io::AsyncRead as _;

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        fn noop_waker() -> Waker {
            Waker::from(Arc::new(NoopWaker))
        }

        #[test]
        fn tokio_io_read_bridges_correctly() {
            // Wrap an Asupersync reader (byte slice) and read via Tokio trait.
            let data: &[u8] = b"hello adapter";
            let mut wrapper = TokioIo::new(data);

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut buf = [0u8; 32];
            let mut tokio_buf = tokio::io::ReadBuf::new(&mut buf);

            let poll = Pin::new(&mut wrapper).poll_read(&mut cx, &mut tokio_buf);
            assert!(matches!(poll, Poll::Ready(Ok(()))));
            assert_eq!(tokio_buf.filled(), b"hello adapter");
        }

        #[test]
        fn tokio_io_write_bridges_correctly() {
            // Wrap an Asupersync writer (Vec<u8>) and write via Tokio trait.
            let mut wrapper = TokioIo::new(Vec::<u8>::new());

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            let poll = <TokioIo<Vec<u8>> as tokio::io::AsyncWrite>::poll_write(
                Pin::new(&mut wrapper),
                &mut cx,
                b"written",
            );
            assert!(matches!(poll, Poll::Ready(Ok(7))));
            assert_eq!(wrapper.inner(), b"written");
        }

        #[test]
        fn tokio_io_flush_and_shutdown() {
            let mut wrapper = TokioIo::new(Vec::<u8>::new());
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            let poll = <TokioIo<Vec<u8>> as tokio::io::AsyncWrite>::poll_flush(
                Pin::new(&mut wrapper),
                &mut cx,
            );
            assert!(matches!(poll, Poll::Ready(Ok(()))));

            let poll = <TokioIo<Vec<u8>> as tokio::io::AsyncWrite>::poll_shutdown(
                Pin::new(&mut wrapper),
                &mut cx,
            );
            assert!(matches!(poll, Poll::Ready(Ok(()))));
        }

        #[test]
        fn asupersync_io_read_bridges_correctly() {
            // Wrap a Tokio reader and read via Asupersync trait.
            // tokio::io::AsyncRead is implemented for &[u8].
            let data: &[u8] = b"from tokio";
            let mut wrapper = AsupersyncIo::new(data);

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut buf = [0u8; 32];
            let mut asupersync_buf = asupersync::io::ReadBuf::new(&mut buf);

            let poll = <AsupersyncIo<&[u8]> as asupersync::io::AsyncRead>::poll_read(
                Pin::new(&mut wrapper),
                &mut cx,
                &mut asupersync_buf,
            );
            assert!(matches!(poll, Poll::Ready(Ok(()))));
            assert_eq!(asupersync_buf.filled(), b"from tokio");
        }

        #[test]
        fn asupersync_io_write_bridges_correctly() {
            // Wrap a Tokio writer and write via Asupersync trait.
            // tokio::io::AsyncWrite is implemented for Vec<u8> (with io-util feature).
            let mut wrapper = AsupersyncIo::new(Vec::<u8>::new());

            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            let poll = <AsupersyncIo<Vec<u8>> as asupersync::io::AsyncWrite>::poll_write(
                Pin::new(&mut wrapper),
                &mut cx,
                b"to asupersync",
            );
            assert!(matches!(poll, Poll::Ready(Ok(13))));
            assert_eq!(wrapper.inner(), b"to asupersync");
        }

        #[test]
        fn round_trip_read_preserves_data() {
            // Read data through TokioIo then AsupersyncIo to verify round-trip.
            let original: &[u8] = b"round trip data";

            // Step 1: Asupersync → Tokio direction
            let mut tokio_wrapper = TokioIo::new(original);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut buf1 = [0u8; 32];
            let mut tokio_buf = tokio::io::ReadBuf::new(&mut buf1);

            let poll = Pin::new(&mut tokio_wrapper).poll_read(&mut cx, &mut tokio_buf);
            assert!(matches!(poll, Poll::Ready(Ok(()))));
            let intermediate = tokio_buf.filled().to_vec();

            // Step 2: Tokio → Asupersync direction
            let mut asupersync_wrapper = AsupersyncIo::new(intermediate.as_slice());
            let mut buf2 = [0u8; 32];
            let mut asupersync_buf = asupersync::io::ReadBuf::new(&mut buf2);

            let poll = <AsupersyncIo<&[u8]> as asupersync::io::AsyncRead>::poll_read(
                Pin::new(&mut asupersync_wrapper),
                &mut cx,
                &mut asupersync_buf,
            );
            assert!(matches!(poll, Poll::Ready(Ok(()))));
            assert_eq!(asupersync_buf.filled(), original);
        }
    }
}
