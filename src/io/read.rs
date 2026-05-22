//! AsyncRead trait and adapters.

use super::ReadBuf;
use std::io::{self, IoSliceMut};
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Async non-blocking read.
pub trait AsyncRead {
    /// Attempt to read data into `buf`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;
}

/// Async non-blocking read into multiple buffers (vectored I/O).
pub trait AsyncReadVectored: AsyncRead {
    /// Attempt to read data into multiple buffers.
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut this = self;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }

            let mut read_buf = ReadBuf::new(buf);
            return match AsyncRead::poll_read(this.as_mut(), cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            };
        }

        Poll::Ready(Ok(0))
    }
}

/// Chain two readers.
#[derive(Debug)]
pub struct Chain<R1, R2> {
    first: R1,
    second: R2,
    done_first: bool,
}

impl<R1, R2> Chain<R1, R2> {
    /// Creates a new `Chain` adapter.
    #[inline]
    #[must_use]
    pub fn new(first: R1, second: R2) -> Self {
        Self {
            first,
            second,
            done_first: false,
        }
    }
}

impl<R1, R2> AsyncRead for Chain<R1, R2>
where
    R1: AsyncRead + Unpin,
    R2: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.done_first {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let before = buf.filled().len();
            match Pin::new(&mut this.first).poll_read(cx, buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() == before {
                        this.done_first = true;
                    } else {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }

        Pin::new(&mut this.second).poll_read(cx, buf)
    }
}

/// Take at most `limit` bytes from a reader.
#[derive(Debug)]
pub struct Take<R> {
    inner: R,
    limit: u64,
}

impl<R> Take<R> {
    /// Creates a new `Take` adapter.
    #[inline]
    #[must_use]
    pub fn new(inner: R, limit: u64) -> Self {
        Self { inner, limit }
    }

    /// Returns the remaining limit.
    #[inline]
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }
}

impl<R> AsyncRead for Take<R>
where
    R: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.limit == 0 {
            return Poll::Ready(Ok(()));
        }

        let max = std::cmp::min(buf.remaining() as u64, this.limit) as usize;
        if max == 0 {
            return Poll::Ready(Ok(()));
        }

        let filled_before = buf.filled().len();
        {
            let unfilled = &mut buf.unfilled()[..max];
            let mut limited = ReadBuf::new(unfilled);
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = limited.filled().len();
                    buf.advance(n);
                }
            }
        }
        let read = buf.filled().len().saturating_sub(filled_before);
        this.limit = this.limit.saturating_sub(read as u64);

        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for &[u8] {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_copy = std::cmp::min(this.len(), buf.remaining());
        buf.put_slice(&this[..to_copy]);
        *this = &this[to_copy..];

        Poll::Ready(Ok(()))
    }
}

impl<T> AsyncRead for std::io::Cursor<T>
where
    T: AsRef<[u8]> + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::io::Read as _;

        let this = self.get_mut();
        let n = this.read(buf.unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl<R> AsyncRead for &mut R
where
    R: AsyncRead + Unpin + ?Sized,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read(cx, buf)
    }
}

impl<R> AsyncRead for Box<R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read(cx, buf)
    }
}

impl<R, P> AsyncRead for Pin<P>
where
    P: DerefMut<Target = R> + Unpin,
    R: AsyncRead + ?Sized,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_read(cx, buf)
    }
}

impl<R1, R2> AsyncReadVectored for Chain<R1, R2>
where
    R1: AsyncRead + Unpin,
    R2: AsyncRead + Unpin,
{
}

impl<R> AsyncReadVectored for Take<R> where R: AsyncRead + Unpin {}

impl AsyncReadVectored for &[u8] {}

impl<T> AsyncReadVectored for std::io::Cursor<T> where T: AsRef<[u8]> + Unpin {}

impl<R> AsyncReadVectored for &mut R
where
    R: AsyncReadVectored + Unpin + ?Sized,
{
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read_vectored(cx, bufs)
    }
}

impl<R> AsyncReadVectored for Box<R>
where
    R: AsyncReadVectored + Unpin + ?Sized,
{
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut **this).poll_read_vectored(cx, bufs)
    }
}

impl<R, P> AsyncReadVectored for Pin<P>
where
    P: DerefMut<Target = R> + Unpin,
    R: AsyncReadVectored + ?Sized,
{
    #[inline]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_read_vectored(cx, bufs)
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
    use pin_project::pin_project;
    use std::marker::PhantomPinned;

    use std::task::{Context, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Debug)]
    struct VectoredProbe {
        data: Vec<u8>,
        pos: usize,
        scalar_calls: usize,
        vectored_calls: usize,
    }

    impl VectoredProbe {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
                scalar_calls: 0,
                vectored_calls: 0,
            }
        }
    }

    impl AsyncRead for VectoredProbe {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.scalar_calls += 1;
            if self.pos >= self.data.len() || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let end = (self.pos + 1).min(self.data.len());
            buf.put_slice(&self.data[self.pos..end]);
            self.pos = end;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncReadVectored for VectoredProbe {
        fn poll_read_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Poll<io::Result<usize>> {
            self.vectored_calls += 1;
            let mut total = 0;

            for buf in bufs {
                if self.pos >= self.data.len() {
                    break;
                }
                if buf.is_empty() {
                    continue;
                }

                let remaining = self.data.len() - self.pos;
                let to_copy = remaining.min(buf.len());
                buf[..to_copy].copy_from_slice(&self.data[self.pos..self.pos + to_copy]);
                self.pos += to_copy;
                total += to_copy;
            }

            Poll::Ready(Ok(total))
        }
    }

    #[derive(Debug)]
    struct DefaultVectoredProbe {
        data: Vec<u8>,
        pos: usize,
        scalar_calls: usize,
    }

    impl DefaultVectoredProbe {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
                scalar_calls: 0,
            }
        }
    }

    impl AsyncRead for DefaultVectoredProbe {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.scalar_calls += 1;
            if self.pos >= self.data.len() || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let end = (self.pos + buf.remaining()).min(self.data.len());
            buf.put_slice(&self.data[self.pos..end]);
            self.pos = end;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncReadVectored for DefaultVectoredProbe {}

    #[derive(Debug, Default)]
    struct ErrorReader {
        scalar_calls: usize,
    }

    impl AsyncRead for ErrorReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.scalar_calls += 1;
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "injected scalar read failure",
            )))
        }
    }

    impl AsyncReadVectored for ErrorReader {}

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn read_from_slice_advances() {
        init_test("read_from_slice_advances");
        let mut input: &[u8] = b"hello";
        let mut buf = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut input).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"he", "filled", b"he", filled);
        crate::assert_with_log!(input == b"llo", "remaining", b"llo", input);
        crate::test_complete!("read_from_slice_advances");
    }

    #[test]
    fn read_from_slice_zero_capacity_does_not_consume() {
        init_test("read_from_slice_zero_capacity_does_not_consume");
        let mut input: &[u8] = b"hello";
        let mut buf = [0u8; 0];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut input).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled_empty = read_buf.filled().is_empty();
        crate::assert_with_log!(filled_empty, "filled empty", true, filled_empty);
        crate::assert_with_log!(input == b"hello", "remaining", b"hello", input);
        crate::test_complete!("read_from_slice_zero_capacity_does_not_consume");
    }

    #[test]
    fn default_read_vectored_uses_first_non_empty_buffer() {
        init_test("default_read_vectored_uses_first_non_empty_buffer");
        let mut reader = DefaultVectoredProbe::new(b"abcdef");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut first = [9u8; 0];
        let mut second = [0u8; 2];
        let mut third = [7u8; 4];

        let poll = {
            let mut bufs = [
                IoSliceMut::new(&mut first),
                IoSliceMut::new(&mut second),
                IoSliceMut::new(&mut third),
            ];
            Pin::new(&mut reader).poll_read_vectored(&mut cx, &mut bufs)
        };
        let ready = matches!(poll, Poll::Ready(Ok(2)));

        crate::assert_with_log!(ready, "read first non-empty length", true, ready);
        crate::assert_with_log!(second == *b"ab", "second buffer", *b"ab", second);
        crate::assert_with_log!(third == [7u8; 4], "third untouched", [7u8; 4], third);
        crate::assert_with_log!(
            reader.scalar_calls == 1,
            "one scalar read",
            1,
            reader.scalar_calls
        );
        crate::assert_with_log!(reader.pos == 2, "reader position", 2, reader.pos);
        crate::test_complete!("default_read_vectored_uses_first_non_empty_buffer");
    }

    #[test]
    fn default_read_vectored_empty_buffers_make_no_read_call() {
        init_test("default_read_vectored_empty_buffers_make_no_read_call");
        let mut reader = DefaultVectoredProbe::new(b"abc");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut first = [0u8; 0];
        let mut second = [0u8; 0];

        let poll = {
            let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
            Pin::new(&mut reader).poll_read_vectored(&mut cx, &mut bufs)
        };
        let ready = matches!(poll, Poll::Ready(Ok(0)));

        crate::assert_with_log!(ready, "empty vectored read returns zero", true, ready);
        crate::assert_with_log!(
            reader.scalar_calls == 0,
            "no scalar read",
            0,
            reader.scalar_calls
        );
        crate::assert_with_log!(reader.pos == 0, "position unchanged", 0, reader.pos);
        crate::test_complete!("default_read_vectored_empty_buffers_make_no_read_call");
    }

    #[test]
    fn default_read_vectored_propagates_scalar_error() {
        init_test("default_read_vectored_propagates_scalar_error");
        let mut reader = ErrorReader::default();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut first = [0u8; 0];
        let mut second = [3u8; 2];

        let err = {
            let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
            match Pin::new(&mut reader).poll_read_vectored(&mut cx, &mut bufs) {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected scalar read error, got {other:?}"),
            }
        };

        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "error kind",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            reader.scalar_calls == 1,
            "one scalar read",
            1,
            reader.scalar_calls
        );
        crate::assert_with_log!(second == [3u8; 2], "buffer unchanged", [3u8; 2], second);
        crate::test_complete!("default_read_vectored_propagates_scalar_error");
    }

    #[test]
    fn chain_reads_both() {
        init_test("chain_reads_both");
        let first: &[u8] = b"hi";
        let second: &[u8] = b"there";
        let mut chain = Chain::new(first, second);
        let mut buf = [0u8; 7];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready first", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"hi", "filled first", b"hi", filled);

        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready second", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"hithere", "filled second", b"hithere", filled);
        crate::test_complete!("chain_reads_both");
    }

    #[test]
    fn chain_does_not_switch_on_full_buffer() {
        init_test("chain_does_not_switch_on_full_buffer");
        let first: &[u8] = b"A";
        let second: &[u8] = b"B";
        let mut chain = Chain::new(first, second);
        let mut buf = [0u8; 0]; // Full buffer (0 capacity)
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Read with full buffer - should return Ok(0) but NOT switch
        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready 1", true, ready);

        // Internal state check: relies on implementation details or observable behavior
        // Since we can't inspect `done_first`, we check the next read behavior.

        // Read with capacity - should get "A"
        let mut buf2 = [0u8; 1];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let poll = Pin::new(&mut chain).poll_read(&mut cx, &mut read_buf2);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready 2", true, ready);
        let filled = read_buf2.filled();

        // If bug exists, it switched to "B" because it thought "A" was done
        crate::assert_with_log!(filled == b"A", "filled", b"A", filled);

        crate::test_complete!("chain_does_not_switch_on_full_buffer");
    }

    #[pin_project]
    struct PinnedReader<R> {
        #[pin]
        inner: R,
        _pin: PhantomPinned,
    }

    impl<R> AsyncRead for PinnedReader<R>
    where
        R: AsyncRead,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.project().inner.poll_read(cx, buf)
        }
    }

    #[pin_project]
    struct PinnedVectoredReader {
        inner: VectoredProbe,
        _pin: PhantomPinned,
    }

    impl PinnedVectoredReader {
        fn new(data: &[u8]) -> Self {
            Self {
                inner: VectoredProbe::new(data),
                _pin: PhantomPinned,
            }
        }
    }

    impl AsyncRead for PinnedVectoredReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut this = self.project();
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }

    impl AsyncReadVectored for PinnedVectoredReader {
        fn poll_read_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Poll<io::Result<usize>> {
            let mut this = self.project();
            Pin::new(&mut this.inner).poll_read_vectored(cx, bufs)
        }
    }

    #[test]
    fn pin_wrapper_read_supports_non_unpin_inner() {
        init_test("pin_wrapper_read_supports_non_unpin_inner");

        let inner: &[u8] = b"ok";
        let mut reader = Box::pin(PinnedReader {
            inner,
            _pin: PhantomPinned,
        });

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"ok", "filled", b"ok", filled);

        crate::test_complete!("pin_wrapper_read_supports_non_unpin_inner");
    }

    #[test]
    fn vectored_wrapper_for_mut_reader_uses_inner_impl() {
        init_test("vectored_wrapper_for_mut_reader_uses_inner_impl");

        let mut inner = VectoredProbe::new(b"abcdef");
        let mut wrapper = &mut inner;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut first = [0u8; 2];
        let mut second = [0u8; 4];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];

        let poll = Pin::new(&mut wrapper).poll_read_vectored(&mut cx, &mut bufs);
        let ready = matches!(poll, Poll::Ready(Ok(6)));
        crate::assert_with_log!(ready, "vectored length", true, ready);
        crate::assert_with_log!(first == *b"ab", "first buffer", *b"ab", first);
        crate::assert_with_log!(second == *b"cdef", "second buffer", *b"cdef", second);
        crate::assert_with_log!(
            inner.vectored_calls == 1,
            "vectored calls",
            1,
            inner.vectored_calls
        );
        crate::assert_with_log!(
            inner.scalar_calls == 0,
            "scalar calls",
            0,
            inner.scalar_calls
        );

        crate::test_complete!("vectored_wrapper_for_mut_reader_uses_inner_impl");
    }

    #[test]
    fn vectored_wrapper_for_box_reader_uses_inner_impl() {
        init_test("vectored_wrapper_for_box_reader_uses_inner_impl");

        let mut reader: Box<VectoredProbe> = Box::new(VectoredProbe::new(b"abcdef"));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut first = [0u8; 2];
        let mut second = [0u8; 4];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];

        let poll = Pin::new(&mut reader).poll_read_vectored(&mut cx, &mut bufs);
        let ready = matches!(poll, Poll::Ready(Ok(6)));
        crate::assert_with_log!(ready, "vectored length", true, ready);
        crate::assert_with_log!(first == *b"ab", "first buffer", *b"ab", first);
        crate::assert_with_log!(second == *b"cdef", "second buffer", *b"cdef", second);
        crate::assert_with_log!(
            reader.vectored_calls == 1,
            "vectored calls",
            1,
            reader.vectored_calls
        );
        crate::assert_with_log!(
            reader.scalar_calls == 0,
            "scalar calls",
            0,
            reader.scalar_calls
        );

        crate::test_complete!("vectored_wrapper_for_box_reader_uses_inner_impl");
    }

    #[test]
    fn vectored_wrapper_for_pin_box_reader_uses_inner_impl() {
        init_test("vectored_wrapper_for_pin_box_reader_uses_inner_impl");

        let mut reader = Box::pin(PinnedVectoredReader::new(b"abcdef"));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut first = [0u8; 2];
        let mut second = [0u8; 4];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];

        let poll = Pin::new(&mut reader).poll_read_vectored(&mut cx, &mut bufs);
        let ready = matches!(poll, Poll::Ready(Ok(6)));
        crate::assert_with_log!(ready, "vectored length", true, ready);
        crate::assert_with_log!(first == *b"ab", "first buffer", *b"ab", first);
        crate::assert_with_log!(second == *b"cdef", "second buffer", *b"cdef", second);
        let inner = &reader.as_ref().get_ref().inner;
        crate::assert_with_log!(
            inner.vectored_calls == 1,
            "vectored calls",
            1,
            inner.vectored_calls
        );
        crate::assert_with_log!(
            inner.scalar_calls == 0,
            "scalar calls",
            0,
            inner.scalar_calls
        );

        crate::test_complete!("vectored_wrapper_for_pin_box_reader_uses_inner_impl");
    }
}
