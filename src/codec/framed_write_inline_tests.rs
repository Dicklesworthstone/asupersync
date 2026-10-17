    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::codec::LinesCodec;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<AtomicBool>);

    use std::task::Wake;
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn track_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(TrackWaker(flag)))
    }

    /// Minimal reference adapter for the `tokio-util` 0.7.x flush loop.
    ///
    /// This mirrors the `FramedImpl::poll_flush` write-side behavior from
    /// `tokio-util`'s `src/codec/framed_impl.rs` against our local
    /// `AsyncWrite`/`Encoder` traits so conformance drift is easy to detect
    /// without importing tokio into the core crate's test surface.
    struct TokioUtilFramedWriteRef<W, E> {
        inner: W,
        encoder: E,
        buffer: BytesMut,
    }

    impl<W, E> TokioUtilFramedWriteRef<W, E> {
        fn new(inner: W, encoder: E) -> Self {
            Self {
                inner,
                encoder,
                buffer: BytesMut::with_capacity(DEFAULT_CAPACITY),
            }
        }

        fn get_ref(&self) -> &W {
            &self.inner
        }

        fn write_buffer(&self) -> &BytesMut {
            &self.buffer
        }
    }

    impl<W, E> TokioUtilFramedWriteRef<W, E>
    where
        W: AsyncWrite + Unpin,
    {
        fn send<I>(&mut self, item: I) -> Result<(), <E as Encoder<I>>::Error>
        where
            E: Encoder<I>,
        {
            self.encoder.encode(item, &mut self.buffer)
        }

        fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while !self.buffer.is_empty() {
                let n = match Pin::new(&mut self.inner).poll_write(cx, &self.buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(n)) => n,
                };

                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write frame to transport",
                    )));
                }

                let _ = self.buffer.split_to(n);
            }

            Pin::new(&mut self.inner).poll_flush(cx)
        }
    }

    #[test]
    fn framed_write_encodes_and_flushes() {
        let output: Vec<u8> = Vec::new();
        let mut framed = FramedWrite::new(output, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        framed.send("hello".to_string()).unwrap();
        framed.send("world".to_string()).unwrap();

        assert_eq!(&framed.write_buffer()[..], b"hello\nworld\n");

        let poll = framed.poll_flush(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        assert!(framed.write_buffer().is_empty());
        assert_eq!(framed.get_ref(), b"hello\nworld\n");
    }

    #[test]
    fn framed_write_close() {
        let output: Vec<u8> = Vec::new();
        let mut framed = FramedWrite::new(output, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        framed.send("bye".to_string()).unwrap();

        let poll = framed.poll_close(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        assert!(framed.write_buffer().is_empty());
        assert_eq!(framed.get_ref(), b"bye\n");
    }

    #[test]
    fn framed_write_accessors() {
        let output: Vec<u8> = Vec::new();
        let mut framed = FramedWrite::new(output, LinesCodec::new());

        assert!(framed.write_buffer().is_empty());
        assert_eq!(
            framed.backpressure_boundary(),
            DEFAULT_BACKPRESSURE_BOUNDARY
        );
        let _encoder = framed.encoder();
        let _encoder_mut = framed.encoder_mut();
        let _writer = framed.get_ref();
        let _writer_mut = framed.get_mut();
    }

    #[test]
    fn framed_write_capacity_sets_initial_backpressure_boundary() {
        let framed = FramedWrite::with_capacity(Vec::<u8>::new(), LinesCodec::new(), 256);
        assert_eq!(framed.backpressure_boundary(), 256);
    }

    #[test]
    fn framed_write_into_parts() {
        let output: Vec<u8> = Vec::new();
        let framed = FramedWrite::new(output, LinesCodec::new());

        let (_writer, _encoder, _buf) = framed.into_parts();
    }

    #[derive(Debug)]
    struct GatedWriter {
        writable: Arc<AtomicBool>,
        inner: Vec<u8>,
    }

    impl GatedWriter {
        fn new(writable: Arc<AtomicBool>) -> Self {
            Self {
                writable,
                inner: Vec::new(),
            }
        }
    }

    impl AsyncWrite for GatedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if !this.writable.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            this.inner.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_write_readiness_bounds_pending_buffer_and_recovers() {
        let writable = Arc::new(AtomicBool::new(false));
        let mut framed =
            FramedWrite::new(GatedWriter::new(Arc::clone(&writable)), LinesCodec::new())
                .with_backpressure_boundary(8);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        framed.start_send("abc".to_string()).unwrap();
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        framed.start_send("def".to_string()).unwrap();
        assert_eq!(framed.write_buffer().len(), 8);

        assert!(matches!(framed.poll_ready(&mut cx), Poll::Pending));
        assert_eq!(
            framed.write_buffer().len(),
            8,
            "pending readiness must not grow the buffered prefix"
        );
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Pending));
        assert_eq!(framed.write_buffer().len(), 8);

        writable.store(true, Ordering::SeqCst);
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert!(framed.write_buffer().is_empty());
        assert_eq!(&framed.get_ref().inner, b"abc\ndef\n");
    }

    #[test]
    fn framed_write_boundary_is_soft_for_one_oversized_frame() {
        let writable = Arc::new(AtomicBool::new(false));
        let mut framed =
            FramedWrite::new(GatedWriter::new(Arc::clone(&writable)), LinesCodec::new())
                .with_backpressure_boundary(4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        framed.start_send("oversized".to_string()).unwrap();
        let oversized_len = framed.write_buffer().len();
        assert!(oversized_len > framed.backpressure_boundary());
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Pending));
        assert_eq!(framed.write_buffer().len(), oversized_len);

        writable.store(true, Ordering::SeqCst);
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert!(framed.write_buffer().is_empty());
    }

    /// Writer that accepts only a few bytes at a time.
    struct SlowWriter {
        inner: Vec<u8>,
        max_per_write: usize,
    }

    impl SlowWriter {
        fn new(max_per_write: usize) -> Self {
            Self {
                inner: Vec::new(),
                max_per_write,
            }
        }
    }

    impl AsyncWrite for SlowWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let n = std::cmp::min(buf.len(), this.max_per_write);
            this.inner.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_write_partial_writes() {
        let output = SlowWriter::new(3);
        let mut framed = FramedWrite::new(output, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        framed.send("abcdef".to_string()).unwrap();

        let poll = framed.poll_flush(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        assert!(framed.write_buffer().is_empty());
        assert_eq!(&framed.get_ref().inner, b"abcdef\n");
    }

    struct AlwaysReadyPartialWriter {
        inner: Vec<u8>,
        max_per_write: usize,
        writes: usize,
        panic_after: usize,
    }

    impl AlwaysReadyPartialWriter {
        fn new(max_per_write: usize, panic_after: usize) -> Self {
            Self {
                inner: Vec::new(),
                max_per_write,
                writes: 0,
                panic_after,
            }
        }
    }

    impl AsyncWrite for AlwaysReadyPartialWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            assert!(
                this.writes < this.panic_after,
                "writer was polled too many times without yielding"
            );
            this.writes += 1;
            let n = std::cmp::min(buf.len(), this.max_per_write);
            this.inner.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_write_yields_cooperatively_on_always_ready_partial_writer() {
        let output = AlwaysReadyPartialWriter::new(1, MAX_WRITE_PASSES_PER_POLL + 1);
        let mut framed = FramedWrite::new(output, LinesCodec::new());
        let woke = Arc::new(AtomicBool::new(false));
        let waker = track_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);

        framed
            .send("x".repeat(MAX_WRITE_PASSES_PER_POLL + 8))
            .expect("encode test frame");

        let poll = framed.poll_flush(&mut cx);
        assert!(matches!(poll, Poll::Pending));
        assert!(
            woke.load(Ordering::SeqCst),
            "cooperative yield should self-wake for continued draining"
        );
        assert_eq!(
            framed.get_ref().writes,
            MAX_WRITE_PASSES_PER_POLL,
            "poll_flush should stop after the cooperative write budget"
        );
        assert!(
            !framed.write_buffer().is_empty(),
            "buffered frame bytes must remain after the cooperative yield"
        );
    }

    #[derive(Clone, Copy)]
    enum WriteStep {
        Write(usize),
        WriteZero,
    }

    struct ScriptedWriter {
        inner: Vec<u8>,
        steps: VecDeque<WriteStep>,
    }

    impl ScriptedWriter {
        fn new(steps: impl IntoIterator<Item = WriteStep>) -> Self {
            Self {
                inner: Vec::new(),
                steps: steps.into_iter().collect(),
            }
        }
    }

    impl AsyncWrite for ScriptedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            match this
                .steps
                .pop_front()
                .unwrap_or(WriteStep::Write(buf.len()))
            {
                WriteStep::WriteZero => Poll::Ready(Ok(0)),
                WriteStep::Write(limit) => {
                    let n = limit.min(buf.len());
                    this.inner.extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_write_write_zero_after_partial_progress_matches_tokio_util_reference() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut actual = FramedWrite::new(
            ScriptedWriter::new([WriteStep::Write(3), WriteStep::WriteZero]),
            LinesCodec::new(),
        );
        let mut reference = TokioUtilFramedWriteRef::new(
            ScriptedWriter::new([WriteStep::Write(3), WriteStep::WriteZero]),
            LinesCodec::new(),
        );

        actual
            .send("abcdef".to_string())
            .expect("encode actual frame");
        reference
            .send("abcdef".to_string())
            .expect("encode reference frame");

        let actual_err = match actual.poll_flush(&mut cx) {
            Poll::Ready(Err(err)) => err,
            other => panic!("expected WriteZero from actual flush, got {other:?}"),
        };
        let reference_err = match reference.poll_flush(&mut cx) {
            Poll::Ready(Err(err)) => err,
            other => panic!("expected WriteZero from reference flush, got {other:?}"),
        };

        assert_eq!(actual_err.kind(), io::ErrorKind::WriteZero);
        assert_eq!(actual_err.kind(), reference_err.kind());
        assert_eq!(actual.get_ref().inner, reference.get_ref().inner);
        assert_eq!(&actual.write_buffer()[..], &reference.write_buffer()[..]);
        assert_eq!(
            &actual.get_ref().inner,
            b"abc",
            "partial progress should commit only the written prefix"
        );
        assert_eq!(
            &actual.write_buffer()[..],
            b"def\n",
            "remaining suffix should stay buffered after WriteZero"
        );
    }
