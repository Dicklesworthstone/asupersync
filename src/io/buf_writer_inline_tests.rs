    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct ReportedProgressWriter {
        reported: std::collections::VecDeque<usize>,
        offered: Vec<Vec<u8>>,
    }

    impl ReportedProgressWriter {
        fn new(reported: impl IntoIterator<Item = usize>) -> Self {
            Self {
                reported: reported.into_iter().collect(),
                offered: Vec::new(),
            }
        }
    }

    impl AsyncWrite for ReportedProgressWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.offered.push(buf.to_vec());
            Poll::Ready(Ok(this
                .reported
                .pop_front()
                .expect("write script exhausted")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn buf_writer_new() {
        init_test("buf_writer_new");
        let writer: Vec<u8> = Vec::new();
        let buf_writer = BufWriter::new(writer);
        let capacity = buf_writer.capacity();
        crate::assert_with_log!(
            capacity == DEFAULT_BUF_CAPACITY,
            "capacity",
            DEFAULT_BUF_CAPACITY,
            capacity
        );
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_writer_new");
    }

    #[test]
    fn buf_writer_with_capacity() {
        init_test("buf_writer_with_capacity");
        let writer: Vec<u8> = Vec::new();
        let buf_writer = BufWriter::with_capacity(256, writer);
        let capacity = buf_writer.capacity();
        crate::assert_with_log!(capacity == 256, "capacity", 256, capacity);
        crate::test_complete!("buf_writer_with_capacity");
    }

    #[test]
    fn buf_writer_get_ref() {
        init_test("buf_writer_get_ref");
        let writer = vec![42];
        let buf_writer = BufWriter::new(writer);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == &[42], "get_ref", &[42], inner);
        crate::test_complete!("buf_writer_get_ref");
    }

    #[test]
    fn buf_writer_into_inner() {
        init_test("buf_writer_into_inner");
        let writer = vec![42];
        let buf_writer = BufWriter::new(writer);
        let inner = buf_writer.into_inner();
        crate::assert_with_log!(inner == vec![42], "into_inner", vec![42], inner);
        crate::test_complete!("buf_writer_into_inner");
    }

    #[test]
    fn buf_writer_small_write_buffered() {
        init_test("buf_writer_small_write_buffered");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(16, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write small data - should be buffered
        let poll = Pin::new(&mut buf_writer).poll_write(&mut cx, b"hello");
        let ready = matches!(poll, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ready, "write 5", true, ready);

        // Data should be in buffer, not in inner writer
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"hello", "buffer", b"hello", buffer);
        let inner_empty = buf_writer.get_ref().is_empty();
        crate::assert_with_log!(inner_empty, "inner empty", true, inner_empty);
        crate::test_complete!("buf_writer_small_write_buffered");
    }

    #[test]
    fn buf_writer_flush_writes_to_inner() {
        init_test("buf_writer_flush_writes_to_inner");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(16, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"hello");
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(!empty, "buffer not empty", false, empty);

        // Flush
        let poll = Pin::new(&mut buf_writer).poll_flush(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "flush ready", true, ready);

        // Buffer should be empty, data in inner
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"hello", "inner", b"hello", inner);
        crate::test_complete!("buf_writer_flush_writes_to_inner");
    }

    #[test]
    fn buf_writer_partial_flush_exposes_only_unwritten_bytes() {
        struct PartialWriter {
            bytes: Vec<u8>,
            interrupted: bool,
            return_error: bool,
        }

        impl AsyncWrite for PartialWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                if this.bytes.len() == 2 && !this.interrupted {
                    this.interrupted = true;
                    if this.return_error {
                        return Poll::Ready(Err(io::Error::other("interrupted flush")));
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let n = buf.len().min(2);
                this.bytes.extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        init_test("buf_writer_partial_flush_exposes_only_unwritten_bytes");
        let mut cx = Context::from_waker(Waker::noop());
        for return_error in [false, true] {
            for recover_inner in [false, true] {
                let inner = PartialWriter {
                    bytes: Vec::new(),
                    interrupted: false,
                    return_error,
                };
                let mut writer = BufWriter::with_capacity(8, inner);
                assert!(matches!(
                    Pin::new(&mut writer).poll_write(&mut cx, b"abcd"),
                    Poll::Ready(Ok(4))
                ));
                let stopped = Pin::new(&mut writer).poll_flush(&mut cx);
                if return_error {
                    assert!(matches!(stopped, Poll::Ready(Err(_))));
                } else {
                    assert!(stopped.is_pending());
                }
                assert_eq!(writer.get_ref().bytes, b"ab", "accepted prefix");
                assert_eq!(
                    writer.buffer(),
                    b"cd",
                    "only unwritten bytes are recoverable"
                );
                if recover_inner {
                    let remaining = writer.buffer().to_vec();
                    let mut inner = writer.into_inner();
                    assert!(matches!(
                        Pin::new(&mut inner).poll_write(&mut cx, &remaining),
                        Poll::Ready(Ok(2))
                    ));
                    assert_eq!(inner.bytes, b"abcd", "recovery does not duplicate bytes");
                } else {
                    assert!(matches!(
                        Pin::new(&mut writer).poll_flush(&mut cx),
                        Poll::Ready(Ok(()))
                    ));
                    assert!(writer.buffer().is_empty());
                    assert_eq!(
                        writer.get_ref().bytes,
                        b"abcd",
                        "retry does not duplicate bytes"
                    );
                }
            }
        }
        crate::test_complete!("buf_writer_partial_flush_exposes_only_unwritten_bytes");
    }

    #[test]
    fn buf_writer_flush_rejects_immediate_overreport_without_advancing() {
        init_test("buf_writer_flush_rejects_immediate_overreport_without_advancing");
        let writer = ReportedProgressWriter::new([5]);
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let buffered = Pin::new(&mut buf_writer).poll_write(&mut cx, b"abcd");
        let buffered_ok = matches!(buffered, Poll::Ready(Ok(4)));
        crate::assert_with_log!(buffered_ok, "buffered write", true, buffered_ok);

        let flushed = Pin::new(&mut buf_writer).poll_flush(&mut cx);
        let invalid_data =
            matches!(flushed, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::InvalidData);
        crate::assert_with_log!(invalid_data, "invalid data", true, invalid_data);
        crate::assert_with_log!(buf_writer.written == 0, "written", 0, buf_writer.written);
        crate::assert_with_log!(
            buf_writer.buffer() == b"abcd",
            "buffer",
            b"abcd",
            buf_writer.buffer()
        );
        crate::assert_with_log!(
            buf_writer.get_ref().offered == vec![b"abcd".to_vec()],
            "offered slices",
            vec![b"abcd".to_vec()],
            buf_writer.get_ref().offered.clone()
        );
        crate::test_complete!("buf_writer_flush_rejects_immediate_overreport_without_advancing");
    }

    #[test]
    fn buf_writer_flush_rejects_overreport_after_valid_partial_progress() {
        init_test("buf_writer_flush_rejects_overreport_after_valid_partial_progress");
        let writer = ReportedProgressWriter::new([2, usize::MAX]);
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let buffered = Pin::new(&mut buf_writer).poll_write(&mut cx, b"abcd");
        let buffered_ok = matches!(buffered, Poll::Ready(Ok(4)));
        crate::assert_with_log!(buffered_ok, "buffered write", true, buffered_ok);

        let flushed = Pin::new(&mut buf_writer).poll_flush(&mut cx);
        let invalid_data =
            matches!(flushed, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::InvalidData);
        crate::assert_with_log!(invalid_data, "invalid data", true, invalid_data);
        crate::assert_with_log!(buf_writer.written == 2, "written", 2, buf_writer.written);
        // Keep the original overreport guard: no bytes or progress beyond
        // the valid prefix were discarded. The public view is the suffix.
        assert_eq!(buf_writer.buf, b"abcd");
        crate::assert_with_log!(
            buf_writer.buffer() == b"cd",
            "buffer",
            b"cd",
            buf_writer.buffer()
        );
        crate::assert_with_log!(
            buf_writer.get_ref().offered == vec![b"abcd".to_vec(), b"cd".to_vec()],
            "offered slices",
            vec![b"abcd".to_vec(), b"cd".to_vec()],
            buf_writer.get_ref().offered.clone()
        );
        crate::test_complete!("buf_writer_flush_rejects_overreport_after_valid_partial_progress");
    }

    #[test]
    fn buf_writer_buffer_full_auto_flush() {
        init_test("buf_writer_buffer_full_auto_flush");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data that fills buffer
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"12345678");
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"12345678", "buffer", b"12345678", buffer);
        let inner_empty = buf_writer.get_ref().is_empty();
        crate::assert_with_log!(inner_empty, "inner empty", true, inner_empty);

        // Write more data - should trigger flush
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"9ABC");

        // First buffer should have been flushed
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"12345678", "inner", b"12345678", inner);
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"9ABC", "buffer", b"9ABC", buffer);
        crate::test_complete!("buf_writer_buffer_full_auto_flush");
    }

    #[test]
    fn buf_writer_large_write_bypasses_buffer() {
        init_test("buf_writer_large_write_bypasses_buffer");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data larger than buffer capacity
        let poll = Pin::new(&mut buf_writer).poll_write(&mut cx, b"this is large data");
        let ready = matches!(poll, Poll::Ready(Ok(18)));
        crate::assert_with_log!(ready, "write 18", true, ready);

        // Data should go directly to inner writer
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(
            inner == b"this is large data",
            "inner",
            b"this is large data",
            inner
        );
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_writer_large_write_bypasses_buffer");
    }

    #[test]
    fn buf_writer_multiple_writes() {
        init_test("buf_writer_multiple_writes");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(32, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Multiple small writes
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"hello ");
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"world");
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"hello world", "buffer", b"hello world", buffer);
        let inner_empty = buf_writer.get_ref().is_empty();
        crate::assert_with_log!(inner_empty, "inner empty", true, inner_empty);

        // Flush
        let _ = Pin::new(&mut buf_writer).poll_flush(&mut cx);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"hello world", "inner", b"hello world", inner);
        crate::test_complete!("buf_writer_multiple_writes");
    }

    #[test]
    fn buf_writer_shutdown_flushes() {
        init_test("buf_writer_shutdown_flushes");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(32, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data
        let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, b"pending data");

        // Shutdown should flush
        let poll = Pin::new(&mut buf_writer).poll_shutdown(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "shutdown ready", true, ready);
        let inner = buf_writer.get_ref();
        crate::assert_with_log!(inner == b"pending data", "inner", b"pending data", inner);
        crate::test_complete!("buf_writer_shutdown_flushes");
    }

    #[test]
    fn buf_writer_vectored_write_buffered() {
        init_test("buf_writer_vectored_write_buffered");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(32, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let bufs = [IoSlice::new(b"hello "), IoSlice::new(b"world")];
        let poll = Pin::new(&mut buf_writer).poll_write_vectored(&mut cx, &bufs);
        let ready = matches!(poll, Poll::Ready(Ok(11)));
        crate::assert_with_log!(ready, "write 11", true, ready);
        let buffer = buf_writer.buffer();
        crate::assert_with_log!(buffer == b"hello world", "buffer", b"hello world", buffer);
        crate::test_complete!("buf_writer_vectored_write_buffered");
    }

    #[test]
    fn buf_writer_vectored_write_large_direct() {
        init_test("buf_writer_vectored_write_large_direct");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::with_capacity(8, writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let bufs = [IoSlice::new(b"this is "), IoSlice::new(b"large data")];
        let poll = Pin::new(&mut buf_writer).poll_write_vectored(&mut cx, &bufs);
        let ready = matches!(poll, Poll::Ready(Ok(_)));
        crate::assert_with_log!(ready, "write ready", true, ready);

        // Should write directly to inner (bypassing buffer)
        // Note: The exact behavior depends on the underlying writer's vectored support
        crate::test_complete!("buf_writer_vectored_write_large_direct");
    }

    #[test]
    fn buf_writer_empty_write() {
        init_test("buf_writer_empty_write");
        let writer = Vec::new();
        let mut buf_writer = BufWriter::new(writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut buf_writer).poll_write(&mut cx, b"");
        let ready = matches!(poll, Poll::Ready(Ok(0)));
        crate::assert_with_log!(ready, "write 0", true, ready);
        let empty = buf_writer.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_writer_empty_write");
    }
