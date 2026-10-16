    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    use std::task::{Context, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_ready<F: Future>(fut: &mut Pin<&mut F>) -> Option<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..1024 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return Some(output);
            }
        }
        None
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn copy_small_data() {
        init_test("copy_small_data");
        let mut reader: &[u8] = b"hello world";
        let mut writer = Vec::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 11, "bytes", 11, n);
        crate::assert_with_log!(writer == b"hello world", "writer", b"hello world", writer);
        crate::test_complete!("copy_small_data");
    }

    #[test]
    fn copy_empty_data() {
        init_test("copy_empty_data");
        let mut reader: &[u8] = b"";
        let mut writer = Vec::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 0, "bytes", 0, n);
        let empty = writer.is_empty();
        crate::assert_with_log!(empty, "writer empty", true, empty);
        crate::test_complete!("copy_empty_data");
    }

    #[test]
    fn copy_large_data() {
        init_test("copy_large_data");
        let data: Vec<u8> = (0u32..32768).map(|i| (i % 256) as u8).collect();
        let mut reader: &[u8] = &data;
        let mut writer = Vec::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 32768, "bytes", 32768, n);
        crate::assert_with_log!(writer == data, "writer", data, writer);
        crate::test_complete!("copy_large_data");
    }

    struct InterruptingWriter {
        written: Vec<u8>,
        remaining_before_interrupt: usize,
    }

    impl InterruptingWriter {
        fn new(prefix_len: usize) -> Self {
            Self {
                written: Vec::new(),
                remaining_before_interrupt: prefix_len,
            }
        }
    }

    impl AsyncWrite for InterruptingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.remaining_before_interrupt == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "writer interrupted",
                )));
            }

            let to_write = this.remaining_before_interrupt.min(buf.len());
            this.written.extend_from_slice(&buf[..to_write]);
            this.remaining_before_interrupt -= to_write;
            Poll::Ready(Ok(to_write))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct OverreportingWriter {
        written: Vec<u8>,
    }

    impl OverreportingWriter {
        fn new() -> Self {
            Self {
                written: Vec::new(),
            }
        }
    }

    impl AsyncWrite for OverreportingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len() + 1))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct ZeroWriter;

    impl AsyncWrite for ZeroWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn copy_rejects_overreported_writer_progress() {
        init_test("copy_rejects_overreported_writer_progress");
        let mut reader: &[u8] = b"abc";
        let mut writer = OverreportingWriter::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect_err("overreported write must fail closed");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            err.kind()
        );
        crate::assert_with_log!(writer.written == b"abc", "written", b"abc", writer.written);
        crate::test_complete!("copy_rejects_overreported_writer_progress");
    }

    #[test]
    fn copy_buf_rejects_overreported_writer_before_consuming_reader() {
        init_test("copy_buf_rejects_overreported_writer_before_consuming_reader");
        let mut reader: &[u8] = b"abc";
        let mut writer = OverreportingWriter::new();
        let mut fut = copy_buf(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect_err("overreported write must fail closed");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            err.kind()
        );
        crate::assert_with_log!(reader == b"abc", "reader not consumed", b"abc", reader);
        crate::assert_with_log!(writer.written == b"abc", "written", b"abc", writer.written);
        crate::test_complete!("copy_buf_rejects_overreported_writer_before_consuming_reader");
    }

    #[test]
    fn copy_buf_rejects_zero_write_before_consuming_reader() {
        init_test("copy_buf_rejects_zero_write_before_consuming_reader");
        let mut reader: &[u8] = b"abc";
        let mut writer = ZeroWriter;
        let mut fut = copy_buf(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect_err("zero-byte write with pending data must fail closed");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::WriteZero,
            "error kind",
            io::ErrorKind::WriteZero,
            err.kind()
        );
        crate::assert_with_log!(reader == b"abc", "reader not consumed", b"abc", reader);
        crate::test_complete!("copy_buf_rejects_zero_write_before_consuming_reader");
    }

    #[test]
    fn copy_with_progress_rejects_overreported_writer_before_progress() {
        init_test("copy_with_progress_rejects_overreported_writer_before_progress");
        let mut reader: &[u8] = b"abc";
        let mut writer = OverreportingWriter::new();
        let mut progress = Vec::new();
        let mut fut = copy_with_progress(&mut reader, &mut writer, |total| {
            progress.push(total);
        });
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect_err("overreported write must fail closed");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            err.kind()
        );
        crate::assert_with_log!(
            progress.is_empty(),
            "progress calls",
            true,
            progress.is_empty()
        );
        crate::test_complete!("copy_with_progress_rejects_overreported_writer_before_progress");
    }

    #[test]
    fn copy_partial_write_interrupt_preserves_committed_prefix() {
        init_test("copy_partial_write_interrupt_preserves_committed_prefix");
        let data: Vec<u8> = (0u32..16384).map(|i| (i % 251) as u8).collect();
        let committed_prefix_len = 5000usize;
        let mut reader: &[u8] = &data;
        let mut writer = InterruptingWriter::new(committed_prefix_len);
        let mut fut = copy(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect_err("copy should stop on interrupted writer");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "error kind",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            writer.written.len() == committed_prefix_len,
            "committed prefix len",
            committed_prefix_len,
            writer.written.len()
        );
        crate::assert_with_log!(
            writer.written == data[..committed_prefix_len],
            "committed prefix data",
            &data[..committed_prefix_len],
            writer.written
        );
        crate::test_complete!("copy_partial_write_interrupt_preserves_committed_prefix");
    }

    #[test]
    fn copy_with_progress_interrupt_reports_only_committed_prefix() {
        init_test("copy_with_progress_interrupt_reports_only_committed_prefix");
        let data: Vec<u8> = (0u32..16384).map(|i| ((i * 7) % 253) as u8).collect();
        let committed_prefix_len = 4097usize;
        let mut reader: &[u8] = &data;
        let mut writer = InterruptingWriter::new(committed_prefix_len);
        let mut progress = Vec::new();
        let mut fut = copy_with_progress(&mut reader, &mut writer, |total| progress.push(total));
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect_err("copy_with_progress should stop on interrupted writer");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "error kind",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        let last_progress = progress.last().copied().unwrap_or_default() as usize;
        crate::assert_with_log!(
            last_progress == committed_prefix_len,
            "last progress equals committed prefix",
            committed_prefix_len,
            last_progress
        );
        crate::assert_with_log!(
            writer.written == data[..committed_prefix_len],
            "committed prefix data",
            &data[..committed_prefix_len],
            writer.written
        );
        crate::test_complete!("copy_with_progress_interrupt_reports_only_committed_prefix");
    }

    #[test]
    fn copy_with_progress_tracks_bytes() {
        init_test("copy_with_progress_tracks_bytes");
        let mut reader: &[u8] = b"hello world";
        let mut writer = Vec::new();
        let mut progress_calls = Vec::new();
        let mut fut = copy_with_progress(&mut reader, &mut writer, |total| {
            progress_calls.push(total);
        });
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 11, "bytes", 11, n);
        crate::assert_with_log!(writer == b"hello world", "writer", b"hello world", writer);
        // Progress should be called with increasing values
        let empty = progress_calls.is_empty();
        crate::assert_with_log!(!empty, "progress calls", false, empty);
        let last = *progress_calls.last().unwrap();
        crate::assert_with_log!(last == 11, "last progress", 11, last);
        crate::test_complete!("copy_with_progress_tracks_bytes");
    }

    #[test]
    fn copy_buf_reads_from_slice() {
        init_test("copy_buf_reads_from_slice");
        let mut reader: &[u8] = b"hello buffer";
        let mut writer = Vec::new();
        let mut fut = copy_buf(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 12, "bytes", 12, n);
        crate::assert_with_log!(writer == b"hello buffer", "writer", b"hello buffer", writer);
        let empty = reader.is_empty();
        crate::assert_with_log!(empty, "reader empty", true, empty);
        crate::test_complete!("copy_buf_reads_from_slice");
    }

    #[test]
    fn copy_buf_reads_from_cursor() {
        init_test("copy_buf_reads_from_cursor");
        let data = b"cursor data";
        let mut reader = std::io::Cursor::new(data);
        let mut writer = Vec::new();
        let mut fut = copy_buf(&mut reader, &mut writer);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 11, "bytes", 11, n);
        crate::assert_with_log!(writer == data, "writer", data, writer);
        crate::test_complete!("copy_buf_reads_from_cursor");
    }

    /// A simple duplex stream for testing bidirectional copy.
    struct TestDuplex {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        shutdown_called: bool,
    }

    impl TestDuplex {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_data: read_data.to_vec(),
                read_pos: 0,
                written: Vec::new(),
                shutdown_called: false,
            }
        }
    }

    impl AsyncRead for TestDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.read_pos >= this.read_data.len() {
                return Poll::Ready(Ok(()));
            }
            let to_copy = std::cmp::min(this.read_data.len() - this.read_pos, buf.remaining());
            buf.put_slice(&this.read_data[this.read_pos..this.read_pos + to_copy]);
            this.read_pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().shutdown_called = true;
            Poll::Ready(Ok(()))
        }
    }

    struct OverreportingDuplex {
        inner: TestDuplex,
    }

    impl OverreportingDuplex {
        fn new(read_data: &[u8]) -> Self {
            Self {
                inner: TestDuplex::new(read_data),
            }
        }
    }

    impl AsyncRead for OverreportingDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for OverreportingDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.inner.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len() + 1))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[test]
    fn copy_bidirectional_rejects_overreported_writer_progress() {
        init_test("copy_bidirectional_rejects_overreported_writer_progress");
        let mut a = TestDuplex::new(b"abc");
        let mut b = OverreportingDuplex::new(b"");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect_err("overreported write must fail closed");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            err.kind()
        );
        crate::assert_with_log!(
            b.inner.written == b"abc",
            "written",
            b"abc",
            b.inner.written
        );
        crate::test_complete!("copy_bidirectional_rejects_overreported_writer_progress");
    }

    #[test]
    fn copy_bidirectional_basic() {
        init_test("copy_bidirectional_basic");
        let mut a = TestDuplex::new(b"from A");
        let mut b = TestDuplex::new(b"from B");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 6, "a_to_b", 6, a_to_b);
        crate::assert_with_log!(b_to_a == 6, "b_to_a", 6, b_to_a);
        crate::assert_with_log!(b.written == b"from A", "b written", b"from A", b.written);
        crate::assert_with_log!(a.written == b"from B", "a written", b"from B", a.written);
        crate::test_complete!("copy_bidirectional_basic");
    }

    #[test]
    fn copy_bidirectional_propagates_shutdown() {
        init_test("copy_bidirectional_propagates_shutdown");
        let mut a = TestDuplex::new(b"from A");
        let mut b = TestDuplex::new(b"from B");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let _ = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();

        crate::assert_with_log!(a.shutdown_called, "a shutdown", true, a.shutdown_called);
        crate::assert_with_log!(b.shutdown_called, "b shutdown", true, b.shutdown_called);
        crate::test_complete!("copy_bidirectional_propagates_shutdown");
    }

    #[test]
    fn copy_bidirectional_asymmetric() {
        init_test("copy_bidirectional_asymmetric");
        let mut a = TestDuplex::new(b"short");
        let mut b = TestDuplex::new(b"this is a longer message");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 5, "a_to_b", 5, a_to_b);
        crate::assert_with_log!(b_to_a == 24, "b_to_a", 24, b_to_a);
        crate::assert_with_log!(b.written == b"short", "b written", b"short", b.written);
        crate::assert_with_log!(
            a.written == b"this is a longer message",
            "a written",
            b"this is a longer message",
            a.written
        );
        crate::test_complete!("copy_bidirectional_asymmetric");
    }

    #[test]
    fn copy_bidirectional_empty() {
        init_test("copy_bidirectional_empty");
        let mut a = TestDuplex::new(b"");
        let mut b = TestDuplex::new(b"");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 0, "a_to_b", 0, a_to_b);
        crate::assert_with_log!(b_to_a == 0, "b_to_a", 0, b_to_a);
        crate::test_complete!("copy_bidirectional_empty");
    }

    /// Duplex that defers shutdown by returning Pending on the first call.
    struct DeferredShutdownDuplex {
        inner: TestDuplex,
        shutdown_poll_count: usize,
    }

    impl DeferredShutdownDuplex {
        fn new(read_data: &[u8]) -> Self {
            Self {
                inner: TestDuplex::new(read_data),
                shutdown_poll_count: 0,
            }
        }
    }

    impl AsyncRead for DeferredShutdownDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DeferredShutdownDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.shutdown_poll_count += 1;
            if this.shutdown_poll_count <= 1 {
                // Defer: register waker and return Pending on first call.
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                this.inner.shutdown_called = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    #[test]
    fn copy_bidirectional_waits_for_shutdown_completion() {
        init_test("copy_bidirectional_waits_for_shutdown_completion");
        let mut a = DeferredShutdownDuplex::new(b"hello");
        let mut b = DeferredShutdownDuplex::new(b"world");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);
        let (a_to_b, b_to_a) = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(a_to_b == 5, "a_to_b", 5, a_to_b);
        crate::assert_with_log!(b_to_a == 5, "b_to_a", 5, b_to_a);
        // Both sides must have completed shutdown.
        let a_shut = a.inner.shutdown_called;
        let b_shut = b.inner.shutdown_called;
        crate::assert_with_log!(a_shut, "a shutdown done", true, a_shut);
        crate::assert_with_log!(b_shut, "b shutdown done", true, b_shut);
        crate::test_complete!("copy_bidirectional_waits_for_shutdown_completion");
    }

    #[test]
    fn copy_bidirectional_yields_on_fast_streams() {
        // Use an infinitely fast, infinite stream.
        struct InfiniteStream;
        impl AsyncRead for InfiniteStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let space = buf.remaining();
                let zeros = vec![0u8; space];
                buf.put_slice(&zeros);
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for InfiniteStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        init_test("copy_bidirectional_yields_on_fast_streams");

        let mut a = InfiniteStream;
        let mut b = InfiniteStream;
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut fut = Pin::new(&mut fut);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Fast streams should yield back to the scheduler instead of spinning forever.
        let poll_result = fut.as_mut().poll(&mut cx);
        let is_pending = matches!(poll_result, Poll::Pending);
        crate::assert_with_log!(is_pending, "poll result is pending", true, is_pending);

        crate::test_complete!("copy_bidirectional_yields_on_fast_streams");
    }

    // =====================================================================
    // Fail-closed repoll-after-completion regression tests (asupersync-u20t2)
    // =====================================================================

    #[test]
    fn copy_repoll_after_completion_fails_closed() {
        init_test("copy_repoll_after_completion_fails_closed");
        let mut reader: &[u8] = b"data";
        let mut writer = Vec::new();
        let mut fut = copy(&mut reader, &mut writer);
        let mut pinned = Pin::new(&mut fut);

        // First poll should complete.
        let first = poll_ready(&mut pinned).expect("future did not resolve");
        assert!(first.is_ok(), "first poll should succeed");

        // Second poll should return an error, NOT panic.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let second = pinned.as_mut().poll(&mut cx);
        match second {
            Poll::Ready(Err(e)) => {
                let msg = e.to_string();
                let ok = msg.contains("polled after completion");
                crate::assert_with_log!(ok, "error message", "polled after completion", msg);
            }
            other => panic!("expected Ready(Err), got {other:?}"), // ubs:ignore - test logic
        }
        crate::test_complete!("copy_repoll_after_completion_fails_closed");
    }

    #[test]
    fn copy_buf_repoll_after_completion_fails_closed() {
        init_test("copy_buf_repoll_after_completion_fails_closed");
        let mut reader: &[u8] = b"data";
        let mut writer = Vec::new();
        let mut fut = copy_buf(&mut reader, &mut writer);
        let mut pinned = Pin::new(&mut fut);

        let first = poll_ready(&mut pinned).expect("future did not resolve");
        assert!(first.is_ok(), "first poll should succeed");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let second = pinned.as_mut().poll(&mut cx);
        match second {
            Poll::Ready(Err(e)) => {
                let msg = e.to_string();
                let ok = msg.contains("polled after completion");
                crate::assert_with_log!(ok, "error message", "polled after completion", msg);
            }
            other => panic!("expected Ready(Err), got {other:?}"), // ubs:ignore - test logic
        }
        crate::test_complete!("copy_buf_repoll_after_completion_fails_closed");
    }

    #[test]
    fn copy_with_progress_repoll_after_completion_fails_closed() {
        init_test("copy_with_progress_repoll_after_completion_fails_closed");
        let mut reader: &[u8] = b"data";
        let mut writer = Vec::new();
        let mut fut = copy_with_progress(&mut reader, &mut writer, |_| {});
        let mut pinned = Pin::new(&mut fut);

        let first = poll_ready(&mut pinned).expect("future did not resolve");
        assert!(first.is_ok(), "first poll should succeed");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let second = pinned.as_mut().poll(&mut cx);
        match second {
            Poll::Ready(Err(e)) => {
                let msg = e.to_string();
                let ok = msg.contains("polled after completion");
                crate::assert_with_log!(ok, "error message", "polled after completion", msg);
            }
            other => panic!("expected Ready(Err), got {other:?}"), // ubs:ignore - test logic
        }
        crate::test_complete!("copy_with_progress_repoll_after_completion_fails_closed");
    }

    #[test]
    fn copy_bidirectional_repoll_after_completion_fails_closed() {
        init_test("copy_bidirectional_repoll_after_completion_fails_closed");
        let mut a = TestDuplex::new(b"hello");
        let mut b = TestDuplex::new(b"world");
        let mut fut = copy_bidirectional(&mut a, &mut b);
        let mut pinned = Pin::new(&mut fut);

        let first = poll_ready(&mut pinned).expect("future did not resolve");
        assert!(first.is_ok(), "first poll should succeed");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let second = pinned.as_mut().poll(&mut cx);
        match second {
            Poll::Ready(Err(e)) => {
                let msg = e.to_string();
                let ok = msg.contains("polled after completion");
                crate::assert_with_log!(ok, "error message", "polled after completion", msg);
            }
            other => panic!("expected Ready(Err), got {other:?}"), // ubs:ignore - test logic
        }
        crate::test_complete!("copy_bidirectional_repoll_after_completion_fails_closed");
    }
