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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
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

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let mut total = 0usize;
            for buf in bufs {
                this.written.extend_from_slice(buf);
                total += buf.len();
            }
            Poll::Ready(Ok(total + 1))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PanicOnUseWriter;

    impl AsyncWrite for PanicOnUseWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            panic!("empty write_all must not poll the writer")
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            panic!("empty write_all must not poll vectored writes")
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("empty write_all must not poll flush")
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("empty write_all must not poll shutdown")
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum ControlStep {
        Pending,
        ReadyOk,
        ReadyErr(io::ErrorKind),
    }

    #[derive(Debug)]
    struct ScriptedControlWriter {
        flush_steps: std::collections::VecDeque<ControlStep>,
        shutdown_steps: std::collections::VecDeque<ControlStep>,
        flush_polls: usize,
        shutdown_polls: usize,
        expected_waker: Waker,
        saw_expected_waker: bool,
    }

    impl ScriptedControlWriter {
        fn new(
            expected_waker: Waker,
            flush_steps: impl IntoIterator<Item = ControlStep>,
            shutdown_steps: impl IntoIterator<Item = ControlStep>,
        ) -> Self {
            Self {
                flush_steps: flush_steps.into_iter().collect(),
                shutdown_steps: shutdown_steps.into_iter().collect(),
                flush_polls: 0,
                shutdown_polls: 0,
                expected_waker,
                saw_expected_waker: false,
            }
        }

        fn poll_control(
            steps: &mut std::collections::VecDeque<ControlStep>,
        ) -> Poll<io::Result<()>> {
            match steps.pop_front().expect("control script exhausted") {
                ControlStep::Pending => Poll::Pending,
                ControlStep::ReadyOk => Poll::Ready(Ok(())),
                ControlStep::ReadyErr(kind) => Poll::Ready(Err(io::Error::from(kind))),
            }
        }
    }

    impl AsyncWrite for ScriptedControlWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bufs.iter().map(|buf| buf.len()).sum()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_polls += 1;
            self.saw_expected_waker = cx.waker().will_wake(&self.expected_waker);
            Self::poll_control(&mut self.flush_steps)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_polls += 1;
            self.saw_expected_waker = cx.waker().will_wake(&self.expected_waker);
            Self::poll_control(&mut self.shutdown_steps)
        }
    }

    fn poll_ready<F: Future>(fut: &mut Pin<&mut F>) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..32 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return output;
            }
        }
        unreachable!("future did not resolve");
    }

    fn assert_invalid_data(err: io::Error) {
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            err.kind()
        );
    }

    #[test]
    fn write_basic_returns_bytes_written() {
        init_test("write_basic_returns_bytes_written");
        let mut output = Vec::new();
        let mut fut = output.write(b"hello");
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).unwrap();
        crate::assert_with_log!(n == 5, "bytes written", 5, n);
        crate::assert_with_log!(output == b"hello", "output", b"hello", output);
        crate::test_complete!("write_basic_returns_bytes_written");
    }

    #[test]
    fn write_empty_returns_zero() {
        init_test("write_empty_returns_zero");
        let mut output = Vec::new();
        let mut fut = output.write(b"");
        let mut fut = Pin::new(&mut fut);

        let n = poll_ready(&mut fut).unwrap();
        crate::assert_with_log!(n == 0, "bytes written", 0, n);
        crate::assert_with_log!(output.is_empty(), "output empty", true, output.is_empty());
        crate::test_complete!("write_empty_returns_zero");
    }

    #[test]
    fn write_preserves_exhausted_cursor_zero_progress() {
        init_test("write_preserves_exhausted_cursor_zero_progress");
        let mut storage = [0u8; 1];
        let mut writer = std::io::Cursor::new(storage.as_mut_slice());
        writer.set_position(1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let direct = AsyncWrite::poll_write(Pin::new(&mut writer), &mut cx, b"x");
        let direct_zero = matches!(direct, Poll::Ready(Ok(0)));
        crate::assert_with_log!(direct_zero, "direct write zero", true, direct_zero);

        let mut fut = writer.write(b"x");
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).expect("single write must preserve zero progress");
        crate::assert_with_log!(n == 0, "extension write zero", 0, n);
        crate::test_complete!("write_preserves_exhausted_cursor_zero_progress");
    }

    #[test]
    fn write_rejects_overreported_writer_progress() {
        init_test("write_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write(b"abc");
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(output.written == b"abc", "written", b"abc", output.written);
        crate::test_complete!("write_rejects_overreported_writer_progress");
    }

    #[test]
    fn write_all_ok() {
        init_test("write_all_ok");
        let mut output = Vec::new();
        let mut fut = output.write_all(b"hello world");
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(output == b"hello world", "output", b"hello world", output);
        crate::test_complete!("write_all_ok");
    }

    #[test]
    fn write_all_empty_returns_without_polling_writer() {
        init_test("write_all_empty_returns_without_polling_writer");
        let mut output = PanicOnUseWriter;
        let mut fut = output.write_all(b"");
        let mut fut = Pin::new(&mut fut);

        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::test_complete!("write_all_empty_returns_without_polling_writer");
    }

    #[test]
    fn write_all_still_rejects_exhausted_cursor_zero_progress() {
        init_test("write_all_still_rejects_exhausted_cursor_zero_progress");
        let mut storage = [0u8; 1];
        let mut writer = std::io::Cursor::new(storage.as_mut_slice());
        writer.set_position(1);
        let mut fut = writer.write_all(b"x");
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("write_all must require forward progress");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::WriteZero,
            "write_all error kind",
            io::ErrorKind::WriteZero,
            err.kind()
        );
        crate::test_complete!("write_all_still_rejects_exhausted_cursor_zero_progress");
    }

    #[test]
    fn write_all_rejects_overreported_writer_progress() {
        init_test("write_all_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write_all(b"abc");
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_all must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(output.written == b"abc", "written", b"abc", output.written);
        crate::test_complete!("write_all_rejects_overreported_writer_progress");
    }

    #[test]
    fn write_u8_ok() {
        init_test("write_u8_ok");
        let mut output = Vec::new();
        let mut fut = output.write_u8(0x42);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(output == vec![0x42], "output", vec![0x42], output);
        crate::test_complete!("write_u8_ok");
    }

    #[test]
    fn write_u8_rejects_overreported_writer_progress() {
        init_test("write_u8_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write_u8(0x42);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_u8 must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(
            output.written == vec![0x42],
            "written",
            vec![0x42],
            output.written
        );
        crate::test_complete!("write_u8_rejects_overreported_writer_progress");
    }

    #[test]
    fn write_i8_ok() {
        init_test("write_i8_ok");
        let mut output = Vec::new();
        let mut fut = output.write_i8(-2);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(output == vec![0xFE], "output", vec![0xFE], output);
        crate::test_complete!("write_i8_ok");
    }

    #[test]
    fn write_u16_big_endian() {
        init_test("write_u16_big_endian");
        let mut output = Vec::new();
        let mut fut = output.write_u16(0x0102);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(
            output == vec![0x01, 0x02],
            "output BE",
            vec![0x01, 0x02],
            output
        );
        crate::test_complete!("write_u16_big_endian");
    }

    #[test]
    fn write_u16_rejects_overreported_writer_progress() {
        init_test("write_u16_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let mut fut = output.write_u16(0x0102);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_u16 must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(
            output.written == vec![0x01, 0x02],
            "written",
            vec![0x01, 0x02],
            output.written
        );
        crate::test_complete!("write_u16_rejects_overreported_writer_progress");
    }

    #[test]
    fn write_u16_le_little_endian() {
        init_test("write_u16_le_little_endian");
        let mut output = Vec::new();
        let mut fut = output.write_u16_le(0x0102);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(
            output == vec![0x02, 0x01],
            "output LE",
            vec![0x02, 0x01],
            output
        );
        crate::test_complete!("write_u16_le_little_endian");
    }

    #[test]
    fn write_u32_big_endian() {
        init_test("write_u32_big_endian");
        let mut output = Vec::new();
        let mut fut = output.write_u32(0x0102_0304);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let expected = vec![0x01, 0x02, 0x03, 0x04];
        crate::assert_with_log!(output == expected, "output BE", expected, output);
        crate::test_complete!("write_u32_big_endian");
    }

    #[test]
    fn write_f64_le_little_endian() {
        init_test("write_f64_le_little_endian");
        let val: f64 = core::f64::consts::PI;
        let mut output = Vec::new();
        let mut fut = output.write_f64_le(val);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let expected = val.to_le_bytes().to_vec();
        crate::assert_with_log!(output == expected, "output f64 LE", expected, output);
        crate::test_complete!("write_f64_le_little_endian");
    }

    #[test]
    fn write_f32_and_f64_preserve_negative_zero_and_nan_payloads() {
        init_test("write_f32_and_f64_preserve_negative_zero_and_nan_payloads");

        // f32 negative zero and NaN with payload
        let neg_zero_32: f32 = -0.0;
        let nan_payload_32 = f32::from_bits(0x7fc0_0123);
        let mut out32_be = Vec::new();
        let mut fut = out32_be.write_f32(neg_zero_32);
        let _ = poll_ready(&mut Pin::new(&mut fut));
        crate::assert_with_log!(
            out32_be == (-0.0f32).to_be_bytes(),
            "f32 -0.0 BE bytes",
            (-0.0f32).to_be_bytes().to_vec(),
            out32_be
        );

        let mut out32_le = Vec::new();
        let mut fut = out32_le.write_f32_le(nan_payload_32);
        let _ = poll_ready(&mut Pin::new(&mut fut));
        crate::assert_with_log!(
            out32_le == nan_payload_32.to_le_bytes(),
            "f32 NaN payload LE bytes",
            nan_payload_32.to_le_bytes().to_vec(),
            out32_le
        );

        // f64 negative zero and NaN with payload
        let neg_zero_64: f64 = -0.0;
        let nan_payload_64 = f64::from_bits(0x7ff8_0000_0000_0123);
        let mut out64_be = Vec::new();
        let mut fut = out64_be.write_f64(neg_zero_64);
        let _ = poll_ready(&mut Pin::new(&mut fut));
        crate::assert_with_log!(
            out64_be == (-0.0f64).to_be_bytes(),
            "f64 -0.0 BE bytes",
            (-0.0f64).to_be_bytes().to_vec(),
            out64_be
        );

        let mut out64_le = Vec::new();
        let mut fut = out64_le.write_f64_le(nan_payload_64);
        let _ = poll_ready(&mut Pin::new(&mut fut));
        crate::assert_with_log!(
            out64_le == nan_payload_64.to_le_bytes(),
            "f64 NaN payload LE bytes",
            nan_payload_64.to_le_bytes().to_vec(),
            out64_le
        );

        crate::test_complete!("write_f32_and_f64_preserve_negative_zero_and_nan_payloads");
    }

    #[test]
    fn float_write_and_read_roundtrip_preserves_sign_and_bits() {
        use crate::io::AsyncReadExt;
        init_test("float_write_and_read_roundtrip_preserves_sign_and_bits");

        let neg_zero: f64 = -0.0;
        let mut buf = Vec::new();
        let mut fut = buf.write_f64(neg_zero);
        let _ = poll_ready(&mut Pin::new(&mut fut));

        let mut reader = &buf[..];
        let mut read_fut = reader.read_f64();
        let val = poll_ready(&mut Pin::new(&mut read_fut)).unwrap();
        crate::assert_with_log!(
            val.to_bits() == neg_zero.to_bits(),
            "roundtrip f64 bits",
            neg_zero.to_bits(),
            val.to_bits()
        );
        crate::assert_with_log!(
            val.is_sign_negative(),
            "roundtrip f64 is_sign_negative",
            true,
            val.is_sign_negative()
        );

        crate::test_complete!("float_write_and_read_roundtrip_preserves_sign_and_bits");
    }

    #[test]
    fn flush_ok() {
        init_test("flush_ok");
        let mut output = Vec::new();
        let mut fut = output.flush();
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::test_complete!("flush_ok");
    }

    #[test]
    fn flush_future_retries_after_pending() {
        init_test("flush_future_retries_after_pending");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = ScriptedControlWriter::new(
            waker.clone(),
            [ControlStep::Pending, ControlStep::ReadyOk],
            [],
        );

        {
            let mut fut = writer.flush();
            let first = Pin::new(&mut fut).poll(&mut cx);
            crate::assert_with_log!(
                matches!(first, Poll::Pending),
                "first flush pending",
                true,
                matches!(first, Poll::Pending)
            );

            let second = Pin::new(&mut fut).poll(&mut cx);
            let ready = matches!(second, Poll::Ready(Ok(())));
            crate::assert_with_log!(ready, "second flush ready", true, ready);
        }

        crate::assert_with_log!(
            writer.flush_polls == 2,
            "flush poll count",
            2,
            writer.flush_polls
        );
        crate::assert_with_log!(
            writer.shutdown_polls == 0,
            "shutdown not polled",
            0,
            writer.shutdown_polls
        );
        crate::assert_with_log!(
            writer.saw_expected_waker,
            "context forwarded",
            true,
            writer.saw_expected_waker
        );
        crate::test_complete!("flush_future_retries_after_pending");
    }

    #[test]
    fn flush_future_error_is_terminal() {
        init_test("flush_future_error_is_terminal");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = ScriptedControlWriter::new(
            waker.clone(),
            [ControlStep::ReadyErr(io::ErrorKind::BrokenPipe)],
            [],
        );

        {
            let mut fut = writer.flush();
            let first = Pin::new(&mut fut).poll(&mut cx);
            let err = match first {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected flush error, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::BrokenPipe,
                "flush error kind",
                io::ErrorKind::BrokenPipe,
                err.kind()
            );

            let second = Pin::new(&mut fut).poll(&mut cx);
            let err = match second {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected post-error completion guard, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::Other,
                "post-error completion guard",
                io::ErrorKind::Other,
                err.kind()
            );
        }

        crate::assert_with_log!(
            writer.flush_polls == 1,
            "flush poll count",
            1,
            writer.flush_polls
        );
        crate::test_complete!("flush_future_error_is_terminal");
    }

    #[test]
    fn shutdown_ok() {
        init_test("shutdown_ok");
        let mut output = Vec::new();
        let mut fut = output.shutdown();
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::test_complete!("shutdown_ok");
    }

    #[test]
    fn shutdown_future_is_single_use_after_ready() {
        init_test("shutdown_future_is_single_use_after_ready");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = ScriptedControlWriter::new(waker.clone(), [], [ControlStep::ReadyOk]);

        {
            let mut fut = writer.shutdown();
            let first = Pin::new(&mut fut).poll(&mut cx);
            let ready = matches!(first, Poll::Ready(Ok(())));
            crate::assert_with_log!(ready, "first shutdown ready", true, ready);

            let second = Pin::new(&mut fut).poll(&mut cx);
            let err = match second {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected post-completion error, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::Other,
                "post-completion error kind",
                io::ErrorKind::Other,
                err.kind()
            );
        }

        crate::assert_with_log!(
            writer.shutdown_polls == 1,
            "shutdown poll count",
            1,
            writer.shutdown_polls
        );
        crate::assert_with_log!(
            writer.flush_polls == 0,
            "flush not polled",
            0,
            writer.flush_polls
        );
        crate::test_complete!("shutdown_future_is_single_use_after_ready");
    }

    #[test]
    fn write_vectored_ok() {
        init_test("write_vectored_ok");
        let mut output = Vec::new();
        let data1 = b"hello ";
        let data2 = b"world";
        let bufs = &[IoSlice::new(data1), IoSlice::new(data2)];
        let mut fut = output.write_vectored(bufs);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).unwrap();
        // Vec's write_vectored writes all buffers.
        crate::assert_with_log!(n == 11, "bytes written", 11, n);
        crate::assert_with_log!(output == b"hello world", "output", b"hello world", output);
        crate::test_complete!("write_vectored_ok");
    }

    #[test]
    fn write_vectored_empty_returns_zero() {
        init_test("write_vectored_empty_returns_zero");
        let mut output = Vec::new();
        let bufs = &[IoSlice::new(b""), IoSlice::new(b"")];
        let mut fut = output.write_vectored(bufs);
        let mut fut = Pin::new(&mut fut);

        let n = poll_ready(&mut fut).unwrap();
        crate::assert_with_log!(n == 0, "bytes written", 0, n);
        crate::assert_with_log!(output.is_empty(), "output empty", true, output.is_empty());
        crate::test_complete!("write_vectored_empty_returns_zero");
    }

    #[test]
    fn write_vectored_preserves_exhausted_cursor_zero_progress() {
        init_test("write_vectored_preserves_exhausted_cursor_zero_progress");
        let mut storage = [0u8; 1];
        let mut writer = std::io::Cursor::new(storage.as_mut_slice());
        writer.set_position(1);
        let bufs = [IoSlice::new(b"x"), IoSlice::new(b"y")];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let direct = AsyncWrite::poll_write_vectored(Pin::new(&mut writer), &mut cx, &bufs);
        let direct_zero = matches!(direct, Poll::Ready(Ok(0)));
        crate::assert_with_log!(direct_zero, "direct vectored zero", true, direct_zero);

        let mut fut = writer.write_vectored(&bufs);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut).expect("single vectored write must preserve zero progress");
        crate::assert_with_log!(n == 0, "extension vectored zero", 0, n);
        crate::test_complete!("write_vectored_preserves_exhausted_cursor_zero_progress");
    }

    #[test]
    fn write_vectored_rejects_overreported_writer_progress() {
        init_test("write_vectored_rejects_overreported_writer_progress");
        let mut output = OverreportingWriter::new();
        let data1 = b"hello ";
        let data2 = b"world";
        let bufs = &[IoSlice::new(data1), IoSlice::new(data2)];
        let mut fut = output.write_vectored(bufs);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_vectored must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(
            output.written == b"hello world",
            "written",
            b"hello world",
            output.written
        );
        crate::test_complete!("write_vectored_rejects_overreported_writer_progress");
    }

    #[test]
    fn write_all_buf_ok() {
        init_test("write_all_buf_ok");
        let mut output = Vec::new();
        let mut input: &[u8] = b"buffered";
        let mut fut = output.write_all_buf(&mut input);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut);
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        let empty = input.is_empty();
        crate::assert_with_log!(empty, "input empty", true, empty);
        crate::assert_with_log!(output == b"buffered", "output", b"buffered", output);
        crate::test_complete!("write_all_buf_ok");
    }

    #[test]
    fn write_all_buf_rejects_overreported_writer_before_advancing_buf() {
        init_test("write_all_buf_rejects_overreported_writer_before_advancing_buf");
        let mut output = OverreportingWriter::new();
        let mut input: &[u8] = b"buffered";
        let mut fut = output.write_all_buf(&mut input);
        let mut fut = Pin::new(&mut fut);

        let err = poll_ready(&mut fut).expect_err("overreported write_all_buf must fail closed");
        assert_invalid_data(err);
        crate::assert_with_log!(input == b"buffered", "input", b"buffered", input);
        crate::assert_with_log!(
            output.written == b"buffered",
            "written",
            b"buffered",
            output.written
        );
        crate::test_complete!("write_all_buf_rejects_overreported_writer_before_advancing_buf");
    }

    #[test]
    fn write_read_roundtrip_u32() {
        use crate::io::ext::read_ext::AsyncReadExt;
        init_test("write_read_roundtrip_u32");
        let expected: u32 = 0xDEAD_BEEF;
        let mut output = Vec::new();

        // Write
        let mut fut = output.write_u32(expected);
        let mut fut = Pin::new(&mut fut);
        poll_ready(&mut fut).unwrap();

        // Read back
        let mut reader: &[u8] = &output;
        let mut fut = reader.read_u32();
        let mut fut = Pin::new(&mut fut);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let val = match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(v)) => v,
            other => panic!("unexpected poll result: {other:?}"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(val == expected, "roundtrip u32", expected, val);
        crate::test_complete!("write_read_roundtrip_u32");
    }
