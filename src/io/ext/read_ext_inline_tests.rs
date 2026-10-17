    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::io::IoSliceMut;
    use std::pin::Pin;

    use std::task::{Context, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct PanicOnUseReader;

    impl AsyncRead for PanicOnUseReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            panic!("empty read_exact must not poll the reader")
        }
    }

    fn poll_ready<F: Future>(fut: &mut Pin<&mut F>) -> Option<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..32 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return Some(output);
            }
        }
        None
    }

    #[test]
    fn read_basic_returns_bytes() {
        init_test("read_basic_returns_bytes");
        let mut reader: &[u8] = b"hello";
        let mut buf = [0u8; 16];
        let mut fut = reader.read(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 5, "bytes read", 5, n);
        crate::assert_with_log!(&buf[..5] == b"hello", "content", b"hello", &buf[..5]);
        crate::test_complete!("read_basic_returns_bytes");
    }

    #[test]
    fn read_basic_returns_zero_on_eof() {
        init_test("read_basic_returns_zero_on_eof");
        let mut reader: &[u8] = b"";
        let mut buf = [0u8; 16];
        let mut fut = reader.read(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 0, "bytes read", 0, n);
        crate::test_complete!("read_basic_returns_zero_on_eof");
    }

    #[test]
    fn read_exact_ok() {
        init_test("read_exact_ok");
        let mut reader: &[u8] = b"abcd";
        let mut buf = [0u8; 4];
        let mut fut = reader.read_exact(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let result = poll_ready(&mut fut).expect("future did not resolve");
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::assert_with_log!(&buf == b"abcd", "buf", b"abcd", buf);
        crate::test_complete!("read_exact_ok");
    }

    #[test]
    fn read_exact_empty_returns_without_polling_reader() {
        init_test("read_exact_empty_returns_without_polling_reader");
        let mut reader = PanicOnUseReader;
        let mut buf = [];
        let mut fut = reader.read_exact(&mut buf);
        let mut fut = Pin::new(&mut fut);

        let result = poll_ready(&mut fut).expect("future did not resolve");
        crate::assert_with_log!(result.is_ok(), "result ok", true, result.is_ok());
        crate::test_complete!("read_exact_empty_returns_without_polling_reader");
    }

    #[test]
    fn read_exact_eof() {
        init_test("read_exact_eof");
        let mut reader: &[u8] = b"ab";
        let mut buf = [0u8; 4];
        let mut fut = reader.read_exact(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::UnexpectedEof,
            "error kind",
            io::ErrorKind::UnexpectedEof,
            kind
        );
        crate::test_complete!("read_exact_eof");
    }

    #[test]
    fn read_to_end_reads_all() {
        init_test("read_to_end_reads_all");
        let mut reader: &[u8] = b"hello";
        let mut buf = Vec::new();
        let mut fut = reader.read_to_end(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 5, "bytes read", 5, n);
        crate::assert_with_log!(buf == b"hello", "buf", b"hello", buf);
        crate::test_complete!("read_to_end_reads_all");
    }

    #[test]
    fn read_to_end_appends_and_counts_only_new_bytes() {
        init_test("read_to_end_appends_and_counts_only_new_bytes");
        let mut reader: &[u8] = b"tail";
        let mut buf = b"head:".to_vec();
        let mut fut = reader.read_to_end(&mut buf);
        let mut fut = Pin::new(&mut fut);

        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 4, "bytes read", 4, n);
        crate::assert_with_log!(buf == b"head:tail", "buf", b"head:tail", buf);
        crate::test_complete!("read_to_end_appends_and_counts_only_new_bytes");
    }

    #[test]
    fn read_to_string_reads_all() {
        init_test("read_to_string_reads_all");
        let mut reader: &[u8] = b"hi";
        let mut buf = String::new();
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 2, "bytes read", 2, n);
        crate::assert_with_log!(buf == "hi", "buf", "hi", buf);
        crate::test_complete!("read_to_string_reads_all");
    }

    #[test]
    fn read_to_string_appends_and_counts_only_new_bytes() {
        init_test("read_to_string_appends_and_counts_only_new_bytes");
        let mut reader: &[u8] = b"tail";
        let mut buf = String::from("head:");
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);

        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 4, "bytes read", 4, n);
        crate::assert_with_log!(buf == "head:tail", "buf", "head:tail", buf);
        crate::test_complete!("read_to_string_appends_and_counts_only_new_bytes");
    }

    #[test]
    fn read_to_string_invalid_utf8_errors() {
        init_test("read_to_string_invalid_utf8_errors");
        let mut reader: &[u8] = &[0xff, 0xfe];
        let mut buf = String::new();
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        let empty = buf.is_empty();
        crate::assert_with_log!(empty, "buf empty", true, empty);
        crate::test_complete!("read_to_string_invalid_utf8_errors");
    }

    #[test]
    fn read_to_string_incomplete_utf8_errors() {
        init_test("read_to_string_incomplete_utf8_errors");
        // 4-byte UTF-8 sequence, missing the final byte.
        let mut reader: &[u8] = &[0xF0, 0x9F, 0x92];
        let mut buf = String::new();
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        let empty = buf.is_empty();
        crate::assert_with_log!(empty, "buf empty", true, empty);
        crate::test_complete!("read_to_string_incomplete_utf8_errors");
    }

    #[test]
    fn read_to_string_invalid_utf8_rolls_back_after_long_valid_prefix() {
        init_test("read_to_string_invalid_utf8_rolls_back_after_long_valid_prefix");
        let mut input = vec![b'a'; 1024];
        input.push(0xFF);
        let mut reader: &[u8] = &input;
        let mut buf = String::from("seed");
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        crate::assert_with_log!(buf == "seed", "buf rollback", "seed", buf);
        crate::test_complete!("read_to_string_invalid_utf8_rolls_back_after_long_valid_prefix");
    }

    #[test]
    fn read_to_string_incomplete_utf8_rolls_back_after_long_valid_prefix() {
        init_test("read_to_string_incomplete_utf8_rolls_back_after_long_valid_prefix");
        let mut input = vec![b'a'; 1024];
        input.extend_from_slice(&[0xF0, 0x9F, 0x92]);
        let mut reader: &[u8] = &input;
        let mut buf = String::from("seed");
        let mut fut = reader.read_to_string(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        let kind = err.kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::InvalidData,
            "error kind",
            io::ErrorKind::InvalidData,
            kind
        );
        crate::assert_with_log!(buf == "seed", "buf rollback", "seed", buf);
        crate::test_complete!("read_to_string_incomplete_utf8_rolls_back_after_long_valid_prefix");
    }

    #[test]
    fn read_u8_reads_byte() {
        init_test("read_u8_reads_byte");
        let mut reader: &[u8] = b"z";
        let mut fut = reader.read_u8();
        let mut fut = Pin::new(&mut fut);
        let byte = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(byte == b'z', "byte", b'z', byte);
        crate::test_complete!("read_u8_reads_byte");
    }

    #[test]
    fn read_i8_reads_signed() {
        init_test("read_i8_reads_signed");
        let mut reader: &[u8] = &[0xFE]; // -2 as i8
        let mut fut = reader.read_i8();
        let mut fut = Pin::new(&mut fut);
        let val = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(val == -2, "i8 value", -2, val);
        crate::test_complete!("read_i8_reads_signed");
    }

    #[test]
    fn read_u16_big_endian() {
        init_test("read_u16_big_endian");
        let mut reader: &[u8] = &[0x01, 0x02]; // 258 in BE
        let mut fut = reader.read_u16();
        let mut fut = Pin::new(&mut fut);
        let val = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(val == 0x0102, "u16 BE", 0x0102u16, val);
        crate::test_complete!("read_u16_big_endian");
    }

    #[test]
    fn read_u16_le_little_endian() {
        init_test("read_u16_le_little_endian");
        let mut reader: &[u8] = &[0x02, 0x01]; // 258 in LE
        let mut fut = reader.read_u16_le();
        let mut fut = Pin::new(&mut fut);
        let val = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(val == 0x0102, "u16 LE", 0x0102u16, val);
        crate::test_complete!("read_u16_le_little_endian");
    }

    #[test]
    fn read_u32_big_endian() {
        init_test("read_u32_big_endian");
        let mut reader: &[u8] = &[0x00, 0x01, 0x00, 0x00]; // 65536 in BE
        let mut fut = reader.read_u32();
        let mut fut = Pin::new(&mut fut);
        let val = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(val == 0x0001_0000, "u32 BE", 0x0001_0000u32, val);
        crate::test_complete!("read_u32_big_endian");
    }

    #[test]
    fn read_u64_big_endian() {
        init_test("read_u64_big_endian");
        let mut reader: &[u8] = &0x0102_0304_0506_0708_u64.to_be_bytes();
        let mut fut = reader.read_u64();
        let mut fut = Pin::new(&mut fut);
        let val = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(
            val == 0x0102_0304_0506_0708,
            "u64 BE",
            0x0102_0304_0506_0708_u64,
            val
        );
        crate::test_complete!("read_u64_big_endian");
    }

    #[test]
    fn read_f32_big_endian() {
        init_test("read_f32_big_endian");
        let expected: f32 = 1.5;
        let mut reader: &[u8] = &expected.to_be_bytes();
        let mut fut = reader.read_f32();
        let mut fut = Pin::new(&mut fut);
        let val = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(
            (val - expected).abs() < f32::EPSILON,
            "f32 BE",
            expected,
            val
        );
        crate::test_complete!("read_f32_big_endian");
    }

    #[test]
    fn read_f64_le_little_endian() {
        init_test("read_f64_le_little_endian");
        let expected: f64 = core::f64::consts::PI;
        let mut reader: &[u8] = &expected.to_le_bytes();
        let mut fut = reader.read_f64_le();
        let mut fut = Pin::new(&mut fut);
        let val = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(
            (val - expected).abs() < f64::EPSILON,
            "f64 LE",
            expected,
            val
        );
        crate::test_complete!("read_f64_le_little_endian");
    }

    #[test]
    fn read_int_eof_returns_unexpected_eof() {
        init_test("read_int_eof_returns_unexpected_eof");
        let mut reader: &[u8] = &[0x01]; // only 1 byte for a u32
        let mut fut = reader.read_u32();
        let mut fut = Pin::new(&mut fut);
        let err = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap_err();
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::UnexpectedEof,
            "error kind",
            io::ErrorKind::UnexpectedEof,
            err.kind()
        );
        crate::test_complete!("read_int_eof_returns_unexpected_eof");
    }

    #[test]
    fn read_vectored_reads_prefix() {
        init_test("read_vectored_reads_prefix");
        let mut reader: &[u8] = b"hello";
        let mut a = [0u8; 2];
        let mut b = [0u8; 3];
        let mut bufs = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];

        let mut fut = reader.read_vectored(&mut bufs);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect("read_vectored failed");

        let mut got = Vec::new();
        let first = n.min(a.len());
        got.extend_from_slice(&a[..first]);
        if n > a.len() {
            got.extend_from_slice(&b[..n - a.len()]);
        }

        let expected = b"hello";
        crate::assert_with_log!(got == expected[..n], "vectored prefix", &expected[..n], got);
        crate::test_complete!("read_vectored_reads_prefix");
    }

    #[derive(Debug)]
    struct YieldingReader<'a> {
        data: &'a [u8],
        pos: usize,
        yield_next: bool,
    }

    impl<'a> YieldingReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self {
                data,
                pos: 0,
                yield_next: false,
            }
        }
    }

    impl AsyncRead for YieldingReader<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.yield_next {
                self.yield_next = false;
                return Poll::Pending;
            }

            if self.pos >= self.data.len() {
                return Poll::Ready(Ok(()));
            }

            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            buf.put_slice(&self.data[self.pos..=self.pos]);
            self.pos += 1;
            self.yield_next = true;

            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn cancel_safety_read_exact_is_not_cancel_safe() {
        init_test("cancel_safety_read_exact_is_not_cancel_safe");
        let mut reader = YieldingReader::new(b"abc");
        let mut buf = [0u8; 3];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = {
            let mut fut = reader.read_exact(&mut buf);
            let mut pinned = Pin::new(&mut fut);
            pinned.as_mut().poll(&mut cx)
        };
        let pending = matches!(poll, Poll::Pending);
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::assert_with_log!(buf[0] == b'a', "prefix", b'a', buf[0]);
        crate::test_complete!("cancel_safety_read_exact_is_not_cancel_safe");
    }

    #[test]
    fn cancel_safety_read_to_end_preserves_bytes() {
        init_test("cancel_safety_read_to_end_preserves_bytes");
        let mut reader = YieldingReader::new(b"abc");
        let mut out = Vec::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = {
            let mut fut = reader.read_to_end(&mut out);
            let mut pinned = Pin::new(&mut fut);
            pinned.as_mut().poll(&mut cx)
        };
        let pending = matches!(poll, Poll::Pending);
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::assert_with_log!(out == b"a", "out", b"a", out);
        crate::test_complete!("cancel_safety_read_to_end_preserves_bytes");
    }

    #[test]
    fn cancel_safety_read_to_string_preserves_prefix() {
        init_test("cancel_safety_read_to_string_preserves_prefix");
        let mut reader = YieldingReader::new(b"abc");
        let mut out = String::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = {
            let mut fut = reader.read_to_string(&mut out);
            let mut pinned = Pin::new(&mut fut);
            pinned.as_mut().poll(&mut cx)
        };
        let pending = matches!(poll, Poll::Pending);
        crate::assert_with_log!(pending, "pending", true, pending);
        crate::assert_with_log!(out == "a", "out", "a", out);
        crate::test_complete!("cancel_safety_read_to_string_preserves_prefix");
    }
