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

    fn poll_buffer_read<R, B>(reader: &mut R, buffer: &mut B) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + Unpin + ?Sized,
        B: crate::bytes::BufMut + ?Sized,
    {
        let mut future = reader.read_buf(buffer);
        Pin::new(&mut future).poll(&mut Context::from_waker(Waker::noop()))
    }

    enum BufferReadStep {
        Pending,
        Data(&'static [u8]),
        PendingData(&'static [u8]),
        ErrorData(&'static [u8]),
        Panic,
    }

    struct BufferReader {
        steps: std::collections::VecDeque<BufferReadStep>,
        polls: usize,
    }

    impl BufferReader {
        fn new(steps: impl IntoIterator<Item = BufferReadStep>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                polls: 0,
            }
        }
    }

    impl AsyncRead for BufferReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.polls += 1;
            match self.steps.pop_front().expect("read script exhausted") {
                BufferReadStep::Pending => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                BufferReadStep::Data(bytes) => {
                    buf.put_slice(bytes);
                    Poll::Ready(Ok(()))
                }
                BufferReadStep::PendingData(bytes) => {
                    buf.put_slice(bytes);
                    Poll::Pending
                }
                BufferReadStep::ErrorData(bytes) => {
                    buf.put_slice(bytes);
                    Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe)))
                }
                BufferReadStep::Panic => panic!("read_buf provider panic sentinel"),
            }
        }
    }

    #[test]
    fn read_buf_appends_to_vec_bytes_mut_and_trait_object() {
        let mut input: &[u8] = b"tail";
        let mut bytes = b"head:".to_vec();
        let destination: &mut dyn crate::bytes::BufMut = &mut bytes;
        assert!(matches!(
            poll_buffer_read(&mut input, destination),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(bytes, b"head:tail");
        assert!(matches!(
            poll_buffer_read(&mut input, &mut bytes),
            Poll::Ready(Ok(0))
        ));
        assert_eq!(bytes, b"head:tail");

        let mut buffer = crate::bytes::BytesMut::from(&b"prefix:"[..]);
        let mut input: &[u8] = b"value";
        assert!(matches!(
            poll_buffer_read(&mut input, &mut buffer),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(&buffer[..], b"prefix:value");
    }

    #[test]
    fn read_buf_direct_window_advances_without_overwriting_tail() {
        let mut storage = [b'_'; 5];
        let mut input: &[u8] = b"abc";
        {
            let mut destination = storage.as_mut_slice();
            assert!(matches!(
                poll_buffer_read(&mut input, &mut destination),
                Poll::Ready(Ok(3))
            ));
            assert_eq!(destination, b"__");
        }
        assert_eq!(&storage, b"abc__");
    }

    #[test]
    fn read_buf_respects_append_and_direct_limits() {
        let mut input: &[u8] = b"abcdef";
        let mut append = crate::bytes::BufMut::limit(Vec::<u8>::new(), 3);
        assert!(matches!(
            poll_buffer_read(&mut input, &mut append),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(append.get_ref(), b"abc");
        assert_eq!(input, b"def");
        assert!(matches!(
            poll_buffer_read(&mut PanicOnUseReader, &mut append),
            Poll::Ready(Ok(0))
        ));

        let mut storage = [0u8; 6];
        let mut direct = crate::bytes::BufMut::limit(storage.as_mut_slice(), 2);
        assert!(matches!(
            poll_buffer_read(&mut input, &mut direct),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(direct.limit(), 0);
        assert_eq!(input, b"f");
        assert_eq!(&storage, b"de\0\0\0\0");

        let mut empty = crate::bytes::BufMut::limit(Vec::<u8>::new(), 0);
        assert!(matches!(
            poll_buffer_read(&mut PanicOnUseReader, &mut empty),
            Poll::Ready(Ok(0))
        ));
        assert!(empty.get_ref().is_empty());
    }

    #[test]
    fn read_buf_append_fallback_is_bounded_per_poll() {
        let payload = vec![7u8; 9000];
        let mut input = payload.as_slice();
        let mut destination = Vec::new();
        assert!(matches!(
            poll_buffer_read(&mut input, &mut destination),
            Poll::Ready(Ok(8192))
        ));
        assert_eq!(input.len(), 808);
        assert_eq!(destination.len(), 8192);
        assert!(matches!(
            poll_buffer_read(&mut input, &mut destination),
            Poll::Ready(Ok(808))
        ));
        assert_eq!(destination, payload);
    }

    #[test]
    fn read_buf_pending_drop_preserves_append_and_direct_cursors() {
        let mut source = BufferReader::new([
            BufferReadStep::Pending,
            BufferReadStep::Data(b"ok"),
        ]);
        let mut append = b"old:".to_vec();
        assert!(poll_buffer_read(&mut source, &mut append).is_pending());
        assert_eq!(append, b"old:");
        assert!(matches!(
            poll_buffer_read(&mut source, &mut append),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(append, b"old:ok");
        assert_eq!(source.polls, 2);

        let mut source = BufferReader::new([
            BufferReadStep::Pending,
            BufferReadStep::Data(b"ok"),
        ]);
        let mut storage = [b'_'; 3];
        {
            let mut direct = storage.as_mut_slice();
            assert!(poll_buffer_read(&mut source, &mut direct).is_pending());
            assert_eq!(direct, b"___");
            assert!(matches!(
                poll_buffer_read(&mut source, &mut direct),
                Poll::Ready(Ok(2))
            ));
            assert_eq!(direct, b"_");
        }
        assert_eq!(&storage, b"ok_");
    }

    #[test]
    fn read_buf_commits_partial_pending_and_error_prefixes() {
        for error in [false, true] {
            let step = || {
                if error {
                    BufferReadStep::ErrorData(b"hi")
                } else {
                    BufferReadStep::PendingData(b"hi")
                }
            };
            let check = |result: Poll<io::Result<usize>>| {
                if error {
                    assert!(matches!(
                        result,
                        Poll::Ready(Err(e)) if e.kind() == ErrorKind::BrokenPipe
                    ));
                } else {
                    assert!(matches!(result, Poll::Ready(Ok(2))));
                }
            };
            let mut source = BufferReader::new([step()]);
            let mut append = b"old:".to_vec();
            check(poll_buffer_read(&mut source, &mut append));
            assert_eq!(append, b"old:hi");

            let mut source = BufferReader::new([step()]);
            let mut storage = [b'_'; 4];
            {
                let mut direct = storage.as_mut_slice();
                check(poll_buffer_read(&mut source, &mut direct));
                assert_eq!(direct, b"__");
            }
            assert_eq!(&storage, b"hi__");
        }
    }

    struct InvalidWritableBuffer {
        logical: usize,
        direct: usize,
        window: usize,
        data: [u8; 2],
    }

    impl crate::bytes::BufMut for InvalidWritableBuffer {
        fn remaining_mut(&self) -> usize {
            self.logical
        }

        fn direct_remaining_mut(&self) -> usize {
            self.direct
        }

        fn chunk_mut(&mut self) -> &mut [u8] {
            &mut self.data[..self.window]
        }

        fn advance_mut(&mut self, _: usize) {
            panic!("invalid writable buffer must not advance");
        }
    }

    #[test]
    fn read_buf_rejects_inconsistent_capacity_before_reading() {
        for (logical, direct, window) in [(1, 2, 1), (2, 2, 0), (2, 1, 2)] {
            let mut buffer = InvalidWritableBuffer {
                logical,
                direct,
                window,
                data: [0; 2],
            };
            assert!(matches!(
                poll_buffer_read(&mut PanicOnUseReader, &mut buffer),
                Poll::Ready(Err(e)) if e.kind() == ErrorKind::InvalidData
            ));
        }
    }

    #[test]
    fn read_buf_error_without_progress_preserves_contents() {
        let mut source = BufferReader::new([BufferReadStep::ErrorData(b"")]);
        let mut destination = b"kept".to_vec();
        assert!(matches!(
            poll_buffer_read(&mut source, &mut destination),
            Poll::Ready(Err(e)) if e.kind() == ErrorKind::BrokenPipe
        ));
        assert_eq!(destination, b"kept");
    }

    #[test]
    fn read_buf_terminal_poll_and_provider_panic_never_reissue_reads() {
        for panics in [false, true] {
            let step = if panics {
                BufferReadStep::Panic
            } else {
                BufferReadStep::Data(b"ok")
            };
            let mut source = BufferReader::new([step]);
            let mut destination = Vec::new();
            {
                let mut future = source.read_buf(&mut destination);
                let mut task = Context::from_waker(Waker::noop());
                let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Pin::new(&mut future).poll(&mut task)
                }));
                if panics {
                    assert!(first.is_err());
                } else {
                    assert!(matches!(first, Ok(Poll::Ready(Ok(2)))));
                }
                assert!(matches!(
                    Pin::new(&mut future).poll(&mut task),
                    Poll::Ready(Err(e)) if e.kind() == ErrorKind::Other
                ));
            }
            assert_eq!(source.polls, 1);
            assert_eq!(destination, if panics { &b""[..] } else { &b"ok"[..] });
        }
    }
