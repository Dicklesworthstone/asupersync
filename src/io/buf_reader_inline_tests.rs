    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::AsyncSeekExt as _;

    use std::collections::VecDeque;
    use std::task::Waker;

    #[derive(Debug, Clone, Copy)]
    enum SeekStep {
        Pending,
        Ready,
        Error(io::ErrorKind),
    }

    #[derive(Debug)]
    struct SeekableReader {
        inner: std::io::Cursor<Vec<u8>>,
        seek_steps: VecDeque<SeekStep>,
        seek_requests: Vec<SeekFrom>,
    }

    impl SeekableReader {
        fn new(data: &[u8]) -> Self {
            Self::with_steps(data, [])
        }

        fn with_steps(data: &[u8], steps: impl IntoIterator<Item = SeekStep>) -> Self {
            Self {
                inner: std::io::Cursor::new(data.to_vec()),
                seek_steps: steps.into_iter().collect(),
                seek_requests: Vec::new(),
            }
        }
    }

    impl AsyncRead for SeekableReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let read = std::io::Read::read(&mut self.inner, buf.unfilled())?;
            buf.advance(read);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncSeek for SeekableReader {
        fn poll_seek(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            pos: SeekFrom,
        ) -> Poll<io::Result<u64>> {
            self.seek_requests.push(pos);
            match self.seek_steps.pop_front().unwrap_or(SeekStep::Ready) {
                SeekStep::Pending => Poll::Pending,
                SeekStep::Ready => Poll::Ready(std::io::Seek::seek(&mut self.inner, pos)),
                SeekStep::Error(kind) => {
                    Poll::Ready(Err(io::Error::new(kind, "injected seek failure")))
                }
            }
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn prime_one_byte(reader: &mut BufReader<SeekableReader>) {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut byte = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut byte);
        let poll = Pin::new(&mut *reader).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"a");
        assert_eq!(reader.buffer(), b"bcd");
    }

    fn read_one_byte(reader: &mut BufReader<SeekableReader>) -> u8 {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut byte = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut byte);
        match Pin::new(reader).poll_read(&mut cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected one ready byte, got {other:?}"),
        }
        assert_eq!(read_buf.filled().len(), 1);
        byte[0]
    }

    #[test]
    fn buf_reader_new() {
        init_test("buf_reader_new");
        let data: &[u8] = b"hello world";
        let reader = BufReader::new(data);
        let capacity = reader.capacity();
        crate::assert_with_log!(
            capacity == DEFAULT_BUF_CAPACITY,
            "capacity",
            DEFAULT_BUF_CAPACITY,
            capacity
        );
        let empty = reader.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_reader_new");
    }

    #[test]
    fn buf_reader_with_capacity() {
        init_test("buf_reader_with_capacity");
        let data: &[u8] = b"test";
        let reader = BufReader::with_capacity(256, data);
        let capacity = reader.capacity();
        crate::assert_with_log!(capacity == 256, "capacity", 256, capacity);
        crate::test_complete!("buf_reader_with_capacity");
    }

    #[test]
    fn buf_reader_get_ref() {
        init_test("buf_reader_get_ref");
        let data: &[u8] = b"hello";
        let reader = BufReader::new(data);
        let inner = *reader.get_ref();
        crate::assert_with_log!(inner == b"hello", "get_ref", b"hello", inner);
        crate::test_complete!("buf_reader_get_ref");
    }

    #[test]
    fn buf_reader_into_inner() {
        init_test("buf_reader_into_inner");
        let data: &[u8] = b"hello";
        let reader = BufReader::new(data);
        let inner = reader.into_inner();
        crate::assert_with_log!(inner == b"hello", "into_inner", b"hello", inner);
        crate::test_complete!("buf_reader_into_inner");
    }

    #[test]
    fn buf_reader_read_small() {
        init_test("buf_reader_read_small");
        let data: &[u8] = b"hello world";
        let mut reader = BufReader::with_capacity(16, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 5];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"hello", "filled", b"hello", filled);

        // Buffer should now contain " world"
        let buffer = reader.buffer();
        crate::assert_with_log!(buffer == b" world", "buffer", b" world", buffer);
        crate::test_complete!("buf_reader_read_small");
    }

    #[test]
    fn buf_reader_read_exact_buffer_size() {
        init_test("buf_reader_read_exact_buffer_size");
        let data: &[u8] = b"exactly sixteen!";
        let mut reader = BufReader::with_capacity(16, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(
            filled == b"exactly sixteen!",
            "filled",
            b"exactly sixteen!",
            filled
        );
        crate::test_complete!("buf_reader_read_exact_buffer_size");
    }

    #[test]
    fn buf_reader_large_read_bypasses_buffer() {
        init_test("buf_reader_large_read_bypasses_buffer");
        let data: &[u8] = b"large data that exceeds buffer capacity easily";
        let mut reader = BufReader::with_capacity(8, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Request more than buffer capacity - should bypass buffer
        let mut buf = [0u8; 32];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        // Should read directly without going through internal buffer
        let len = read_buf.filled().len();
        let within = len <= 32;
        crate::assert_with_log!(within, "len <= 32", true, within);
        crate::test_complete!("buf_reader_large_read_bypasses_buffer");
    }

    #[test]
    fn buf_reader_zero_capacity_is_clamped() {
        init_test("buf_reader_zero_capacity_is_clamped");
        let data: &[u8] = b"x";
        let reader = BufReader::with_capacity(0, data);
        let capacity = reader.capacity();
        crate::assert_with_log!(capacity == 1, "capacity", 1, capacity);
        crate::test_complete!("buf_reader_zero_capacity_is_clamped");
    }

    #[test]
    fn buf_reader_zero_capacity_fill_buf_progresses() {
        init_test("buf_reader_zero_capacity_fill_buf_progresses");
        let data: &[u8] = b"xyz";
        let mut reader = BufReader::with_capacity(0, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        let filled = match poll {
            Poll::Ready(Ok(bytes)) => bytes.to_vec(),
            other => panic!("expected Poll::Ready(Ok(_)), got {other:?}"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(filled == b"x", "filled", b"x", filled);
        crate::test_complete!("buf_reader_zero_capacity_fill_buf_progresses");
    }

    #[test]
    fn buf_reader_poll_fill_buf() {
        init_test("buf_reader_poll_fill_buf");
        let data: &[u8] = b"buffered content";
        let mut reader = BufReader::with_capacity(32, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        let ready = matches!(&poll, Poll::Ready(Ok(_)));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        if let Poll::Ready(Ok(buf)) = poll {
            crate::assert_with_log!(
                buf == b"buffered content",
                "buffer",
                b"buffered content",
                buf
            );
        }
        crate::test_complete!("buf_reader_poll_fill_buf");
    }

    #[test]
    fn buf_reader_consume() {
        init_test("buf_reader_consume");
        let data: &[u8] = b"consume me";
        let mut reader = BufReader::with_capacity(32, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Fill buffer
        let _ = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        let buffer = reader.buffer();
        crate::assert_with_log!(buffer == b"consume me", "buffer", b"consume me", buffer);

        // Consume 8 bytes
        Pin::new(&mut reader).consume(8);
        let buffer = reader.buffer();
        crate::assert_with_log!(buffer == b"me", "buffer after consume", b"me", buffer);

        // Consume rest
        Pin::new(&mut reader).consume(2);
        let empty = reader.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_reader_consume");
    }

    #[test]
    fn oversized_consume_clamps_without_replaying_buffered_bytes() {
        init_test("oversized_consume_clamps_without_replaying_buffered_bytes");
        let data: &[u8] = b"abcdef";
        let mut reader = BufReader::with_capacity(3, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = match Pin::new(&mut reader).poll_fill_buf(&mut cx) {
            Poll::Ready(Ok(bytes)) => bytes.to_vec(),
            other => panic!("expected first buffer, got {other:?}"),
        };
        assert_eq!(first, b"abc");
        Pin::new(&mut reader).consume(1);
        assert_eq!(reader.buffer(), b"bc");

        let consume = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut reader).consume(usize::MAX);
        }));
        assert!(consume.is_ok());
        assert!(reader.buffer().is_empty());

        let next = match Pin::new(&mut reader).poll_fill_buf(&mut cx) {
            Poll::Ready(Ok(bytes)) => bytes.to_vec(),
            other => panic!("expected next buffer, got {other:?}"),
        };
        assert_eq!(next, b"def");
        crate::test_complete!("oversized_consume_clamps_without_replaying_buffered_bytes");
    }

    #[test]
    fn buf_reader_discard_buffer() {
        init_test("buf_reader_discard_buffer");
        let data: &[u8] = b"discard this";
        let mut reader = BufReader::with_capacity(32, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Fill buffer
        let _ = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        let empty = reader.buffer().is_empty();
        crate::assert_with_log!(!empty, "buffer not empty", false, empty);

        // Discard
        reader.discard_buffer();
        let empty = reader.buffer().is_empty();
        crate::assert_with_log!(empty, "buffer empty", true, empty);
        crate::test_complete!("buf_reader_discard_buffer");
    }

    #[test]
    fn buf_reader_empty_source() {
        init_test("buf_reader_empty_source");
        let data: &[u8] = b"";
        let mut reader = BufReader::new(data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut reader).poll_fill_buf(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(buf)) if buf.is_empty());
        crate::assert_with_log!(ready, "empty buf ready", true, ready);
        crate::test_complete!("buf_reader_empty_source");
    }

    #[test]
    fn buf_reader_multiple_reads() {
        init_test("buf_reader_multiple_reads");
        let data: &[u8] = b"first second third";
        let mut reader = BufReader::with_capacity(8, data);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First read
        let mut buf1 = [0u8; 6];
        let mut read_buf1 = ReadBuf::new(&mut buf1);
        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf1);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready 1", true, ready);
        let filled1 = read_buf1.filled();
        crate::assert_with_log!(filled1 == b"first ", "filled1", b"first ", filled1);

        // Second read (from buffer)
        let mut buf2 = [0u8; 6];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf2);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready 2", true, ready);
        let filled2 = read_buf2.filled();
        crate::assert_with_log!(filled2 == b"se", "filled2", b"se", filled2);

        // Third read (needs refill)
        let mut buf3 = [0u8; 10];
        let mut read_buf3 = ReadBuf::new(&mut buf3);
        let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf3);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready 3", true, ready);
        // Result depends on buffer state
        crate::test_complete!("buf_reader_multiple_reads");
    }

    #[test]
    fn seek_start_and_end_discard_buffer_and_restart_reads() {
        init_test("seek_start_and_end_discard_buffer_and_restart_reads");
        let mut reader = BufReader::with_capacity(4, SeekableReader::new(b"abcdef"));
        prime_one_byte(&mut reader);

        let start =
            futures_lite::future::block_on(reader.seek(SeekFrom::Start(0))).expect("seek to start");
        assert_eq!(start, 0);
        assert!(reader.buffer().is_empty());
        assert_eq!(read_one_byte(&mut reader), b'a');
        assert_eq!(reader.buffer(), b"bcd");

        let end =
            futures_lite::future::block_on(reader.seek(SeekFrom::End(-1))).expect("seek from end");
        assert_eq!(end, 5);
        assert!(reader.buffer().is_empty());
        assert_eq!(read_one_byte(&mut reader), b'f');
        crate::test_complete!("seek_start_and_end_discard_buffer_and_restart_reads");
    }

    #[test]
    fn current_seek_uses_logical_position_for_zero_positive_and_negative_offsets() {
        init_test("current_seek_uses_logical_position_for_zero_positive_and_negative_offsets");

        let mut zero = BufReader::with_capacity(4, SeekableReader::new(b"abcdef"));
        prime_one_byte(&mut zero);
        let position = futures_lite::future::block_on(zero.stream_position())
            .expect("logical stream position");
        assert_eq!(position, 1);
        assert_eq!(zero.get_ref().seek_requests, [SeekFrom::Current(-3)]);

        let mut positive = BufReader::with_capacity(4, SeekableReader::new(b"abcdef"));
        prime_one_byte(&mut positive);
        let position = futures_lite::future::block_on(positive.seek(SeekFrom::Current(2)))
            .expect("positive logical seek");
        assert_eq!(position, 3);
        assert_eq!(positive.get_ref().seek_requests, [SeekFrom::Current(-1)]);

        let mut negative = BufReader::with_capacity(4, SeekableReader::new(b"abcdef"));
        prime_one_byte(&mut negative);
        let position = futures_lite::future::block_on(negative.seek(SeekFrom::Current(-1)))
            .expect("negative logical seek");
        assert_eq!(position, 0);
        assert_eq!(negative.get_ref().seek_requests, [SeekFrom::Current(-4)]);
        crate::test_complete!(
            "current_seek_uses_logical_position_for_zero_positive_and_negative_offsets"
        );
    }

    #[test]
    fn pending_seek_retries_adjusted_request_and_preserves_buffer() {
        init_test("pending_seek_retries_adjusted_request_and_preserves_buffer");
        let inner = SeekableReader::with_steps(b"abcdef", [SeekStep::Pending, SeekStep::Ready]);
        let mut reader = BufReader::with_capacity(4, inner);
        prime_one_byte(&mut reader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut reader).poll_seek(&mut cx, SeekFrom::Current(0));
        assert!(matches!(first, Poll::Pending));
        assert_eq!(reader.buffer(), b"bcd");
        assert_eq!(reader.get_ref().seek_requests, [SeekFrom::Current(-3)]);

        let second = Pin::new(&mut reader).poll_seek(&mut cx, SeekFrom::Current(0));
        assert!(matches!(second, Poll::Ready(Ok(1))));
        assert!(reader.buffer().is_empty());
        assert_eq!(
            reader.get_ref().seek_requests,
            [SeekFrom::Current(-3), SeekFrom::Current(-3)]
        );
        crate::test_complete!("pending_seek_retries_adjusted_request_and_preserves_buffer");
    }

    #[test]
    fn failed_seek_preserves_buffer_and_read_continuity() {
        init_test("failed_seek_preserves_buffer_and_read_continuity");
        let inner =
            SeekableReader::with_steps(b"abcdef", [SeekStep::Error(io::ErrorKind::InvalidInput)]);
        let mut reader = BufReader::with_capacity(4, inner);
        prime_one_byte(&mut reader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let error = match Pin::new(&mut reader).poll_seek(&mut cx, SeekFrom::Start(0)) {
            Poll::Ready(Err(error)) => error,
            other => panic!("expected injected seek error, got {other:?}"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(reader.buffer(), b"bcd");
        assert_eq!(read_one_byte(&mut reader), b'b');
        assert_eq!(reader.buffer(), b"cd");
        crate::test_complete!("failed_seek_preserves_buffer_and_read_continuity");
    }

    #[test]
    fn current_underflow_uses_two_phase_seek_across_pending() {
        init_test("current_underflow_uses_two_phase_seek_across_pending");
        let mut inner =
            SeekableReader::with_steps(b"", [SeekStep::Ready, SeekStep::Pending, SeekStep::Ready]);
        inner.inner.set_position(u64::MAX);
        let mut reader = BufReader::with_capacity(4, inner);
        reader.buf[..3].copy_from_slice(b"xyz");
        reader.pos = 0;
        reader.cap = 3;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut reader).poll_seek(&mut cx, SeekFrom::Current(i64::MIN));
        assert!(matches!(first, Poll::Pending));
        assert!(reader.buffer().is_empty());
        assert_eq!(
            reader.get_ref().seek_requests,
            [SeekFrom::Current(-3), SeekFrom::Current(i64::MIN)]
        );

        let second = Pin::new(&mut reader).poll_seek(&mut cx, SeekFrom::Current(i64::MIN));
        assert!(matches!(second, Poll::Ready(Ok(position)) if position == i64::MAX as u64 - 3));
        assert_eq!(
            reader.get_ref().seek_requests,
            [
                SeekFrom::Current(-3),
                SeekFrom::Current(i64::MIN),
                SeekFrom::Current(i64::MIN),
            ]
        );
        crate::test_complete!("current_underflow_uses_two_phase_seek_across_pending");
    }
