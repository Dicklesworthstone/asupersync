    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream;

    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn poll_read<R: AsyncRead + Unpin>(reader: &mut R, out: &mut [u8]) -> Poll<io::Result<usize>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut read_buf = ReadBuf::new(out);
        match Pin::new(reader).poll_read(&mut cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    #[test]
    fn reader_stream_yields_chunks() {
        init_test("reader_stream_yields_chunks");
        let input: &[u8] = b"abcdef";
        let mut stream = ReaderStream::with_capacity(input, 2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(first, Poll::Ready(Some(Ok(chunk))) if chunk == b"ab");
        crate::assert_with_log!(ok, "first chunk", true, ok);

        let second = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(second, Poll::Ready(Some(Ok(chunk))) if chunk == b"cd");
        crate::assert_with_log!(ok, "second chunk", true, ok);

        let third = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(third, Poll::Ready(Some(Ok(chunk))) if chunk == b"ef");
        crate::assert_with_log!(ok, "third chunk", true, ok);

        let done = Pin::new(&mut stream).poll_next(&mut cx);
        let ok = matches!(done, Poll::Ready(None));
        crate::assert_with_log!(ok, "terminal none", true, ok);
        crate::test_complete!("reader_stream_yields_chunks");
    }

    #[test]
    fn stream_reader_reads_across_multiple_chunks() {
        init_test("stream_reader_reads_across_multiple_chunks");
        let chunks = vec![Ok(vec![1_u8, 2]), Ok(vec![3]), Ok(vec![4, 5])];
        let stream = stream::iter(chunks);
        let mut reader = StreamReader::new(stream);

        let mut out = [0_u8; 5];
        let read = poll_read(&mut reader, &mut out);
        let ok = matches!(read, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ok, "read length", true, ok);
        crate::assert_with_log!(out == [1, 2, 3, 4, 5], "content", [1, 2, 3, 4, 5], out);

        let mut eof = [0_u8; 4];
        let read = poll_read(&mut reader, &mut eof);
        let ok = matches!(read, Poll::Ready(Ok(0)));
        crate::assert_with_log!(ok, "eof", true, ok);
        crate::test_complete!("stream_reader_reads_across_multiple_chunks");
    }

    #[test]
    fn stream_reader_defers_error_until_partial_data_consumed() {
        init_test("stream_reader_defers_error_until_partial_data_consumed");
        let chunks = vec![
            Ok(vec![10_u8, 11]),
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream failed")),
            Ok(vec![12]),
        ];
        let stream = stream::iter(chunks);
        let mut reader = StreamReader::new(stream);

        let mut out = [0_u8; 8];
        let read = poll_read(&mut reader, &mut out);
        let ok = matches!(read, Poll::Ready(Ok(2)));
        crate::assert_with_log!(ok, "partial read before error", true, ok);
        crate::assert_with_log!(out[..2] == [10, 11], "partial content", [10, 11], &out[..2]);

        let mut second = [0_u8; 8];
        let read = poll_read(&mut reader, &mut second);
        let ok = matches!(read, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe);
        crate::assert_with_log!(ok, "error surfaced on next read", true, ok);
        crate::assert_with_log!(
            !reader.done,
            "deferred error is not eof",
            false,
            reader.done
        );

        let mut trailing = [0_u8; 8];
        let read = poll_read(&mut reader, &mut trailing);
        let ok = matches!(read, Poll::Ready(Ok(1)));
        crate::assert_with_log!(ok, "data after deferred error", true, ok);
        crate::assert_with_log!(trailing[0] == 12, "trailing content", 12, trailing[0]);
        crate::assert_with_log!(reader.done, "true eof fuses reader", true, reader.done);

        let mut eof = [0_u8; 1];
        let read = poll_read(&mut reader, &mut eof);
        let ok = matches!(read, Poll::Ready(Ok(0)));
        crate::assert_with_log!(ok, "fused eof", true, ok);
        crate::test_complete!("stream_reader_defers_error_until_partial_data_consumed");
    }

    #[test]
    fn stream_reader_continues_after_immediate_error() {
        init_test("stream_reader_continues_after_immediate_error");
        let chunks = vec![
            Err(io::Error::new(io::ErrorKind::Interrupted, "retry read")),
            Ok(vec![1_u8, 2]),
        ];
        let stream = stream::iter(chunks);
        let mut reader = StreamReader::new(stream);

        let mut first = [0_u8; 2];
        let read = poll_read(&mut reader, &mut first);
        let ok = matches!(read, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted);
        crate::assert_with_log!(ok, "immediate error", true, ok);
        crate::assert_with_log!(!reader.done, "error is not eof", false, reader.done);

        let mut data = [0_u8; 2];
        let read = poll_read(&mut reader, &mut data);
        let ok = matches!(read, Poll::Ready(Ok(2)));
        crate::assert_with_log!(ok, "data after error", true, ok);
        crate::assert_with_log!(data == [1, 2], "data content", [1, 2], data);

        let mut eof = [0_u8; 1];
        let read = poll_read(&mut reader, &mut eof);
        let ok = matches!(read, Poll::Ready(Ok(0)));
        crate::assert_with_log!(ok, "true eof", true, ok);
        crate::assert_with_log!(reader.done, "true eof fuses reader", true, reader.done);

        let read = poll_read(&mut reader, &mut eof);
        let ok = matches!(read, Poll::Ready(Ok(0)));
        crate::assert_with_log!(ok, "repeated fused eof", true, ok);
        crate::test_complete!("stream_reader_continues_after_immediate_error");
    }

    struct PendingThenDataStream {
        state: u8,
    }

    impl PendingThenDataStream {
        fn new() -> Self {
            Self { state: 0 }
        }
    }

    impl Stream for PendingThenDataStream {
        type Item = io::Result<Vec<u8>>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.state {
                0 => {
                    self.state = 1;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                1 => {
                    self.state = 2;
                    Poll::Ready(Some(Ok(vec![7, 8, 9])))
                }
                _ => Poll::Ready(None),
            }
        }
    }

    #[test]
    fn stream_reader_pending_without_buffered_data() {
        init_test("stream_reader_pending_without_buffered_data");
        let mut reader = StreamReader::new(PendingThenDataStream::new());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = [0_u8; 3];
        let mut read_buf = ReadBuf::new(&mut out);
        let first = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ok = first.is_pending();
        crate::assert_with_log!(ok, "first poll pending", true, ok);

        let mut out = [0_u8; 3];
        let mut read_buf = ReadBuf::new(&mut out);
        let second = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        let ok = matches!(second, Poll::Ready(Ok(()))) && read_buf.filled() == [7, 8, 9];
        crate::assert_with_log!(ok, "second poll reads data", true, ok);
        crate::test_complete!("stream_reader_pending_without_buffered_data");
    }
