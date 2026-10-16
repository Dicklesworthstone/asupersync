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

    /// A simple stream that supports both read and write.
    struct TestStream {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl TestStream {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_data: read_data.to_vec(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for TestStream {
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

    impl AsyncWrite for TestStream {
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
            Poll::Ready(Ok(()))
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn split_stream_creates_halves() {
        init_test("split_stream_creates_halves");
        let stream = TestStream::new(b"hello");
        let wrapper = SplitStream::new(stream);
        let (read_half, write_half) = wrapper.split();

        // Verify the halves exist - use _ = to drop without triggering clippy
        let _ = read_half;
        let _ = write_half;

        // Access the underlying stream
        let inner = wrapper.get_ref();
        crate::assert_with_log!(inner.read_pos == 0, "read_pos", 0, inner.read_pos);
        let empty = inner.written.is_empty();
        crate::assert_with_log!(empty, "written empty", true, empty);
        crate::test_complete!("split_stream_creates_halves");
    }

    #[test]
    fn read_half_reads() {
        init_test("read_half_reads");
        let stream = TestStream::new(b"hello");
        let wrapper = SplitStream::new(stream);
        let (mut read_half, _write_half) = wrapper.split();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 5];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut read_half).poll_read(&mut cx, &mut read_buf);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "poll ready", true, ready);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == b"hello", "filled", b"hello", filled);
        crate::test_complete!("read_half_reads");
    }

    #[test]
    fn write_half_writes() {
        init_test("write_half_writes");
        let stream = TestStream::new(b"");
        let wrapper = SplitStream::new(stream);
        let (_read_half, mut write_half) = wrapper.split();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut write_half).poll_write(&mut cx, b"world");
        let ready = matches!(poll, Poll::Ready(Ok(5)));
        crate::assert_with_log!(ready, "write 5", true, ready);

        // Check the underlying stream - use _ = to drop without triggering clippy
        let _ = write_half;
        let inner = wrapper.get_ref();
        crate::assert_with_log!(
            inner.written == b"world",
            "written",
            b"world",
            inner.written
        );
        crate::test_complete!("write_half_writes");
    }

    #[test]
    fn write_half_flush_and_shutdown() {
        init_test("write_half_flush_and_shutdown");
        let stream = TestStream::new(b"");
        let wrapper = SplitStream::new(stream);
        let (_read_half, mut write_half) = wrapper.split();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut write_half).poll_flush(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "flush ready", true, ready);

        let poll = Pin::new(&mut write_half).poll_shutdown(&mut cx);
        let ready = matches!(poll, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "shutdown ready", true, ready);
        crate::test_complete!("write_half_flush_and_shutdown");
    }

    #[test]
    fn into_inner_works() {
        init_test("into_inner_works");
        let stream = TestStream::new(b"test");
        let wrapper = SplitStream::new(stream);
        let stream = wrapper.into_inner();
        crate::assert_with_log!(
            stream.read_data == b"test",
            "read_data",
            b"test",
            stream.read_data
        );
        crate::test_complete!("into_inner_works");
    }
