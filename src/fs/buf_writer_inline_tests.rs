    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::fs::File;
    use crate::io::AsyncWriteExt;
    use std::task::Waker;
    use tempfile::tempdir;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Debug)]
    struct BlockingPartialWriter {
        written: Vec<u8>,
        max_chunk: usize,
        blocked: bool,
        should_block_after_first_write: bool,
    }

    impl BlockingPartialWriter {
        fn new(max_chunk: usize) -> Self {
            Self {
                written: Vec::new(),
                max_chunk,
                blocked: false,
                should_block_after_first_write: true,
            }
        }

        fn unblock(&mut self) {
            self.blocked = false;
        }
    }

    impl AsyncWrite for BlockingPartialWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std_io::Result<usize>> {
            let this = self.get_mut();
            if this.blocked {
                return Poll::Pending;
            }

            let n = buf.len().min(this.max_chunk);
            this.written.extend_from_slice(&buf[..n]);
            if this.should_block_after_first_write {
                this.should_block_after_first_write = false;
                this.blocked = true;
            }
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std_io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std_io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_buf_writer_basic() {
        init_test("test_buf_writer_basic");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test_write.txt");

            let file = File::create(&path).await.unwrap();
            let mut writer = BufWriter::new(file);

            writer.write_all(b"hello ").await.unwrap();
            writer.write_all(b"world").await.unwrap();
            writer.flush().await.unwrap();

            let contents = crate::fs::read_to_string(&path).await.unwrap();
            crate::assert_with_log!(
                contents == "hello world",
                "contents",
                "hello world",
                contents
            );
        });
        crate::test_complete!("test_buf_writer_basic");
    }

    #[test]
    fn test_buf_writer_large() {
        init_test("test_buf_writer_large");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test_large.txt");

            let file = File::create(&path).await.unwrap();
            let mut writer = BufWriter::with_capacity(1024, file);

            // Write more than buffer capacity
            let data = vec![b'x'; 10000];
            writer.write_all(&data).await.unwrap();
            writer.flush().await.unwrap();

            let contents = crate::fs::read(&path).await.unwrap();
            let len = contents.len();
            crate::assert_with_log!(len == 10000, "length", 10000, len);
            let all_x = contents.iter().all(|&b| b == b'x');
            crate::assert_with_log!(all_x, "all x", true, all_x);
        });
        crate::test_complete!("test_buf_writer_large");
    }

    #[test]
    fn test_buf_writer_does_not_accept_new_data_while_flush_is_in_progress() {
        init_test("test_buf_writer_does_not_accept_new_data_while_flush_is_in_progress");

        let inner = BlockingPartialWriter::new(2);
        let mut writer = BufWriter::with_capacity(8, inner);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_write = Pin::new(&mut writer).poll_write(&mut cx, b"1234");
        let ready = matches!(first_write, Poll::Ready(Ok(4)));
        crate::assert_with_log!(ready, "initial write buffered", true, ready);

        let first_flush = Pin::new(&mut writer).poll_flush(&mut cx);
        let pending = matches!(first_flush, Poll::Pending);
        crate::assert_with_log!(pending, "flush pending", true, pending);
        crate::assert_with_log!(
            writer.get_ref().written == b"12",
            "partially flushed bytes",
            b"12",
            writer.get_ref().written.as_slice()
        );
        crate::assert_with_log!(
            writer.buffer() == b"34",
            "unwritten suffix preserved during partial flush",
            b"34",
            writer.buffer()
        );

        let second_write = Pin::new(&mut writer).poll_write(&mut cx, b"56");
        let pending = matches!(second_write, Poll::Pending);
        crate::assert_with_log!(
            pending,
            "new write waits for in-flight flush",
            true,
            pending
        );
        crate::assert_with_log!(
            writer.buffer() == b"34",
            "unwritten suffix unchanged while flush blocked",
            b"34",
            writer.buffer()
        );
        assert_eq!(
            writer.get_ref().written,
            b"12",
            "blocked write made no progress"
        );

        writer.get_mut().unblock();

        let second_write = Pin::new(&mut writer).poll_write(&mut cx, b"56");
        let ready = matches!(second_write, Poll::Ready(Ok(2)));
        crate::assert_with_log!(ready, "second write buffered after flush", true, ready);
        crate::assert_with_log!(
            writer.buffer() == b"56",
            "buffer after resumed flush",
            b"56",
            writer.buffer()
        );

        let final_flush = Pin::new(&mut writer).poll_flush(&mut cx);
        let ready = matches!(final_flush, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready, "final flush ready", true, ready);
        crate::assert_with_log!(
            writer.get_ref().written == b"123456",
            "final write order preserved",
            b"123456",
            writer.get_ref().written.as_slice()
        );

        crate::test_complete!(
            "test_buf_writer_does_not_accept_new_data_while_flush_is_in_progress"
        );
    }
