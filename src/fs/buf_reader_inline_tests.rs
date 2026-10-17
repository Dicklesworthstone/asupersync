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
    use crate::io::{AsyncReadExt as _, AsyncSeekExt as _};
    use crate::stream::StreamExt as _;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_buf_reader_basic() {
        init_test("test_buf_reader_basic");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test.txt");
            crate::fs::write(&path, b"hello\nworld\n").await.unwrap();

            let file = File::open(&path).await.unwrap();
            let reader = BufReader::new(file);

            let mut lines = reader.lines();
            let first = lines.next().await.unwrap().unwrap();
            crate::assert_with_log!(first == "hello", "first line", "hello", first);
            let second = lines.next().await.unwrap().unwrap();
            crate::assert_with_log!(second == "world", "second line", "world", second);
        });
        crate::test_complete!("test_buf_reader_basic");
    }

    #[test]
    fn test_buf_reader_lines() {
        init_test("test_buf_reader_lines");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test_lines.txt");
            crate::fs::write(&path, b"line1\nline2\nline3")
                .await
                .unwrap();

            let file = File::open(&path).await.unwrap();
            let reader = BufReader::new(file);
            let lines: Vec<_> = reader.lines().try_collect().await.unwrap();

            let expected = vec!["line1", "line2", "line3"];
            crate::assert_with_log!(lines == expected, "lines", expected, lines);
        });
        crate::test_complete!("test_buf_reader_lines");
    }

    #[test]
    fn test_buf_reader_lines_zero_capacity() {
        init_test("test_buf_reader_lines_zero_capacity");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("test_lines_zero_cap.txt");
            crate::fs::write(&path, b"line-a\nline-b\n").await.unwrap();

            let file = File::open(&path).await.unwrap();
            let reader = BufReader::with_capacity(0, file);
            let lines: Vec<_> = reader.lines().try_collect().await.unwrap();

            let expected = vec!["line-a", "line-b"];
            crate::assert_with_log!(lines == expected, "lines", expected, lines);
        });
        crate::test_complete!("test_buf_reader_lines_zero_capacity");
    }

    #[test]
    fn test_buf_reader_capacity_delegates() {
        init_test("test_buf_reader_capacity_delegates");
        let reader = BufReader::with_capacity(32, b"data".as_slice());
        let capacity = reader.capacity();
        crate::assert_with_log!(capacity == 32, "capacity", 32, capacity);
        crate::test_complete!("test_buf_reader_capacity_delegates");
    }

    #[test]
    fn test_oversized_consume_delegates_without_replay() {
        init_test("test_oversized_consume_delegates_without_replay");
        let data: &[u8] = b"abcdef";
        let mut reader = BufReader::with_capacity(3, data);
        let waker = std::task::Waker::noop().clone();
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
        crate::test_complete!("test_oversized_consume_delegates_without_replay");
    }

    #[test]
    fn test_seek_delegates_with_logical_buffer_position() {
        init_test("test_seek_delegates_with_logical_buffer_position");
        futures_lite::future::block_on(async {
            let temp = tempdir().unwrap();
            let path = temp.path().join("seek.txt");
            crate::fs::write(&path, b"abcdef").await.unwrap();

            let file = File::open(&path).await.unwrap();
            let mut reader = BufReader::with_capacity(4, file);
            let mut first = [0u8; 1];
            reader.read_exact(&mut first).await.unwrap();
            assert_eq!(first, *b"a");
            assert_eq!(reader.buffer(), b"bcd");

            let logical = reader.stream_position().await.unwrap();
            assert_eq!(logical, 1);
            assert!(reader.buffer().is_empty());

            reader.rewind().await.unwrap();
            let mut contents = Vec::new();
            reader.read_to_end(&mut contents).await.unwrap();
            assert_eq!(contents, b"abcdef");
        });
        crate::test_complete!("test_seek_delegates_with_logical_buffer_position");
    }
