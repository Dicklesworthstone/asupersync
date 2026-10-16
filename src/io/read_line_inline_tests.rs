    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::BufReader;
    use crate::io::{AsyncBufRead, AsyncRead, ReadBuf};

    use std::task::{Poll, Waker};

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

    struct SplitReader {
        chunks: Vec<Vec<u8>>,
    }

    impl AsyncRead for SplitReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            unreachable!("read_line should use poll_fill_buf for this test")
        }
    }

    impl AsyncBufRead for SplitReader {
        fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let this = self.get_mut();
            if this.chunks.is_empty() {
                Poll::Ready(Ok(&[]))
            } else {
                Poll::Ready(Ok(&this.chunks[0]))
            }
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            let this = self.get_mut();
            if this.chunks.is_empty() {
                return;
            }
            if amt >= this.chunks[0].len() {
                this.chunks.remove(0);
            } else {
                this.chunks[0] = this.chunks[0][amt..].to_vec();
            }
        }
    }

    struct PendingBetweenChunksReader {
        chunks: Vec<Vec<u8>>,
        pending_once: bool,
    }

    impl AsyncRead for PendingBetweenChunksReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            unreachable!("read_line should use poll_fill_buf for this test")
        }
    }

    impl AsyncBufRead for PendingBetweenChunksReader {
        fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let this = self.get_mut();
            if this.pending_once {
                this.pending_once = false;
                return Poll::Pending;
            }

            if this.chunks.is_empty() {
                Poll::Ready(Ok(&[]))
            } else {
                Poll::Ready(Ok(&this.chunks[0]))
            }
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            let this = self.get_mut();
            if this.chunks.is_empty() {
                return;
            }

            if amt >= this.chunks[0].len() {
                this.chunks.remove(0);
                this.pending_once = !this.chunks.is_empty();
            } else {
                this.chunks[0] = this.chunks[0][amt..].to_vec();
            }
        }
    }

    #[test]
    fn read_line_basic() {
        init_test("read_line_basic");
        let mut reader = BufReader::new(&b"hello\nworld\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 6, "bytes", 6, n);
        crate::assert_with_log!(line == "hello\n", "line", "hello\n", line);
        crate::test_complete!("read_line_basic");
    }

    #[test]
    fn read_line_crlf() {
        init_test("read_line_crlf");
        let mut reader = BufReader::new(&b"hello\r\nworld\r\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        // \r\n is 7 bytes read, but \r is stripped from the string
        crate::assert_with_log!(n == 7, "bytes", 7, n);
        crate::assert_with_log!(line == "hello\n", "line", "hello\n", line);
        crate::test_complete!("read_line_crlf");
    }

    #[test]
    fn read_line_eof_no_newline() {
        init_test("read_line_eof_no_newline");
        let mut reader = BufReader::new(&b"no newline"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 10, "bytes", 10, n);
        crate::assert_with_log!(line == "no newline", "line", "no newline", line);
        crate::test_complete!("read_line_eof_no_newline");
    }

    #[test]
    fn read_line_empty() {
        init_test("read_line_empty");
        let mut reader = BufReader::new(&b""[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 0, "bytes", 0, n);
        let empty = line.is_empty();
        crate::assert_with_log!(empty, "line empty", true, empty);
        crate::test_complete!("read_line_empty");
    }

    #[test]
    fn read_line_successive() {
        init_test("read_line_successive");
        let mut reader = BufReader::new(&b"first\nsecond\n"[..]);

        let mut line1 = String::new();
        let mut fut = read_line(&mut reader, &mut line1);
        let mut fut = Pin::new(&mut fut);
        let n1 = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n1 == 6, "bytes1", 6, n1);
        crate::assert_with_log!(line1 == "first\n", "line1", "first\n", line1);

        let mut line2 = String::new();
        let mut fut = read_line(&mut reader, &mut line2);
        let mut fut = Pin::new(&mut fut);
        let n2 = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n2 == 7, "bytes2", 7, n2);
        crate::assert_with_log!(line2 == "second\n", "line2", "second\n", line2);

        // EOF
        let mut line3 = String::new();
        let mut fut = read_line(&mut reader, &mut line3);
        let mut fut = Pin::new(&mut fut);
        let n3 = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n3 == 0, "bytes3", 0, n3);
        crate::test_complete!("read_line_successive");
    }

    #[test]
    fn read_line_only_newline() {
        init_test("read_line_only_newline");
        let mut reader = BufReader::new(&b"\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("future did not resolve")
            .unwrap();
        crate::assert_with_log!(n == 1, "bytes", 1, n);
        crate::assert_with_log!(line == "\n", "line", "\n", line);
        crate::test_complete!("read_line_only_newline");
    }

    #[test]
    fn read_line_invalid_utf8() {
        init_test("read_line_invalid_utf8");
        let mut reader = BufReader::new(&[0xff, 0xfe, b'\n'][..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
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
        crate::test_complete!("read_line_invalid_utf8");
    }

    #[test]
    fn read_line_split_utf8_across_chunks() {
        init_test("read_line_split_utf8_across_chunks");

        let mut reader = SplitReader {
            chunks: vec![vec![0xF0, 0x9F], vec![0x94, 0xA5, b'\n']],
        };
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
        let mut fut = Pin::new(&mut fut);
        let bytes = poll_ready(&mut fut)
            .expect("future did not resolve")
            .expect("split UTF-8 line should decode");
        crate::assert_with_log!(bytes == "🔥\n".len(), "bytes", "🔥\n".len(), bytes);
        crate::assert_with_log!(line == "🔥\n", "line", "🔥\n", line);
        crate::test_complete!("read_line_split_utf8_across_chunks");
    }

    #[test]
    fn read_line_crlf_is_normalized_after_cancel_and_restart() {
        init_test("read_line_crlf_is_normalized_after_cancel_and_restart");

        let mut reader = PendingBetweenChunksReader {
            chunks: vec![b"hello\r".to_vec(), b"\n".to_vec()],
            pending_once: false,
        };
        let mut line = String::new();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut first = read_line(&mut reader, &mut line);
            let first_poll = Pin::new(&mut first).poll(&mut cx);
            let first_pending = matches!(first_poll, Poll::Pending);
            crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);
        }
        crate::assert_with_log!(line == "hello\r", "partial line", "hello\r", line);

        let mut resumed = read_line(&mut reader, &mut line);
        let mut resumed = Pin::new(&mut resumed);
        let bytes = poll_ready(&mut resumed)
            .expect("future did not resolve")
            .expect("resumed read_line should succeed");

        crate::assert_with_log!(bytes == 1, "bytes", 1, bytes);
        crate::assert_with_log!(line == "hello\n", "line", "hello\n", line);
        crate::test_complete!("read_line_crlf_is_normalized_after_cancel_and_restart");
    }

    #[test]
    fn read_line_repoll_after_completion_fails_closed() {
        init_test("read_line_repoll_after_completion_fails_closed");
        let mut reader = BufReader::new(&b"hello\n"[..]);
        let mut line = String::new();
        let mut fut = read_line(&mut reader, &mut line);
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
        crate::test_complete!("read_line_repoll_after_completion_fails_closed");
    }

    // ====================================================================
    // br-asupersync-ghv5u1: LineReader cancel-safety across multi-byte
    // UTF-8 boundary. The free read_line loses the prefix on cancel;
    // LineReader hoists it to the wrapper so the next read_line picks
    // up where the prior one left off.
    // ====================================================================

    #[test]
    fn ghv5u1_line_reader_resumes_partial_utf8_after_cancel() {
        // A 4-byte emoji split across two reads, with the reader pending in
        // between. The first read_line takes the partial prefix and parks;
        // it is dropped there. The prefix lives on the LineReader, so the
        // next read_line decodes the emoji. (This test used to complete its
        // first call through EOF, and passed only because an incomplete
        // code point at EOF stayed in `pending` forever.)
        let emoji = "\u{1F600}\n"; // U+1F600 = F0 9F 98 80, then a newline
        let bytes = emoji.as_bytes();
        let mut reader = LineReader::new(PendingBetweenChunksReader {
            chunks: vec![bytes[..2].to_vec(), bytes[2..].to_vec()],
            pending_once: false,
        });
        let mut buf = String::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut fut = reader.read_line(&mut buf);
            let poll = Pin::new(&mut fut).poll(&mut cx);
            assert!(poll.is_pending(), "the first call parks between chunks");
        }
        assert!(buf.is_empty());

        let mut fut = reader.read_line(&mut buf);
        let mut fut = Pin::new(&mut fut);
        let n = poll_ready(&mut fut)
            .expect("the resumed call completes")
            .expect("the emoji decodes");
        assert_eq!(n, bytes.len());
        assert_eq!(buf, emoji);
    }

    /// Invalid UTF-8 before a line's `\n`, with the newline in a later
    /// buffer: the error used to consume only the current buffer, so the
    /// rest of the bad line came back as the next "line".
    #[test]
    fn read_line_skips_the_rest_of_an_invalid_line() {
        init_test("read_line_skips_the_rest_of_an_invalid_line");
        let chunks = || vec![b"ab\xFFcd".to_vec(), b"ef\nnext\n".to_vec()];

        let mut reader = SplitReader { chunks: chunks() };
        let mut line = String::new();
        let err = {
            let mut fut = read_line(&mut reader, &mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut)
                .expect("resolves")
                .expect_err("invalid line")
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        line.clear();
        let n = {
            let mut fut = read_line(&mut reader, &mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut).expect("resolves").expect("next line")
        };
        assert_eq!((n, line.as_str()), (5, "next\n"));

        let mut reader = LineReader::new(SplitReader { chunks: chunks() });
        let mut line = String::new();
        let err = {
            let mut fut = reader.read_line(&mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut)
                .expect("resolves")
                .expect_err("invalid line")
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        line.clear();
        let n = {
            let mut fut = reader.read_line(&mut line);
            let mut fut = Pin::new(&mut fut);
            poll_ready(&mut fut).expect("resolves").expect("next line")
        };
        assert_eq!((n, line.as_str()), (5, "next\n"));
    }

    /// A line that is not UTF-8 leaves the caller's buffer as it was, whether
    /// the bad byte arrives with the line's `\n`, before EOF, or as a code
    /// point that EOF cuts off.
    #[test]
    fn an_invalid_line_leaves_the_buffer_as_it_was() {
        init_test("an_invalid_line_leaves_the_buffer_as_it_was");
        for input in [&b"ab\xFFcd\n"[..], &b"ab\xFF"[..], &b"ab\xF0\x9F"[..]] {
            let mut reader = BufReader::new(input);
            let mut line = String::from("kept ");
            let err = {
                let mut fut = read_line(&mut reader, &mut line);
                let mut fut = Pin::new(&mut fut);
                poll_ready(&mut fut)
                    .expect("resolves")
                    .expect_err("invalid line")
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(line, "kept ", "read_line on {input:?}");

            let mut reader = LineReader::new(BufReader::new(input));
            let mut line = String::from("kept ");
            let err = {
                let mut fut = reader.read_line(&mut line);
                let mut fut = Pin::new(&mut fut);
                poll_ready(&mut fut)
                    .expect("resolves")
                    .expect_err("invalid line")
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(line, "kept ", "LineReader::read_line on {input:?}");
        }
    }

    /// A stream that ends inside a code point is an error once; the call
    /// after it used to fail the same way forever instead of seeing EOF.
    #[test]
    fn line_reader_reports_eof_after_an_incomplete_code_point() {
        init_test("line_reader_reports_eof_after_an_incomplete_code_point");
        let mut reader = LineReader::new(BufReader::new(&b"ok\n\xF0\x9F"[..]));
        let mut results = Vec::new();
        for _ in 0..3 {
            let mut line = String::new();
            let mut fut = reader.read_line(&mut line);
            let mut fut = Pin::new(&mut fut);
            let result = poll_ready(&mut fut).expect("resolves");
            results.push(result.map_err(|err| err.kind()));
        }
        assert_eq!(results, vec![Ok(3), Err(io::ErrorKind::InvalidData), Ok(0)]);
    }

    #[test]
    fn ghv5u1_line_reader_completes_full_utf8_in_one_call() {
        // Sanity: when the full codepoint is available in one read,
        // LineReader behaves identically to the free read_line.
        use crate::io::BufReader;
        let mut reader = LineReader::new(BufReader::new(&b"hello\n"[..]));
        let mut buf = String::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = reader.read_line(&mut buf);
        let mut pinned = std::pin::Pin::new(&mut fut);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(Ok(n)) => {
                    assert_eq!(n, 6);
                    assert_eq!(buf, "hello\n");
                    return;
                }
                Poll::Ready(Err(e)) => panic!("unexpected error: {e}"), // ubs:ignore
                Poll::Pending => {}                                     // drive again
            }
        }
    }
