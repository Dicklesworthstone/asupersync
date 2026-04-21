#![allow(clippy::all)]
//! Regression test for `read_line` across split UTF-8 boundaries.

use asupersync::io::{AsyncBufRead, AsyncRead, ReadBuf};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

struct SplitReader {
    chunks: Vec<Vec<u8>>,
}

impl AsyncRead for SplitReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // SplitReader only supports buffered reads via AsyncBufRead.
        // Direct poll_read signals EOF so callers use the buffered path.
        Poll::Ready(Ok(()))
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

#[test]
fn test_split_utf8_read_line() {
    let mut reader = SplitReader {
        // "🔥\n" is 4 bytes + 1 byte
        // 🔥 is [0xF0, 0x9F, 0x94, 0xA5]
        chunks: vec![vec![0xF0, 0x9F], vec![0x94, 0xA5, b'\n']],
    };
    let mut line = String::new();
    let mut fut = Box::pin(asupersync::io::read_line(&mut reader, &mut line));
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(res) => {
            let bytes_read = res.expect("split UTF-8 line should decode");
            assert_eq!(bytes_read, "🔥\n".len());
            assert_eq!(line, "🔥\n");
        }
        Poll::Pending => panic!("Pending?"),
    }
}

#[test]
fn split_reader_poll_read_returns_ready_eof_without_consuming_chunks() {
    let mut reader = SplitReader {
        chunks: vec![b"still buffered".to_vec()],
    };
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut storage = [0u8; 8];
    let mut read_buf = ReadBuf::new(&mut storage);

    let poll = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);

    assert!(matches!(poll, Poll::Ready(Ok(()))));
    assert!(read_buf.filled().is_empty());
    assert_eq!(reader.chunks, vec![b"still buffered".to_vec()]);
}
