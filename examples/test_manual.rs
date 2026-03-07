//! Manual smoke test for `read_line` behavior.

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
        unimplemented!()
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

fn main() {
    let mut reader = SplitReader {
        chunks: vec![vec![0xF0, 0x9F], vec![0x94, 0xA5, b'\n']],
    };
    let mut line = String::new();
    let mut fut = Box::pin(asupersync::io::read_line(&mut reader, &mut line));
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(res) => {
                println!("Result: {res:?}");
                break;
            }
            Poll::Pending => {
                println!("Pending...");
            }
        }
    }
    println!("Line: {line:?}");
}
