//! Regression test for `io::Chain::read_to_end` across both chained readers.

use asupersync::io::{AsyncRead, AsyncReadExt, Chain, ReadBuf};
use futures_lite::future::block_on;
use std::pin::Pin;
use std::task::{Context, Poll};

struct MockReader {
    data: Vec<u8>,
}

impl AsyncRead for MockReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.data.is_empty() {
            let len = std::cmp::min(self.data.len(), buf.remaining());
            buf.put_slice(&self.data[..len]);
            self.data.drain(..len);
        }
        Poll::Ready(Ok(()))
    }
}

#[test]
fn test_chain_bug() {
    block_on(async {
        let mut r1 = MockReader { data: vec![1, 2] };
        let mut r2 = MockReader { data: vec![3, 4] };
        let mut chain = Chain::new(&mut r1, &mut r2);

        let mut buf = Vec::new();
        let n = chain.read_to_end(&mut buf).await.unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, vec![1, 2, 3, 4]);
    });
}
