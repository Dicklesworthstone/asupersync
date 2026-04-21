#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::websocket::{Message, WebSocketAcceptor};
use futures_lite::future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

struct TestIo {
    read_data: Vec<u8>,
    read_pos: usize,
    written: Vec<u8>,
}

impl TestIo {
    fn new(read_data: Vec<u8>) -> Self {
        Self {
            read_data,
            read_pos: 0,
            written: Vec::new(),
        }
    }
}

impl AsyncRead for TestIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = &self.read_data[self.read_pos..];
        let to_read = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..to_read]);
        self.read_pos += to_read;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn test_acceptor_with_trailing_non_utf8_bytes() {
    let req = b"GET / HTTP/1.1\r\n\
                Host: localhost\r\n\
                Upgrade: websocket\r\n\
                Connection: Upgrade\r\n\
                Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                Sec-WebSocket-Version: 13\r\n\
                \r\n";

    // A valid binary frame (client masked, size=2, payload=[0xFF, 0x00], mask=[0x11, 0x22, 0x33, 0x44])
    // FIN=1, Opcode=2 -> 0x82
    // MASK=1, Len=2 -> 0x82
    // Mask key: 0x11, 0x22, 0x33, 0x44
    // Payload: [0xFF ^ 0x11 = 0xEE, 0x00 ^ 0x22 = 0x22]
    let trailing = vec![0x82, 0x82, 0x11, 0x22, 0x33, 0x44, 0xEE, 0x22];

    let mut request_bytes = req.to_vec();
    request_bytes.extend_from_slice(&trailing);

    let acceptor = WebSocketAcceptor::new();
    let cx = Cx::for_testing();

    // The stream is empty because everything was read into request_bytes
    let io = TestIo::new(vec![]);

    let mut ws = future::block_on(acceptor.accept(&cx, &request_bytes, io)).expect("should accept");

    // Attempt to receive a message without the stream returning any more data
    let msg = future::block_on(ws.recv(&cx))
        .expect("should not err")
        .expect("should not be None");

    match msg {
        Message::Binary(data) => {
            assert_eq!(data.as_ref(), &[0xFF, 0x00]);
        }
        _ => panic!("Expected binary message, got {msg:?}"),
    }
}
