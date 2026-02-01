use crate::websocket_e2e::util::{init_ws_test, write_all};
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder};
use asupersync::cx::Cx;
use asupersync::io::AsyncRead;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{Frame, FrameCodec, Message, WebSocket, WebSocketConfig};
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;

async fn read_one_frame<IO: AsyncRead + Unpin>(
    codec: &mut FrameCodec,
    io: &mut IO,
    buf: &mut BytesMut,
) -> io::Result<Frame> {
    let mut temp = [0u8; 256];
    loop {
        if let Some(frame) = codec
            .decode(buf)
            .map_err(|e| io::Error::other(e.to_string()))?
        {
            return Ok(frame);
        }

        let n = poll_fn(|cx| {
            let mut read_buf = asupersync::io::ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF reading frame",
            ));
        }
        buf.extend_from_slice(&temp[..n]);
    }
}

#[test]
fn ws_conformance_ping_triggers_pong_and_is_not_exposed_as_message() {
    init_ws_test("ws_conformance_ping_triggers_pong_and_is_not_exposed_as_message");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40301".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40302".parse().unwrap();
        let (client_io, mut server_io) = VirtualTcpStream::pair(client_addr, server_addr);

        let cx = Cx::for_testing();
        let mut client_ws = WebSocket::from_upgraded(client_io, WebSocketConfig::default());

        // Server (manually) writes a ping followed by a text message.
        let mut server_codec = FrameCodec::server();
        let mut out = BytesMut::new();
        server_codec
            .encode(Frame::ping("keepalive"), &mut out)
            .expect("encode ping");
        server_codec
            .encode(Frame::text("hello"), &mut out)
            .expect("encode text");
        write_all(&mut server_io, &out)
            .await
            .expect("write ping+text");

        // Client recv should ignore ping/pong and return the first data message.
        let msg = client_ws.recv(&cx).await.expect("recv").expect("some msg");
        assert!(matches!(msg, Message::Text(s) if s == "hello"));

        // Server should receive a pong back from the client.
        let mut inbuf = BytesMut::new();
        let frame = read_one_frame(&mut FrameCodec::server(), &mut server_io, &mut inbuf)
            .await
            .expect("read pong frame");
        assert_eq!(frame.opcode, asupersync::net::websocket::Opcode::Pong);
        assert_eq!(frame.payload.as_ref(), b"keepalive");
    });
}
