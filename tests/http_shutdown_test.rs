#![allow(missing_docs)]

use asupersync::http::h1::server::{ConnectionPhase, Http1Server};
use asupersync::http::h1::types::Response;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::runtime::RuntimeBuilder;
use asupersync::server::shutdown::ShutdownSignal;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

// Mock IO that allows controlling read/write behavior
struct MockIo {
    read_data: Vec<u8>,
    write_data: Vec<u8>,
}

impl MockIo {
    fn new(data: Vec<u8>) -> Self {
        Self {
            read_data: data,
            write_data: Vec::new(),
        }
    }
}

impl AsyncRead for MockIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_data.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let n = std::cmp::min(buf.remaining(), self.read_data.len());
        buf.put_slice(&self.read_data[..n]);
        self.read_data.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_data.extend_from_slice(buf);
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
fn test_shutdown_signal() {
    let signal = ShutdownSignal::new();

    let server = Http1Server::new(|_req| async move { Response::new(200, "OK", vec![]) })
        .with_shutdown_signal(signal.clone());

    // Create a mock IO with a simple GET request
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let io = MockIo::new(request.to_vec());

    // Trigger shutdown immediately (begin drain phase).
    let began = signal.begin_drain(Duration::from_millis(0));
    assert!(began);

    // Serve should return successfully but stop processing due to shutdown
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build test runtime");
    let result = runtime.block_on(async { server.serve(io).await });
    assert!(result.is_ok());

    // The connection state should indicate it's closing
    let state = result.unwrap();
    assert!(matches!(state.phase, ConnectionPhase::Closing));
}
