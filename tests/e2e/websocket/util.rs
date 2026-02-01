//! Shared helpers for WebSocket E2E tests.

use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;

pub fn init_ws_test(test_name: &str) {
    crate::common::init_test_logging();
    crate::test_phase!(test_name);
}

/// Build a minimal RFC 6455 client handshake request.
pub fn ws_handshake_request_bytes(
    path: &str,
    host_header: &str,
    sec_websocket_key_b64: &str,
    protocols: Option<&str>,
) -> Vec<u8> {
    let mut req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {sec_websocket_key_b64}\r\n\
         Sec-WebSocket-Version: 13\r\n"
    );

    if let Some(p) = protocols {
        req.push_str("Sec-WebSocket-Protocol: ");
        req.push_str(p);
        req.push_str("\r\n");
    }

    req.push_str("\r\n");
    req.into_bytes()
}

/// Read bytes from an AsyncRead stream until the end of HTTP headers (`\r\n\r\n`).
pub async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    // Keep this small: websockets handshake headers should be tiny.
    const MAX: usize = 16 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 256];

    loop {
        let n = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
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
                "EOF before HTTP headers complete",
            ));
        }

        buf.extend_from_slice(&temp[..n]);

        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }

        if buf.len() > MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }
    }
}

/// Write all bytes to an AsyncWrite stream.
pub async fn write_all<IO: AsyncWrite + Unpin>(io: &mut IO, buf: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, &buf[written..])).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        written += n;
    }
    Ok(())
}

/// Read exactly `n` bytes from an AsyncRead stream.
pub async fn read_exact<IO: AsyncRead + Unpin>(io: &mut IO, n: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    let mut filled = 0;

    while filled < n {
        let got = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut out[filled..]);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before read_exact completed",
            ));
        }

        filled += got;
    }

    Ok(out)
}
