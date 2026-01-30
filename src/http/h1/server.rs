//! HTTP/1.1 server connection handler.
//!
//! [`Http1Server`] wraps a service and drives an HTTP/1.1 connection,
//! reading requests and writing responses using [`Http1Codec`] over a
//! framed transport.

use crate::codec::Framed;
use crate::http::h1::codec::{Http1Codec, HttpError};
use crate::http::h1::types::{Request, Response};
use crate::io::{AsyncRead, AsyncWrite};
use crate::stream::Stream;
use std::future::Future;
use std::pin::Pin;

/// Configuration for HTTP/1.1 server connections.
#[derive(Debug, Clone)]
pub struct Http1Config {
    /// Maximum header block size in bytes.
    pub max_headers_size: usize,
    /// Whether to support HTTP/1.1 keep-alive.
    pub keep_alive: bool,
}

impl Default for Http1Config {
    fn default() -> Self {
        Self {
            max_headers_size: 64 * 1024,
            keep_alive: true,
        }
    }
}

/// HTTP/1.1 server that processes requests using a service function.
///
/// Reads requests from the transport, passes them to the service, and
/// writes responses back. Supports keep-alive by default.
///
/// # Example
///
/// ```ignore
/// let server = Http1Server::new(|req| async move {
///     Response::new(200, "OK", b"Hello".to_vec())
/// });
/// server.serve(tcp_stream).await?;
/// ```
pub struct Http1Server<F> {
    handler: F,
    config: Http1Config,
}

impl<F, Fut> Http1Server<F>
where
    F: Fn(Request) -> Fut,
    Fut: Future<Output = Response>,
{
    /// Create a new server with the given handler function.
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            config: Http1Config::default(),
        }
    }

    /// Create a new server with custom configuration.
    pub fn with_config(handler: F, config: Http1Config) -> Self {
        Self { handler, config }
    }

    /// Serve a single connection, processing requests until the connection
    /// closes or an error occurs.
    pub async fn serve<T>(self, io: T) -> Result<(), HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let codec = Http1Codec::new().max_headers_size(self.config.max_headers_size);
        let mut framed = Framed::new(io, codec);

        loop {
            // Read next request
            let req = match Pin::new(&mut framed).poll_next_ready().await {
                Some(Ok(req)) => req,
                Some(Err(e)) => return Err(e),
                None => return Ok(()), // Connection closed
            };

            // Check Connection: close before processing
            let close_after = should_close(&req, self.config.keep_alive);

            // Process request through handler
            let resp = (self.handler)(req).await;

            // Write response
            framed.send(resp)?;

            if close_after {
                break;
            }
        }

        Ok(())
    }
}

/// Determine whether the connection should close after this request.
fn should_close(req: &Request, keep_alive_enabled: bool) -> bool {
    if !keep_alive_enabled {
        return true;
    }

    // Check Connection header
    for (name, value) in &req.headers {
        if name.eq_ignore_ascii_case("connection") {
            if value.eq_ignore_ascii_case("close") {
                return true;
            }
            if value.eq_ignore_ascii_case("keep-alive") {
                return false;
            }
        }
    }

    // HTTP/1.0 defaults to close; HTTP/1.1 defaults to keep-alive
    req.version == crate::http::h1::types::Version::Http10
}

/// Helper trait to await the next item from a `Stream` (since `Stream`
/// provides `poll_next`, not an async method).
trait StreamNextExt: Stream {
    async fn poll_next_ready(&mut self) -> Option<Self::Item>
    where
        Self: Unpin,
    {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl<T: Stream + Unpin> StreamNextExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_close_connection_header() {
        let req_close = Request {
            method: crate::http::h1::types::Method::Get,
            uri: "/".into(),
            version: crate::http::h1::types::Version::Http11,
            headers: vec![("Connection".into(), "close".into())],
            body: Vec::new(),
        };
        assert!(should_close(&req_close, true));

        let req_keepalive = Request {
            method: crate::http::h1::types::Method::Get,
            uri: "/".into(),
            version: crate::http::h1::types::Version::Http11,
            headers: vec![("Connection".into(), "keep-alive".into())],
            body: Vec::new(),
        };
        assert!(!should_close(&req_keepalive, true));
    }

    #[test]
    fn should_close_http10_default() {
        let req = Request {
            method: crate::http::h1::types::Method::Get,
            uri: "/".into(),
            version: crate::http::h1::types::Version::Http10,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(should_close(&req, true));
    }

    #[test]
    fn should_close_http11_default() {
        let req = Request {
            method: crate::http::h1::types::Method::Get,
            uri: "/".into(),
            version: crate::http::h1::types::Version::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(!should_close(&req, true));
    }

    #[test]
    fn should_close_keepalive_disabled() {
        let req = Request {
            method: crate::http::h1::types::Method::Get,
            uri: "/".into(),
            version: crate::http::h1::types::Version::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(should_close(&req, false));
    }
}
