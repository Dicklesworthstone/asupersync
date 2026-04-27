//! HTTP/3 client implementation over QUIC.

extern crate bytes as bytes_crate;
extern crate http as http_crate;

use bytes_crate::Bytes;
use h3::client::{Connection as H3Connection, RequestStream, SendRequest};
use h3::error::{Code, ConnectionError};

use crate::cx::Cx;
use crate::net::quic::QuicConnection;

use super::body::H3Body;
use super::error::H3Error;
use http_crate::{Request, Response};

/// HTTP/3 client handle for issuing requests.
pub struct H3Client {
    quic: QuicConnection,
    send_request: H3SendRequest,
}

/// Driver that must be polled to make progress on the HTTP/3 connection.
pub struct H3Driver {
    connection: H3DriverInner,
}

type H3QuinnConnection = h3_quinn::Connection;
type H3SendRequest = SendRequest<h3_quinn::OpenStreams, Bytes>;
pub(crate) type H3RequestStream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3DriverInner = H3Connection<H3QuinnConnection, Bytes>;

impl H3Client {
    /// Create a new HTTP/3 client from an existing QUIC connection.
    ///
    /// Returns both the client handle and a driver that must be polled
    /// concurrently to maintain the connection state.
    pub async fn new(cx: &Cx, quic: QuicConnection) -> Result<(Self, H3Driver), H3Error> {
        cx.checkpoint()?;

        let h3_conn = h3_quinn::Connection::new(quic.inner().clone());
        let (connection, send_request) = h3::client::new(h3_conn).await?;

        Ok((Self { quic, send_request }, H3Driver { connection }))
    }

    /// Access the underlying QUIC connection.
    #[must_use]
    pub fn quic(&self) -> &QuicConnection {
        &self.quic
    }

    /// Send a request without a body.
    pub async fn request(
        &mut self,
        cx: &Cx,
        request: Request<()>,
    ) -> Result<Response<H3Body>, H3Error> {
        cx.checkpoint()?;
        let mut stream = self.send_request.send_request(request).await?;

        if let Err(err) = cx.checkpoint() {
            cancel_request(&mut stream);
            return Err(err.into());
        }

        stream.finish().await?;

        if let Err(err) = cx.checkpoint() {
            cancel_request(&mut stream);
            return Err(err.into());
        }

        let response = stream.recv_response().await?;

        Ok(response.map(|_| H3Body::new(stream)))
    }

    /// Send a request with a single body chunk.
    pub async fn request_with_body(
        &mut self,
        cx: &Cx,
        request: Request<Bytes>,
    ) -> Result<Response<H3Body>, H3Error> {
        cx.checkpoint()?;
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, ());

        let mut stream = self.send_request.send_request(request).await?;

        if let Err(err) = cx.checkpoint() {
            cancel_request(&mut stream);
            return Err(err.into());
        }

        if !body.is_empty() {
            stream.send_data(body).await?;
        }

        if let Err(err) = cx.checkpoint() {
            cancel_request(&mut stream);
            return Err(err.into());
        }

        stream.finish().await?;

        if let Err(err) = cx.checkpoint() {
            cancel_request(&mut stream);
            return Err(err.into());
        }

        let response = stream.recv_response().await?;

        Ok(response.map(|_| H3Body::new(stream)))
    }
}

impl H3Driver {
    /// Drive the connection to completion, returning `Ok(())` for clean shutdown.
    pub async fn run(mut self) -> Result<(), H3Error> {
        let close = std::future::poll_fn(|cx| self.connection.poll_close(cx)).await;
        map_close_result(close)
    }

    /// Initiate graceful shutdown of the connection.
    pub async fn shutdown(&mut self, max_push_id: usize) -> Result<(), H3Error> {
        self.connection.shutdown(max_push_id).await?;
        Ok(())
    }

    /// Wait until the connection becomes idle.
    pub async fn wait_idle(&mut self) -> Result<(), H3Error> {
        let close = self.connection.wait_idle().await;
        map_close_result(close)
    }
}

fn cancel_request(stream: &mut H3RequestStream) {
    let _ = stream.stop_stream(Code::H3_REQUEST_CANCELLED);
    let _ = stream.stop_sending(Code::H3_REQUEST_CANCELLED);
}

fn map_close_result(err: ConnectionError) -> Result<(), H3Error> {
    if err.is_h3_no_error() {
        Ok(())
    } else {
        Err(err.into())
    }
}
