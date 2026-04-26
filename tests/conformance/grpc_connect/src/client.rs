#![allow(warnings)]
#![allow(clippy::all)]
//! gRPC client implementations for conformance testing

use anyhow::Result;
use asupersync::cx::Cx;
use asupersync::grpc::client::{RequestSink, ResponseFuture, ResponseStream};
use asupersync::grpc::{Channel, GrpcClient, Request, Response, Status};
use bytes::Bytes;
use std::time::Duration;
use tracing::debug;

/// Connect-compatible client for conformance testing
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConformanceClient {
    inner: GrpcClient,
    server_address: String,
}

#[allow(dead_code)]

impl ConformanceClient {
    pub async fn connect(server_address: &str) -> Result<Self> {
        let channel = Channel::connect(server_address).await?;
        let client = GrpcClient::new(channel);

        Ok(Self {
            inner: client,
            server_address: server_address.to_string(),
        })
    }

    pub async fn unary_call(
        &mut self,
        cx: &Cx,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, asupersync::grpc::Status> {
        debug!("Making unary call to {}", self.server_address);
        self.inner
            .unary("/conformance.TestService/UnaryCall", request)
            .await
    }

    /// Server streaming — single request, multiple responses. Returns the
    /// initial gRPC `Response` whose body is a `ResponseStream<Bytes>` the
    /// caller polls for individual messages.
    pub async fn server_streaming_call(
        &mut self,
        _cx: &Cx,
        request: Request<Bytes>,
    ) -> Result<Response<ResponseStream<Bytes>>, Status> {
        debug!("Opening server-streaming call to {}", self.server_address);
        self.inner
            .server_streaming("/conformance.TestService/ServerStreamingCall", request)
            .await
    }

    /// Client streaming — multiple requests, single response. Returns
    /// `(RequestSink, ResponseFuture)`: send messages on the sink, then
    /// `close()` and `await` the future for the final aggregate response.
    pub async fn client_streaming_call(
        &mut self,
        _cx: &Cx,
    ) -> Result<(RequestSink<Bytes>, ResponseFuture<Bytes>), Status> {
        debug!("Opening client-streaming call to {}", self.server_address);
        self.inner
            .client_streaming("/conformance.TestService/ClientStreamingCall")
            .await
    }

    /// Bidirectional streaming — multiple requests, multiple responses.
    /// Returns `(RequestSink, ResponseStream)` for full-duplex messaging.
    pub async fn bidirectional_streaming_call(
        &mut self,
        _cx: &Cx,
    ) -> Result<(RequestSink<Bytes>, ResponseStream<Bytes>), Status> {
        debug!("Opening bidi-streaming call to {}", self.server_address);
        self.inner
            .bidi_streaming("/conformance.TestService/BidirectionalStreamingCall")
            .await
    }
}
