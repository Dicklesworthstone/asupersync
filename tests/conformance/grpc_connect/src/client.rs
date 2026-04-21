#![allow(clippy::all)]
//! gRPC client implementations for conformance testing

use anyhow::Result;
use asupersync::cx::Cx;
use asupersync::grpc::{Channel, GrpcClient, Request, Response};
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
        request: Request<Bytes>
    ) -> Result<Response<Bytes>, asupersync::grpc::Status> {
        debug!("Making unary call to {}", self.server_address);
        self.inner.unary("/conformance.TestService/UnaryCall", request).await
    }

    // TODO: Add streaming method implementations when available
    // pub async fn server_streaming_call(...)
    // pub async fn client_streaming_call(...)
    // pub async fn bidirectional_streaming_call(...)
}