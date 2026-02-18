//! gRPC protocol implementation.
//!
//! This module provides a gRPC implementation over HTTP/2, supporting all four
//! streaming patterns: unary, server streaming, client streaming, and bidirectional.
//!
//! # Overview
//!
//! gRPC is a high-performance RPC framework that uses Protocol Buffers for
//! serialization and HTTP/2 for transport. This implementation provides:
//!
//! - Message framing codec for gRPC over HTTP/2
//! - All streaming patterns
//! - Status codes and error handling
//! - Service definition traits
//! - Server and client infrastructure
//!
//! # Example
//!
//! ```ignore
//! use asupersync::grpc::{Channel, Request, Response, Status};
//!
//! // Connect to a server
//! let channel = Channel::connect("http://localhost:50051").await?;
//!
//! // Create a client and make a call
//! let mut client = GrpcClient::new(channel);
//! let response = client.unary("/service/Method", Request::new(message)).await?;
//! ```
//!
//! # Modules
//!
//! - [`codec`]: Message framing and serialization
//! - [`streaming`]: Request/response types and streaming patterns
//! - [`status`]: gRPC status codes and errors
//! - [`service`]: Service definition traits
//! - [`server`]: Server infrastructure
//! - [`client`]: Client infrastructure
//! - [`health`]: gRPC Health Checking Protocol
//! - [`interceptor`]: Interceptor middleware and layers

pub mod client;
pub mod codec;
pub mod health;
pub mod interceptor;
pub mod server;
pub mod service;
pub mod status;
pub mod streaming;

// Re-export commonly used types
pub use client::{Channel, ChannelBuilder, ChannelConfig, GrpcClient, ResponseStream};
pub use codec::{Codec, FramedCodec, GrpcCodec, GrpcMessage, IdentityCodec};
pub use health::{
    HealthCheckRequest, HealthCheckResponse, HealthReporter, HealthService, HealthServiceBuilder,
    ServingStatus,
};
pub use interceptor::{
    BearerAuthInterceptor, BearerAuthValidator, FnInterceptor, InterceptorLayer,
    LoggingInterceptor, MetadataPropagator, RateLimitInterceptor, TimeoutInterceptor,
    TracingInterceptor, auth_bearer_interceptor, auth_validator, fn_interceptor,
    logging_interceptor, metadata_propagator, rate_limiter, timeout_interceptor, trace_interceptor,
};
pub use server::{
    CallContext, CallContextWithCx, Interceptor, Server, ServerBuilder, ServerConfig,
};
pub use service::{
    BidiStreamingMethod, ClientStreamingMethod, MethodDescriptor, NamedService,
    ServerStreamingMethod, ServiceDescriptor, ServiceHandler, UnaryMethod,
};
pub use status::{Code, GrpcError, Status};
pub use streaming::{
    Bidirectional, ClientStreaming, Metadata, MetadataValue, Request, Response, ServerStreaming,
    Streaming, StreamingRequest,
};
