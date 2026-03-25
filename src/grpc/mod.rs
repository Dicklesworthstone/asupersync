//! gRPC protocol implementation.
//!
//! This module provides gRPC protocol building blocks plus the current
//! loopback-only client/server surface for unary, server streaming, client
//! streaming, and bidirectional streaming flows.
//!
//! # Overview
//!
//! gRPC is a high-performance RPC framework that uses Protocol Buffers for
//! serialization and typically runs over HTTP/2 transport. This implementation
//! currently provides deterministic in-memory loopback client behavior plus the
//! surrounding framing, status, service, and interceptor surfaces:
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
//! // Connect to the current loopback transport
//! let channel = Channel::connect("http://loopback:50051").await?;
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
//! - [`web`]: gRPC-Web protocol support (HTTP/1.1, base64 text mode)

pub mod client;
pub mod codec;
pub mod health;
pub mod interceptor;
pub mod reflection;
pub mod server;
pub mod service;
pub mod status;
pub mod streaming;
pub mod web;

/// Default maximum gRPC message size (4 MiB).
///
/// This is the single source of truth for the default message size limit,
/// used by both [`codec::GrpcCodec`] and [`protobuf::ProtobufCodec`].
/// Override via the `max_message_size` field on the respective codec builder
/// or via [`ServerConfig`] / [`ChannelConfig`].
///
/// Matches the gRPC ecosystem convention (gRPC-Go, Tonic both default to 4 MiB).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

// Re-export commonly used types
pub use client::{
    Channel, ChannelBuilder, ChannelConfig, ClientInterceptor, CompressionEncoding, GrpcClient,
    MetadataInterceptor, ResponseStream,
};
pub use codec::{
    Codec, FrameCompressor, FrameDecompressor, FramedCodec, GrpcCodec, GrpcMessage, IdentityCodec,
};
#[cfg(feature = "compression")]
pub use codec::{gzip_frame_compress, gzip_frame_decompress};
pub use health::{
    HealthCheckRequest, HealthCheckResponse, HealthReporter, HealthService, HealthServiceBuilder,
    HealthWatcher, ServingStatus,
};
pub use interceptor::{
    BearerAuthInterceptor, BearerAuthValidator, FnInterceptor, InterceptorLayer,
    LoggingInterceptor, MetadataPropagator, RateLimitInterceptor, TimeoutInterceptor,
    TracingInterceptor, auth_bearer_interceptor, auth_validator, fn_interceptor,
    logging_interceptor, metadata_propagator, rate_limiter, timeout_interceptor, trace_interceptor,
};
pub use reflection::{
    ReflectedMethod, ReflectedService, ReflectionDescribeServiceRequest,
    ReflectionDescribeServiceResponse, ReflectionListServicesRequest,
    ReflectionListServicesResponse, ReflectionService,
};
pub use server::{
    CallContext, CallContextWithCx, Interceptor, Server, ServerBuilder, ServerConfig,
    format_grpc_timeout, parse_grpc_timeout,
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
pub use web::{
    ContentType as WebContentType, TrailerFrame, WebFrame, WebFrameCodec, base64_decode,
    base64_encode, decode_trailers, encode_trailers, is_grpc_web_request, is_text_mode,
};
