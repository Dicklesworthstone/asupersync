//! HTTP/1.1 protocol implementation.
//!
//! This module provides request parsing, response serialization, and
//! connection handling for HTTP/1.1.
//!
//! - [`codec`]: [`Http1Codec`] for framed request/response I/O
//! - [`types`]: [`Method`], [`Version`], [`Request`], [`Response`]
//! - [`server`]: [`Http1Server`] for serving connections
//! - [`client`]: [`Http1Client`] for sending requests
//! - [`stream`]: Streaming body types for incremental I/O

pub mod client;
pub mod codec;
pub mod listener;
pub mod server;
pub mod stream;
pub mod types;

pub use client::{Http1Client, Http1ClientCodec};
pub use codec::{Http1Codec, HttpError};
pub use listener::{Http1Listener, Http1ListenerConfig};
pub use server::{ConnectionPhase, ConnectionState, Http1Config, Http1Server};
pub use stream::{
    BodyKind, ChunkedEncoder, IncomingBody, IncomingBodyWriter, OutgoingBody, OutgoingBodySender,
    RequestHead, ResponseHead, StreamingRequest, StreamingResponse,
};
pub use types::{Method, Request, Response, Version};
