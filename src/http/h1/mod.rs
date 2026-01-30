//! HTTP/1.1 protocol implementation.
//!
//! This module provides request parsing, response serialization, and
//! connection handling for HTTP/1.1.
//!
//! - [`codec`]: [`Http1Codec`](codec::Http1Codec) for framed request/response I/O
//! - [`types`]: [`Method`](types::Method), [`Version`](types::Version),
//!   [`Request`](types::Request), [`Response`](types::Response)
//! - [`server`]: [`Http1Server`](server::Http1Server) for serving connections
//! - [`client`]: [`Http1Client`](client::Http1Client) for sending requests

pub mod client;
pub mod codec;
pub mod server;
pub mod types;

pub use client::{Http1Client, Http1ClientCodec};
pub use codec::{Http1Codec, HttpError};
pub use server::{Http1Config, Http1Server};
pub use types::{Method, Request, Response, Version};
