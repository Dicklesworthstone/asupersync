//! HTTP protocol support for Asupersync.
//!
//! This module provides HTTP/1.1 and HTTP/2 protocol implementations
//! with cancel-safe body handling and connection pooling.
//!
//! # Body Types
//!
//! The [`body`] module provides the [`Body`] trait and common
//! implementations for streaming HTTP message bodies.
//!
//! # HTTP/2
//!
//! The [`h2`] module provides HTTP/2 protocol support including frame
//! parsing, HPACK compression, and flow control.
//!
//! # Connection Pooling
//!
//! The [`pool`] module provides connection pool management for HTTP clients,
//! enabling connection reuse for improved performance.

pub mod body;
pub mod compress;
pub mod h1;
pub mod h2;
#[cfg(feature = "http3")]
pub mod h3;
pub mod h3_native;
pub mod pool;

pub use body::{Body, Empty, Frame, Full, HeaderMap, HeaderName, HeaderValue, SizeHint};
#[cfg(feature = "http3")]
pub use h3::{H3Body, H3Client, H3Driver, H3Error};
pub use h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3Frame as NativeH3Frame, H3NativeError,
    H3PseudoHeaders, H3QpackMode, H3RequestHead, H3RequestStreamState, H3ResponseHead,
    H3Settings as NativeH3Settings, H3UniStreamType, QpackFieldPlan, UnknownSetting,
    qpack_static_plan_for_request, qpack_static_plan_for_response, validate_request_pseudo_headers,
    validate_response_pseudo_headers,
};
pub use pool::{Pool, PoolConfig, PoolKey, PoolStats, PooledConnectionMeta, PooledConnectionState};
