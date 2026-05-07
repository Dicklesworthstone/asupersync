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

// Conformance tests for H1 vs H2 header decoder equivalence
#[cfg(test)]
mod h1_h2_header_conformance_test;

/// Native HTTP/3 API surface (T4.1).
///
/// This module intentionally exports Tokio-free HTTP/3 primitives from
/// `h3_native` under a feature boundary (`http3`) so users can adopt HTTP/3
/// contracts without enabling parked compatibility wrappers.
#[cfg(feature = "http3")]
pub mod h3 {
    pub use super::h3_native::{
        H3ConnectionConfig, H3ConnectionState, H3ControlState, H3EndpointRole, H3Frame,
        H3NativeError as H3Error, H3PseudoHeaders, H3QpackMode, H3RequestHead,
        H3RequestStreamState, H3ResponseHead, H3Settings, H3UniStreamType, QpackFieldPlan,
        UnknownSetting, qpack_decode_field_section, qpack_encode_field_section,
        qpack_encode_request_field_section, qpack_encode_response_field_section,
        qpack_plan_to_header_fields, qpack_static_plan_for_request, qpack_static_plan_for_response,
        validate_request_pseudo_headers, validate_response_pseudo_headers,
    };
}
pub mod h3_native;
pub mod pool;

pub use body::{Body, Empty, Frame, Full, HeaderMap, HeaderName, HeaderValue, SizeHint};
pub use h1::http_client::HttpClientBuilder;
// br-asupersync-um5wbj: H3Error is the public-facing alias for
// H3NativeError; expose it unconditionally (was previously gated behind
// `feature = "http3"` while H3NativeError was unconditional, producing
// surface inconsistency under non-default feature configs where one
// name was reachable and the other was not). Both names now resolve to
// the same type regardless of feature flags.
pub use h3_native::H3NativeError as H3Error;
pub use h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3ControlState, H3EndpointRole,
    H3Frame as NativeH3Frame, H3NativeError, H3PseudoHeaders, H3QpackMode, H3RequestHead,
    H3RequestStreamState, H3ResponseHead, H3Settings as NativeH3Settings, H3UniStreamType,
    QpackFieldPlan, UnknownSetting, qpack_decode_field_section, qpack_encode_field_section,
    qpack_encode_request_field_section, qpack_encode_response_field_section,
    qpack_plan_to_header_fields, qpack_static_plan_for_request, qpack_static_plan_for_response,
    validate_request_pseudo_headers, validate_response_pseudo_headers,
};
pub use pool::{Pool, PoolConfig, PoolKey, PoolStats, PooledConnectionMeta, PooledConnectionState};
