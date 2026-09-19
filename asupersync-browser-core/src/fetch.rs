//! Awaitable, capability-checked browser fetch with bounded response buffering.
//!
//! [`fetch_bytes`] owns its host abort controller and response reader in the
//! caller's Rust future. Dropping that future aborts the request; closing its
//! canonical browser scope also aborts it. No detached Rust task is created.
//! Used inside [`crate::local::spawn_local_future`], cancellation retires both
//! the Rust computation and its in-flight fetch instead of abandoning a Promise.
//!
//! Authority is checked before host dispatch. This additive Rust API refuses
//! redirects (including same-origin redirects) rather than treating authority
//! for the original URL as authority for a redirect target. The existing JS v1
//! fetch export and its response format are unchanged.
//!
//! Limits cover offered request-body bytes, retained Rust response bytes and
//! body read calls, including empty chunks and EOF. They do not bound browser
//! network buffers, an already-delivered JS chunk, allocator overhead, the
//! caller's preexisting request storage, concurrent calls, or elapsed time.
//! A stalled network still needs owner cancellation; this is not a deadline.
//! Host abort cannot undo a server-side effect that has already happened.

use asupersync::types::{WasmAbiVersion, WasmFetchRequest};
use std::fmt;

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(any(target_arch = "wasm32", test))]
mod state;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

/// Explicit per-operation limits. Zero is valid and refuses the corresponding
/// work; a null response body needs no reader calls, while a stream needs a read
/// call even to observe EOF. There is deliberately no implicit unlimited mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchBytesLimits {
    /// Maximum offered request-body length, checked before a JS copy or dispatch.
    pub max_request_bytes: usize,
    /// Maximum retained response-body length, checked before each Rust copy.
    pub max_response_bytes: usize,
    /// Maximum `reader.read()` calls, including empty chunks and the EOF read.
    pub max_body_reads: usize,
}

impl FetchBytesLimits {
    /// Construct an explicit request, response and read-work envelope.
    #[must_use]
    pub const fn new(request_bytes: usize, response_bytes: usize, body_reads: usize) -> Self {
        Self {
            max_request_bytes: request_bytes,
            max_response_bytes: response_bytes,
            max_body_reads: body_reads,
        }
    }
}

/// A complete response body, not just a successful response-header arrival.
/// HTTP error status codes remain ordinary responses for the caller to handle.
/// Debug output excludes body contents; explicit access can contain secrets.
#[derive(PartialEq, Eq)]
#[must_use]
pub struct FetchBytesResponse {
    /// HTTP status returned by the browser, including 4xx and 5xx responses.
    pub status: u16,
    /// Complete body bytes after actual stream EOF (or a null response body).
    pub body: Vec<u8>,
}

impl fmt::Debug for FetchBytesResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchBytesResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Host boundary at which an operation failed. Arbitrary JavaScript rejection
/// values, URL query strings, credentials and body contents are not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchBytesStage {
    /// Abort controller or supported Window/Worker fetch host setup.
    Setup,
    /// Waiting for the browser's response, including refused redirects.
    Response,
    /// Acquiring exclusive ownership of the response body stream.
    Reader,
    /// Waiting for a body chunk or EOF.
    Read,
}

/// Typed refusal/failure for an explicitly bounded browser fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchBytesError {
    /// The URL/method/body combination was rejected before host dispatch.
    InvalidRequest,
    /// The owning scope did not grant origin, method or credential authority.
    CapabilityDenied,
    /// The requested consumer ABI is incompatible with the dispatcher.
    IncompatibleAbi,
    /// The admission scope is stale, closed, or has the wrong handle kind.
    OwnerUnavailable,
    /// The offered request body exceeds its explicit byte limit.
    RequestLimit {
        /// Configured maximum request-body bytes.
        limit: usize,
    },
    /// A received chunk would exceed the response limit. No partial body returns.
    ResponseLimit {
        /// Configured maximum retained response-body bytes.
        limit: usize,
    },
    /// Another body read would exceed the explicit read-work budget.
    ReadLimit {
        /// Configured maximum body read calls.
        limit: usize,
    },
    /// Response-length arithmetic cannot represent the next complete chunk.
    LengthOverflow,
    /// Fallible Rust response-buffer allocation failed.
    Allocation,
    /// No actual browser fetch implementation exists on this target.
    UnsupportedHost,
    /// A host Promise/API rejected without an observed owner cancellation.
    Host {
        /// Boundary that failed; never includes the host's arbitrary payload.
        stage: FetchBytesStage,
    },
    /// The host returned a non-Response, opaque/error response, malformed chunk
    /// or non-boolean stream completion flag.
    InvalidResponse,
    /// Owner closure or the operation's AbortSignal invalidated this result.
    Cancelled,
    /// A real result could not be published to its canonical live handle.
    Publication,
}

impl fmt::Display for FetchBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bounded browser fetch failed: {self:?}")
    }
}

impl std::error::Error for FetchBytesError {}

/// Fetch and buffer a complete body under an existing browser scope's authority.
///
/// Nothing happens before this future is polled. Admission normalizes the
/// request and checks limits, scope identity, ABI and fetch authority before
/// calling the host. The body is read incrementally and checked before each
/// copy into Rust, never through an unbounded `Response.arrayBuffer()` call.
///
/// A dropped future aborts the host request and releases its canonical handle.
/// Closing the scope aborts a suspended host operation; when polled again it
/// returns [`FetchBytesError::Cancelled`], never a stale success. Cancellation
/// can race server-side effects; it does not roll them back. No native runtime
/// `Cx`, timer or independent task is manufactured by this adapter.
///
/// On non-wasm targets this returns [`FetchBytesError::UnsupportedHost`] without
/// admitting work or pretending that an HTTP request was performed.
pub async fn fetch_bytes(
    request: WasmFetchRequest,
    limits: FetchBytesLimits,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<FetchBytesResponse, FetchBytesError> {
    #[cfg(target_arch = "wasm32")]
    {
        browser::fetch_bytes(request, limits, consumer_version).await
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (request, limits, consumer_version);
        Err(FetchBytesError::UnsupportedHost)
    }
}
