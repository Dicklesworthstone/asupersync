//! I/O capability trait for explicit capability-based I/O access.
//!
//! The [`IoCap`] trait defines the capability boundary for I/O operations.
//! Tasks can only perform I/O if they have access to an `IoCap` implementation.
//!
//! # Design Rationale
//!
//! Asupersync uses explicit capability security - no ambient authority. I/O operations
//! are only available when the runtime provides an `IoCap` implementation:
//!
//! - Production runtime provides a real I/O capability backed by the reactor
//! - Lab runtime provides a virtual I/O capability for deterministic testing
//! - Tests can verify that code correctly handles "no I/O" scenarios
//!
//! # Two-Phase I/O Model
//!
//! I/O operations in Asupersync follow a two-phase commit model:
//!
//! 1. **Submit**: Create an I/O operation (returns a handle/obligation)
//! 2. **Complete**: Wait for completion or cancel
//!
//! This model allows for proper cancellation tracking and budget accounting.

use std::fmt::Debug;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

/// Capability surface advertised by an [`IoCap`] implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct IoCapabilities {
    /// Supports real file descriptor backed operations.
    pub file_ops: bool,
    /// Supports real socket operations.
    pub network_ops: bool,
    /// Supports timer-backed I/O wakeups.
    pub timer_integration: bool,
    /// Provides deterministic virtual I/O semantics.
    pub deterministic: bool,
}

impl IoCapabilities {
    /// Capability descriptor for virtual deterministic I/O.
    pub const LAB: Self = Self {
        file_ops: false,
        network_ops: false,
        timer_integration: true,
        deterministic: true,
    };
}

/// Snapshot of I/O operation counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoStats {
    /// Number of operations submitted through the capability.
    pub submitted: u64,
    /// Number of operations completed through the capability.
    pub completed: u64,
}

/// HTTP method allowlist for browser fetch capability checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
    /// HTTP HEAD.
    Head,
    /// HTTP OPTIONS.
    Options,
}

/// Request envelope used for explicit fetch authority checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    /// HTTP method.
    pub method: FetchMethod,
    /// Absolute URL.
    pub url: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// Whether credentials are requested.
    pub credentials: bool,
}

impl FetchRequest {
    /// Creates a new request envelope.
    #[must_use]
    pub fn new(method: FetchMethod, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            credentials: false,
        }
    }

    /// Adds a request header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    /// Enables credentialed fetch.
    #[must_use]
    pub fn with_credentials(mut self) -> Self {
        self.credentials = true;
        self
    }

    fn origin(&self) -> Option<&str> {
        let scheme_end = self.url.find("://")?;
        if scheme_end == 0 {
            return None;
        }
        let rest = &self.url[scheme_end + 3..];
        if rest.is_empty() {
            return None;
        }
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        if authority_end == 0 {
            return None;
        }
        Some(&self.url[..scheme_end + 3 + authority_end])
    }
}

/// Deterministic policy errors for fetch capability checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchPolicyError {
    /// URL did not contain a valid origin.
    InvalidUrl(String),
    /// Origin is outside the explicit allowlist.
    OriginDenied(String),
    /// Method is outside the explicit allowlist.
    MethodDenied(FetchMethod),
    /// Credentialed fetch is not permitted by policy.
    CredentialsDenied,
    /// Header count exceeds policy.
    TooManyHeaders {
        /// Header count found in the request.
        count: usize,
        /// Maximum allowed header count.
        limit: usize,
    },
}

impl std::fmt::Display for FetchPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid fetch URL: {url}"),
            Self::OriginDenied(origin) => write!(f, "fetch origin denied by policy: {origin}"),
            Self::MethodDenied(method) => write!(f, "fetch method denied by policy: {method:?}"),
            Self::CredentialsDenied => write!(f, "credentialed fetch denied by policy"),
            Self::TooManyHeaders { count, limit } => {
                write!(f, "header count {count} exceeds fetch policy limit {limit}")
            }
        }
    }
}

impl std::error::Error for FetchPolicyError {}

/// Explicit authority boundaries for browser fetch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchAuthority {
    /// Allowed origins (`scheme://host[:port]`). `"*"` allows all.
    pub allowed_origins: Vec<String>,
    /// Allowed HTTP methods.
    pub allowed_methods: Vec<FetchMethod>,
    /// Whether credentialed requests are permitted.
    pub allow_credentials: bool,
    /// Maximum allowed header count.
    pub max_header_count: usize,
}

impl Default for FetchAuthority {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_owned()],
            allowed_methods: vec![
                FetchMethod::Get,
                FetchMethod::Post,
                FetchMethod::Put,
                FetchMethod::Patch,
                FetchMethod::Delete,
                FetchMethod::Head,
                FetchMethod::Options,
            ],
            allow_credentials: false,
            max_header_count: 64,
        }
    }
}

impl FetchAuthority {
    /// Validates a request against authority boundaries.
    pub fn authorize(&self, request: &FetchRequest) -> Result<(), FetchPolicyError> {
        let origin = request
            .origin()
            .ok_or_else(|| FetchPolicyError::InvalidUrl(request.url.clone()))?;

        let origin_allowed = self
            .allowed_origins
            .iter()
            .any(|candidate| candidate == "*" || candidate == origin);
        if !origin_allowed {
            return Err(FetchPolicyError::OriginDenied(origin.to_owned()));
        }

        if !self.allowed_methods.contains(&request.method) {
            return Err(FetchPolicyError::MethodDenied(request.method));
        }

        if request.credentials && !self.allow_credentials {
            return Err(FetchPolicyError::CredentialsDenied);
        }

        if request.headers.len() > self.max_header_count {
            return Err(FetchPolicyError::TooManyHeaders {
                count: request.headers.len(),
                limit: self.max_header_count,
            });
        }

        Ok(())
    }
}

/// Timeout policy for browser fetch operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchTimeoutPolicy {
    /// End-to-end timeout for request lifecycle.
    pub request_timeout_ms: u64,
    /// Maximum wait for first response byte.
    pub first_byte_timeout_ms: u64,
    /// Maximum idle gap between streamed response chunks.
    pub between_chunks_timeout_ms: u64,
}

impl Default for FetchTimeoutPolicy {
    fn default() -> Self {
        Self {
            request_timeout_ms: 30_000,
            first_byte_timeout_ms: 10_000,
            between_chunks_timeout_ms: 5_000,
        }
    }
}

/// Streaming and header/body bounds for browser fetch operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchStreamPolicy {
    /// Maximum serialized request body size.
    pub max_request_body_bytes: usize,
    /// Maximum streamed response body size.
    pub max_response_body_bytes: usize,
    /// Maximum aggregate response header bytes.
    pub max_response_header_bytes: usize,
}

impl Default for FetchStreamPolicy {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 4 * 1024 * 1024,
            max_response_body_bytes: 16 * 1024 * 1024,
            max_response_header_bytes: 16 * 1024,
        }
    }
}

/// Cancellation contract for fetch adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchCancellationPolicy {
    /// Cancellation requires host abort signaling and drains partial body state.
    AbortSignalWithDrain,
    /// Cancellation requests cooperative stop without host-level abort.
    CooperativeOnly,
}

/// Fetch capability interface surfaced through [`IoCap`].
pub trait FetchIoCap: Send + Sync + Debug {
    /// Validates a request against explicit authority policy.
    fn authorize(&self, request: &FetchRequest) -> Result<(), FetchPolicyError>;

    /// Returns the timeout policy.
    fn timeout_policy(&self) -> FetchTimeoutPolicy;

    /// Returns streaming/header-body bounds.
    fn stream_policy(&self) -> FetchStreamPolicy;

    /// Returns cancellation semantics.
    fn cancellation_policy(&self) -> FetchCancellationPolicy;
}

/// Browser-oriented fetch adapter carrying explicit authority and policy.
#[derive(Debug, Clone)]
pub struct BrowserFetchIoCap {
    authority: FetchAuthority,
    timeout: FetchTimeoutPolicy,
    stream: FetchStreamPolicy,
    cancellation: FetchCancellationPolicy,
}

impl BrowserFetchIoCap {
    /// Creates a new browser fetch capability adapter.
    #[must_use]
    pub fn new(
        authority: FetchAuthority,
        timeout: FetchTimeoutPolicy,
        stream: FetchStreamPolicy,
        cancellation: FetchCancellationPolicy,
    ) -> Self {
        Self {
            authority,
            timeout,
            stream,
            cancellation,
        }
    }
}

/// The I/O capability trait.
///
/// Implementations of this trait provide access to I/O operations. The runtime
/// configures which implementation to use:
///
/// - Production: Real I/O via reactor (epoll/kqueue/IOCP)
/// - Lab: Virtual I/O for deterministic testing
///
/// # Example
///
/// ```ignore
/// async fn read_file(cx: &Cx, path: &str) -> io::Result<Vec<u8>> {
///     let io = cx.io().ok_or_else(|| {
///         io::Error::new(io::ErrorKind::Unsupported, "I/O not available")
///     })?;
///
///     // Open the file using the I/O capability
///     let file = io.open(path).await?;
///
///     // Read contents
///     let mut buf = Vec::new();
///     io.read_to_end(&file, &mut buf).await?;
///     Ok(buf)
/// }
/// ```
pub trait IoCap: Send + Sync + Debug {
    /// Returns true if this I/O capability supports real system I/O.
    ///
    /// Lab/test implementations return false.
    fn is_real_io(&self) -> bool;

    /// Returns the name of this I/O capability implementation.
    ///
    /// Useful for debugging and diagnostics.
    fn name(&self) -> &'static str;

    /// Returns the supported I/O features for this capability.
    fn capabilities(&self) -> IoCapabilities;

    /// Returns capability-local operation counters.
    fn stats(&self) -> IoStats {
        IoStats::default()
    }

    /// Returns the fetch adapter capability, when available.
    ///
    /// Most I/O capabilities do not expose browser fetch semantics and return
    /// `None`. Browser-oriented adapters return `Some(...)`.
    fn fetch_cap(&self) -> Option<&dyn FetchIoCap> {
        None
    }
}

/// Error returned when I/O is not available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoNotAvailable;

impl std::fmt::Display for IoNotAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "I/O capability not available")
    }
}

impl std::error::Error for IoNotAvailable {}

impl From<IoNotAvailable> for io::Error {
    fn from(_: IoNotAvailable) -> Self {
        Self::new(io::ErrorKind::Unsupported, "I/O capability not available")
    }
}

/// Lab I/O capability for testing.
///
/// This implementation provides virtual I/O that can be controlled by tests:
/// - Deterministic timing
/// - Fault injection
/// - Replay support
#[derive(Debug, Default)]
pub struct LabIoCap {
    submitted: AtomicU64,
    completed: AtomicU64,
}

impl LabIoCap {
    /// Creates a new lab I/O capability.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a submitted virtual I/O operation.
    pub fn record_submit(&self) {
        self.submitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a completed virtual I/O operation.
    pub fn record_complete(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }
}

impl IoCap for LabIoCap {
    fn is_real_io(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "lab"
    }

    fn capabilities(&self) -> IoCapabilities {
        IoCapabilities::LAB
    }

    fn stats(&self) -> IoStats {
        IoStats {
            submitted: self.submitted.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
        }
    }
}

impl FetchIoCap for BrowserFetchIoCap {
    fn authorize(&self, request: &FetchRequest) -> Result<(), FetchPolicyError> {
        self.authority.authorize(request)
    }

    fn timeout_policy(&self) -> FetchTimeoutPolicy {
        self.timeout
    }

    fn stream_policy(&self) -> FetchStreamPolicy {
        self.stream
    }

    fn cancellation_policy(&self) -> FetchCancellationPolicy {
        self.cancellation
    }
}

impl IoCap for BrowserFetchIoCap {
    fn is_real_io(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "browser-fetch"
    }

    fn capabilities(&self) -> IoCapabilities {
        IoCapabilities {
            file_ops: false,
            network_ops: true,
            timer_integration: true,
            deterministic: false,
        }
    }

    fn fetch_cap(&self) -> Option<&dyn FetchIoCap> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_io_cap_is_not_real() {
        let cap = LabIoCap::new();
        assert!(!cap.is_real_io());
        assert_eq!(cap.name(), "lab");
        assert_eq!(cap.capabilities(), IoCapabilities::LAB);
    }

    #[test]
    fn io_not_available_error() {
        let err = IoNotAvailable;
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn io_not_available_debug_clone_eq() {
        let e = IoNotAvailable;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("IoNotAvailable"), "{dbg}");
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn lab_io_cap_debug_default() {
        let c = LabIoCap::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("LabIoCap"), "{dbg}");
    }

    #[test]
    fn lab_io_cap_stats_track_activity() {
        let cap = LabIoCap::new();
        assert_eq!(cap.stats(), IoStats::default());
        cap.record_submit();
        cap.record_submit();
        cap.record_complete();
        assert_eq!(
            cap.stats(),
            IoStats {
                submitted: 2,
                completed: 1
            }
        );
    }

    #[test]
    fn fetch_authority_allows_expected_origin_and_method() {
        let authority = FetchAuthority {
            allowed_origins: vec!["https://api.example.com".to_owned()],
            allowed_methods: vec![FetchMethod::Get, FetchMethod::Post],
            allow_credentials: false,
            max_header_count: 8,
        };
        let request = FetchRequest::new(FetchMethod::Get, "https://api.example.com/v1/data")
            .with_header("x-trace-id", "t-1");
        assert_eq!(authority.authorize(&request), Ok(()));
    }

    #[test]
    fn fetch_authority_denies_unlisted_origin() {
        let authority = FetchAuthority {
            allowed_origins: vec!["https://api.example.com".to_owned()],
            ..FetchAuthority::default()
        };
        let request = FetchRequest::new(FetchMethod::Get, "https://evil.example.com/v1/data");
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::OriginDenied(
                "https://evil.example.com".to_owned()
            ))
        );
    }

    #[test]
    fn fetch_authority_denies_credentials_when_disallowed() {
        let authority = FetchAuthority {
            allowed_origins: vec!["https://api.example.com".to_owned()],
            allow_credentials: false,
            ..FetchAuthority::default()
        };
        let request = FetchRequest::new(FetchMethod::Get, "https://api.example.com/v1/data")
            .with_credentials();
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::CredentialsDenied)
        );
    }

    #[test]
    fn fetch_authority_rejects_invalid_url() {
        let authority = FetchAuthority::default();
        let request = FetchRequest::new(FetchMethod::Get, "not-a-url");
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::InvalidUrl("not-a-url".to_owned()))
        );
    }

    #[test]
    fn browser_fetch_cap_exposes_policies_through_iocap() {
        let timeout = FetchTimeoutPolicy {
            request_timeout_ms: 15_000,
            first_byte_timeout_ms: 2_000,
            between_chunks_timeout_ms: 1_500,
        };
        let stream = FetchStreamPolicy {
            max_request_body_bytes: 1024,
            max_response_body_bytes: 2048,
            max_response_header_bytes: 512,
        };
        let cap = BrowserFetchIoCap::new(
            FetchAuthority::default(),
            timeout,
            stream,
            FetchCancellationPolicy::AbortSignalWithDrain,
        );

        let io_cap: &dyn IoCap = &cap;
        let fetch_cap = io_cap.fetch_cap().expect("fetch cap should be present");
        assert_eq!(fetch_cap.timeout_policy(), timeout);
        assert_eq!(fetch_cap.stream_policy(), stream);
        assert_eq!(
            fetch_cap.cancellation_policy(),
            FetchCancellationPolicy::AbortSignalWithDrain
        );
    }
}
