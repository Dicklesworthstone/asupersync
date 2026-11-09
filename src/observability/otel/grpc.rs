//! Native OTLP/gRPC export over a caller-owned channel, with opt-in bounded retries.

use super::{
    OTLP_HTTP_MAX_AUTH_HEADER_NAME_BYTES, OTLP_HTTP_MAX_AUTH_HEADER_VALUE_BYTES,
    OTLP_HTTP_MAX_AUTH_HEADERS, OTLP_HTTP_MAX_ENDPOINT_BYTES, OTLP_HTTP_MAX_RESOURCE_ATTRIBUTES,
    OTLP_HTTP_MAX_RESPONSE_BYTES, OtlpHttpResponse, OtlpLogKeyValueInput, OtlpLogRecordInput,
    OtlpTraceSpanInput, OwnedOtlpLogs, OwnedOtlpMetrics, OwnedOtlpPolicyReport, OwnedOtlpTraces,
    decode_otlp_http_response, transport_owns_header, valid_otlp_resource_attribute,
};
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::grpc::client::{Channel, CompressionEncoding, GrpcClient, encode_grpc_timeout};
use crate::grpc::{Code, Metadata, MetadataValue, Request, Response};
use crate::types::CancelKind;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

mod policy;
mod retry;
mod retry_info;
pub use retry::{OTLP_GRPC_MAX_RETRIES, OtlpGrpcRetryPolicy};

#[cfg(test)]
mod policy_transport_tests;

/// Maximum configured native OTLP request or response message size: 4 MiB.
///
/// This matches the owned OTLP encoders and response decoder. A caller's
/// smaller channel limit remains effective; larger or unbounded limits are
/// rejected at construction instead of being silently changed.
pub const OTLP_GRPC_MAX_MESSAGE_BYTES: usize = OTLP_HTTP_MAX_RESPONSE_BYTES;

/// Maximum configured metadata size, including binary base64 expansion and
/// HTTP/2's 32-byte accounting overhead for each field.
pub const OTLP_GRPC_MAX_METADATA_BYTES: usize = 8 * 1024;

/// Default bound for each native export request, including unary admission,
/// connection establishment, upload, response, and terminal gRPC status.
pub const OTLP_GRPC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// OTLP signal and its canonical unary collector service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpGrpcSignal {
    /// Runtime or application metrics.
    Metrics,
    /// Distributed trace spans.
    Traces,
    /// Structured log records.
    Logs,
}

impl OtlpGrpcSignal {
    /// Canonical OTLP/gRPC Export method; independent of channel URI paths.
    #[must_use]
    pub const fn method_path(self) -> &'static str {
        match self {
            Self::Metrics => "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
            Self::Traces => "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
            Self::Logs => "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
        }
    }
}

/// Stable, value-redacted export failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtlpGrpcErrorKind {
    /// The endpoint exceeds its bound or selects the deterministic fake peer.
    InvalidChannel,
    /// A channel message-size limit is zero or exceeds the owned wire ceiling.
    InvalidLimit,
    /// A configured request timeout is zero.
    InvalidTimeout,
    /// Metadata is malformed, repeated, reserved, or outside its finite bounds.
    InvalidMetadata,
    /// Configured metadata would be sent on an unencrypted native connection.
    InsecureMetadata,
    /// Resource attributes are malformed, repeated, or exceed their bounds.
    InvalidResourceAttributes,
    /// The channel selects gzip without the crate's compression feature.
    UnsupportedCompression,
    /// A request exceeds the caller's configured send-message limit.
    RequestTooLarge,
    /// The owned signal mapper refused the collection before network I/O.
    Mapping,
    /// The explicit owner context refused work before the native call.
    Context,
    /// The unary call failed, including non-OK status or invalid gRPC framing.
    Rpc,
    /// The collector's successful unary response is malformed OTLP protobuf.
    InvalidResponse,
    /// A retry count or exponential delay bound is invalid.
    InvalidRetryPolicy,
    /// Bounded retry requires an authorized timer from the supplied context.
    RetryTimerUnavailable,
    /// Jittered retry requires the supplied context's entropy authority.
    RetryEntropyUnavailable,
    /// The configured number of retries has been consumed.
    RetryExhausted,
    /// The total export deadline elapsed or cannot accommodate the next delay.
    RetryBudgetExhausted,
}

impl OtlpGrpcErrorKind {
    /// Static machine-readable code with no endpoint, metadata, or payload.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidChannel => "otlp.grpc.invalid_channel",
            Self::InvalidLimit => "otlp.grpc.invalid_limit",
            Self::InvalidTimeout => "otlp.grpc.invalid_timeout",
            Self::InvalidMetadata => "otlp.grpc.invalid_metadata",
            Self::InsecureMetadata => "otlp.grpc.insecure_metadata",
            Self::InvalidResourceAttributes => "otlp.grpc.invalid_resource_attributes",
            Self::UnsupportedCompression => "otlp.grpc.unsupported_compression",
            Self::RequestTooLarge => "otlp.grpc.request_too_large",
            Self::Mapping => "otlp.grpc.mapping",
            Self::Context => "otlp.grpc.context",
            Self::Rpc => "otlp.grpc.rpc",
            Self::InvalidResponse => "otlp.grpc.invalid_response",
            Self::InvalidRetryPolicy => "otlp.grpc.invalid_retry_policy",
            Self::RetryTimerUnavailable => "otlp.grpc.retry_timer_unavailable",
            Self::RetryEntropyUnavailable => "otlp.grpc.retry_entropy_unavailable",
            Self::RetryExhausted => "otlp.grpc.retry_exhausted",
            Self::RetryBudgetExhausted => "otlp.grpc.retry_budget_exhausted",
        }
    }
}

/// A terminal collector receipt, decoded only after the complete unary call
/// succeeds. Metrics, traces, and logs share this protobuf acknowledgement.
///
/// A partial-success receipt must never cause the same request to be replayed,
/// even when every item was rejected. A zero-rejected diagnostic is a warning.
/// Presence of an empty partial-success field is retained for inspection.
#[derive(Clone, PartialEq, Eq)]
pub struct OtlpGrpcResponse {
    signal: OtlpGrpcSignal,
    acknowledgement: OtlpHttpResponse,
}

impl OtlpGrpcResponse {
    /// Signal acknowledged by this receipt.
    #[must_use]
    pub const fn signal(&self) -> OtlpGrpcSignal {
        self.signal
    }

    /// Whether the collector populated the partial-success field.
    #[must_use]
    pub const fn is_partial_success(&self) -> bool {
        self.acknowledgement.is_partial_success()
    }

    /// Rejected data points, spans, or log records, according to the signal.
    #[must_use]
    pub const fn rejected_items(&self) -> u64 {
        self.acknowledgement.rejected_items()
    }

    /// Explicit access to the collector diagnostic, bounded to 4096 bytes.
    ///
    /// This untrusted text may contain sensitive telemetry echoed by the
    /// collector. Debug and error formatting never include it.
    #[must_use]
    pub fn error_message(&self) -> &str {
        self.acknowledgement.error_message()
    }
}

impl fmt::Debug for OtlpGrpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpGrpcResponse")
            .field("signal", &self.signal)
            .field("partial_success", &self.is_partial_success())
            .field("rejected_items", &self.rejected_items())
            .field("diagnostic_present", &!self.error_message().is_empty())
            .finish()
    }
}

/// Receipts for the independently encoded requests in one owned collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtlpGrpcExportReport {
    responses: Vec<OtlpGrpcResponse>,
}

impl OtlpGrpcExportReport {
    /// Completed requests in their original send order, including partial
    /// success and warnings. An empty collection has no receipts or I/O.
    #[must_use]
    pub fn responses(&self) -> &[OtlpGrpcResponse] {
        &self.responses
    }
}

/// An export failure that never retains peer status messages, binary status
/// details, metadata, endpoint text, or telemetry payloads.
///
/// If a later request in an owned collection fails, previous receipts remain
/// available through [`Self::completed_responses`]. Those requests must not be
/// replayed. The failing request may also have reached the collector; this
/// interface makes no exporter-level retry decision.
#[derive(Clone, PartialEq, Eq)]
pub struct OtlpGrpcError {
    kind: OtlpGrpcErrorKind,
    grpc_code: Option<Code>,
    mapping_code: Option<&'static str>,
    completed: Vec<OtlpGrpcResponse>,
    retry_delay: Option<Duration>,
    retry_info_valid: bool,
    policy_report: Option<OwnedOtlpPolicyReport>,
}

impl OtlpGrpcError {
    fn new(kind: OtlpGrpcErrorKind) -> Self {
        Self {
            kind,
            grpc_code: None,
            mapping_code: None,
            completed: Vec::new(),
            retry_delay: None,
            retry_info_valid: true,
            policy_report: None,
        }
    }

    fn rpc(status: &crate::grpc::Status) -> Self {
        // Keep only the validated numeric throttle. Raw peer details and
        // messages never enter the export error or its automatic formatting.
        let delay = retry_info::retry_delay(status);
        Self {
            grpc_code: Some(status.code()),
            retry_delay: delay.as_ref().ok().copied().flatten(),
            retry_info_valid: delay.is_ok(),
            ..Self::new(OtlpGrpcErrorKind::Rpc)
        }
    }

    fn mapping(code: &'static str) -> Self {
        Self {
            mapping_code: Some(code),
            ..Self::new(OtlpGrpcErrorKind::Mapping)
        }
    }

    /// Stable failure category.
    #[must_use]
    pub const fn kind(&self) -> OtlpGrpcErrorKind {
        self.kind
    }

    /// Native gRPC or local context status code, without peer-controlled text.
    /// This is not an OTLP retry predicate.
    #[must_use]
    pub const fn grpc_code(&self) -> Option<Code> {
        self.grpc_code
    }

    /// Static error code from the owned metrics, traces, or logs mapper.
    #[must_use]
    pub const fn mapping_code(&self) -> Option<&'static str> {
        self.mapping_code
    }

    /// Earlier acknowledged requests from the same owned collection.
    #[must_use]
    pub fn completed_responses(&self) -> &[OtlpGrpcResponse] {
        &self.completed
    }

    /// A validated minimum delay requested by the collector's RetryInfo.
    /// This alone is not permission to retry: the status, context, attempt
    /// bound, and remaining total export budget must also permit it.
    #[must_use]
    pub const fn retry_delay(&self) -> Option<Duration> {
        self.retry_delay
    }

    /// Completed local filtering from a policy-aware collection whose size
    /// preflight, context checkpoint, or delivery subsequently failed.
    /// This describes local filtering, not collector acceptance. Earlier
    /// collector acknowledgements remain in [`Self::completed_responses`].
    #[must_use]
    pub const fn policy_report(&self) -> Option<&OwnedOtlpPolicyReport> {
        self.policy_report.as_ref()
    }
}

impl fmt::Debug for OtlpGrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpGrpcError")
            .field("kind", &self.kind)
            .field("grpc_code", &self.grpc_code)
            .field("mapping_code", &self.mapping_code)
            .field("completed_requests", &self.completed.len())
            .field("retry_delay", &self.retry_delay)
            .field("policy_report", &self.policy_report)
            .finish()
    }
}

impl fmt::Display for OtlpGrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.code())?;
        if let Some(code) = self.grpc_code {
            write!(f, ": {code:?}")?;
        }
        if let Some(code) = self.mapping_code {
            write!(f, ": {code}")?;
        }
        if !self.completed.is_empty() {
            write!(
                f,
                "; {} earlier requests acknowledged",
                self.completed.len()
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for OtlpGrpcError {}

/// Native OTLP/gRPC for all three signals, using the existing owned protobuf
/// models and the caller's native unary channel.
///
/// Construction does not dial, read environment variables, start a runtime,
/// spawn workers, or change channel authority, TLS roots, compression, pooling,
/// or admission. The `metrics` feature enables this native-only exporter.
/// Configure the channel's explicit TLS connector before supplying credentials.
///
/// By default each encoded request makes one logical native unary invocation
/// and carries the smaller of the exporter timeout (10 seconds by default)
/// and any channel timeout. [`Self::send_with_retry`] explicitly opts one
/// request into finite retries under that single total timeout. An enabled pool keeps
/// its existing recovery on a fresh connection when a reused connection proves
/// a call unprocessed; acknowledged requests are never replayed. The native
/// client also enforces the explicit [`Cx`]'s cancellation, deadline, and budget.
/// Owned collection mapping is synchronous and bracketed by checkpoints;
/// the per-request timeout is not advertised as a whole-collection timeout.
/// Supply an owner deadline to bound a collection across mapping and requests.
///
/// ```no_run
/// use asupersync::{Cx, grpc::client::Channel};
/// use asupersync::observability::otel::{
///     OtlpGrpcError, OtlpGrpcExporter, OtlpGrpcSignal,
/// };
///
/// async fn export(cx: &Cx, channel: Channel, encoded: Vec<u8>) -> Result<(), OtlpGrpcError> {
///     let exporter = OtlpGrpcExporter::new(channel)?;
///     let receipt = exporter.send_once(cx, OtlpGrpcSignal::Metrics, encoded).await?;
///     // Inspect partial rejection without replaying an acknowledged request.
///     let _rejected = receipt.rejected_items();
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct OtlpGrpcExporter {
    channel: Channel,
    metadata: Metadata,
    resource_attributes: Vec<(String, String)>,
    timeout: Duration,
}

impl fmt::Debug for OtlpGrpcExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpGrpcExporter")
            .field("encrypted", &self.encrypted())
            .field("metadata_count", &self.metadata.len())
            .field("resource_attribute_count", &self.resource_attributes.len())
            .field("timeout", &self.timeout)
            .field(
                "max_send_message_size",
                &self.channel.config().max_send_message_size,
            )
            .field(
                "max_recv_message_size",
                &self.channel.config().max_recv_message_size,
            )
            .finish_non_exhaustive()
    }
}

impl OtlpGrpcExporter {
    /// Validate a caller-owned native channel without performing network I/O.
    ///
    /// Message limits must be nonzero and at most 4 MiB. The deterministic
    /// `loopback` transport is rejected because it cannot reach a collector.
    /// A channel with no default timeout uses this exporter's 10-second bound.
    pub fn new(channel: Channel) -> Result<Self, OtlpGrpcError> {
        let uri = channel.uri();
        let fake_loopback = uri.split_once("://").is_some_and(|(_, rest)| {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            let host_port = authority.rsplit('@').next().unwrap_or("");
            !host_port.starts_with('[')
                && host_port
                    .split(':')
                    .next()
                    .is_some_and(|host| host.eq_ignore_ascii_case("loopback"))
        });
        if uri.len() > OTLP_HTTP_MAX_ENDPOINT_BYTES || fake_loopback {
            return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidChannel));
        }
        let config = channel.config();
        if [config.max_send_message_size, config.max_recv_message_size]
            .into_iter()
            .any(|limit| limit == 0 || limit > OTLP_GRPC_MAX_MESSAGE_BYTES)
        {
            return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidLimit));
        }
        if config.timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidTimeout));
        }
        if !cfg!(feature = "compression")
            && (config.send_compression == Some(CompressionEncoding::Gzip)
                || config
                    .accept_compression
                    .contains(&CompressionEncoding::Gzip))
        {
            return Err(OtlpGrpcError::new(
                OtlpGrpcErrorKind::UnsupportedCompression,
            ));
        }
        Ok(Self {
            channel,
            metadata: Metadata::new(),
            resource_attributes: Vec::new(),
            timeout: OTLP_GRPC_DEFAULT_TIMEOUT,
        })
    }

    /// Set the per-request timeout, preserving a shorter channel timeout and
    /// any earlier owner deadline. Zero is invalid; no retry delay is added.
    pub fn try_with_timeout(mut self, timeout: Duration) -> Result<Self, OtlpGrpcError> {
        if timeout.is_zero() {
            return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidTimeout));
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Configure bounded collector metadata. All supplied values are treated
    /// as potentially sensitive and require an encrypted native channel.
    ///
    /// Keys must be unique, valid lowercase gRPC names and must not reserve
    /// transport headers or the `grpc-` prefix. At most 32 fields and 8 KiB of
    /// HTTP/2 header-list bytes are admitted. Binary values include their
    /// base64 expansion in that bound. Values are copied into compact owned
    /// storage so a small binary slice or string cannot retain a much larger
    /// caller allocation. A failed builder makes no network call.
    pub fn try_with_metadata(mut self, metadata: Metadata) -> Result<Self, OtlpGrpcError> {
        validate_metadata(&metadata)?;
        if !metadata.is_empty() && !self.encrypted() {
            return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::InsecureMetadata));
        }
        let mut compact = Metadata::new();
        for (key, value) in metadata.iter() {
            let inserted = match value {
                MetadataValue::Ascii(value) => compact.insert(key, value.as_str()),
                MetadataValue::Binary(value) => {
                    compact.insert_bin(key, Bytes::copy_from_slice(value.as_ref()))
                }
            };
            if !inserted {
                return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidMetadata));
            }
        }
        self.metadata = compact;
        Ok(self)
    }

    /// Configure at most 128 unique string resource attributes for the owned
    /// signal conveniences. Keys and values are validated before storage and
    /// ordered deterministically. Raw [`Self::send_once`] bodies are unchanged.
    /// Apply the existing privacy-aware record or snapshot builders before
    /// encoding when filtering is required; this transport adds no new policy.
    pub fn try_with_resource_attributes(
        mut self,
        attrs: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, OtlpGrpcError> {
        let mut bounded = BTreeMap::new();
        for (key, value) in attrs {
            if bounded.len() == OTLP_HTTP_MAX_RESOURCE_ATTRIBUTES
                || !valid_otlp_resource_attribute(&key, &value)
                || bounded.contains_key(&key)
            {
                return Err(OtlpGrpcError::new(
                    OtlpGrpcErrorKind::InvalidResourceAttributes,
                ));
            }
            bounded.insert(key, value);
        }
        self.resource_attributes = bounded.into_iter().collect();
        Ok(self)
    }

    /// Validated resource attributes, for adapters using their own encoder.
    pub fn resource_attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.resource_attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Submit an already-encoded OTLP request to one native unary invocation.
    /// Bytes are moved into the native identity codec; the caller must not
    /// prepend a gRPC frame. No exporter-level retry is performed. The caller's
    /// enabled channel pool retains recovery for provably unprocessed calls.
    ///
    /// Full success, partial rejection, and warnings are terminal receipts.
    /// The native unary client validates exact response cardinality and final
    /// status before the bounded OTLP decoder runs. Acknowledged telemetry is
    /// never replayed, including partial success and collector warnings.
    pub async fn send_once(
        &self,
        cx: &Cx,
        signal: OtlpGrpcSignal,
        request_body: Vec<u8>,
    ) -> Result<OtlpGrpcResponse, OtlpGrpcError> {
        // Keep the native transport's recursive future graph out of callers'
        // type computation and make the exporter future's Send contract clear.
        let operation: Pin<
            Box<dyn Future<Output = Result<OtlpGrpcResponse, OtlpGrpcError>> + Send + '_>,
        > = Box::pin(self.send_once_inner(cx, signal, request_body));
        operation.await
    }

    async fn send_once_inner(
        &self,
        cx: &Cx,
        signal: OtlpGrpcSignal,
        request_body: Vec<u8>,
    ) -> Result<OtlpGrpcResponse, OtlpGrpcError> {
        self.send_attempt(
            cx,
            signal,
            Bytes::from(request_body),
            self.effective_timeout(),
        )
        .await
    }

    fn effective_timeout(&self) -> Duration {
        self.channel
            .config()
            .timeout
            .map_or(self.timeout, |limit| limit.min(self.timeout))
    }

    async fn send_attempt(
        &self,
        cx: &Cx,
        signal: OtlpGrpcSignal,
        request_body: Bytes,
        timeout: Duration,
    ) -> Result<OtlpGrpcResponse, OtlpGrpcError> {
        checkpoint(cx)?;
        self.validate_request_size(request_body.len())?;
        let mut metadata = self.metadata.clone();
        // Caller metadata cannot set this reserved field. unary_with_cx further
        // tightens it to the remaining owner deadline without replacing Cx.
        let _ = metadata.insert_or_replace("grpc-timeout", encode_grpc_timeout(timeout));
        let request = Request::with_metadata(request_body, metadata);
        let mut client = GrpcClient::new(self.channel.clone());
        let response: Response<Bytes> = client
            .unary_with_cx(cx, signal.method_path(), request)
            .await
            .map_err(|status| OtlpGrpcError::rpc(&status))?;
        let acknowledgement = decode_otlp_http_response(&response.into_inner())
            .map_err(|_| OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidResponse))?;
        Ok(OtlpGrpcResponse {
            signal,
            acknowledgement,
        })
    }

    /// Collect and send owned metrics using an explicit Unix point timestamp.
    /// The complete collection is mapped and size-checked before its first
    /// request. Every request has its own timeout and one native unary call.
    pub async fn send_owned_metrics(
        &self,
        cx: &Cx,
        metrics: &OwnedOtlpMetrics,
        point_time_unix_nano: u64,
    ) -> Result<OtlpGrpcExportReport, OtlpGrpcError> {
        checkpoint(cx)?;
        let attributes: Vec<_> = self.resource_attributes().collect();
        let requests = metrics
            .collect(point_time_unix_nano, &attributes)
            .map_err(|error| OtlpGrpcError::mapping(error.code()))?;
        self.send_collection(cx, OtlpGrpcSignal::Metrics, requests)
            .await
    }

    /// Map borrowed trace spans with the supplied mapper's sampling, lineage,
    /// and finite limits, then send each encoded request once.
    /// Earlier receipts survive a later request failure.
    pub async fn send_owned_traces(
        &self,
        cx: &Cx,
        traces: &OwnedOtlpTraces,
        spans: &[OtlpTraceSpanInput<'_>],
    ) -> Result<OtlpGrpcExportReport, OtlpGrpcError> {
        checkpoint(cx)?;
        let attributes: Vec<_> = self.resource_attributes().collect();
        let requests = traces
            .collect(spans, &attributes)
            .map_err(|error| OtlpGrpcError::mapping(error.code()))?
            .into_requests();
        self.send_collection(cx, OtlpGrpcSignal::Traces, requests)
            .await
    }

    /// Map borrowed log records with the supplied mapper's finite limits, then
    /// send each encoded request once. Empty input performs no I/O.
    /// Earlier receipts survive a later request failure.
    pub async fn send_owned_logs(
        &self,
        cx: &Cx,
        logs: &OwnedOtlpLogs,
        records: &[OtlpLogRecordInput<'_>],
    ) -> Result<OtlpGrpcExportReport, OtlpGrpcError> {
        checkpoint(cx)?;
        let attributes: Vec<_> = self
            .resource_attributes()
            .map(|(key, value)| OtlpLogKeyValueInput::string(key, value))
            .collect();
        let requests = logs
            .collect(records, &attributes)
            .map_err(|error| OtlpGrpcError::mapping(error.code()))?
            .into_requests();
        self.send_collection(cx, OtlpGrpcSignal::Logs, requests)
            .await
    }

    async fn send_collection(
        &self,
        cx: &Cx,
        signal: OtlpGrpcSignal,
        requests: Vec<Vec<u8>>,
    ) -> Result<OtlpGrpcExportReport, OtlpGrpcError> {
        checkpoint(cx)?;
        for request in &requests {
            self.validate_request_size(request.len())?;
        }
        let mut report = OtlpGrpcExportReport::default();
        for request in requests {
            match self.send_once(cx, signal, request).await {
                Ok(response) => report.responses.push(response),
                Err(mut error) => {
                    error.completed = report.responses;
                    return Err(error);
                }
            }
        }
        Ok(report)
    }

    // Queue credit covers retained string/binary payload allocations, while
    // finite container overhead and caller-owned channel resources are extra.
    // Metadata is compacted on admission; resource strings retain their actual
    // capacities. Charging this for every batch is conservative for a shared
    // immutable transport. Saturation makes any overflow fail queue admission.
    pub(super) fn configuration_bytes(&self) -> usize {
        let mut bytes = self.channel.uri().len();
        for (key, value) in self.metadata.iter() {
            let value_bytes = match value {
                MetadataValue::Ascii(value) => value.capacity(),
                MetadataValue::Binary(value) => value.len(),
            };
            bytes = bytes.saturating_add(key.len()).saturating_add(value_bytes);
        }
        for (key, value) in &self.resource_attributes {
            bytes = bytes
                .saturating_add(key.capacity())
                .saturating_add(value.capacity());
        }
        bytes
    }

    pub(super) fn validate_request_size(&self, size: usize) -> Result<(), OtlpGrpcError> {
        if size > self.channel.config().max_send_message_size {
            return Err(OtlpGrpcError::new(OtlpGrpcErrorKind::RequestTooLarge));
        }
        Ok(())
    }

    fn encrypted(&self) -> bool {
        self.channel.config().use_tls
            || self
                .channel
                .uri()
                .split_once("://")
                .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
    }
}

fn checkpoint(cx: &Cx) -> Result<(), OtlpGrpcError> {
    cx.checkpoint().map_err(|_| {
        let code = match cx.cancel_reason().map(|reason| reason.kind) {
            Some(CancelKind::Timeout | CancelKind::Deadline) => Code::DeadlineExceeded,
            Some(CancelKind::PollQuota | CancelKind::CostBudget) => Code::ResourceExhausted,
            _ => Code::Cancelled,
        };
        OtlpGrpcError {
            grpc_code: Some(code),
            ..OtlpGrpcError::new(OtlpGrpcErrorKind::Context)
        }
    })
}

fn validate_metadata(metadata: &Metadata) -> Result<(), OtlpGrpcError> {
    let invalid = || OtlpGrpcError::new(OtlpGrpcErrorKind::InvalidMetadata);
    if metadata.len() > OTLP_HTTP_MAX_AUTH_HEADERS {
        return Err(invalid());
    }
    let mut keys = BTreeSet::new();
    let mut wire_bytes = 0_usize;
    for (key, value) in metadata.iter() {
        if key.is_empty()
            || key.len() > OTLP_HTTP_MAX_AUTH_HEADER_NAME_BYTES
            || !key.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
            || key.starts_with("grpc-")
            || transport_owns_header(key)
            || !keys.insert(key)
        {
            return Err(invalid());
        }
        let value_bytes = match value {
            MetadataValue::Ascii(value) => {
                if key.ends_with("-bin")
                    || value.len() > OTLP_HTTP_MAX_AUTH_HEADER_VALUE_BYTES
                    || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                {
                    return Err(invalid());
                }
                value.len()
            }
            MetadataValue::Binary(value) => {
                if !key.ends_with("-bin") || value.len() > OTLP_HTTP_MAX_AUTH_HEADER_VALUE_BYTES {
                    return Err(invalid());
                }
                // Conservative padded-base64 length also bounds unpadded wire encoding.
                value
                    .len()
                    .checked_add(2)
                    .and_then(|len| (len / 3).checked_mul(4))
                    .ok_or_else(invalid)?
            }
        };
        wire_bytes = wire_bytes
            .checked_add(key.len())
            .and_then(|sum| sum.checked_add(value_bytes))
            .and_then(|sum| sum.checked_add(32))
            .ok_or_else(invalid)?;
        if wire_bytes > OTLP_GRPC_MAX_METADATA_BYTES {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "grpc_tests.rs"]
mod tests;
