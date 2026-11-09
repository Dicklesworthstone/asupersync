//! OpenTelemetry SDK spans delivered through an acknowledged native queue.

use super::common::{
    SdkResource, SdkValueError, ValueBudget, attribute_nodes, nanos, owned_attributes,
    owned_attributes_last_wins,
};
use crate::cx::Cx;
use crate::grpc::protobuf::ProtoMessage;
use crate::observability::otel::export_policy::compare_policy_attributes;
use crate::observability::otel::{
    OtlpGrpcSignal, OwnedOtlpExportPolicy, OwnedOtlpPolicyError, OwnedOtlpPolicyOutput,
    OwnedOtlpPolicyReport, QueuedOtlpGrpcExporter,
};
use crate::observability::otlp_proto::collector::trace::ExportTraceServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{InstrumentationScope, Resource};
use crate::observability::otlp_proto::trace::{
    ResourceSpans, ScopeSpans, Span, SpanEvent, SpanLink, Status,
};
use opentelemetry::InstrumentationScope as SdkScope;
use opentelemetry::trace::{SpanId, SpanKind, Status as SdkStatus, TraceState};
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

const MAX_SPANS: usize = 4096;
const MAX_SCOPES: usize = 128;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 64;
const MAX_EVENTS: usize = 128;
const MAX_LINKS: usize = 128;
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Value-free mapping and admission errors for the SDK span adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtlpSdkTraceError {
    /// A finite configuration limit is zero or above the supported maximum.
    InvalidConfiguration,
    /// A collection, scope, attribute, array, event, link, or request is too large.
    LimitExceeded,
    /// An attribute has an empty key or unsupported value, or metadata has duplicate keys.
    InvalidAttributes,
    /// An attribute contains a non-finite floating-point number.
    InvalidNumericValue,
    /// A timestamp is zero, predates the epoch, overflows, or ends before its span starts.
    InvalidTimestamp,
    /// A trace/span identifier or a span/event name is invalid.
    InvalidSpan,
    /// Trace state exceeds its finite envelope or violates the wire schema.
    InvalidTraceState,
    /// The input contains the same trace/span identity more than once.
    DuplicateSpan,
    /// The SDK exporter was invoked from an active native runtime context.
    NativeContext,
    /// The explicit shared filtering policy rejected the mapped model.
    Policy(OwnedOtlpPolicyError),
    /// A finite mapped request cannot fit the owned OTLP schema or byte envelope.
    WireEnvelopeExceeded,
}

impl OtlpSdkTraceError {
    /// Stable code without input attributes, resource values, or collector text.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "otlp.sdk.traces.invalid_configuration",
            Self::LimitExceeded => "otlp.sdk.traces.limit_exceeded",
            Self::InvalidAttributes => "otlp.sdk.traces.invalid_attributes",
            Self::InvalidNumericValue => "otlp.sdk.traces.invalid_numeric_value",
            Self::InvalidTimestamp => "otlp.sdk.traces.invalid_timestamp",
            Self::InvalidSpan => "otlp.sdk.traces.invalid_span",
            Self::InvalidTraceState => "otlp.sdk.traces.invalid_trace_state",
            Self::DuplicateSpan => "otlp.sdk.traces.duplicate_span",
            Self::NativeContext => "otlp.sdk.traces.native_context",
            Self::Policy(error) => error.code(),
            Self::WireEnvelopeExceeded => "otlp.sdk.traces.wire_envelope_exceeded",
        }
    }
}

impl fmt::Display for OtlpSdkTraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for OtlpSdkTraceError {}

impl From<SdkValueError> for OtlpSdkTraceError {
    fn from(error: SdkValueError) -> Self {
        match error {
            SdkValueError::LimitExceeded => Self::LimitExceeded,
            SdkValueError::InvalidAttributes => Self::InvalidAttributes,
            SdkValueError::InvalidNumericValue => Self::InvalidNumericValue,
            SdkValueError::InvalidTimestamp => Self::InvalidTimestamp,
        }
    }
}

impl From<OwnedOtlpPolicyError> for OtlpSdkTraceError {
    fn from(error: OwnedOtlpPolicyError) -> Self {
        Self::Policy(error)
    }
}

/// Finite limits for one complete SDK export call.
///
/// Defaults allow 4096 spans, 128 scopes, and 4 MiB of conservatively accounted
/// input and aggregate encoded output. Each span admits at most 128 events and
/// links, with the shared 128-attribute/128-array-item bounds. Requests pack
/// multiple scope groups and split only between complete spans, at most 64 RPCs.
/// One span that cannot fit a request is refused before any batch is admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtlpSdkTraceConfig {
    max_spans: usize,
    max_scopes: usize,
    max_collection_bytes: usize,
    max_request_bytes: usize,
}

impl Default for OtlpSdkTraceConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl OtlpSdkTraceConfig {
    /// Finite defaults; does not create an SDK provider or worker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_spans: MAX_SPANS,
            max_scopes: MAX_SCOPES,
            max_collection_bytes: MAX_BYTES,
            max_request_bytes: MAX_BYTES,
        }
    }

    /// Set the complete-batch span bound, at most 4096.
    #[must_use]
    pub const fn with_max_spans(mut self, limit: usize) -> Self {
        self.max_spans = limit;
        self
    }

    /// Set the number of distinct input instrumentation scopes, at most 128.
    #[must_use]
    pub const fn with_max_scopes(mut self, limit: usize) -> Self {
        self.max_scopes = limit;
        self
    }

    /// Set input-accounting and aggregate encoded-output limits, at most 4 MiB.
    #[must_use]
    pub const fn with_max_collection_bytes(mut self, limit: usize) -> Self {
        self.max_collection_bytes = limit;
        self
    }

    /// Set the request bound, at most 4 MiB. A smaller caller channel bound is
    /// still enforced during atomic queue admission.
    #[must_use]
    pub const fn with_max_request_bytes(mut self, limit: usize) -> Self {
        self.max_request_bytes = limit;
        self
    }

    /// Maximum spans admitted in a complete SDK batch.
    #[must_use]
    pub const fn max_spans(&self) -> usize {
        self.max_spans
    }

    /// Maximum distinct input instrumentation scopes.
    #[must_use]
    pub const fn max_scopes(&self) -> usize {
        self.max_scopes
    }

    /// Complete input-accounting and encoded-output limit.
    #[must_use]
    pub const fn max_collection_bytes(&self) -> usize {
        self.max_collection_bytes
    }

    /// Per-request byte limit before a smaller native channel limit.
    #[must_use]
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    fn validate(self) -> Result<(), OtlpSdkTraceError> {
        if self.max_spans == 0
            || self.max_spans > MAX_SPANS
            || self.max_scopes == 0
            || self.max_scopes > MAX_SCOPES
            || self.max_collection_bytes == 0
            || self.max_collection_bytes > MAX_BYTES
            || self.max_request_bytes == 0
            || self.max_request_bytes > MAX_BYTES
        {
            return Err(OtlpSdkTraceError::InvalidConfiguration);
        }
        Ok(())
    }
}

type TraceResource = SdkResource;

/// An explicitly installed SDK span exporter using a caller-managed native queue.
///
/// Start `queue().spawn_queued` before the caller's SDK processor exports spans.
/// This adapter creates no provider, processor, background thread, or runtime.
/// Use a caller-installed SDK batch processor, or emit spans using its simple
/// processor on a thread outside the native runtime. SDK simple processors
/// synchronously wait for export on the emitting thread. Therefore this SDK
/// exporter refuses an active native `Cx` before admission; native async callers
/// can use the owned trace exporter directly.
/// The simple processor acquires its own exporter mutex before this guard runs,
/// so the guard does not replace the off-runtime emission requirement.
///
/// Export completes only after every admitted request has a terminal collector
/// response. Valid partial success is terminal success: rejected span counts are
/// recorded in the queue and never trigger whole-collection replay. The full
/// input is checked and encoded before admission, then its owned SDK batch is
/// dropped before waiting for the acknowledged queue receipt.
///
/// SDK resource and scope metadata retain separate schema URLs. Transport
/// resource defaults are not reapplied. Explicit policy overrides and privacy
/// filtering happen on typed owned models. SDK attribute updates are normalized
/// with the last value for a key winning; every raw entry is validated first.
/// Producer dropped counts, event/link order, timestamps and context flags are
/// preserved. This exporter does not resample, require parents in the batch, or
/// constrain a child's/event's time to a parent/span interval. Duplicate span
/// identities within one batch are refused.
///
/// The SDK resource setter cannot return an error. Invalid resource updates
/// replace the prior resource with a static failure, reported by later export;
/// oversized or invalid source values are not retained. Synchronous flush has
/// a five-second bound, and shutdown uses the supplied timeout. SDK callbacks
/// and processor/provider blocking behavior are outside these bounds.
/// Shutdown seals every clone sharing the queue; dedicate a queue to each
/// independently managed provider. Native async shutdown uses managed drain/join.
#[derive(Clone)]
pub struct OtlpSdkSpanExporter {
    queue: QueuedOtlpGrpcExporter,
    config: OtlpSdkTraceConfig,
    policy: OwnedOtlpExportPolicy,
    resource: Result<Arc<TraceResource>, OtlpSdkTraceError>,
}

impl fmt::Debug for OtlpSdkSpanExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpSdkSpanExporter")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .field("queue", &self.queue)
            .field("resource_valid", &self.resource.is_ok())
            .field(
                "resource_attributes",
                &self
                    .resource
                    .as_ref()
                    .map_or(0, |resource| resource.resource.attributes.len()),
            )
            .finish()
    }
}

impl OtlpSdkSpanExporter {
    /// Wrap an existing queue with finite mapper defaults and an empty resource.
    #[must_use]
    pub fn new(queue: QueuedOtlpGrpcExporter) -> Self {
        Self {
            queue,
            config: OtlpSdkTraceConfig::new(),
            policy: OwnedOtlpExportPolicy::new(),
            resource: Ok(Arc::new(TraceResource::empty())),
        }
    }

    /// Validate every mapper bound before constructing an exporter.
    pub fn try_with_config(
        queue: QueuedOtlpGrpcExporter,
        config: OtlpSdkTraceConfig,
    ) -> Result<Self, OtlpSdkTraceError> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new(queue)
        })
    }

    /// Apply an immutable explicit resource/scope/privacy policy.
    #[must_use]
    pub fn with_policy(mut self, policy: OwnedOtlpExportPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Shared queue for startup, terminal partial counters and async drain/join.
    #[must_use]
    pub const fn queue(&self) -> &QueuedOtlpGrpcExporter {
        &self.queue
    }

    /// Validated immutable mapper configuration.
    #[must_use]
    pub const fn config(&self) -> &OtlpSdkTraceConfig {
        &self.config
    }
}

impl SpanExporter for OtlpSdkSpanExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        if Cx::current().is_some() {
            return Err(sdk_error(OtlpSdkTraceError::NativeContext.code()));
        }
        self.queue
            .ensure_managed_active()
            .map_err(|_| sdk_error("otlp.sdk.traces.owner_unavailable"))?;
        let resource = self
            .resource
            .as_ref()
            .map_err(|error| sdk_error(error.code()))?;
        let mapped = map_traces(&batch, resource, &self.policy, &self.config);
        // Caller-owned spare capacities must not survive through transport waits.
        drop(batch);
        let (requests, _) = mapped
            .map_err(|error| sdk_error(error.code()))?
            .into_parts();
        self.queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Traces, requests)
            .map_err(|_| sdk_error("otlp.sdk.traces.admission_refused"))?
            .await
            .map(|_| ())
            .map_err(|error| sdk_error(error.code()))
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.queue
            .force_flush_blocking(FLUSH_TIMEOUT)
            .map_err(|_| sdk_error("otlp.sdk.traces.flush_incomplete"))
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.queue
            .shutdown_blocking(timeout)
            .map_err(|_| sdk_error("otlp.sdk.traces.shutdown_incomplete"))
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.resource = prepare_resource(resource, &self.config).map(Arc::new);
    }
}

fn sdk_error(code: &'static str) -> OTelSdkError {
    OTelSdkError::InternalFailure(code.to_owned())
}

fn prepare_resource(
    input: &opentelemetry_sdk::Resource,
    config: &OtlpSdkTraceConfig,
) -> Result<TraceResource, OtlpSdkTraceError> {
    SdkResource::prepare(input, config.max_collection_bytes).map_err(Into::into)
}

fn trace_state_size(state: &TraceState) -> Result<usize, OtlpSdkTraceError> {
    let mut bytes = 0usize;
    let mut keys = BTreeSet::new();
    for (index, (key, value)) in state.into_iter().enumerate() {
        if index == 32 || !keys.insert(key) {
            return Err(OtlpSdkTraceError::InvalidTraceState);
        }
        bytes = bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .and_then(|bytes| bytes.checked_add(if index == 0 { 1 } else { 2 }))
            .filter(|bytes| *bytes <= 512)
            .ok_or(OtlpSdkTraceError::InvalidTraceState)?;
    }
    Ok(bytes)
}

fn owned_trace_state(state: &TraceState) -> Result<String, OtlpSdkTraceError> {
    let mut output = String::with_capacity(trace_state_size(state)?);
    for (index, (key, value)) in state.into_iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(key);
        output.push('=');
        output.push_str(value);
    }
    Ok(output)
}

fn preflight<'a>(
    spans: &'a [SpanData],
    resource: &TraceResource,
    policy: &OwnedOtlpExportPolicy,
    config: &OtlpSdkTraceConfig,
) -> Result<Vec<&'a SdkScope>, OtlpSdkTraceError> {
    if spans.len() > config.max_spans {
        return Err(OtlpSdkTraceError::LimitExceeded);
    }
    let mut budget = ValueBudget::new(config.max_collection_bytes);
    budget.reserve_owned(resource.input_bytes, resource.value_nodes)?;
    let mut identities = BTreeSet::new();
    let mut scopes = Vec::new();
    for span in spans {
        if !span.span_context.is_valid() || span.name.is_empty() {
            return Err(OtlpSdkTraceError::InvalidSpan);
        }
        if !identities.insert((
            span.span_context.trace_id().to_bytes(),
            span.span_context.span_id().to_bytes(),
        )) {
            return Err(OtlpSdkTraceError::DuplicateSpan);
        }
        budget.bytes(std::mem::size_of::<Span>().saturating_add(32))?;
        budget.text(&span.name, 1024)?;
        budget.bytes(trace_state_size(span.span_context.trace_state())?)?;
        let start = nanos(span.start_time, false)?;
        let end = nanos(span.end_time, false)?;
        if start > end {
            return Err(OtlpSdkTraceError::InvalidTimestamp);
        }
        budget.attribute_list(
            span.attributes
                .iter()
                .map(|kv| (kv.key.as_str(), &kv.value)),
        )?;
        if span.events.len() > MAX_EVENTS || span.links.len() > MAX_LINKS {
            return Err(OtlpSdkTraceError::LimitExceeded);
        }
        for event in &span.events.events {
            if event.name.is_empty() {
                return Err(OtlpSdkTraceError::InvalidSpan);
            }
            budget.bytes(std::mem::size_of::<SpanEvent>())?;
            budget.text(&event.name, 1024)?;
            nanos(event.timestamp, true)?;
            budget.attribute_list(
                event
                    .attributes
                    .iter()
                    .map(|kv| (kv.key.as_str(), &kv.value)),
            )?;
        }
        for link in &span.links.links {
            if !link.span_context.is_valid() {
                return Err(OtlpSdkTraceError::InvalidSpan);
            }
            budget.bytes(std::mem::size_of::<SpanLink>().saturating_add(24))?;
            budget.bytes(trace_state_size(link.span_context.trace_state())?)?;
            budget.attribute_list(
                link.attributes
                    .iter()
                    .map(|kv| (kv.key.as_str(), &kv.value)),
            )?;
        }
        if let SdkStatus::Error { description } = &span.status {
            budget.bytes(std::mem::size_of::<Status>())?;
            budget.text(description, 4096)?;
        }
        if !scopes.contains(&&span.instrumentation_scope) {
            if scopes.len() == config.max_scopes {
                return Err(OtlpSdkTraceError::LimitExceeded);
            }
            let scope = &span.instrumentation_scope;
            budget.bytes(
                std::mem::size_of::<ScopeSpans>()
                    .saturating_add(std::mem::size_of::<InstrumentationScope>()),
            )?;
            budget.text(scope.name(), 1024)?;
            budget.text(scope.version().unwrap_or_default(), 1024)?;
            budget.text(scope.schema_url().unwrap_or_default(), 2048)?;
            budget.attributes(scope.attributes().map(|kv| (kv.key.as_str(), &kv.value)))?;
            scopes.push(scope);
        }
    }
    let (resource_extra, scope_extra) = policy.sdk_metadata_reserve();
    budget.bytes(resource_extra.saturating_add(scope_extra.saturating_mul(scopes.len())))?;
    Ok(scopes)
}

fn flags(trace_flags: u8, remote: bool) -> u32 {
    u32::from(trace_flags) | 0x100 | if remote { 0x200 } else { 0 }
}

fn owned_span(input: &SpanData) -> Result<Span, OtlpSdkTraceError> {
    let kind = match input.span_kind {
        SpanKind::Internal => 1,
        SpanKind::Server => 2,
        SpanKind::Client => 3,
        SpanKind::Producer => 4,
        SpanKind::Consumer => 5,
    };
    let (code, message) = match &input.status {
        SdkStatus::Unset => (0, String::new()),
        SdkStatus::Ok => (1, String::new()),
        SdkStatus::Error { description } => (2, description.to_string()),
    };
    Ok(Span {
        trace_id: input.span_context.trace_id().to_bytes().to_vec(),
        span_id: input.span_context.span_id().to_bytes().to_vec(),
        trace_state: owned_trace_state(input.span_context.trace_state())?,
        parent_span_id: if input.parent_span_id == SpanId::INVALID {
            Vec::new()
        } else {
            input.parent_span_id.to_bytes().to_vec()
        },
        flags: flags(
            input.span_context.trace_flags().to_u8(),
            input.parent_span_is_remote,
        ),
        name: input.name.to_string(),
        kind,
        start_time_unix_nano: nanos(input.start_time, false)?,
        end_time_unix_nano: nanos(input.end_time, false)?,
        attributes: owned_attributes_last_wins(
            input
                .attributes
                .iter()
                .map(|kv| (kv.key.as_str(), &kv.value)),
        )?,
        dropped_attributes_count: input.dropped_attributes_count,
        events: input
            .events
            .events
            .iter()
            .map(|event| {
                Ok(SpanEvent {
                    time_unix_nano: nanos(event.timestamp, true)?,
                    name: event.name.to_string(),
                    attributes: owned_attributes_last_wins(
                        event
                            .attributes
                            .iter()
                            .map(|kv| (kv.key.as_str(), &kv.value)),
                    )?,
                    dropped_attributes_count: event.dropped_attributes_count,
                    ..SpanEvent::default()
                })
            })
            .collect::<Result<Vec<_>, OtlpSdkTraceError>>()?,
        dropped_events_count: input.events.dropped_count,
        links: input
            .links
            .links
            .iter()
            .map(|link| {
                Ok(SpanLink {
                    trace_id: link.span_context.trace_id().to_bytes().to_vec(),
                    span_id: link.span_context.span_id().to_bytes().to_vec(),
                    trace_state: owned_trace_state(link.span_context.trace_state())?,
                    attributes: owned_attributes_last_wins(
                        link.attributes
                            .iter()
                            .map(|kv| (kv.key.as_str(), &kv.value)),
                    )?,
                    dropped_attributes_count: link.dropped_attributes_count,
                    flags: flags(
                        link.span_context.trace_flags().to_u8(),
                        link.span_context.is_remote(),
                    ),
                    ..SpanLink::default()
                })
            })
            .collect::<Result<Vec<_>, OtlpSdkTraceError>>()?,
        dropped_links_count: input.links.dropped_count,
        status: Some(Status {
            message,
            code,
            ..Status::default()
        }),
        ..Span::default()
    })
}

fn compare_scope(left: &ScopeSpans, right: &ScopeSpans) -> Ordering {
    match (left.scope.as_ref(), right.scope.as_ref()) {
        (Some(left_scope), Some(right_scope)) => (
            left_scope.name.as_str(),
            left_scope.version.as_str(),
            left.schema_url.as_str(),
        )
            .cmp(&(
                right_scope.name.as_str(),
                right_scope.version.as_str(),
                right.schema_url.as_str(),
            ))
            .then_with(|| {
                compare_policy_attributes(&left_scope.attributes, &right_scope.attributes)
            })
            .then_with(|| {
                left_scope
                    .dropped_attributes_count
                    .cmp(&right_scope.dropped_attributes_count)
            }),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => left.schema_url.cmp(&right.schema_url),
    }
}

fn span_nodes(span: &Span) -> usize {
    span.events
        .iter()
        .fold(attribute_nodes(&span.attributes), |nodes, event| {
            nodes.saturating_add(attribute_nodes(&event.attributes))
        })
        .saturating_add(span.links.iter().fold(0usize, |nodes, link| {
            nodes.saturating_add(attribute_nodes(&link.attributes))
        }))
}

fn append_request(
    resource: &Resource,
    resource_schema: &str,
    scopes: Vec<ScopeSpans>,
    requests: &mut Vec<Vec<u8>>,
    encoded_bytes: &mut usize,
    config: &OtlpSdkTraceConfig,
) -> Result<(), OtlpSdkTraceError> {
    if scopes.is_empty() {
        return Ok(());
    }
    if requests.len() == MAX_REQUESTS {
        return Err(OtlpSdkTraceError::LimitExceeded);
    }
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(resource.clone()),
            schema_url: resource_schema.to_owned(),
            scope_spans: scopes,
            ..ResourceSpans::default()
        }],
        ..ExportTraceServiceRequest::default()
    };
    let encoded = request
        .encode_to_bytes(crate::observability::otel::otlp_request_limits(
            config.max_request_bytes,
        ))
        .map_err(|_| OtlpSdkTraceError::WireEnvelopeExceeded)?;
    *encoded_bytes = encoded_bytes
        .checked_add(encoded.len())
        .filter(|bytes| *bytes <= config.max_collection_bytes)
        .ok_or(OtlpSdkTraceError::LimitExceeded)?;
    requests.push(encoded.to_vec());
    Ok(())
}

fn encode_scopes(
    resource: &Resource,
    resource_schema: &str,
    scopes: Vec<ScopeSpans>,
    config: &OtlpSdkTraceConfig,
) -> Result<Vec<Vec<u8>>, OtlpSdkTraceError> {
    let limits = crate::observability::otel::otlp_request_limits(config.max_request_bytes);
    let resource_bytes = resource
        .encode_to_bytes(limits)
        .map_err(|_| OtlpSdkTraceError::WireEnvelopeExceeded)?
        .len()
        .saturating_add(resource_schema.len())
        .saturating_add(24);
    let resource_nodes = attribute_nodes(&resource.attributes);
    let resource_items = resource_nodes.saturating_mul(2).saturating_add(2);
    let mut batch = Vec::new();
    let mut batch_bytes = resource_bytes;
    let mut batch_nodes = resource_nodes;
    let mut batch_items = resource_items;
    let mut requests = Vec::new();
    let mut encoded_bytes = 0usize;
    for mut scope in scopes {
        let scope_value = scope
            .scope
            .as_ref()
            .ok_or(OtlpSdkTraceError::WireEnvelopeExceeded)?;
        let scope_bytes = scope_value
            .encode_to_bytes(limits)
            .map_err(|_| OtlpSdkTraceError::WireEnvelopeExceeded)?
            .len()
            .saturating_add(scope.schema_url.len())
            .saturating_add(24);
        let scope_nodes = attribute_nodes(&scope_value.attributes);
        let scope_items = scope_nodes.saturating_mul(2).saturating_add(1);
        let mut new_scope = true;
        for span in std::mem::take(&mut scope.spans) {
            // Validate each indivisible span; only its size is retained.
            let span_bytes = span
                .encode_to_bytes(limits)
                .map_err(|_| OtlpSdkTraceError::WireEnvelopeExceeded)?
                .len()
                .saturating_add(6);
            let nodes = span_nodes(&span);
            let items = nodes
                .saturating_mul(2)
                .saturating_add(span.events.len())
                .saturating_add(span.links.len())
                .saturating_add(1);
            let cost_bytes = span_bytes.saturating_add(if new_scope { scope_bytes } else { 0 });
            let cost_nodes = nodes.saturating_add(if new_scope { scope_nodes } else { 0 });
            let cost_items = items.saturating_add(if new_scope { scope_items } else { 0 });
            if !batch.is_empty()
                && (batch_bytes.saturating_add(cost_bytes) > config.max_request_bytes
                    || batch_nodes.saturating_add(cost_nodes) > 4096
                    || batch_items.saturating_add(cost_items) > 32_768
                    || (new_scope && batch.len() == MAX_SCOPES))
            {
                append_request(
                    resource,
                    resource_schema,
                    std::mem::take(&mut batch),
                    &mut requests,
                    &mut encoded_bytes,
                    config,
                )?;
                batch_bytes = resource_bytes;
                batch_nodes = resource_nodes;
                batch_items = resource_items;
                new_scope = true;
            }
            let cost_bytes = span_bytes.saturating_add(if new_scope { scope_bytes } else { 0 });
            let cost_nodes = nodes.saturating_add(if new_scope { scope_nodes } else { 0 });
            let cost_items = items.saturating_add(if new_scope { scope_items } else { 0 });
            if batch_bytes.saturating_add(cost_bytes) > config.max_request_bytes
                || batch_nodes.saturating_add(cost_nodes) > 4096
                || batch_items.saturating_add(cost_items) > 32_768
            {
                return Err(OtlpSdkTraceError::WireEnvelopeExceeded);
            }
            batch_bytes = batch_bytes.saturating_add(cost_bytes);
            batch_nodes = batch_nodes.saturating_add(cost_nodes);
            batch_items = batch_items.saturating_add(cost_items);
            if new_scope {
                batch.push(ScopeSpans {
                    scope: scope.scope.clone(),
                    schema_url: scope.schema_url.clone(),
                    ..ScopeSpans::default()
                });
                new_scope = false;
            }
            batch
                .last_mut()
                .ok_or(OtlpSdkTraceError::WireEnvelopeExceeded)?
                .spans
                .push(span);
        }
    }
    append_request(
        resource,
        resource_schema,
        batch,
        &mut requests,
        &mut encoded_bytes,
        config,
    )?;
    Ok(requests)
}

fn map_traces(
    spans: &[SpanData],
    resource: &TraceResource,
    policy: &OwnedOtlpExportPolicy,
    config: &OtlpSdkTraceConfig,
) -> Result<OwnedOtlpPolicyOutput<Vec<Vec<u8>>>, OtlpSdkTraceError> {
    let source_scopes = preflight(spans, resource, policy, config)?;
    let mut report = OwnedOtlpPolicyReport::default();
    let mut resource_value = resource.resource.clone();
    let mut resource_schema = resource.schema_url.clone();
    policy.sdk_resource(&mut resource_value, &mut resource_schema, &mut report)?;
    let mut scopes = Vec::with_capacity(source_scopes.len());
    for source in &source_scopes {
        let mut scope = InstrumentationScope {
            name: source.name().to_owned(),
            version: source.version().unwrap_or_default().to_owned(),
            attributes: owned_attributes(
                source.attributes().map(|kv| (kv.key.as_str(), &kv.value)),
            )?,
            ..InstrumentationScope::default()
        };
        let mut schema_url = source.schema_url().unwrap_or_default().to_owned();
        policy.sdk_scope(&mut scope, &mut schema_url, &mut report)?;
        scopes.push(ScopeSpans {
            scope: Some(scope),
            schema_url,
            ..ScopeSpans::default()
        });
    }
    for source in spans {
        let index = source_scopes
            .iter()
            .position(|scope| **scope == source.instrumentation_scope)
            .ok_or(OtlpSdkTraceError::InvalidSpan)?;
        let mut span = owned_span(source)?;
        policy.span(&mut span, &mut report)?;
        scopes[index].spans.push(span);
    }
    scopes.sort_by(compare_scope);
    let requests = if spans.is_empty() {
        Vec::new()
    } else {
        encode_scopes(&resource_value, &resource_schema, scopes, config)?
    };
    Ok(OwnedOtlpPolicyOutput::new(requests, report))
}

#[cfg(test)]
#[path = "traces_tests.rs"]
mod tests;
