//! Typed OpenTelemetry SDK logs with acknowledged native delivery.

use super::common::{
    SdkResource, SdkValueError, ValueBudget, attribute_nodes, nanos, owned_attributes,
    owned_log_attributes, owned_log_value, value_nodes,
};
use crate::cx::Cx;
use crate::grpc::protobuf::ProtoMessage;
use crate::observability::otel::export_policy::compare_policy_attributes;
use crate::observability::otel::{
    OtlpGrpcSignal, OwnedOtlpExportPolicy, OwnedOtlpPolicyError, OwnedOtlpPolicyOutput,
    OwnedOtlpPolicyReport, QueuedOtlpGrpcExporter,
};
use crate::observability::otlp_proto::collector::logs::ExportLogsServiceRequest;
use crate::observability::otlp_proto::common_and_resource::{InstrumentationScope, Resource};
use crate::observability::otlp_proto::logs::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry::logs::Severity;
use opentelemetry::{Array as SdkArray, InstrumentationScope as SdkScope, Value as SdkValue};
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

const MAX_RECORDS: usize = 4096;
const MAX_SCOPES: usize = 128;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 64;

/// Value-free configuration and mapping failures from the SDK log bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtlpSdkLogError {
    /// A finite limit is zero or exceeds the supported maximum.
    InvalidConfiguration,
    /// A collection, scope, body, map, array, attribute or request is oversized.
    LimitExceeded,
    /// A key is invalid, metadata keys are duplicated, or a value is unsupported.
    InvalidAttributes,
    /// A body or attribute contains a non-finite floating-point number.
    InvalidNumericValue,
    /// A supplied timestamp predates the epoch or cannot fit OTLP nanoseconds.
    InvalidTimestamp,
    /// The SDK exporter was invoked from an active native runtime context.
    NativeContext,
    /// The explicit shared policy rejected a typed mapped value.
    Policy(OwnedOtlpPolicyError),
    /// An indivisible record or complete request cannot fit the owned wire schema.
    WireEnvelopeExceeded,
}

impl OtlpSdkLogError {
    /// A stable code without resource, payload, policy or collector contents.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "otlp.sdk.logs.invalid_configuration",
            Self::LimitExceeded => "otlp.sdk.logs.limit_exceeded",
            Self::InvalidAttributes => "otlp.sdk.logs.invalid_attributes",
            Self::InvalidNumericValue => "otlp.sdk.logs.invalid_numeric_value",
            Self::InvalidTimestamp => "otlp.sdk.logs.invalid_timestamp",
            Self::NativeContext => "otlp.sdk.logs.native_context",
            Self::Policy(error) => error.code(),
            Self::WireEnvelopeExceeded => "otlp.sdk.logs.wire_envelope_exceeded",
        }
    }
}

impl fmt::Display for OtlpSdkLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for OtlpSdkLogError {}

impl From<SdkValueError> for OtlpSdkLogError {
    fn from(error: SdkValueError) -> Self {
        match error {
            SdkValueError::LimitExceeded => Self::LimitExceeded,
            SdkValueError::InvalidAttributes => Self::InvalidAttributes,
            SdkValueError::InvalidNumericValue => Self::InvalidNumericValue,
            SdkValueError::InvalidTimestamp => Self::InvalidTimestamp,
        }
    }
}

impl From<OwnedOtlpPolicyError> for OtlpSdkLogError {
    fn from(error: OwnedOtlpPolicyError) -> Self {
        Self::Policy(error)
    }
}

/// Finite limits for a complete borrowed SDK log batch.
///
/// Defaults admit 4096 records, 128 source-scope/target groups, and 4 MiB of
/// conservative input accounting and aggregate encoded output. Recursive values
/// retain the owned schema's 16-level, 128-item and 4096-byte scalar limits.
/// Every raw attribute update counts toward the 128-attribute admission bound.
/// Every record's source scope counts toward the complete traversal budget,
/// including repeated equal metadata. Group identities use bounded sorted
/// borrowed keys, without repeated SDK scope sorting during lookup.
/// Hash-map capacity is charged before iteration so sparse maps cannot hide
/// unbounded traversal behind a small entry count. The output uses at most
/// 64 requests, packing multiple scope groups and splitting between records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtlpSdkLogConfig {
    max_records: usize,
    max_scopes: usize,
    max_collection_bytes: usize,
    max_request_bytes: usize,
}

impl Default for OtlpSdkLogConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl OtlpSdkLogConfig {
    /// Finite defaults, without creating an SDK logger, provider or processor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_records: MAX_RECORDS,
            max_scopes: MAX_SCOPES,
            max_collection_bytes: MAX_BYTES,
            max_request_bytes: MAX_BYTES,
        }
    }

    /// Set the complete batch record bound, at most 4096.
    #[must_use]
    pub const fn with_max_records(mut self, limit: usize) -> Self {
        self.max_records = limit;
        self
    }

    /// Set the source-scope/target group bound, at most 128.
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

    /// Set each request's byte bound, at most 4 MiB. A smaller channel limit is
    /// still checked during atomic admission of the complete collection.
    #[must_use]
    pub const fn with_max_request_bytes(mut self, limit: usize) -> Self {
        self.max_request_bytes = limit;
        self
    }

    /// Maximum records in one SDK export call.
    #[must_use]
    pub const fn max_records(&self) -> usize {
        self.max_records
    }

    /// Maximum source-scope/target groups before any explicit policy override.
    #[must_use]
    pub const fn max_scopes(&self) -> usize {
        self.max_scopes
    }

    /// Complete input-accounting and encoded-output bound.
    #[must_use]
    pub const fn max_collection_bytes(&self) -> usize {
        self.max_collection_bytes
    }

    /// Request byte bound before a smaller caller channel limit.
    #[must_use]
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    fn validate(self) -> Result<(), OtlpSdkLogError> {
        if self.max_records == 0
            || self.max_records > MAX_RECORDS
            || self.max_scopes == 0
            || self.max_scopes > MAX_SCOPES
            || self.max_collection_bytes == 0
            || self.max_collection_bytes > MAX_BYTES
            || self.max_request_bytes == 0
            || self.max_request_bytes > MAX_BYTES
        {
            return Err(OtlpSdkLogError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// An explicitly installed SDK log exporter backed by a managed native queue.
///
/// Start `queue().spawn_queued` before the caller's SDK processor exports logs.
/// This adapter creates no provider, processor, global state, runtime or thread.
/// The SDK simple log processor synchronously waits on its emitting thread;
/// use it outside the native runtime, or install the SDK's batch processor.
/// Export refuses an active native `Cx` before admission once the SDK invokes
/// it. The simple processor may already block on its own exporter mutex before
/// that guard runs, so all simple-processor emission must stay off the native
/// runtime thread. Native async callers can use the owned log exporter directly.
///
/// The complete borrowed batch is validated and encoded before admission.
/// Success means every request received a terminal collector response, including
/// valid partial success. Rejected log counts remain visible in queue statistics;
/// they never cause whole-collection replay. Queue retry policy is request-scoped.
///
/// SDK resources and scopes keep separate schema URLs. A record's explicit
/// target replaces its scope name; an explicit shared policy can override that
/// result. Other scope fields remain intact, even for equal target names.
/// Transport resource defaults are not reapplied to encoded SDK data. Repeated
/// record attributes use last-value-wins after validating all raw updates.
/// SDK 0.32 exposes no producer attribute-drop count on log records, so policy
/// drops start from zero. Missing timestamps map to zero without reading a clock;
/// supplied severity, event name and trace correlation are preserved.
///
/// Bodies and attributes preserve nested typed maps, arrays and scalar values.
/// Shared privacy rules visit strings and map keys; bytes remain opaque and are
/// never interpreted as text. Drop a byte-containing key or omit its body when
/// binary data must not be exported. Invalid resource updates latch a static
/// failure without retaining the rejected resource contents.
///
/// `LogExporter` has no force-flush hook. The caller's provider/processor owns
/// buffered-log flush; [`Self::force_flush_queue`] observes already admitted
/// native work only. Shutdown uses its supplied timeout and seals admission for
/// every clone sharing the queue. Dedicate a queue to independently managed SDK
/// providers. Use managed drain/join for native async shutdown; upstream SDK
/// callbacks and processor/provider blocking are outside this adapter's bounds.
#[derive(Clone)]
pub struct OtlpSdkLogExporter {
    queue: QueuedOtlpGrpcExporter,
    config: OtlpSdkLogConfig,
    policy: OwnedOtlpExportPolicy,
    resource: Result<Arc<SdkResource>, OtlpSdkLogError>,
}

impl fmt::Debug for OtlpSdkLogExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpSdkLogExporter")
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

impl OtlpSdkLogExporter {
    /// Wrap a caller-managed queue with finite defaults and an empty resource.
    #[must_use]
    pub fn new(queue: QueuedOtlpGrpcExporter) -> Self {
        Self {
            queue,
            config: OtlpSdkLogConfig::new(),
            policy: OwnedOtlpExportPolicy::new(),
            resource: Ok(Arc::new(SdkResource::empty())),
        }
    }

    /// Validate all mapping limits before constructing an exporter.
    pub fn try_with_config(
        queue: QueuedOtlpGrpcExporter,
        config: OtlpSdkLogConfig,
    ) -> Result<Self, OtlpSdkLogError> {
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

    /// Shared queue for managed startup, rejection counters and async drain/join.
    #[must_use]
    pub const fn queue(&self) -> &QueuedOtlpGrpcExporter {
        &self.queue
    }

    /// Immutable validated mapper limits.
    #[must_use]
    pub const fn config(&self) -> &OtlpSdkLogConfig {
        &self.config
    }

    /// Wait for already admitted native work, bounded by `timeout`.
    ///
    /// This does not flush an SDK processor's own buffer. Call the owning
    /// provider's flush first. A pending blocking wait inside native `Cx` is
    /// refused; use the managed async drain/join path there.
    pub fn force_flush_queue(&self, timeout: Duration) -> OTelSdkResult {
        self.queue
            .force_flush_blocking(timeout)
            .map_err(|_| sdk_error("otlp.sdk.logs.flush_incomplete"))
    }
}

impl LogExporter for OtlpSdkLogExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        if Cx::current().is_some() {
            return Err(sdk_error(OtlpSdkLogError::NativeContext.code()));
        }
        self.queue
            .ensure_managed_active()
            .map_err(|_| sdk_error("otlp.sdk.logs.owner_unavailable"))?;
        let resource = self
            .resource
            .as_ref()
            .map_err(|error| sdk_error(error.code()))?;
        // LogBatch borrows the SDK's records; only compact encoded buffers are
        // transferred to the native queue. No source records are cloned here.
        let (requests, _) = map_logs(&batch, resource, &self.policy, &self.config)
            .map_err(|error| sdk_error(error.code()))?
            .into_parts();
        self.queue
            .enqueue_encoded_with_receipt(OtlpGrpcSignal::Logs, requests)
            .map_err(|_| sdk_error("otlp.sdk.logs.admission_refused"))?
            .await
            .map(|_| ())
            .map_err(|error| sdk_error(error.code()))
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.queue
            .shutdown_blocking(timeout)
            .map_err(|_| sdk_error("otlp.sdk.logs.shutdown_incomplete"))
    }

    fn event_enabled(&self, _: Severity, _: &str, _: Option<&str>) -> bool {
        // The SDK may ask on a native emitting thread before its own worker
        // performs export. Do not prematurely discard that valid batch path.
        true
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.resource = SdkResource::prepare(resource, self.config.max_collection_bytes)
            .map(Arc::new)
            .map_err(Into::into);
    }
}

fn sdk_error(code: &'static str) -> OTelSdkError {
    OTelSdkError::InternalFailure(code.to_owned())
}

struct InputScope<'a> {
    scope: &'a SdkScope,
    target: Option<&'a str>,
}

/// One canonical borrowed identity per inspected scope. All values have passed
/// the shared traversal budget before this key is constructed or compared.
struct ScopeKey<'a> {
    name: &'a str,
    version: Option<&'a str>,
    schema: Option<&'a str>,
    target: Option<&'a str>,
    attributes: Vec<(&'a str, &'a SdkValue)>,
}

impl PartialEq for ScopeKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ScopeKey<'_> {}

impl PartialOrd for ScopeKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScopeKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let metadata = (self.name, self.version, self.schema, self.target).cmp(&(
            other.name,
            other.version,
            other.schema,
            other.target,
        ));
        if metadata != Ordering::Equal {
            return metadata;
        }
        for ((left_key, left_value), (right_key, right_value)) in
            self.attributes.iter().zip(&other.attributes)
        {
            let order = left_key
                .cmp(right_key)
                .then_with(|| compare_sdk_value(left_value, right_value));
            if order != Ordering::Equal {
                return order;
            }
        }
        self.attributes.len().cmp(&other.attributes.len())
    }
}

fn sdk_value_kind(value: &SdkValue) -> u8 {
    match value {
        SdkValue::Bool(_) => 0,
        SdkValue::I64(_) => 1,
        SdkValue::F64(_) => 2,
        SdkValue::String(_) => 3,
        SdkValue::Array(SdkArray::Bool(_)) => 4,
        SdkValue::Array(SdkArray::I64(_)) => 5,
        SdkValue::Array(SdkArray::F64(_)) => 6,
        SdkValue::Array(SdkArray::String(_)) => 7,
        _ => unreachable!("scope values are validated before indexing"),
    }
}

fn compare_sdk_float(left: f64, right: f64) -> Ordering {
    // SDK equality treats the two finite zero representations as equal.
    let left = if left == 0.0 { 0.0 } else { left };
    let right = if right == 0.0 { 0.0 } else { right };
    left.total_cmp(&right)
}

fn compare_sdk_value(left: &SdkValue, right: &SdkValue) -> Ordering {
    sdk_value_kind(left)
        .cmp(&sdk_value_kind(right))
        .then_with(|| match (left, right) {
            (SdkValue::Bool(left), SdkValue::Bool(right)) => left.cmp(right),
            (SdkValue::I64(left), SdkValue::I64(right)) => left.cmp(right),
            (SdkValue::F64(left), SdkValue::F64(right)) => compare_sdk_float(*left, *right),
            (SdkValue::String(left), SdkValue::String(right)) => left.as_str().cmp(right.as_str()),
            (SdkValue::Array(SdkArray::Bool(left)), SdkValue::Array(SdkArray::Bool(right))) => {
                left.cmp(right)
            }
            (SdkValue::Array(SdkArray::I64(left)), SdkValue::Array(SdkArray::I64(right))) => {
                left.cmp(right)
            }
            (SdkValue::Array(SdkArray::F64(left)), SdkValue::Array(SdkArray::F64(right))) => left
                .iter()
                .zip(right)
                .map(|(left, right)| compare_sdk_float(*left, *right))
                .find(|order| *order != Ordering::Equal)
                .unwrap_or_else(|| left.len().cmp(&right.len())),
            (SdkValue::Array(SdkArray::String(left)), SdkValue::Array(SdkArray::String(right))) => {
                left.iter()
                    .map(|value| value.as_str())
                    .cmp(right.iter().map(|value| value.as_str()))
            }
            _ => unreachable!("equal prevalidated value kinds have matching variants"),
        })
}

struct Admitted<'a> {
    records: Vec<(&'a SdkLogRecord, usize)>,
    scopes: Vec<InputScope<'a>>,
}

fn preflight<'a>(
    batch: &'a LogBatch<'_>,
    resource: &SdkResource,
    policy: &OwnedOtlpExportPolicy,
    config: &OtlpSdkLogConfig,
) -> Result<Admitted<'a>, OtlpSdkLogError> {
    let mut budget = ValueBudget::new(config.max_collection_bytes);
    budget.reserve_owned(resource.input_bytes, resource.value_nodes)?;
    let mut records = Vec::new();
    let mut scopes = Vec::<InputScope<'a>>::new();
    let mut scope_indices = BTreeMap::new();
    for (record, scope) in batch.iter() {
        if records.len() == config.max_records {
            return Err(OtlpSdkLogError::LimitExceeded);
        }
        budget.bytes(
            std::mem::size_of::<LogRecord>()
                .saturating_add(std::mem::size_of::<(&SdkLogRecord, usize)>()),
        )?;
        budget.text(record.event_name().unwrap_or_default(), 1024)?;
        budget.text(record.severity_text().unwrap_or_default(), 1024)?;
        if let Some(time) = record.timestamp() {
            nanos(time, true)?;
        }
        if let Some(time) = record.observed_timestamp() {
            nanos(time, true)?;
        }
        if record.trace_context().is_some() {
            budget.bytes(24)?;
        }
        if let Some(body) = record.body() {
            budget.log_value(body, 1)?;
        }
        budget.log_attributes(
            record
                .attributes_iter()
                .map(|(key, value)| (key.as_str(), value)),
        )?;
        let target = record.target().map(|target| target.as_ref());
        if let Some(target) = target {
            budget.text(target, 1024)?;
        }

        // Charge every inspection, including repeated equal metadata, before
        // constructing a sorted borrowed lookup key. SDK scope equality is not
        // used: it would re-sort attributes for each candidate comparison.
        budget.bytes(
            std::mem::size_of::<ScopeLogs>()
                .saturating_add(std::mem::size_of::<InstrumentationScope>())
                .saturating_add(std::mem::size_of::<ScopeKey<'_>>()),
        )?;
        budget.text(scope.name(), 1024)?;
        budget.text(scope.version().unwrap_or_default(), 1024)?;
        budget.text(scope.schema_url().unwrap_or_default(), 2048)?;
        budget.attributes(scope.attributes().map(|kv| (kv.key.as_str(), &kv.value)))?;
        let mut attributes: Vec<_> = scope
            .attributes()
            .map(|kv| (kv.key.as_str(), &kv.value))
            .collect();
        attributes.sort_by(|left, right| left.0.cmp(right.0));
        let key = ScopeKey {
            name: scope.name(),
            version: scope.version(),
            schema: scope.schema_url(),
            target,
            attributes,
        };
        let index = if let Some(index) = scope_indices.get(&key) {
            *index
        } else {
            if scopes.len() == config.max_scopes {
                return Err(OtlpSdkLogError::LimitExceeded);
            }
            let index = scopes.len();
            scope_indices.insert(key, index);
            scopes.push(InputScope { scope, target });
            index
        };
        records.push((record, index));
    }
    let (resource_extra, scope_extra) = policy.sdk_metadata_reserve();
    budget.bytes(resource_extra.saturating_add(scope_extra.saturating_mul(scopes.len())))?;
    Ok(Admitted { records, scopes })
}

fn owned_record(input: &SdkLogRecord) -> Result<LogRecord, OtlpSdkLogError> {
    Ok(LogRecord {
        time_unix_nano: input
            .timestamp()
            .map(|time| nanos(time, true))
            .transpose()?
            .unwrap_or(0),
        observed_time_unix_nano: input
            .observed_timestamp()
            .map(|time| nanos(time, true))
            .transpose()?
            .unwrap_or(0),
        severity_number: input
            .severity_number()
            .map_or(0, |severity| severity as i32),
        severity_text: input.severity_text().unwrap_or_default().to_owned(),
        event_name: input.event_name().unwrap_or_default().to_owned(),
        body: input.body().map(owned_log_value).transpose()?,
        attributes: owned_log_attributes(
            input
                .attributes_iter()
                .map(|(key, value)| (key.as_str(), value)),
        )?,
        trace_id: input
            .trace_context()
            .map_or_else(Vec::new, |context| context.trace_id.to_bytes().to_vec()),
        span_id: input
            .trace_context()
            .map_or_else(Vec::new, |context| context.span_id.to_bytes().to_vec()),
        flags: input
            .trace_context()
            .and_then(|context| context.trace_flags)
            .map_or(0, |flags| u32::from(flags.to_u8())),
        ..LogRecord::default()
    })
}

fn compare_scope(left: &ScopeLogs, right: &ScopeLogs) -> Ordering {
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

fn append_request(
    resource: &Resource,
    resource_schema: &str,
    scopes: Vec<ScopeLogs>,
    requests: &mut Vec<Vec<u8>>,
    encoded_bytes: &mut usize,
    config: &OtlpSdkLogConfig,
) -> Result<(), OtlpSdkLogError> {
    if scopes.is_empty() {
        return Ok(());
    }
    if requests.len() == MAX_REQUESTS {
        return Err(OtlpSdkLogError::LimitExceeded);
    }
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(resource.clone()),
            schema_url: resource_schema.to_owned(),
            scope_logs: scopes,
            ..ResourceLogs::default()
        }],
        ..ExportLogsServiceRequest::default()
    };
    let encoded = request
        .encode_to_bytes(crate::observability::otel::otlp_request_limits(
            config.max_request_bytes,
        ))
        .map_err(|_| OtlpSdkLogError::WireEnvelopeExceeded)?;
    *encoded_bytes = encoded_bytes
        .checked_add(encoded.len())
        .filter(|bytes| *bytes <= config.max_collection_bytes)
        .ok_or(OtlpSdkLogError::LimitExceeded)?;
    requests.push(encoded.to_vec());
    Ok(())
}

fn encode_scopes(
    resource: &Resource,
    resource_schema: &str,
    scopes: Vec<ScopeLogs>,
    config: &OtlpSdkLogConfig,
) -> Result<Vec<Vec<u8>>, OtlpSdkLogError> {
    let limits = crate::observability::otel::otlp_request_limits(config.max_request_bytes);
    let resource_bytes = resource
        .encode_to_bytes(limits)
        .map_err(|_| OtlpSdkLogError::WireEnvelopeExceeded)?
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
            .ok_or(OtlpSdkLogError::WireEnvelopeExceeded)?;
        let scope_bytes = scope_value
            .encode_to_bytes(limits)
            .map_err(|_| OtlpSdkLogError::WireEnvelopeExceeded)?
            .len()
            .saturating_add(scope.schema_url.len())
            .saturating_add(24);
        let scope_nodes = attribute_nodes(&scope_value.attributes);
        let scope_items = scope_nodes.saturating_mul(2).saturating_add(1);
        let mut new_scope = true;
        for record in std::mem::take(&mut scope.log_records) {
            let record_bytes = record
                .encode_to_bytes(limits)
                .map_err(|_| OtlpSdkLogError::WireEnvelopeExceeded)?
                .len()
                .saturating_add(6);
            let nodes = attribute_nodes(&record.attributes)
                .saturating_add(record.body.as_ref().map_or(0, value_nodes));
            let items = nodes.saturating_mul(2).saturating_add(1);
            let costs = |new_scope: bool| {
                (
                    record_bytes.saturating_add(if new_scope { scope_bytes } else { 0 }),
                    nodes.saturating_add(if new_scope { scope_nodes } else { 0 }),
                    items.saturating_add(if new_scope { scope_items } else { 0 }),
                )
            };
            let (bytes, nodes, items) = costs(new_scope);
            if !batch.is_empty()
                && (batch_bytes.saturating_add(bytes) > config.max_request_bytes
                    || batch_nodes.saturating_add(nodes) > 4096
                    || batch_items.saturating_add(items) > 32_768
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
            let (bytes, nodes, items) = costs(new_scope);
            if batch_bytes.saturating_add(bytes) > config.max_request_bytes
                || batch_nodes.saturating_add(nodes) > 4096
                || batch_items.saturating_add(items) > 32_768
            {
                return Err(OtlpSdkLogError::WireEnvelopeExceeded);
            }
            batch_bytes = batch_bytes.saturating_add(bytes);
            batch_nodes = batch_nodes.saturating_add(nodes);
            batch_items = batch_items.saturating_add(items);
            if new_scope {
                batch.push(ScopeLogs {
                    scope: scope.scope.clone(),
                    schema_url: scope.schema_url.clone(),
                    ..ScopeLogs::default()
                });
                new_scope = false;
            }
            batch
                .last_mut()
                .ok_or(OtlpSdkLogError::WireEnvelopeExceeded)?
                .log_records
                .push(record);
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

fn map_logs(
    batch: &LogBatch<'_>,
    resource: &SdkResource,
    policy: &OwnedOtlpExportPolicy,
    config: &OtlpSdkLogConfig,
) -> Result<OwnedOtlpPolicyOutput<Vec<Vec<u8>>>, OtlpSdkLogError> {
    let admitted = preflight(batch, resource, policy, config)?;
    let mut report = OwnedOtlpPolicyReport::default();
    let mut resource_value = resource.resource.clone();
    let mut resource_schema = resource.schema_url.clone();
    policy.sdk_resource(&mut resource_value, &mut resource_schema, &mut report)?;
    let mut scopes = Vec::with_capacity(admitted.scopes.len());
    for source in &admitted.scopes {
        let mut scope = InstrumentationScope {
            name: source.target.unwrap_or(source.scope.name()).to_owned(),
            version: source.scope.version().unwrap_or_default().to_owned(),
            attributes: owned_attributes(
                source
                    .scope
                    .attributes()
                    .map(|kv| (kv.key.as_str(), &kv.value)),
            )?,
            ..InstrumentationScope::default()
        };
        let mut schema_url = source.scope.schema_url().unwrap_or_default().to_owned();
        policy.sdk_scope(&mut scope, &mut schema_url, &mut report)?;
        scopes.push(ScopeLogs {
            scope: Some(scope),
            schema_url,
            ..ScopeLogs::default()
        });
    }
    for (source, index) in admitted.records {
        let mut record = owned_record(source)?;
        policy.log(&mut record, &mut report)?;
        scopes[index].log_records.push(record);
    }
    scopes.sort_by(compare_scope);
    let requests = if scopes.is_empty() {
        Vec::new()
    } else {
        encode_scopes(&resource_value, &resource_schema, scopes, config)?
    };
    Ok(OwnedOtlpPolicyOutput::new(requests, report))
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
