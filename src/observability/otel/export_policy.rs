//! Opt-in policy shared by the owned metrics, traces, and logs mappers.
//!
//! This layer visits bounded owned models, never encoded protobuf. It retains
//! the established `PrivacyConfig` matching/redaction behavior and leaves the
//! existing collection entry points unchanged.

use super::{
    OWNED_OTLP_MAX_ATTRIBUTE_KEY_BYTES, OWNED_OTLP_MAX_ATTRIBUTE_VALUE_BYTES,
    OWNED_OTLP_MAX_ATTRIBUTES, OtlpLogKeyValueInput, OtlpLogRecordInput, OtlpTraceSpanInput,
    OwnedOtlpLogCollection, OwnedOtlpLogError, OwnedOtlpLogs, OwnedOtlpMetrics,
    OwnedOtlpMetricsError, OwnedOtlpTraceCollection, OwnedOtlpTraceError, OwnedOtlpTraces,
    PrivacyConfig,
};
use crate::grpc::protobuf::ProtoMessage;
use crate::observability::otlp_proto::common_and_resource::{
    AnyValue, AnyValueValue, InstrumentationScope, KeyValue, Resource,
};
use crate::observability::otlp_proto::metrics::{Exemplar, Metric, MetricData};
use std::fmt;

const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_PRIVACY_RULES_PER_KIND: usize = 128;
const MAX_PII_PATTERNS: usize = 32;
const MAX_POLICY_PATTERN_BYTES: usize = 1024;
const MAX_COMPILED_PATTERN_BYTES: usize = 256 * 1024;
const MAX_SCHEMA_URL_BYTES: usize = 2048;

/// Value-free failure from policy admission or owned signal collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnedOtlpPolicyError {
    /// A policy field is empty, duplicated, oversized, or otherwise invalid.
    InvalidConfiguration,
    /// A privacy pattern is invalid or exceeds its finite compilation budget.
    InvalidPrivacyPattern,
    /// Merged metadata or a filtered collection exceeds its admitted envelope.
    LimitExceeded,
    /// Filtering would collapse distinct points of one metric into one series.
    MetricSeriesCollision,
    /// The existing metrics mapper rejected the collection.
    Metrics(OwnedOtlpMetricsError),
    /// The existing trace mapper rejected the collection.
    Traces(OwnedOtlpTraceError),
    /// The existing log mapper rejected the collection.
    Logs(OwnedOtlpLogError),
}

impl OwnedOtlpPolicyError {
    /// A stable code containing no policy, resource, or telemetry values.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "otlp.policy.invalid_configuration",
            Self::InvalidPrivacyPattern => "otlp.policy.invalid_privacy_pattern",
            Self::LimitExceeded => "otlp.policy.limit_exceeded",
            Self::MetricSeriesCollision => "otlp.policy.metric_series_collision",
            Self::Metrics(error) => error.code(),
            Self::Traces(error) => error.code(),
            Self::Logs(error) => error.code(),
        }
    }
}

impl fmt::Display for OwnedOtlpPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for OwnedOtlpPolicyError {}

impl From<OwnedOtlpMetricsError> for OwnedOtlpPolicyError {
    fn from(error: OwnedOtlpMetricsError) -> Self {
        Self::Metrics(error)
    }
}

impl From<OwnedOtlpTraceError> for OwnedOtlpPolicyError {
    fn from(error: OwnedOtlpTraceError) -> Self {
        Self::Traces(error)
    }
}

impl From<OwnedOtlpLogError> for OwnedOtlpPolicyError {
    fn from(error: OwnedOtlpLogError) -> Self {
        Self::Logs(error)
    }
}

/// Saturating, value-free counts of policy effects in one logical collection.
///
/// Resource and scope effects are counted once even when metadata is repeated
/// in several requests. Producer-reported drops and unsampled spans remain in
/// the original collection result; they are never counted again here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnedOtlpPolicyReport {
    /// Top-level resource, scope, metric-point, span, event, link, or log
    /// attributes removed by key policy. Corresponding OTLP entity drop counts
    /// are increased where the schema provides such a field.
    pub dropped_attributes: usize,
    /// String values whose contents changed. A sensitive schema URL or W3C
    /// tracestate is cleared as one value instead of emitting invalid syntax.
    pub redacted_values: usize,
    /// Nested key/value-list entries removed inside typed log values,
    /// including structured resources and record attributes as well as bodies.
    /// OTLP has no drop-count field for those nested lists.
    pub dropped_log_body_fields: usize,
}

/// A normal collection/transport result together with its policy effects.
///
/// `Debug` intentionally excludes the wrapped payload, even when `T: Debug`.
#[derive(Clone)]
#[must_use]
pub struct OwnedOtlpPolicyOutput<T> {
    output: T,
    report: OwnedOtlpPolicyReport,
}

impl<T> OwnedOtlpPolicyOutput<T> {
    pub(super) const fn new(output: T, report: OwnedOtlpPolicyReport) -> Self {
        Self { output, report }
    }

    /// The mapper or transport result, including its original receipt counts.
    #[must_use]
    pub const fn output(&self) -> &T {
        &self.output
    }

    /// Count-only filtering effects for this collection.
    #[must_use]
    pub const fn report(&self) -> &OwnedOtlpPolicyReport {
        &self.report
    }

    /// Recover the result and its filtering report without copying payloads.
    #[must_use]
    pub fn into_parts(self) -> (T, OwnedOtlpPolicyReport) {
        (self.output, self.report)
    }
}

impl<T> fmt::Debug for OwnedOtlpPolicyOutput<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedOtlpPolicyOutput")
            .field("output", &"[REDACTED]")
            .field("report", &self.report)
            .finish()
    }
}

/// Immutable, bounded resource/scope and privacy policy for owned OTLP signals.
///
/// The default retains each mapper's scope, schema, and payload bytes. Explicit
/// resource attributes override caller attributes with the same key; merged
/// attributes and scope attributes are sorted and filtered using the supplied
/// [`PrivacyConfig`]. A merged entity must fit its mapper's attribute limit.
///
/// Strings are scanned in resource/scope values, metric labels, span/event
/// names and attributes, links, status messages, tracestate, and typed log
/// values recursively. Attribute keys use drop/allow rules and are not renamed.
/// Numeric values, IDs, and opaque bytes are preserved. In particular, bytes
/// are **not** interpreted as text: callers must omit binary secrets or drop
/// their enclosing key. Fixed runtime metric names/units retain their meaning.
///
/// Configuration is limited to 64 KiB of text, 128 resource/scope attributes,
/// 128 rules per key-rule list, and 32 regex patterns of at most 1024 bytes.
/// Each compiled pattern has a 256 KiB expression and DFA-cache budget. The
/// accepted `PrivacyConfig` scanner selection and matching semantics are
/// reused; this policy never enables an experimental scanner path.
///
/// Oversized values and ambiguous post-filter metric series are rejected,
/// rather than silently truncating or combining cumulative measurements.
#[derive(Clone, Default)]
pub struct OwnedOtlpExportPolicy {
    scope: Option<(String, String)>,
    schema_url: Option<String>,
    resource_attributes: Vec<(String, String)>,
    scope_attributes: Vec<(String, String)>,
    privacy: PrivacyConfig,
}

impl fmt::Debug for OwnedOtlpExportPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedOtlpExportPolicy")
            .field("scope_override", &self.scope.is_some())
            .field("schema_override", &self.schema_url.is_some())
            .field("resource_attributes", &self.resource_attributes.len())
            .field("scope_attributes", &self.scope_attributes.len())
            .field("privacy", &"[REDACTED]")
            .finish()
    }
}

impl OwnedOtlpExportPolicy {
    /// Preserve the existing mapper configuration and apply no filtering.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override instrumentation scope identity for every signal.
    pub fn try_with_scope(
        mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, OwnedOtlpPolicyError> {
        let name = name.into();
        let version = version.into();
        if name.is_empty() || name.len() > 1024 || version.len() > 1024 {
            return Err(OwnedOtlpPolicyError::InvalidConfiguration);
        }
        self.scope = Some((compact(name), compact(version)));
        self.validate_size()?;
        Ok(self)
    }

    /// Override both resource and instrumentation-scope schema URLs. An empty
    /// value explicitly clears an inherited schema URL.
    pub fn try_with_schema_url(
        mut self,
        schema_url: impl Into<String>,
    ) -> Result<Self, OwnedOtlpPolicyError> {
        let schema_url = schema_url.into();
        if schema_url.len() > MAX_SCHEMA_URL_BYTES {
            return Err(OwnedOtlpPolicyError::InvalidConfiguration);
        }
        self.schema_url = Some(compact(schema_url));
        self.validate_size()?;
        Ok(self)
    }

    /// Replace policy resource attributes. Keys must be unique and nonempty;
    /// a matching caller resource key is overridden before privacy filtering.
    pub fn try_with_resource_attributes(
        mut self,
        attributes: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, OwnedOtlpPolicyError> {
        self.resource_attributes = admit_attributes(attributes)?;
        self.validate_size()?;
        Ok(self)
    }

    /// Replace instrumentation-scope attributes for this explicit policy.
    pub fn try_with_scope_attributes(
        mut self,
        attributes: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, OwnedOtlpPolicyError> {
        self.scope_attributes = admit_attributes(attributes)?;
        self.validate_size()?;
        Ok(self)
    }

    /// Freeze and validate the current public privacy configuration. Patterns
    /// are recompiled once so direct legacy-field mutations cannot leave a
    /// stale cache or defer an invalid expression until export time.
    pub fn try_with_privacy(
        mut self,
        mut privacy: PrivacyConfig,
    ) -> Result<Self, OwnedOtlpPolicyError> {
        for rules in [
            &privacy.drop_attributes,
            &privacy.drop_labels,
            &privacy.allowed_fields,
        ] {
            if rules.len() > MAX_PRIVACY_RULES_PER_KIND
                || rules
                    .iter()
                    .any(|rule| rule.is_empty() || rule.len() > MAX_POLICY_PATTERN_BYTES)
            {
                return Err(OwnedOtlpPolicyError::InvalidConfiguration);
            }
        }
        if privacy.pii_patterns.len() > MAX_PII_PATTERNS
            || privacy
                .pii_patterns
                .iter()
                .any(|pattern| pattern.len() > MAX_POLICY_PATTERN_BYTES)
        {
            return Err(OwnedOtlpPolicyError::InvalidConfiguration);
        }
        // Check aggregate text before compiling or copying any pattern.
        privacy.compiled_pii_patterns.clear();
        self.privacy = privacy;
        self.validate_size()?;
        for rules in [
            &mut self.privacy.drop_attributes,
            &mut self.privacy.drop_labels,
            &mut self.privacy.allowed_fields,
            &mut self.privacy.pii_patterns,
        ] {
            for rule in rules.iter_mut() {
                *rule = compact(std::mem::take(rule));
            }
            *rules = std::mem::take(rules).into_boxed_slice().into_vec();
        }
        self.privacy.compiled_pii_patterns = self
            .privacy
            .pii_patterns
            .iter()
            .map(|pattern| {
                regex::RegexBuilder::new(pattern)
                    .size_limit(MAX_COMPILED_PATTERN_BYTES)
                    .dfa_size_limit(MAX_COMPILED_PATTERN_BYTES)
                    .build()
                    .map_err(|_| OwnedOtlpPolicyError::InvalidPrivacyPattern)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self)
    }

    fn validate_size(&self) -> Result<(), OwnedOtlpPolicyError> {
        let mut bytes = 0usize;
        let mut add = |len: usize| {
            bytes = bytes
                .checked_add(len)
                .filter(|bytes| *bytes <= MAX_POLICY_BYTES)
                .ok_or(OwnedOtlpPolicyError::LimitExceeded)?;
            Ok::<(), OwnedOtlpPolicyError>(())
        };
        if let Some((name, version)) = &self.scope {
            add(name.len())?;
            add(version.len())?;
        }
        if let Some(schema_url) = &self.schema_url {
            add(schema_url.len())?;
        }
        for (key, value) in self
            .resource_attributes
            .iter()
            .chain(&self.scope_attributes)
        {
            add(key.len())?;
            add(value.len())?;
        }
        for rule in self
            .privacy
            .drop_attributes
            .iter()
            .chain(&self.privacy.drop_labels)
            .chain(&self.privacy.allowed_fields)
            .chain(&self.privacy.pii_patterns)
        {
            add(rule.len())?;
        }
        Ok(())
    }

    fn redact(
        &self,
        key: &str,
        value: &mut String,
        limit: usize,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        if !self.privacy.auto_pii_detection && self.privacy.pii_patterns.is_empty() {
            return Ok(());
        }
        let filtered = self.privacy.redact_pii(key, value);
        if filtered.len() > limit {
            return Err(OwnedOtlpPolicyError::LimitExceeded);
        }
        if filtered != *value {
            *value = filtered;
            report.redacted_values = report.redacted_values.saturating_add(1);
        }
        Ok(())
    }

    fn redact_opaque_text(
        &self,
        key: &str,
        value: &mut String,
        report: &mut OwnedOtlpPolicyReport,
    ) {
        if !value.is_empty()
            && (!self.privacy.pii_patterns.is_empty() || self.privacy.auto_pii_detection)
            && self.privacy.redact_pii(key, value) != *value
        {
            value.clear();
            report.redacted_values = report.redacted_values.saturating_add(1);
        }
    }

    fn attributes(
        &self,
        attributes: &mut Vec<KeyValue>,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<u32, OwnedOtlpPolicyError> {
        let before = attributes.len();
        attributes.retain(|attribute| !self.privacy.should_drop_field(&attribute.key));
        let dropped = before.saturating_sub(attributes.len());
        report.dropped_attributes = report.dropped_attributes.saturating_add(dropped);
        for attribute in attributes {
            if let Some(value) = &mut attribute.value {
                self.value(&attribute.key, value, report)?;
            }
        }
        Ok(u32::try_from(dropped).unwrap_or(u32::MAX))
    }

    // Inputs have already passed the existing depth, node, width and byte
    // preflight. Policy values contain only bounded scalar strings.
    fn value(
        &self,
        key: &str,
        value: &mut AnyValue,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        match value.value.as_mut() {
            Some(AnyValueValue::String(value)) => {
                self.redact(key, value, OWNED_OTLP_MAX_ATTRIBUTE_VALUE_BYTES, report)?;
            }
            Some(AnyValueValue::Array(array)) => {
                for value in &mut array.values {
                    self.value(key, value, report)?;
                }
            }
            Some(AnyValueValue::KeyValueList(list)) => {
                let before = list.values.len();
                list.values
                    .retain(|entry| !self.privacy.should_drop_field(&entry.key));
                report.dropped_log_body_fields = report
                    .dropped_log_body_fields
                    .saturating_add(before.saturating_sub(list.values.len()));
                for entry in &mut list.values {
                    if let Some(value) = &mut entry.value {
                        self.value(&entry.key, value, report)?;
                    }
                }
            }
            // Bytes and numeric values retain their original OTLP type.
            Some(
                AnyValueValue::Bool(_)
                | AnyValueValue::Int(_)
                | AnyValueValue::Double(_)
                | AnyValueValue::Bytes(_)
                | AnyValueValue::StringIndex(_),
            )
            | None => {}
        }
        Ok(())
    }

    fn metadata(
        &self,
        mut resource: Resource,
        mut scope: InstrumentationScope,
        schema_url: &str,
        attribute_limit: usize,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<Metadata, OwnedOtlpPolicyError> {
        for (key, value) in &self.resource_attributes {
            match resource
                .attributes
                .binary_search_by(|entry| entry.key.cmp(key))
            {
                Ok(index) => resource.attributes[index] = string_attribute(key, value),
                Err(index) => {
                    if resource.attributes.len() == attribute_limit {
                        return Err(OwnedOtlpPolicyError::LimitExceeded);
                    }
                    resource
                        .attributes
                        .insert(index, string_attribute(key, value));
                }
            }
        }
        if self.scope_attributes.len() > attribute_limit {
            return Err(OwnedOtlpPolicyError::LimitExceeded);
        }
        if let Some((name, version)) = &self.scope {
            scope.name.clone_from(name);
            scope.version.clone_from(version);
        }
        scope.attributes = self
            .scope_attributes
            .iter()
            .map(|(key, value)| string_attribute(key, value))
            .collect();
        resource.dropped_attributes_count = resource
            .dropped_attributes_count
            .saturating_add(self.attributes(&mut resource.attributes, report)?);
        scope.dropped_attributes_count = scope
            .dropped_attributes_count
            .saturating_add(self.attributes(&mut scope.attributes, report)?);
        self.redact("scope.name", &mut scope.name, 1024, report)?;
        self.redact("scope.version", &mut scope.version, 1024, report)?;
        let mut schema_url = self.schema_url.as_deref().unwrap_or(schema_url).to_owned();
        self.redact_opaque_text("schema_url", &mut schema_url, report);
        Ok(Metadata {
            resource,
            scope,
            schema_url,
        })
    }

    /// Apply policy to a prevalidated SDK resource without changing a separate
    /// instrumentation-scope schema URL.
    pub(super) fn sdk_resource(
        &self,
        resource: &mut Resource,
        schema_url: &mut String,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        merge_sdk_attributes(&mut resource.attributes, &self.resource_attributes)?;
        resource.dropped_attributes_count = resource
            .dropped_attributes_count
            .saturating_add(self.attributes(&mut resource.attributes, report)?);
        if let Some(override_url) = &self.schema_url {
            schema_url.clone_from(override_url);
        }
        self.redact_opaque_text("resource.schema_url", schema_url, report);
        Ok(())
    }

    /// Preserve SDK scope metadata unless the caller explicitly overrides it.
    pub(super) fn sdk_scope(
        &self,
        scope: &mut InstrumentationScope,
        schema_url: &mut String,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        if let Some((name, version)) = &self.scope {
            scope.name.clone_from(name);
            scope.version.clone_from(version);
        }
        merge_sdk_attributes(&mut scope.attributes, &self.scope_attributes)?;
        scope.dropped_attributes_count = scope
            .dropped_attributes_count
            .saturating_add(self.attributes(&mut scope.attributes, report)?);
        self.redact("scope.name", &mut scope.name, 1024, report)?;
        self.redact("scope.version", &mut scope.version, 1024, report)?;
        if let Some(override_url) = &self.schema_url {
            schema_url.clone_from(override_url);
        }
        self.redact_opaque_text("scope.schema_url", schema_url, report);
        Ok(())
    }

    /// Conservative additional metadata ownership, admitted before copying SDK
    /// input. Original metadata is charged separately even if an override wins.
    pub(super) fn sdk_metadata_reserve(&self) -> (usize, usize) {
        let attributes = |values: &[(String, String)]| {
            values.iter().fold(0usize, |bytes, (key, value)| {
                bytes
                    .saturating_add(key.len())
                    .saturating_add(value.len())
                    .saturating_add(std::mem::size_of::<KeyValue>())
                    .saturating_add(std::mem::size_of::<AnyValue>())
            })
        };
        let schema_bytes = self.schema_url.as_ref().map_or(0, String::len);
        let resource = attributes(&self.resource_attributes).saturating_add(schema_bytes);
        let scope = attributes(&self.scope_attributes)
            .saturating_add(schema_bytes)
            .saturating_add(self.scope.as_ref().map_or(0, |(name, version)| {
                name.len().saturating_add(version.len())
            }));
        (resource, scope)
    }

    pub(super) fn metric(
        &self,
        metric: &mut Metric,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        self.attributes(&mut metric.metadata, report)?;
        match metric.data.as_mut() {
            Some(MetricData::Gauge(data)) => self.metric_points(
                data.data_points
                    .iter_mut()
                    .map(|point| (&mut point.attributes, Some(&mut point.exemplars))),
                report,
            ),
            Some(MetricData::Sum(data)) => self.metric_points(
                data.data_points
                    .iter_mut()
                    .map(|point| (&mut point.attributes, Some(&mut point.exemplars))),
                report,
            ),
            Some(MetricData::Histogram(data)) => self.metric_points(
                data.data_points
                    .iter_mut()
                    .map(|point| (&mut point.attributes, Some(&mut point.exemplars))),
                report,
            ),
            Some(MetricData::ExponentialHistogram(data)) => self.metric_points(
                data.data_points
                    .iter_mut()
                    .map(|point| (&mut point.attributes, Some(&mut point.exemplars))),
                report,
            ),
            Some(MetricData::Summary(data)) => self.metric_points(
                data.data_points
                    .iter_mut()
                    .map(|point| (&mut point.attributes, None)),
                report,
            ),
            None => Ok(()),
        }
    }

    fn metric_points<'a>(
        &self,
        points: impl Iterator<Item = (&'a mut Vec<KeyValue>, Option<&'a mut Vec<Exemplar>>)>,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        let mut identities = Vec::<&[KeyValue]>::new();
        for (attributes, exemplars) in points {
            self.attributes(attributes, report)?;
            if let Some(exemplars) = exemplars {
                for exemplar in exemplars {
                    self.attributes(&mut exemplar.filtered_attributes, report)?;
                }
            }
            identities.push(attributes.as_slice());
        }
        identities.sort_by(|left, right| compare_policy_attributes(left, right));
        if identities
            .windows(2)
            .any(|pair| compare_policy_attributes(pair[0], pair[1]).is_eq())
        {
            return Err(OwnedOtlpPolicyError::MetricSeriesCollision);
        }
        Ok(())
    }

    fn span(
        &self,
        span: &mut crate::observability::otlp_proto::trace::Span,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        self.redact(
            "span.name",
            &mut span.name,
            super::OWNED_OTLP_MAX_SPAN_NAME_BYTES,
            report,
        )?;
        self.redact_opaque_text("trace_state", &mut span.trace_state, report);
        span.dropped_attributes_count = span
            .dropped_attributes_count
            .saturating_add(self.attributes(&mut span.attributes, report)?);
        if let Some(status) = &mut span.status {
            self.redact(
                "status.message",
                &mut status.message,
                OWNED_OTLP_MAX_ATTRIBUTE_VALUE_BYTES,
                report,
            )?;
        }
        for event in &mut span.events {
            self.redact(
                "event.name",
                &mut event.name,
                super::OWNED_OTLP_MAX_EVENT_NAME_BYTES,
                report,
            )?;
            event.dropped_attributes_count = event
                .dropped_attributes_count
                .saturating_add(self.attributes(&mut event.attributes, report)?);
        }
        for link in &mut span.links {
            self.redact_opaque_text("trace_state", &mut link.trace_state, report);
            link.dropped_attributes_count = link
                .dropped_attributes_count
                .saturating_add(self.attributes(&mut link.attributes, report)?);
        }
        Ok(())
    }

    fn log(
        &self,
        record: &mut crate::observability::otlp_proto::logs::LogRecord,
        report: &mut OwnedOtlpPolicyReport,
    ) -> Result<(), OwnedOtlpPolicyError> {
        record.dropped_attributes_count = record
            .dropped_attributes_count
            .saturating_add(self.attributes(&mut record.attributes, report)?);
        if let Some(body) = &mut record.body {
            self.value("body", body, report)?;
        }
        self.redact(
            "severity_text",
            &mut record.severity_text,
            super::OWNED_OTLP_MAX_LOG_SEVERITY_TEXT_BYTES,
            report,
        )?;
        self.redact(
            "event_name",
            &mut record.event_name,
            super::OWNED_OTLP_MAX_LOG_EVENT_NAME_BYTES,
            report,
        )?;
        Ok(())
    }
}

fn compact(value: String) -> String {
    value.into_boxed_str().into_string()
}

fn merge_sdk_attributes(
    attributes: &mut Vec<KeyValue>,
    overrides: &[(String, String)],
) -> Result<(), OwnedOtlpPolicyError> {
    for (key, value) in overrides {
        match attributes.binary_search_by(|attribute| attribute.key.cmp(key)) {
            Ok(index) => attributes[index] = string_attribute(key, value),
            Err(index) => {
                if attributes.len() >= OWNED_OTLP_MAX_ATTRIBUTES {
                    return Err(OwnedOtlpPolicyError::LimitExceeded);
                }
                attributes.insert(index, string_attribute(key, value));
            }
        }
    }
    Ok(())
}

/// Compare complete typed attribute identities without serializing or cloning.
/// Input sets are sorted and validated; floating zero has one semantic identity.
pub(super) fn compare_policy_attributes(
    left: &[KeyValue],
    right: &[KeyValue],
) -> std::cmp::Ordering {
    for (left, right) in left.iter().zip(right) {
        let order = left
            .key
            .cmp(&right.key)
            .then_with(|| compare_policy_values(left.value.as_ref(), right.value.as_ref()));
        if !order.is_eq() {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_policy_values(left: Option<&AnyValue>, right: Option<&AnyValue>) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let left = left.and_then(|value| value.value.as_ref());
    let right = right.and_then(|value| value.value.as_ref());
    let tag = |value: Option<&AnyValueValue>| match value {
        None => 0,
        Some(AnyValueValue::String(_)) => 1,
        Some(AnyValueValue::Bool(_)) => 2,
        Some(AnyValueValue::Int(_)) => 3,
        Some(AnyValueValue::Double(_)) => 4,
        Some(AnyValueValue::Array(_)) => 5,
        Some(AnyValueValue::KeyValueList(_)) => 6,
        Some(AnyValueValue::Bytes(_)) => 7,
        Some(AnyValueValue::StringIndex(_)) => 8,
    };
    match (left, right) {
        (Some(AnyValueValue::String(left)), Some(AnyValueValue::String(right))) => left.cmp(right),
        (Some(AnyValueValue::Bool(left)), Some(AnyValueValue::Bool(right))) => left.cmp(right),
        (Some(AnyValueValue::Int(left)), Some(AnyValueValue::Int(right))) => left.cmp(right),
        (Some(AnyValueValue::Double(left)), Some(AnyValueValue::Double(right))) => {
            if left == right {
                Ordering::Equal
            } else {
                left.total_cmp(right)
            }
        }
        (Some(AnyValueValue::Array(left)), Some(AnyValueValue::Array(right))) => {
            for (left, right) in left.values.iter().zip(&right.values) {
                let order = compare_policy_values(Some(left), Some(right));
                if !order.is_eq() {
                    return order;
                }
            }
            left.values.len().cmp(&right.values.len())
        }
        (Some(AnyValueValue::KeyValueList(left)), Some(AnyValueValue::KeyValueList(right))) => {
            compare_policy_attributes(&left.values, &right.values)
        }
        (Some(AnyValueValue::Bytes(left)), Some(AnyValueValue::Bytes(right))) => left.cmp(right),
        (Some(AnyValueValue::StringIndex(left)), Some(AnyValueValue::StringIndex(right))) => {
            left.cmp(right)
        }
        _ => tag(left).cmp(&tag(right)),
    }
}

fn admit_attributes(
    attributes: impl IntoIterator<Item = (String, String)>,
) -> Result<Vec<(String, String)>, OwnedOtlpPolicyError> {
    let mut admitted = Vec::new();
    let mut bytes = 0usize;
    for (key, value) in attributes {
        if admitted.len() == OWNED_OTLP_MAX_ATTRIBUTES
            || key.is_empty()
            || key.len() > OWNED_OTLP_MAX_ATTRIBUTE_KEY_BYTES
            || value.len() > OWNED_OTLP_MAX_ATTRIBUTE_VALUE_BYTES
        {
            return Err(OwnedOtlpPolicyError::InvalidConfiguration);
        }
        bytes = bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .filter(|bytes| *bytes <= MAX_POLICY_BYTES)
            .ok_or(OwnedOtlpPolicyError::LimitExceeded)?;
        admitted.push((compact(key), compact(value)));
    }
    admitted.sort_unstable();
    if admitted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(OwnedOtlpPolicyError::InvalidConfiguration);
    }
    Ok(admitted.into_boxed_slice().into_vec())
}

fn string_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue {
            value: Some(AnyValueValue::String(value.to_owned())),
            ..AnyValue::default()
        }),
        ..KeyValue::default()
    }
}

struct Metadata {
    resource: Resource,
    scope: InstrumentationScope,
    schema_url: String,
}

impl Metadata {
    fn bytes(&self) -> usize {
        attributes_bytes(&self.resource.attributes)
            .saturating_add(attributes_bytes(&self.scope.attributes))
            .saturating_add(self.scope.name.len())
            .saturating_add(self.scope.version.len())
            .saturating_add(self.schema_url.len().saturating_mul(2))
    }

    fn nodes(&self) -> usize {
        attributes_nodes(&self.resource.attributes)
            .saturating_add(attributes_nodes(&self.scope.attributes))
    }
}

fn attributes_bytes(attributes: &[KeyValue]) -> usize {
    attributes.iter().fold(0usize, |bytes, entry| {
        bytes
            .saturating_add(entry.key.len())
            .saturating_add(entry.value.as_ref().map_or(0, value_bytes))
    })
}

fn value_bytes(value: &AnyValue) -> usize {
    match value.value.as_ref() {
        Some(AnyValueValue::String(value)) => value.len(),
        Some(AnyValueValue::Bytes(value)) => value.len(),
        Some(AnyValueValue::Array(array)) => array.values.iter().fold(0usize, |bytes, value| {
            bytes.saturating_add(value_bytes(value))
        }),
        Some(AnyValueValue::KeyValueList(list)) => attributes_bytes(&list.values),
        _ => 0,
    }
}

fn attributes_nodes(attributes: &[KeyValue]) -> usize {
    attributes.iter().fold(0usize, |nodes, entry| {
        nodes.saturating_add(entry.value.as_ref().map_or(0, value_nodes))
    })
}

fn value_nodes(value: &AnyValue) -> usize {
    match value.value.as_ref() {
        Some(AnyValueValue::Array(array)) => array.values.iter().fold(1usize, |nodes, value| {
            nodes.saturating_add(value_nodes(value))
        }),
        Some(AnyValueValue::KeyValueList(list)) => {
            1usize.saturating_add(attributes_nodes(&list.values))
        }
        _ => 1,
    }
}

pub(super) fn collect_metrics(
    mapper: &OwnedOtlpMetrics,
    point_time_unix_nano: u64,
    resource_attributes: &[(&str, &str)],
    policy: &OwnedOtlpExportPolicy,
) -> Result<OwnedOtlpPolicyOutput<Vec<Vec<u8>>>, OwnedOtlpPolicyError> {
    use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
    use crate::observability::otlp_proto::metrics::{ResourceMetrics, ScopeMetrics};

    let mut state = mapper.state.lock();
    if let Some(error) = state.terminal_error {
        return Err(error.into());
    }
    if point_time_unix_nano == 0
        || point_time_unix_nano < state.epoch_start_unix_nano
        || point_time_unix_nano < state.last_collection_unix_nano
    {
        return Err(OwnedOtlpMetricsError::InvalidTimestamp.into());
    }
    let resource = Resource {
        attributes: super::owned_otlp_attributes(resource_attributes)?,
        ..Resource::default()
    };
    let scope = InstrumentationScope {
        name: "asupersync".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        ..InstrumentationScope::default()
    };
    let mut report = OwnedOtlpPolicyReport::default();
    let metadata = policy.metadata(resource, scope, "", OWNED_OTLP_MAX_ATTRIBUTES, &mut report)?;
    let mut metrics = super::build_owned_otlp_metrics(&state, point_time_unix_nano)?;
    // Check all metric identities before encoding any request. Refusing an
    // ambiguous series never advances this provider's collection timestamp.
    for metric in &mut metrics {
        policy.metric(metric, &mut report)?;
    }
    let mut requests = Vec::new();
    for chunk in metrics.chunks(mapper.config.max_metrics_per_request) {
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(metadata.resource.clone()),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(metadata.scope.clone()),
                    metrics: chunk.to_vec(),
                    schema_url: metadata.schema_url.clone(),
                    ..ScopeMetrics::default()
                }],
                schema_url: metadata.schema_url.clone(),
                ..ResourceMetrics::default()
            }],
            ..ExportMetricsServiceRequest::default()
        };
        let bytes = request
            .encode_to_bytes(super::otlp_request_limits(mapper.config.max_request_bytes))
            .map_err(|_| OwnedOtlpMetricsError::WireEnvelopeExceeded)?;
        requests.push(bytes.to_vec());
    }
    state.last_collection_unix_nano = point_time_unix_nano;
    Ok(OwnedOtlpPolicyOutput::new(requests, report))
}

pub(super) fn collect_traces(
    mapper: &OwnedOtlpTraces,
    spans: &[OtlpTraceSpanInput<'_>],
    resource_attributes: &[(&str, &str)],
    policy: &OwnedOtlpExportPolicy,
) -> Result<OwnedOtlpPolicyOutput<OwnedOtlpTraceCollection>, OwnedOtlpPolicyError> {
    use crate::observability::otlp_proto::collector::trace::ExportTraceServiceRequest;
    use crate::observability::otlp_proto::trace::{ResourceSpans, ScopeSpans};

    let sampled_count = spans.iter().filter(|span| span.is_sampled()).count();
    let unsampled_spans = spans.len().saturating_sub(sampled_count);
    if sampled_count == 0 {
        return Ok(OwnedOtlpPolicyOutput::new(
            OwnedOtlpTraceCollection {
                requests: Vec::new(),
                sampled_spans: 0,
                unsampled_spans,
            },
            OwnedOtlpPolicyReport::default(),
        ));
    }
    if sampled_count > mapper.config.max_spans_per_collection {
        return Err(OwnedOtlpTraceError::LimitExceeded.into());
    }
    super::validate_owned_trace_attributes(resource_attributes, &mapper.config)?;
    let request_count = sampled_count.div_ceil(mapper.config.max_spans_per_request);
    let original_metadata_bytes = super::trace_attribute_bytes(resource_attributes)?
        .saturating_add("asupersync".len())
        .saturating_add(env!("CARGO_PKG_VERSION").len())
        .saturating_mul(request_count);
    let sampled = spans
        .iter()
        .filter(|span| span.is_sampled())
        .collect::<Vec<_>>();
    let mut span_bytes = 0usize;
    for span in &sampled {
        span_bytes =
            span_bytes.saturating_add(super::validate_owned_trace_span(span, &mapper.config)?);
        if original_metadata_bytes.saturating_add(span_bytes) > mapper.config.max_owned_bytes {
            return Err(OwnedOtlpTraceError::LimitExceeded.into());
        }
    }
    let ordered = super::deterministic_trace_order(&sampled)?;

    // All borrowed input passes the existing preflight before caller text is
    // copied into models. Policy metadata is separately admitted and counted.
    let resource = Resource {
        attributes: super::owned_otlp_attributes(resource_attributes)
            .map_err(|_| OwnedOtlpTraceError::InvalidAttributes)?,
        ..Resource::default()
    };
    let scope = InstrumentationScope {
        name: "asupersync".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        ..InstrumentationScope::default()
    };
    let mut report = OwnedOtlpPolicyReport::default();
    let metadata = policy.metadata(
        resource,
        scope,
        "",
        mapper.config.max_attributes_per_entity,
        &mut report,
    )?;
    let metadata_bytes = metadata.bytes().saturating_mul(request_count);
    if metadata_bytes.saturating_add(span_bytes) > mapper.config.max_owned_bytes {
        return Err(OwnedOtlpPolicyError::LimitExceeded);
    }
    let mut mapped = Vec::with_capacity(sampled_count);
    let mut filtered_bytes = metadata_bytes;
    for span in ordered {
        let mut span = super::owned_otlp_trace_span(span)?;
        policy.span(&mut span, &mut report)?;
        filtered_bytes = filtered_bytes.saturating_add(trace_span_bytes(&span));
        if filtered_bytes > mapper.config.max_owned_bytes {
            return Err(OwnedOtlpPolicyError::LimitExceeded);
        }
        mapped.push(span);
    }

    let mut requests = Vec::with_capacity(request_count);
    for chunk in mapped.chunks(mapper.config.max_spans_per_request) {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(metadata.resource.clone()),
                scope_spans: vec![ScopeSpans {
                    scope: Some(metadata.scope.clone()),
                    spans: chunk.to_vec(),
                    schema_url: metadata.schema_url.clone(),
                    ..ScopeSpans::default()
                }],
                schema_url: metadata.schema_url.clone(),
                ..ResourceSpans::default()
            }],
            ..ExportTraceServiceRequest::default()
        };
        let bytes = request
            .encode_to_bytes(super::otlp_request_limits(mapper.config.max_request_bytes))
            .map_err(|error| match error {
                crate::grpc::protobuf::ProtobufWireError::SchemaInvariant {
                    invariant: "trace state must use the W3C tracestate format",
                    ..
                } => OwnedOtlpTraceError::InvalidTraceState,
                _ => OwnedOtlpTraceError::WireEnvelopeExceeded,
            })?;
        requests.push(bytes.to_vec());
    }
    Ok(OwnedOtlpPolicyOutput::new(
        OwnedOtlpTraceCollection {
            requests,
            sampled_spans: sampled_count,
            unsampled_spans,
        },
        report,
    ))
}

fn trace_span_bytes(span: &crate::observability::otlp_proto::trace::Span) -> usize {
    let mut bytes = span
        .name
        .len()
        .saturating_add(span.trace_state.len())
        .saturating_add(
            span.status
                .as_ref()
                .map_or(0, |status| status.message.len()),
        )
        .saturating_add(attributes_bytes(&span.attributes));
    for event in &span.events {
        bytes = bytes
            .saturating_add(event.name.len())
            .saturating_add(attributes_bytes(&event.attributes));
    }
    for link in &span.links {
        bytes = bytes
            .saturating_add(link.trace_state.len())
            .saturating_add(attributes_bytes(&link.attributes));
    }
    bytes
}

pub(super) fn collect_logs(
    mapper: &OwnedOtlpLogs,
    records: &[OtlpLogRecordInput<'_>],
    resource_attributes: &[OtlpLogKeyValueInput<'_>],
    policy: &OwnedOtlpExportPolicy,
) -> Result<OwnedOtlpPolicyOutput<OwnedOtlpLogCollection>, OwnedOtlpPolicyError> {
    use crate::observability::otlp_proto::collector::logs::ExportLogsServiceRequest;
    use crate::observability::otlp_proto::logs::{ResourceLogs, ScopeLogs};

    if records.is_empty() {
        return Ok(OwnedOtlpPolicyOutput::new(
            OwnedOtlpLogCollection {
                requests: Vec::new(),
                record_count: 0,
                producer_dropped_attributes: 0,
            },
            OwnedOtlpPolicyReport::default(),
        ));
    }
    if records.len() > mapper.config.max_records_per_collection {
        return Err(OwnedOtlpLogError::LimitExceeded.into());
    }
    let resource_stats = super::validate_owned_log_key_values(
        resource_attributes,
        &mapper.config,
        mapper.config.max_attributes_per_entity,
        1,
    )?;
    let request_count = records
        .len()
        .div_ceil(mapper.config.max_records_per_request);
    let original_metadata_bytes = resource_stats
        .bytes
        .saturating_add(mapper.config.scope_name.len())
        .saturating_add(mapper.config.scope_version.len())
        .saturating_add(mapper.config.schema_url.len().saturating_mul(2))
        .saturating_mul(request_count);
    let mut record_bytes = 0usize;
    let mut producer_dropped_attributes = 0u64;
    let mut record_stats = Vec::with_capacity(records.len());
    for record in records {
        let stats = super::validate_owned_log_record(record, &mapper.config)?;
        record_bytes = record_bytes.saturating_add(stats.bytes);
        if original_metadata_bytes.saturating_add(record_bytes) > mapper.config.max_owned_bytes {
            return Err(OwnedOtlpLogError::LimitExceeded.into());
        }
        producer_dropped_attributes =
            producer_dropped_attributes.saturating_add(u64::from(record.dropped_attributes_count));
        record_stats.push(stats);
    }
    for chunk in record_stats.chunks(mapper.config.max_records_per_request) {
        let nodes = chunk.iter().fold(resource_stats.nodes, |nodes, stats| {
            nodes.saturating_add(stats.nodes)
        });
        if nodes > super::OWNED_OTLP_MAX_LOG_BODY_NODES_PER_REQUEST {
            return Err(OwnedOtlpLogError::LimitExceeded.into());
        }
    }

    let resource = Resource {
        attributes: super::owned_log_key_values(resource_attributes),
        ..Resource::default()
    };
    let scope = InstrumentationScope {
        name: mapper.config.scope_name.clone(),
        version: mapper.config.scope_version.clone(),
        ..InstrumentationScope::default()
    };
    let mut report = OwnedOtlpPolicyReport::default();
    let metadata = policy.metadata(
        resource,
        scope,
        &mapper.config.schema_url,
        mapper.config.max_attributes_per_entity,
        &mut report,
    )?;
    let metadata_bytes = metadata.bytes().saturating_mul(request_count);
    if metadata_bytes.saturating_add(record_bytes) > mapper.config.max_owned_bytes {
        return Err(OwnedOtlpPolicyError::LimitExceeded);
    }
    for chunk in record_stats.chunks(mapper.config.max_records_per_request) {
        let nodes = chunk.iter().fold(metadata.nodes(), |nodes, stats| {
            nodes.saturating_add(stats.nodes)
        });
        if nodes > super::OWNED_OTLP_MAX_LOG_BODY_NODES_PER_REQUEST {
            return Err(OwnedOtlpPolicyError::LimitExceeded);
        }
    }

    let mut filtered_bytes = metadata_bytes;
    let mut requests = Vec::with_capacity(request_count);
    for chunk in records.chunks(mapper.config.max_records_per_request) {
        let mut mapped = Vec::with_capacity(chunk.len());
        for record in chunk {
            let mut record = super::owned_log_record(record);
            policy.log(&mut record, &mut report)?;
            filtered_bytes = filtered_bytes.saturating_add(log_record_bytes(&record));
            if filtered_bytes > mapper.config.max_owned_bytes {
                return Err(OwnedOtlpPolicyError::LimitExceeded);
            }
            mapped.push(record);
        }
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(metadata.resource.clone()),
                scope_logs: vec![ScopeLogs {
                    scope: Some(metadata.scope.clone()),
                    log_records: mapped,
                    schema_url: metadata.schema_url.clone(),
                    ..ScopeLogs::default()
                }],
                schema_url: metadata.schema_url.clone(),
                ..ResourceLogs::default()
            }],
            ..ExportLogsServiceRequest::default()
        };
        let bytes = request
            .encode_to_bytes(super::otlp_request_limits(mapper.config.max_request_bytes))
            .map_err(|_| OwnedOtlpLogError::WireEnvelopeExceeded)?;
        requests.push(bytes.to_vec());
    }
    Ok(OwnedOtlpPolicyOutput::new(
        OwnedOtlpLogCollection {
            requests,
            record_count: records.len(),
            producer_dropped_attributes,
        },
        report,
    ))
}

fn log_record_bytes(record: &crate::observability::otlp_proto::logs::LogRecord) -> usize {
    record
        .severity_text
        .len()
        .saturating_add(record.event_name.len())
        .saturating_add(record.trace_id.len())
        .saturating_add(record.span_id.len())
        .saturating_add(record.body.as_ref().map_or(0, value_bytes))
        .saturating_add(attributes_bytes(&record.attributes))
}

#[cfg(test)]
#[path = "export_policy_tests.rs"]
mod tests;
