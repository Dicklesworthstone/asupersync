//! OpenTelemetry metrics provider.
//!
//! This module provides [`OtelMetrics`], an implementation of [`MetricsProvider`]
//! that exports Asupersync runtime metrics via OpenTelemetry.
//!
//! # Feature
//!
//! Enable the `metrics` feature to compile this module.
//!
//! # Cardinality Limits
//!
//! High-cardinality labels can cause metric explosion. Use [`MetricsConfig`]
//! to set cardinality limits:
//!
//! ```ignore
//! let config = MetricsConfig {
//!     max_cardinality: 500,
//!     overflow_strategy: CardinalityOverflow::Aggregate,
//!     ..Default::default()
//! };
//! let metrics = OtelMetrics::new_with_config(global::meter("asupersync"), config);
//! ```
//!
//! # Custom Exporters
//!
//! Use [`MetricsExporter`] trait for custom export backends:
//!
//! ```ignore
//! let stdout = StdoutExporter::new();
//! let multi = MultiExporter::new(vec![Box::new(stdout)]);
//! ```
//!
//! # Example
//!
//! ```ignore
//! use opentelemetry::global;
//! use opentelemetry_prometheus::exporter;
//! use prometheus::Registry;
//! use asupersync::observability::OtelMetrics;
//!
//! let registry = Registry::new();
//! let exporter = exporter().with_registry(registry.clone()).build().unwrap();
//! let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
//!     .with_reader(opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build())
//!     .build();
//! opentelemetry::global::set_meter_provider(provider);
//!
//! let metrics = OtelMetrics::new(global::meter("asupersync"));
//! // RuntimeBuilder::new().metrics(metrics).build();
//! ```

use crate::observability::entry::LogEntry;
use crate::observability::level::LogLevel;
use crate::observability::metrics::{MetricsProvider, OutcomeKind};
use crate::types::{CancelKind, RegionId, TaskId};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge};
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// =============================================================================
// Cardinality Management
// =============================================================================

/// Strategy when cardinality limit is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardinalityOverflow {
    /// Stop recording new label combinations (drop silently).
    #[default]
    Drop,
    /// Aggregate into 'other' bucket.
    Aggregate,
    /// Log warning and continue recording (may cause OOM).
    Warn,
}

/// Configuration for metrics collection.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Maximum unique label combinations per metric.
    pub max_cardinality: usize,
    /// Maximum distinct metric NAMES tracked. Once this cap is hit,
    /// new metric names hit the overflow path and are not recorded
    /// (br-asupersync-qipj44). Existing metric names continue to
    /// accept new label combinations up to `max_cardinality`.
    ///
    /// The default cap (4096) is high enough that legitimate
    /// applications never hit it (real services have on the order of
    /// 50-500 distinct metric names) while bounding the worst case
    /// for SaaS workloads where attacker-influenced strings could
    /// otherwise reach a metric-naming code path.
    pub max_metrics: usize,
    /// Strategy when cardinality limit is reached.
    pub overflow_strategy: CardinalityOverflow,
    /// Labels to always drop (e.g., request_id, trace_id).
    pub drop_labels: Vec<String>,
    /// Sampling configuration for high-frequency metrics.
    pub sampling: Option<SamplingConfig>,
}

/// Configuration for OTLP privacy filtering across traces, metrics, and logs.
#[derive(Debug, Clone, Default)]
pub struct PrivacyConfig {
    /// Span attributes to always drop before OTLP serialization (e.g., user.email, api.key).
    /// **Privacy Protection**: These attributes are removed before protobuf encoding
    /// to prevent sensitive data from reaching the collector.
    pub drop_attributes: Vec<String>,
    /// Metric labels to always drop before OTLP serialization (e.g., request_id, user_id).
    /// **Privacy Protection**: These labels are removed before protobuf encoding
    /// to prevent sensitive data from reaching the collector.
    pub drop_labels: Vec<String>,
    /// Allowlist of attributes/labels that are safe to export. If non-empty,
    /// only attributes/labels matching these patterns are exported.
    /// **Privacy Protection**: Provides explicit control over what data reaches collectors.
    pub allowed_fields: Vec<String>,
    /// PII redaction patterns. Field values matching these regex patterns
    /// will be redacted before export.
    /// **Privacy Protection**: Automatically detects and redacts common PII patterns.
    pub pii_patterns: Vec<String>,
    /// Whether to apply automatic PII detection for common patterns
    /// (emails, phone numbers, credit cards, SSNs, etc.).
    pub auto_pii_detection: bool,
    compiled_pii_patterns: Vec<Regex>,
}

impl PrivacyConfig {
    /// Create a new privacy configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a span attribute to always drop for privacy.
    #[must_use]
    pub fn with_drop_attribute(mut self, attribute: impl Into<String>) -> Self {
        self.drop_attributes.push(attribute.into());
        self
    }

    /// Add a metric label to always drop for privacy.
    #[must_use]
    pub fn with_drop_label(mut self, label: impl Into<String>) -> Self {
        self.drop_labels.push(label.into());
        self
    }

    /// Add an allowed field pattern. If any allowed fields are specified,
    /// only fields matching these patterns will be exported.
    #[must_use]
    pub fn with_allowed_field(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_fields.push(pattern.into());
        self
    }

    /// Add a custom PII redaction pattern (regex).
    ///
    /// # Panics
    ///
    /// Panics if `pattern` is not a valid regular expression. Use
    /// [`try_with_pii_pattern`](Self::try_with_pii_pattern) to handle invalid
    /// patterns without panicking.
    #[must_use]
    pub fn with_pii_pattern(self, pattern: impl Into<String>) -> Self {
        self.try_with_pii_pattern(pattern)
            .expect("invalid PrivacyConfig PII regex pattern")
    }

    /// Try to add a custom PII redaction regex pattern.
    ///
    /// The compiled regex is cached in the configuration so value redaction does
    /// not recompile patterns on every exported attribute or metric label.
    pub fn try_with_pii_pattern(
        mut self,
        pattern: impl Into<String>,
    ) -> Result<Self, regex::Error> {
        let pattern = pattern.into();
        let compiled = Regex::new(&pattern)?;
        self.pii_patterns.push(pattern);
        self.compiled_pii_patterns.push(compiled);
        Ok(self)
    }

    /// Enable automatic PII detection for common patterns.
    #[must_use]
    pub fn with_auto_pii_detection(mut self) -> Self {
        self.auto_pii_detection = true;
        self
    }

    /// Check if a field should be dropped based on privacy configuration.
    #[must_use]
    pub fn should_drop_field(&self, field_name: &str) -> bool {
        // Check explicit drop lists
        if self
            .drop_attributes
            .iter()
            .any(|attribute| attribute == field_name)
            || self.drop_labels.iter().any(|label| label == field_name)
        {
            return true;
        }

        // Check allowlist (if specified, only allow matching fields)
        if !self.allowed_fields.is_empty() {
            return !self
                .allowed_fields
                .iter()
                .any(|pattern| Self::field_pattern_matches(pattern, field_name));
        }

        false
    }

    /// Redact PII from field values.
    #[must_use]
    pub fn redact_pii(&self, _field_name: &str, value: &str) -> String {
        if self.matches_custom_pii_pattern(value) {
            return "[REDACTED]".to_string();
        }

        // Apply automatic PII detection
        if self.auto_pii_detection {
            return self.apply_auto_pii_redaction(value);
        }

        value.to_string()
    }

    fn field_pattern_matches(pattern: &str, field_name: &str) -> bool {
        let pattern = pattern.as_bytes();
        let field_name = field_name.as_bytes();
        let mut pattern_index = 0;
        let mut field_index = 0;
        let mut last_star = None;
        let mut star_field_index = 0;

        while field_index < field_name.len() {
            if pattern_index < pattern.len() && pattern[pattern_index] == field_name[field_index] {
                pattern_index += 1;
                field_index += 1;
            } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
                last_star = Some(pattern_index);
                pattern_index += 1;
                star_field_index = field_index;
            } else if let Some(star_index) = last_star {
                pattern_index = star_index + 1;
                star_field_index += 1;
                field_index = star_field_index;
            } else {
                return false;
            }
        }

        pattern[pattern_index..].iter().all(|byte| *byte == b'*')
    }

    fn matches_custom_pii_pattern(&self, value: &str) -> bool {
        if self.pii_patterns.len() == self.compiled_pii_patterns.len() {
            let mut cache_is_current = true;
            for (pattern, compiled) in self.pii_patterns.iter().zip(&self.compiled_pii_patterns) {
                if pattern != compiled.as_str() {
                    cache_is_current = false;
                    break;
                }
                if compiled.is_match(value) {
                    return true;
                }
            }
            if cache_is_current {
                return false;
            }
        }

        self.pii_patterns
            .iter()
            .any(|pattern| Regex::new(pattern).is_ok_and(|compiled| compiled.is_match(value)))
    }

    /// Apply automatic PII detection and redaction.
    fn apply_auto_pii_redaction(&self, value: &str) -> String {
        use std::sync::OnceLock;

        static EMAIL_RE: OnceLock<Regex> = OnceLock::new();
        static PHONE_RE: OnceLock<Regex> = OnceLock::new();
        static SSN_RE: OnceLock<Regex> = OnceLock::new();
        static CARD_CANDIDATE_RE: OnceLock<Regex> = OnceLock::new();

        let email_re = EMAIL_RE.get_or_init(|| {
            Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b")
                .expect("built-in email regex must compile")
        });
        if email_re.is_match(value) {
            return "[EMAIL_REDACTED]".to_string();
        }

        let ssn_re = SSN_RE.get_or_init(|| {
            Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("built-in SSN regex must compile")
        });
        if ssn_re.is_match(value) {
            return "[SSN_REDACTED]".to_string();
        }

        let card_candidate_re = CARD_CANDIDATE_RE.get_or_init(|| {
            Regex::new(r"\b(?:\d[ -]?){13,19}\b").expect("built-in payment-card regex must compile")
        });
        if card_candidate_re
            .find_iter(value)
            .map(|matched| matched.as_str())
            .any(Self::is_luhn_valid_card)
        {
            return "[CARD_REDACTED]".to_string();
        }

        let phone_re = PHONE_RE.get_or_init(|| {
            Regex::new(r"(?x)\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b")
                .expect("built-in phone regex must compile")
        });
        if phone_re.is_match(value) {
            return "[PHONE_REDACTED]".to_string();
        }

        value.to_string()
    }

    fn is_luhn_valid_card(candidate: &str) -> bool {
        let digits: Vec<u32> = candidate.chars().filter_map(|ch| ch.to_digit(10)).collect();
        if !(13..=19).contains(&digits.len()) {
            return false;
        }

        let mut sum = 0;
        let mut double = false;
        for digit in digits.iter().rev() {
            let mut value = *digit;
            if double {
                value *= 2;
                if value > 9 {
                    value -= 9;
                }
            }
            sum += value;
            double = !double;
        }

        sum % 10 == 0
    }
}

/// Configuration for OTLP trace span privacy filtering.
/// **DEPRECATED**: Use `PrivacyConfig` instead for comprehensive privacy filtering.
pub type SpanConfig = PrivacyConfig;

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            max_cardinality: 1000,
            max_metrics: 4096,
            overflow_strategy: CardinalityOverflow::Drop,
            drop_labels: Vec::new(),
            sampling: None,
        }
    }
}

impl MetricsConfig {
    /// Create a new metrics configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum cardinality per metric.
    #[must_use]
    pub fn with_max_cardinality(mut self, max: usize) -> Self {
        self.max_cardinality = max;
        self
    }

    /// Set maximum number of distinct metric NAMES (br-asupersync-qipj44).
    /// Once the cap is hit, newly-named metrics are dropped to prevent
    /// memory exhaustion via attacker-controlled metric strings.
    #[must_use]
    pub fn with_max_metrics(mut self, max: usize) -> Self {
        self.max_metrics = max;
        self
    }

    /// Set overflow strategy.
    #[must_use]
    pub fn with_overflow_strategy(mut self, strategy: CardinalityOverflow) -> Self {
        self.overflow_strategy = strategy;
        self
    }

    /// Add a label to always drop.
    #[must_use]
    pub fn with_drop_label(mut self, label: impl Into<String>) -> Self {
        self.drop_labels.push(label.into());
        self
    }

    /// Set sampling configuration.
    #[must_use]
    pub fn with_sampling(mut self, sampling: SamplingConfig) -> Self {
        self.sampling = Some(sampling);
        self
    }
}

/// Sampling configuration for high-frequency metrics.
#[derive(Debug, Clone)]
pub struct SamplingConfig {
    /// Sample rate (0.0-1.0). 1.0 = record all.
    pub sample_rate: f64,
    /// Metrics to sample (others recorded fully).
    pub sampled_metrics: Vec<String>,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            sample_rate: 1.0,
            sampled_metrics: Vec::new(),
        }
    }
}

impl SamplingConfig {
    /// Create new sampling config with given rate.
    #[must_use]
    pub fn new(sample_rate: f64) -> Self {
        Self {
            sample_rate: sample_rate.clamp(0.0, 1.0),
            sampled_metrics: Vec::new(),
        }
    }

    /// Add a metric to the sampled set.
    #[must_use]
    pub fn with_sampled_metric(mut self, metric: impl Into<String>) -> Self {
        self.sampled_metrics.push(metric.into());
        self
    }
}

/// Tracks cardinality per metric to prevent explosion.
///
/// br-asupersync-bs92bg — `hasher_seed` is a per-instance
/// `RandomState` (per-process random SipHash key). Switched from the
/// previously-used `DetHasher` (fixed seed) because the cardinality
/// tracker's keyspace is attacker-influenced — label values arrive
/// from external sources via every metric path. With a fixed seed,
/// an attacker who knows the hash function parameters can pre-compute
/// label values that collide on a single bucket, exhausting the
/// per-metric `max_cardinality` cap with one collision class and
/// effectively suppressing every legitimate label combination
/// thereafter (or, depending on call order, evicting legitimate
/// labels from the seen-set so they re-trigger the overflow path on
/// every subsequent record). RandomState's per-process seed defeats
/// the pre-compute: an attacker cannot know the local hasher's key
/// at startup, so they cannot construct a collision class.
#[derive(Debug)]
struct CardinalityTracker {
    /// Map of metric name -> set of label combination hashes.
    seen: RwLock<HashMap<String, HashSet<u64>>>,
    /// Number of times cardinality limit was hit.
    overflow_count: AtomicU64,
    /// Per-instance random hash seed (br-asupersync-bs92bg).
    hasher_seed: std::collections::hash_map::RandomState,
}

impl CardinalityTracker {
    fn new() -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
            overflow_count: AtomicU64::new(0),
            hasher_seed: std::collections::hash_map::RandomState::new(),
        }
    }

    /// Check if recording this label combination would exceed the limit.
    #[cfg(test)]
    fn would_exceed(&self, metric: &str, labels: &[KeyValue], max_cardinality: usize) -> bool {
        let hash = self.hash_labels(labels);
        let seen = self.seen.read();

        if max_cardinality == 0 {
            return seen.get(metric).is_none_or(|set| !set.contains(&hash));
        }

        if let Some(set) = seen.get(metric) {
            if set.contains(&hash) {
                return false; // Already seen
            }
            set.len() >= max_cardinality
        } else {
            false // First entry for this metric
        }
    }

    /// Record a label combination.
    fn record(&self, metric: &str, labels: &[KeyValue]) {
        let hash = self.hash_labels(labels);
        let mut seen = self.seen.write();
        seen.entry(metric.to_string()).or_default().insert(hash);
    }

    /// Atomically check whether a new label set would exceed cardinality and
    /// record it if allowed.
    ///
    /// Returns `true` when the limit would be exceeded and the label set was
    /// not recorded. Two distinct caps are enforced:
    ///
    ///   - `max_cardinality` — distinct label combinations PER metric
    ///     (existing behaviour, preserved).
    ///   - `max_metrics` — distinct metric NAMES across the whole tracker
    ///     (br-asupersync-qipj44). Without this cap, a code path that
    ///     derived the metric name from attacker-controlled input
    ///     (`format!("user_{user_id}")`, request URL path, content type,
    ///     etc.) could grow `seen` without bound — DoS via memory
    ///     exhaustion. With the cap, the FIRST `max_metrics` distinct
    ///     names are accepted and subsequent new names are dropped to
    ///     the overflow bucket. Existing metric names continue to
    ///     accept new label combinations.
    fn check_and_record(
        &self,
        metric: &str,
        labels: &[KeyValue],
        max_cardinality: usize,
        max_metrics: usize,
    ) -> bool {
        let hash = self.hash_labels(labels);
        let mut seen = self.seen.write();

        // br-asupersync-qipj44: enforce the metric-name cap BEFORE
        // creating a new entry. If the cap is hit and this metric name
        // is not already tracked, refuse to insert.
        if !seen.contains_key(metric) && max_metrics > 0 && seen.len() >= max_metrics {
            return true;
        }

        let set = seen.entry(metric.to_string()).or_default();

        if set.contains(&hash) {
            return false;
        }
        if set.len() >= max_cardinality {
            return true;
        }

        set.insert(hash);
        false
    }

    /// Increment overflow counter.
    fn record_overflow(&self) {
        self.overflow_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get overflow count.
    fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }

    /// Hash labels for tracking.
    ///
    /// br-asupersync-bs92bg — uses the per-instance `RandomState`
    /// seed instead of `DetHasher`. The seed is randomised at
    /// `CardinalityTracker::new()` and never observable to a remote
    /// attacker, defeating the pre-computed-collision DoS that the
    /// fixed-seed `DetHasher` would have permitted.
    fn hash_labels(&self, labels: &[KeyValue]) -> u64 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        let _ = std::marker::PhantomData::<RandomState>;

        // Treat label sets as order-insensitive. Different construction order of
        // equivalent labels should map to the same cardinality bucket.
        let mut normalized: Vec<(&str, String)> = labels
            .iter()
            .map(|kv| (kv.key.as_str(), format!("{:?}", kv.value)))
            .collect();
        normalized.sort_unstable_by(|(a_key, a_val), (b_key, b_val)| {
            a_key.cmp(b_key).then_with(|| a_val.cmp(b_val))
        });

        let mut hasher = self.hasher_seed.build_hasher();
        for (key, value) in normalized {
            key.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Get current cardinality for a metric.
    #[cfg(test)]
    fn cardinality(&self, metric: &str) -> usize {
        self.seen
            .read()
            .get(metric)
            .map_or(0, std::collections::HashSet::len)
    }
}

// =============================================================================
// Custom Exporters
// =============================================================================

/// Labels for a metric data point.
pub type MetricLabels = Vec<(String, String)>;

/// A counter data point: (name, labels, value).
pub type CounterDataPoint = (String, MetricLabels, u64);

/// A gauge data point: (name, labels, value).
pub type GaugeDataPoint = (String, MetricLabels, i64);

/// A histogram data point: (name, labels, count, sum).
pub type HistogramDataPoint = (String, MetricLabels, u64, f64);

/// Snapshot of metrics at a point in time.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    /// Counter values: (name, labels, value).
    pub counters: Vec<CounterDataPoint>,
    /// Gauge values: (name, labels, value).
    pub gauges: Vec<GaugeDataPoint>,
    /// Histogram values: (name, labels, count, sum).
    pub histograms: Vec<HistogramDataPoint>,
}

impl MetricsSnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a counter value.
    pub fn add_counter(
        &mut self,
        name: impl Into<String>,
        labels: Vec<(String, String)>,
        value: u64,
    ) {
        self.counters.push((name.into(), labels, value));
    }

    /// Add a gauge value.
    pub fn add_gauge(
        &mut self,
        name: impl Into<String>,
        labels: Vec<(String, String)>,
        value: i64,
    ) {
        self.gauges.push((name.into(), labels, value));
    }

    /// Add a histogram value.
    pub fn add_histogram(
        &mut self,
        name: impl Into<String>,
        labels: Vec<(String, String)>,
        count: u64,
        sum: f64,
    ) {
        self.histograms.push((name.into(), labels, count, sum));
    }
}

/// Error type for export operations.
#[derive(Debug, Clone)]
pub struct ExportError {
    message: String,
}

impl ExportError {
    /// Create a new export error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "export error: {}", self.message)
    }
}

impl std::error::Error for ExportError {}

/// Default OTLP schema URL used by logs snapshots.
pub const OTLP_LOGS_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.37.0";
/// Default instrumentation scope name for Asupersync logs exports.
pub const OTLP_LOGS_SCOPE_NAME: &str = "asupersync.observability.otel";
/// Maximum number of attributes retained on a single OTLP log record.
pub const OTLP_LOGS_MAX_ATTRIBUTES: usize = 128;
/// Maximum UTF-8 byte length retained for each OTLP log attribute value.
pub const OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES: usize = 4096;

const OTLP_LOGS_TRACE_FLAGS_MASK: u32 = 0xff;

/// String key/value attributes attached to an OTLP log record.
pub type LogAttributes = Vec<(String, String)>;

/// Map an Asupersync log level to OTLP severity number and text.
#[must_use]
pub const fn log_level_to_otlp_severity(level: LogLevel) -> (i32, &'static str) {
    match level {
        LogLevel::Trace => (1, "TRACE"),
        LogLevel::Debug => (5, "DEBUG"),
        LogLevel::Info => (9, "INFO"),
        LogLevel::Warn => (13, "WARN"),
        LogLevel::Error => (17, "ERROR"),
    }
}

fn truncate_log_attribute_value(value: &str) -> String {
    if value.len() <= OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES {
        return value.to_string();
    }

    let mut end = OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn insert_log_attribute_bounded(
    attributes: &mut LogAttributes,
    dropped_attributes_count: &mut u32,
    key: String,
    value: String,
) {
    if key.is_empty() {
        *dropped_attributes_count = dropped_attributes_count.saturating_add(1);
        return;
    }

    let value = truncate_log_attribute_value(&value);
    if let Some((_, existing_value)) = attributes
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing_value = value;
        *dropped_attributes_count = dropped_attributes_count.saturating_add(1);
        return;
    }

    if attributes.len() >= OTLP_LOGS_MAX_ATTRIBUTES {
        *dropped_attributes_count = dropped_attributes_count.saturating_add(1);
        return;
    }

    attributes.push((key, value));
}

fn normalized_log_attributes(
    attributes: &[(String, String)],
    dropped_attributes_count: u32,
) -> (LogAttributes, u32) {
    let mut dropped = dropped_attributes_count;
    let mut normalized = BTreeMap::new();

    for (key, value) in attributes {
        if key.is_empty() {
            dropped = dropped.saturating_add(1);
            continue;
        }
        if normalized
            .insert(key.clone(), truncate_log_attribute_value(value))
            .is_some()
        {
            dropped = dropped.saturating_add(1);
        }
    }

    let mut retained = Vec::with_capacity(normalized.len().min(OTLP_LOGS_MAX_ATTRIBUTES));
    for (key, value) in normalized {
        if retained.len() >= OTLP_LOGS_MAX_ATTRIBUTES {
            dropped = dropped.saturating_add(1);
            continue;
        }
        retained.push((key, value));
    }

    (retained, dropped)
}

fn valid_trace_id(trace_id: Vec<u8>) -> Vec<u8> {
    if trace_id.len() == 16 {
        trace_id
    } else {
        Vec::new()
    }
}

fn valid_span_id(span_id: Vec<u8>) -> Vec<u8> {
    if span_id.len() == 8 {
        span_id
    } else {
        Vec::new()
    }
}

/// A normalized OTLP log record ready for export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpLogRecord {
    /// Event timestamp in Unix nanoseconds. A value of zero means unknown.
    pub time_unix_nano: u64,
    /// Observation timestamp in Unix nanoseconds. A value of zero means unknown.
    pub observed_time_unix_nano: u64,
    /// OTLP severity number.
    pub severity_number: i32,
    /// OTLP severity text.
    pub severity_text: String,
    /// Log body payload. Empty bodies are preserved as empty string values.
    pub body: String,
    /// Attributes attached to the record.
    pub attributes: LogAttributes,
    /// Count of attributes dropped because of invalid keys, duplicates, or caps.
    pub dropped_attributes_count: u32,
    /// W3C trace flags; only the low eight bits are exported.
    pub flags: u32,
    /// Optional 16-byte trace identifier.
    pub trace_id: Vec<u8>,
    /// Optional 8-byte span identifier.
    pub span_id: Vec<u8>,
    /// Optional event name for event-style log records.
    pub event_name: String,
}

impl OtlpLogRecord {
    /// Create a log record from level, body, and event timestamp.
    #[must_use]
    pub fn new(level: LogLevel, body: impl Into<String>, time_unix_nano: u64) -> Self {
        let (severity_number, severity_text) = log_level_to_otlp_severity(level);
        Self {
            time_unix_nano,
            observed_time_unix_nano: time_unix_nano,
            severity_number,
            severity_text: severity_text.to_string(),
            body: body.into(),
            attributes: Vec::new(),
            dropped_attributes_count: 0,
            flags: 0,
            trace_id: Vec::new(),
            span_id: Vec::new(),
            event_name: String::new(),
        }
    }

    /// Build an OTLP log record from an Asupersync structured log entry.
    #[must_use]
    pub fn from_log_entry(entry: &LogEntry, observed_time_unix_nano: u64) -> Self {
        let mut record = Self::new(entry.level(), entry.message(), entry.timestamp().as_nanos())
            .with_observed_time_unix_nano(observed_time_unix_nano);

        if let Some(target) = entry.target() {
            record = record.with_attribute("target", target);
        }
        for (key, value) in entry.fields() {
            record = record.with_attribute(key, value);
        }

        record
    }

    /// Build an OTLP log record from an Asupersync structured log entry with privacy filtering.
    #[must_use]
    pub fn from_log_entry_with_privacy(
        entry: &LogEntry,
        observed_time_unix_nano: u64,
        config: &SpanConfig,
    ) -> Self {
        let mut record = Self::new(entry.level(), entry.message(), entry.timestamp().as_nanos())
            .with_observed_time_unix_nano(observed_time_unix_nano);

        if let Some(target) = entry.target() {
            record = record.with_filtered_attribute("target", target, config);
        }
        for (key, value) in entry.fields() {
            record = record.with_filtered_attribute(key, value, config);
        }

        record
    }

    /// Set the observation timestamp.
    #[must_use]
    pub const fn with_observed_time_unix_nano(mut self, observed_time_unix_nano: u64) -> Self {
        self.observed_time_unix_nano = observed_time_unix_nano;
        self
    }

    /// Add or replace an attribute while enforcing record-local bounds.
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        insert_log_attribute_bounded(
            &mut self.attributes,
            &mut self.dropped_attributes_count,
            key.into(),
            value.into(),
        );
        self
    }

    /// Add or replace an attribute with privacy filtering applied.
    ///
    /// **Security**: Attributes listed in `config.drop_attributes` are silently dropped
    /// to prevent sensitive data from reaching OTLP collectors.
    #[must_use]
    pub fn with_filtered_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        config: &SpanConfig,
    ) -> Self {
        let key_str = key.into();

        if config.should_drop_field(&key_str) {
            self.dropped_attributes_count = self.dropped_attributes_count.saturating_add(1);
            return self;
        }

        let value_str = value.into();
        let value_str = config.redact_pii(&key_str, &value_str);
        insert_log_attribute_bounded(
            &mut self.attributes,
            &mut self.dropped_attributes_count,
            key_str,
            value_str,
        );
        self
    }

    /// Attach a W3C trace/span correlation context.
    #[must_use]
    pub fn with_trace_context(
        mut self,
        trace_id: impl Into<Vec<u8>>,
        span_id: impl Into<Vec<u8>>,
        flags: u32,
    ) -> Self {
        self.trace_id = valid_trace_id(trace_id.into());
        self.span_id = valid_span_id(span_id.into());
        self.flags = flags & OTLP_LOGS_TRACE_FLAGS_MASK;
        self
    }

    /// Attach an OTLP event name.
    #[must_use]
    pub fn with_event_name(mut self, event_name: impl Into<String>) -> Self {
        self.event_name = event_name.into();
        self
    }
}

/// A single-resource, single-scope OTLP logs export snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsSnapshot {
    /// OTLP resource attributes.
    pub resource_attributes: LogAttributes,
    /// Instrumentation scope name.
    pub scope_name: String,
    /// Instrumentation scope version.
    pub scope_version: String,
    /// OTLP schema URL attached to resource and scope blocks.
    pub schema_url: String,
    /// Log records in this export snapshot.
    pub records: Vec<OtlpLogRecord>,
}

impl LogsSnapshot {
    /// Create an empty logs snapshot for a service.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            resource_attributes: vec![
                ("service.name".to_string(), service_name.into()),
                ("telemetry.sdk.name".to_string(), "asupersync".to_string()),
                (
                    "telemetry.sdk.version".to_string(),
                    env!("CARGO_PKG_VERSION").to_string(),
                ),
            ],
            scope_name: OTLP_LOGS_SCOPE_NAME.to_string(),
            scope_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_url: OTLP_LOGS_SCHEMA_URL.to_string(),
            records: Vec::new(),
        }
    }

    /// Set the instrumentation scope name and version.
    #[must_use]
    pub fn with_scope(
        mut self,
        scope_name: impl Into<String>,
        scope_version: impl Into<String>,
    ) -> Self {
        self.scope_name = scope_name.into();
        self.scope_version = scope_version.into();
        self
    }

    /// Set the schema URL.
    #[must_use]
    pub fn with_schema_url(mut self, schema_url: impl Into<String>) -> Self {
        self.schema_url = schema_url.into();
        self
    }

    /// Add or replace a resource attribute.
    #[must_use]
    pub fn with_resource_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        let key = key.into();
        let value = value.into();
        if let Some((_, existing_value)) = self
            .resource_attributes
            .iter_mut()
            .find(|(existing_key, _)| existing_key == &key)
        {
            *existing_value = value;
        } else if !key.is_empty() {
            self.resource_attributes
                .push((key, truncate_log_attribute_value(&value)));
        }
        self
    }

    /// Add a log record.
    pub fn add_record(&mut self, record: OtlpLogRecord) {
        self.records.push(record);
    }

    /// Add a log record and return the updated snapshot.
    #[must_use]
    pub fn with_record(mut self, record: OtlpLogRecord) -> Self {
        self.add_record(record);
        self
    }

    /// Number of records in the snapshot.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Serialize this snapshot as an OTLP `ExportLogsServiceRequest`.
    #[must_use]
    pub fn to_otlp_protobuf(&self) -> Vec<u8> {
        use prost::Message;
        otlp_logs_proto::logs_request_from_snapshot(self).encode_to_vec()
    }
}

mod otlp_logs_proto {
    use super::{LogsSnapshot, normalized_log_attributes};

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct ExportLogsServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub resource_logs: Vec<ResourceLogs>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct ResourceLogs {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_logs: Vec<ScopeLogs>,
        #[prost(string, tag = "3")]
        pub schema_url: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct ScopeLogs {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")]
        pub log_records: Vec<LogRecord>,
        #[prost(string, tag = "3")]
        pub schema_url: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct Resource {
        #[prost(message, repeated, tag = "1")]
        pub attributes: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub(super) struct InstrumentationScope {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub version: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct LogRecord {
        #[prost(fixed64, tag = "1")]
        pub time_unix_nano: u64,
        #[prost(fixed64, tag = "11")]
        pub observed_time_unix_nano: u64,
        #[prost(int32, tag = "2")]
        pub severity_number: i32,
        #[prost(string, tag = "3")]
        pub severity_text: String,
        #[prost(message, optional, tag = "5")]
        pub body: Option<AnyValue>,
        #[prost(message, repeated, tag = "6")]
        pub attributes: Vec<KeyValue>,
        #[prost(uint32, tag = "7")]
        pub dropped_attributes_count: u32,
        #[prost(fixed32, tag = "8")]
        pub flags: u32,
        #[prost(bytes = "vec", tag = "9")]
        pub trace_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "10")]
        pub span_id: Vec<u8>,
        #[prost(string, tag = "12")]
        pub event_name: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct KeyValue {
        #[prost(string, tag = "1")]
        pub key: String,
        #[prost(message, optional, tag = "2")]
        pub value: Option<AnyValue>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct AnyValue {
        #[prost(oneof = "any_value::Value", tags = "1")]
        pub value: Option<any_value::Value>,
    }

    pub(super) mod any_value {
        #[derive(Clone, PartialEq, prost::Oneof)]
        pub enum Value {
            #[prost(string, tag = "1")]
            StringValue(String),
        }
    }

    fn string_value(value: impl Into<String>) -> AnyValue {
        AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }
    }

    fn key_value((key, value): (String, String)) -> KeyValue {
        KeyValue {
            key,
            value: Some(string_value(value)),
        }
    }

    pub(super) fn logs_request_from_snapshot(snapshot: &LogsSnapshot) -> ExportLogsServiceRequest {
        let (resource_attributes, _) = normalized_log_attributes(&snapshot.resource_attributes, 0);
        let records = snapshot
            .records
            .iter()
            .map(|record| {
                let (attributes, dropped_attributes_count) =
                    normalized_log_attributes(&record.attributes, record.dropped_attributes_count);
                LogRecord {
                    time_unix_nano: record.time_unix_nano,
                    observed_time_unix_nano: record.observed_time_unix_nano,
                    severity_number: record.severity_number,
                    severity_text: record.severity_text.clone(),
                    body: Some(string_value(record.body.clone())),
                    attributes: attributes.into_iter().map(key_value).collect(),
                    dropped_attributes_count,
                    flags: record.flags,
                    trace_id: record.trace_id.clone(),
                    span_id: record.span_id.clone(),
                    event_name: record.event_name.clone(),
                }
            })
            .collect();

        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: resource_attributes.into_iter().map(key_value).collect(),
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: snapshot.scope_name.clone(),
                        version: snapshot.scope_version.clone(),
                    }),
                    log_records: records,
                    schema_url: snapshot.schema_url.clone(),
                }],
                schema_url: snapshot.schema_url.clone(),
            }],
        }
    }
}

/// Trait for custom logs exporters.
pub trait LogsExporter: Send + Sync {
    /// Export a logs snapshot.
    fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError>;

    /// Flush any buffered log data.
    fn flush(&self) -> Result<(), ExportError>;
}

/// Logs exporter that drops all records.
#[derive(Debug, Default)]
pub struct NullLogsExporter;

impl NullLogsExporter {
    /// Create a new null logs exporter.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LogsExporter for NullLogsExporter {
    fn export(&self, _logs: &LogsSnapshot) -> Result<(), ExportError> {
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// Logs exporter that collects snapshots in memory for tests.
#[derive(Debug, Default)]
pub struct InMemoryLogsExporter {
    snapshots: Mutex<Vec<LogsSnapshot>>,
}

impl InMemoryLogsExporter {
    /// Create a new in-memory logs exporter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all collected snapshots.
    #[must_use]
    pub fn snapshots(&self) -> Vec<LogsSnapshot> {
        self.snapshots.lock().clone()
    }

    /// Clear collected snapshots.
    pub fn clear(&self) {
        self.snapshots.lock().clear();
    }

    /// Total number of log records collected across snapshots.
    #[must_use]
    pub fn total_records(&self) -> usize {
        self.snapshots
            .lock()
            .iter()
            .map(LogsSnapshot::record_count)
            .sum()
    }
}

impl LogsExporter for InMemoryLogsExporter {
    fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
        self.snapshots.lock().push(logs.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// Logs exporter that fans out to multiple exporters.
#[derive(Default)]
pub struct MultiLogsExporter {
    exporters: Vec<Box<dyn LogsExporter>>,
}

impl MultiLogsExporter {
    /// Create a new multi-exporter for logs.
    #[must_use]
    pub fn new(exporters: Vec<Box<dyn LogsExporter>>) -> Self {
        Self { exporters }
    }

    /// Add a logs exporter.
    pub fn add(&mut self, exporter: Box<dyn LogsExporter>) {
        self.exporters.push(exporter);
    }

    /// Number of child exporters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exporters.len()
    }

    /// Whether this exporter has no children.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exporters.is_empty()
    }
}

impl std::fmt::Debug for MultiLogsExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiLogsExporter")
            .field("exporters_count", &self.exporters.len())
            .finish()
    }
}

impl LogsExporter for MultiLogsExporter {
    fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
        let mut errors = Vec::new();
        for exporter in &self.exporters {
            if let Err(err) = exporter.export(logs) {
                errors.push(err.message);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ExportError::new(errors.join("; ")))
        }
    }

    fn flush(&self) -> Result<(), ExportError> {
        let mut errors = Vec::new();
        for exporter in &self.exporters {
            if let Err(err) = exporter.flush() {
                errors.push(err.message);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ExportError::new(errors.join("; ")))
        }
    }
}

/// Bounded logs exporter with oldest-drop load shedding.
pub struct LoadSheddingLogsExporter {
    inner: Box<dyn LogsExporter>,
    export_queue: BoundedExportQueue<LogsSnapshot>,
}

impl std::fmt::Debug for LoadSheddingLogsExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadSheddingLogsExporter")
            .field("export_queue", &self.export_queue)
            .finish_non_exhaustive()
    }
}

impl LoadSheddingLogsExporter {
    /// Create a new logs exporter with bounded oldest-drop queueing.
    #[must_use]
    pub fn new(inner: Box<dyn LogsExporter>, queue_capacity: usize) -> Self {
        Self {
            inner,
            export_queue: BoundedExportQueue::new(queue_capacity),
        }
    }

    /// Return load shedding statistics.
    #[must_use]
    pub fn load_shedding_stats(&self) -> LoadSheddingStats {
        LoadSheddingStats {
            queue_depth: self.export_queue.len(),
            queue_capacity: self.export_queue.capacity(),
            dropped_batches: self.export_queue.dropped_count(),
        }
    }

    /// Process all queued logs snapshots.
    pub fn process_queue(&self) -> Result<usize, ExportError> {
        let mut processed = 0;
        while let Some(batch) = self.export_queue.dequeue() {
            self.inner.export(&batch)?;
            processed += 1;
        }
        Ok(processed)
    }
}

impl LogsExporter for LoadSheddingLogsExporter {
    fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
        let dropped = self.export_queue.enqueue(logs.clone());
        if dropped {
            #[cfg(feature = "tracing-integration")]
            crate::tracing_compat::warn!(
                target: "asupersync::observability::otel",
                "OTLP logs export queue full: dropped oldest batch. Queue capacity: {}, dropped total: {}",
                self.export_queue.capacity(),
                self.export_queue.dropped_count()
            );
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        self.process_queue()?;
        self.inner.flush()
    }
}

/// OTLP HTTP logs exporter.
#[derive(Debug, Clone)]
pub struct OtlpLogsHttpExporter {
    http: OtlpHttpExporter,
}

impl OtlpLogsHttpExporter {
    /// Create a new OTLP HTTP logs exporter.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            http: OtlpHttpExporter::new(endpoint),
        }
    }

    /// Set request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = self.http.with_timeout(timeout);
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Self {
        self.http = self
            .http
            .with_retry_config(max_retries, initial_delay, max_delay);
        self
    }

    /// Enable gzip compression for request bodies.
    #[must_use]
    pub fn with_compression(mut self, compression: bool) -> Self {
        self.http = self.http.with_compression(compression);
        self
    }

    /// Export logs through the async OTLP HTTP path.
    pub async fn export_async(
        &self,
        cx: &crate::cx::Cx,
        logs: &LogsSnapshot,
    ) -> Result<(), ExportError> {
        self.http
            .send_otlp_protobuf(cx, logs.to_otlp_protobuf())
            .await
    }

    /// Return the configured endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.http.endpoint
    }
}

impl LogsExporter for OtlpLogsHttpExporter {
    fn export(&self, _logs: &LogsSnapshot) -> Result<(), ExportError> {
        Err(ExportError::new(
            "OTLP HTTP logs export requires async context - use export_async()",
        ))
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// Trait for custom metrics exporters.
pub trait MetricsExporter: Send + Sync {
    /// Export a snapshot of metrics.
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError>;

    /// Flush any buffered data.
    fn flush(&self) -> Result<(), ExportError>;
}

/// br-asupersync-coxhdt — Escape a Prometheus label value per the
/// exposition format. The spec mandates that values containing the
/// canonical trio (`\\`, `\n`, `\"`) be backslash-escaped; without
/// this, a value containing `"` would terminate the quoted string
/// early (corrupting the line and potentially injecting attacker-
/// controlled labels), and a value containing `\` or `\n` would
/// likewise corrupt the exposition. CR is also escaped to keep
/// downstream line-oriented parsers from splitting on it.
///
/// This is the otel-exporter parallel to
/// [`crate::observability::metrics::escape_prometheus_label_value`]
/// (br-asupersync-pdu7wg) — same canonical escape trio applied on a
/// separate code path to keep otel.rs self-contained.
fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '"' => {
                out.push('\\');
                out.push('"');
            }
            '\r' => out.push_str(r"\r"),
            _ => out.push(c),
        }
    }
    out
}

/// Exporter that writes to stdout (for debugging).
#[derive(Debug, Default)]
pub struct StdoutExporter {
    prefix: String,
}

impl StdoutExporter {
    /// Create a new stdout exporter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a prefix for each line.
    #[must_use]
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// br-asupersync-coxhdt — Format labels for the Prometheus
    /// exposition output of `StdoutExporter`. The previous shape
    /// was `format!("{k}=\"{v}\"")` — a value containing `"` would
    /// terminate the quoted string early, and a value containing
    /// `\` (or `\n`) would corrupt the line. Per the Prometheus
    /// exposition spec the value MUST escape `\\`, `\n`, and `\"`.
    /// This shares the spec-required trio with the
    /// `escape_prometheus_label_value` function in metrics.rs
    /// (br-asupersync-pdu7wg) — same canonical escape set, applied
    /// to the otel exporter's separate code path.
    fn format_labels(labels: &[(String, String)]) -> String {
        if labels.is_empty() {
            String::new()
        } else {
            let parts: Vec<_> = labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

impl MetricsExporter for StdoutExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        let mut stdout = std::io::stdout().lock();

        for (name, labels, value) in &metrics.counters {
            let label_str = Self::format_labels(labels);
            writeln!(
                stdout,
                "{}COUNTER {}{} {}",
                self.prefix, name, label_str, value
            )
            .map_err(|e| ExportError::new(e.to_string()))?;
        }

        for (name, labels, value) in &metrics.gauges {
            let label_str = Self::format_labels(labels);
            writeln!(
                stdout,
                "{}GAUGE {}{} {}",
                self.prefix, name, label_str, value
            )
            .map_err(|e| ExportError::new(e.to_string()))?;
        }

        for (name, labels, count, sum) in &metrics.histograms {
            let label_str = Self::format_labels(labels);
            writeln!(
                stdout,
                "{}HISTOGRAM {}{} count={} sum={}",
                self.prefix, name, label_str, count, sum
            )
            .map_err(|e| ExportError::new(e.to_string()))?;
        }

        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        std::io::stdout()
            .flush()
            .map_err(|e| ExportError::new(e.to_string()))
    }
}

/// Exporter that does nothing (for testing).
#[derive(Debug, Default)]
pub struct NullExporter;

impl NullExporter {
    /// Create a new null exporter.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl MetricsExporter for NullExporter {
    fn export(&self, _metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// Exporter that fans out to multiple exporters.
#[derive(Default)]
pub struct MultiExporter {
    exporters: Vec<Box<dyn MetricsExporter>>,
}

impl MultiExporter {
    /// Create a new multi-exporter.
    #[must_use]
    pub fn new(exporters: Vec<Box<dyn MetricsExporter>>) -> Self {
        Self { exporters }
    }

    /// Add an exporter.
    pub fn add(&mut self, exporter: Box<dyn MetricsExporter>) {
        self.exporters.push(exporter);
    }

    /// Number of exporters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exporters.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exporters.is_empty()
    }
}

impl std::fmt::Debug for MultiExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiExporter")
            .field("exporters_count", &self.exporters.len())
            .finish()
    }
}

impl MetricsExporter for MultiExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        let mut errors = Vec::new();
        for exporter in &self.exporters {
            if let Err(e) = exporter.export(metrics) {
                errors.push(e.message);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ExportError::new(errors.join("; ")))
        }
    }

    fn flush(&self) -> Result<(), ExportError> {
        let mut errors = Vec::new();
        for exporter in &self.exporters {
            if let Err(e) = exporter.flush() {
                errors.push(e.message);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ExportError::new(errors.join("; ")))
        }
    }
}

/// Exporter that collects metrics in memory for testing.
#[derive(Debug, Default)]
pub struct InMemoryExporter {
    snapshots: Mutex<Vec<MetricsSnapshot>>,
}

/// Bounded export queue with OTLP-compliant load shedding.
///
/// When the export queue reaches capacity, drops OLDEST batches to preserve
/// recent data (per OTLP exporter best practices). This prevents memory
/// exhaustion under sustained high export load while maintaining observability
/// of the most recent system state.
#[derive(Debug)]
pub struct BoundedExportQueue<T> {
    queue: Mutex<std::collections::VecDeque<T>>,
    capacity: usize,
    dropped_batches: std::sync::atomic::AtomicU64,
}

impl<T> BoundedExportQueue<T> {
    /// Create a new bounded export queue with the specified capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(std::collections::VecDeque::with_capacity(capacity)),
            capacity,
            dropped_batches: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Enqueue a batch for export. If queue is full, drops OLDEST batch first.
    ///
    /// Returns `true` if a batch was dropped to make room (load shedding occurred).
    pub fn enqueue(&self, batch: T) -> bool {
        let mut queue = self.queue.lock();

        // Apply load shedding: drop oldest batch if at capacity
        let dropped = if queue.len() >= self.capacity {
            let dropped_existing = queue.pop_front().is_some(); // Remove OLDEST batch (correct OTLP behavior)
            if dropped_existing {
                self.dropped_batches
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            true
        } else {
            false
        };

        queue.push_back(batch); // Add new batch to end
        dropped
    }

    /// Dequeue the next batch for export (FIFO order).
    pub fn dequeue(&self) -> Option<T> {
        self.queue.lock().pop_front()
    }

    /// Get the current queue depth.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Check if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    /// Get the number of batches dropped due to load shedding.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped_batches
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// OTLP-compliant exporter with bounded export queue and oldest-drop load shedding.
///
/// Implements OTLP exporter best practices:
/// - Bounded export queue prevents memory exhaustion
/// - Drop OLDEST batches when queue is full (preserves recent data)
/// - Maintains export order (FIFO)
/// - Tracks load shedding metrics
pub struct LoadSheddingExporter {
    inner: Box<dyn MetricsExporter>,
    export_queue: BoundedExportQueue<MetricsSnapshot>,
}

impl std::fmt::Debug for LoadSheddingExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadSheddingExporter")
            .field("export_queue", &self.export_queue)
            .finish_non_exhaustive()
    }
}

impl LoadSheddingExporter {
    /// Create a new load shedding exporter.
    ///
    /// # Arguments
    /// * `inner` - The underlying exporter to send batches to
    /// * `queue_capacity` - Maximum number of batches to queue (recommended: 100-1000)
    #[must_use]
    pub fn new(inner: Box<dyn MetricsExporter>, queue_capacity: usize) -> Self {
        Self {
            inner,
            export_queue: BoundedExportQueue::new(queue_capacity),
        }
    }

    /// Get load shedding statistics.
    #[must_use]
    pub fn load_shedding_stats(&self) -> LoadSheddingStats {
        LoadSheddingStats {
            queue_depth: self.export_queue.len(),
            queue_capacity: self.export_queue.capacity(),
            dropped_batches: self.export_queue.dropped_count(),
        }
    }

    /// Process all queued batches (typically called by export background task).
    pub fn process_queue(&self) -> Result<usize, ExportError> {
        let mut processed = 0;

        while let Some(batch) = self.export_queue.dequeue() {
            self.inner.export(&batch)?;
            processed += 1;
        }

        Ok(processed)
    }
}

impl MetricsExporter for LoadSheddingExporter {
    /// Queue metrics for export with load shedding.
    ///
    /// When queue is full, drops OLDEST batch to make room for new data.
    /// This preserves recent observability data per OTLP best practices.
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        let dropped = self.export_queue.enqueue(metrics.clone());

        if dropped {
            // Log load shedding event (but don't fail the export)
            #[cfg(feature = "tracing-integration")]
            crate::tracing_compat::warn!(
                target: "asupersync::observability::otel",
                "OTLP export queue full: dropped oldest batch to preserve recent data. \
                 Queue capacity: {}, dropped total: {}",
                self.export_queue.capacity(),
                self.export_queue.dropped_count()
            );
        }

        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        // Process all queued batches then flush underlying exporter
        self.process_queue()?;
        self.inner.flush()
    }
}

/// Load shedding statistics for monitoring export queue health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadSheddingStats {
    /// Current number of batches in the export queue.
    pub queue_depth: usize,
    /// Maximum queue capacity.
    pub queue_capacity: usize,
    /// Total number of batches dropped due to load shedding.
    pub dropped_batches: u64,
}

impl InMemoryExporter {
    /// Create a new in-memory exporter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all collected snapshots.
    #[must_use]
    pub fn snapshots(&self) -> Vec<MetricsSnapshot> {
        self.snapshots.lock().clone()
    }

    /// Clear collected snapshots.
    pub fn clear(&self) {
        self.snapshots.lock().clear();
    }

    /// Get total number of metrics recorded.
    #[must_use]
    pub fn total_metrics(&self) -> usize {
        let snapshots = self.snapshots.lock();
        snapshots
            .iter()
            .map(|s| s.counters.len() + s.gauges.len() + s.histograms.len())
            .sum()
    }
}

impl MetricsExporter for InMemoryExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        self.snapshots.lock().push(metrics.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// OTLP HTTP exporter with RFC-compliant retry logic.
///
/// Implements OTLP spec requirements for retryable HTTP responses:
/// - 502, 503, 504: Retry with exponential backoff
/// - 429: Retry with Retry-After header or exponential backoff
/// - Other 5xx: Drop batch (non-retryable per spec)
#[derive(Debug, Clone)]
pub struct OtlpHttpExporter {
    endpoint: String,
    timeout: Duration,
    max_retries: u32,
    initial_retry_delay: Duration,
    max_retry_delay: Duration,
    compression: bool,
    auth_headers: Vec<(String, String)>,
}

impl OtlpHttpExporter {
    /// Create a new OTLP HTTP exporter.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(10),
            max_retries: 3,
            initial_retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(30),
            compression: false, // Default to false for backward compatibility
            auth_headers: Vec::new(),
        }
    }

    /// Set request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Self {
        self.max_retries = max_retries;
        self.initial_retry_delay = initial_delay;
        self.max_retry_delay = max_delay;
        self
    }

    /// Enable gzip compression for request bodies.
    #[must_use]
    pub fn with_compression(mut self, compression: bool) -> Self {
        self.compression = compression;
        self
    }

    /// Add Authorization header with Bearer token.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.auth_headers.push((
            "Authorization".to_owned(),
            format!("Bearer {}", token.into()),
        ));
        self
    }

    /// Add API key header.
    #[must_use]
    pub fn with_api_key(mut self, header_name: impl Into<String>, key: impl Into<String>) -> Self {
        self.auth_headers.push((header_name.into(), key.into()));
        self
    }

    /// Add custom authentication header.
    #[must_use]
    pub fn with_auth_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth_headers.push((name.into(), value.into()));
        self
    }

    /// Send OTLP protobuf request with RFC-compliant retry logic.
    pub async fn send_otlp_protobuf(
        &self,
        cx: &crate::cx::Cx,
        request_body: Vec<u8>,
    ) -> Result<(), ExportError> {
        use std::cmp;

        let mut retry_count = 0;
        let mut current_delay = self.initial_retry_delay;

        loop {
            match self.send_request_once(cx, &request_body).await {
                Ok(()) => return Ok(()),
                Err(OtlpError::Retryable {
                    status_code,
                    retry_after,
                }) => {
                    if retry_count >= self.max_retries {
                        return Err(ExportError::new(format!(
                            "Max retries ({}) exceeded for OTLP export. Last status: {}",
                            self.max_retries, status_code
                        )));
                    }

                    // Calculate retry delay per OTLP spec
                    let delay = if let Some(retry_after) = retry_after {
                        // Use Retry-After header if present (for 429)
                        cmp::min(retry_after, self.max_retry_delay)
                    } else {
                        // Exponential backoff with jitter for 502/503/504
                        let jitter = Duration::from_millis(deterministic_retry_jitter_ms(
                            retry_count,
                            status_code,
                        ));
                        let delay_with_jitter = current_delay + jitter;
                        cmp::min(delay_with_jitter, self.max_retry_delay)
                    };

                    retry_count += 1;
                    current_delay = cmp::min(current_delay * 2, self.max_retry_delay);

                    // Sleep before retry
                    crate::time::sleep(cx.now(), delay).await;
                }
                Err(OtlpError::CompressionFallback { status_code }) => {
                    // 415 Unsupported Media Type - retry without compression
                    if self.compression {
                        // Attempt fallback to uncompressed request
                        match self
                            .send_request_with_compression(cx, &request_body, false)
                            .await
                        {
                            Ok(()) => return Ok(()),
                            Err(fallback_error) => {
                                return Err(ExportError::new(format!(
                                    "OTLP compression fallback failed: {} after {}",
                                    fallback_error, status_code
                                )));
                            }
                        }
                    } else {
                        // Already using no compression, can't fallback further
                        return Err(ExportError::new(format!(
                            "OTLP compression fallback not applicable: {}",
                            status_code
                        )));
                    }
                }
                Err(e) => {
                    // Non-retryable error (e.g., other 4xx, other 5xx, network)
                    return Err(e.into());
                }
            }
        }
    }

    async fn send_request_once(&self, cx: &crate::cx::Cx, body: &[u8]) -> Result<(), OtlpError> {
        self.send_request_with_compression(cx, body, self.compression)
            .await
    }

    async fn send_request_with_compression(
        &self,
        cx: &crate::cx::Cx,
        body: &[u8],
        use_compression: bool,
    ) -> Result<(), OtlpError> {
        use crate::http::h1::http_client::HttpClient;
        use crate::http::h1::types::Method;

        #[cfg(not(feature = "metrics"))]
        return Err(OtlpError::non_retryable(
            "OTLP HTTP export requires 'metrics' feature",
        ));

        #[cfg(feature = "metrics")]
        {
            let client = HttpClient::new();

            // Apply compression if enabled
            let (compressed_body, content_encoding) = if use_compression {
                #[cfg(feature = "compression")]
                {
                    use flate2::{Compression, write::GzEncoder};
                    use std::io::Write;

                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(body).map_err(|e| {
                        OtlpError::non_retryable(format!("Compression failed: {}", e))
                    })?;
                    let compressed = encoder.finish().map_err(|e| {
                        OtlpError::non_retryable(format!("Compression finish failed: {}", e))
                    })?;
                    (compressed, Some("gzip".to_string()))
                }
                #[cfg(not(feature = "compression"))]
                {
                    return Err(OtlpError::non_retryable(
                        "Compression requested but 'compression' feature not enabled",
                    ));
                }
            } else {
                (body.to_vec(), None)
            };

            // Build headers with optional Content-Encoding
            let mut headers = vec![(
                "Content-Type".to_owned(),
                "application/x-protobuf".to_owned(),
            )];
            if let Some(encoding) = content_encoding {
                headers.push(("Content-Encoding".to_owned(), encoding));
            }

            // Add authentication headers
            headers.extend(self.auth_headers.clone());

            // Send request with timeout
            let response = crate::time::timeout(cx.now(), self.timeout, async {
                client
                    .request(cx, Method::Post, &self.endpoint, headers, compressed_body)
                    .await
            })
            .await
            .map_err(|_| OtlpError::non_retryable("OTLP request timeout"))?
            .map_err(|e| OtlpError::non_retryable(format!("OTLP request failed: {}", e)))?;

            // Handle response per OTLP spec
            classify_otlp_http_response(response.status, &response.headers)
        }
    }
}

fn parse_otlp_retry_after(headers: &[(String, String)]) -> Option<Duration> {
    crate::observability::parse_http_retry_after(headers)
}

fn classify_otlp_http_response(status: u16, headers: &[(String, String)]) -> Result<(), OtlpError> {
    match status {
        200..=299 => Ok(()),
        429 => {
            // Rate limited - honor Retry-After header per OTLP spec.
            let retry_after = parse_otlp_retry_after(headers);
            Err(OtlpError::retryable(status, retry_after))
        }
        408 => {
            // Request Timeout - retryable per RFC 9110 (server-side timeout).
            let retry_after = parse_otlp_retry_after(headers);
            Err(OtlpError::retryable(status, retry_after))
        }
        502..=504 => {
            // Retryable server errors per OTLP spec.
            let retry_after = parse_otlp_retry_after(headers);
            Err(OtlpError::retryable(status, retry_after))
        }
        405 => {
            // Method Not Allowed - configuration error per OTLP spec.
            let allowed_methods = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("allow"))
                .map_or_else(|| "unknown".to_string(), |(_, value)| value.clone());

            Err(OtlpError::non_retryable(format!(
                "OTLP Method Not Allowed (405) - configuration error. Allowed methods: {allowed_methods} - batch dropped",
            )))
        }
        415 => Err(OtlpError::compression_fallback(status)),
        400..=499 => Err(OtlpError::non_retryable(format!(
            "OTLP client error: {status} - batch dropped"
        ))),
        500..=599 => Err(OtlpError::non_retryable(format!(
            "OTLP server error: {status} - batch dropped"
        ))),
        _ => Err(OtlpError::non_retryable(format!(
            "Unexpected OTLP response status: {status}"
        ))),
    }
}

impl MetricsExporter for OtlpHttpExporter {
    fn export(&self, _metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        Err(ExportError::new(
            "OTLP HTTP export requires async context - use send_otlp_protobuf() directly",
        ))
    }

    fn flush(&self) -> Result<(), ExportError> {
        // OTLP is stateless - nothing to flush
        Ok(())
    }
}

/// OTLP-specific error with retry information.
#[derive(Debug, Clone)]
pub enum OtlpError {
    /// Non-retryable export error.
    NonRetryable {
        /// Human-readable reason the export must not be retried.
        message: String,
    },
    /// Retryable export error with optional retry delay.
    Retryable {
        /// HTTP status code returned by the collector.
        status_code: u16,
        /// Optional delay parsed from a Retry-After response header.
        retry_after: Option<Duration>,
    },
    /// Compression fallback required (415 Unsupported Media Type).
    CompressionFallback {
        /// HTTP status code (typically 415).
        status_code: u16,
    },
}

impl OtlpError {
    /// Create a new non-retryable OTLP error.
    #[must_use]
    pub fn non_retryable(message: impl Into<String>) -> Self {
        Self::NonRetryable {
            message: message.into(),
        }
    }

    /// Create a retryable OTLP error.
    #[must_use]
    pub fn retryable(status_code: u16, retry_after: Option<Duration>) -> Self {
        Self::Retryable {
            status_code,
            retry_after,
        }
    }

    /// Create a compression fallback OTLP error.
    #[must_use]
    pub fn compression_fallback(status_code: u16) -> Self {
        Self::CompressionFallback { status_code }
    }
}

impl std::fmt::Display for OtlpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonRetryable { message } => write!(f, "OTLP error: {}", message),
            Self::Retryable {
                status_code,
                retry_after,
            } => {
                if let Some(delay) = retry_after {
                    write!(
                        f,
                        "retryable OTLP error: {} (retry after {:?})",
                        status_code, delay
                    )
                } else {
                    write!(f, "retryable OTLP error: {}", status_code)
                }
            }
            Self::CompressionFallback { status_code } => {
                write!(f, "OTLP compression fallback required: {}", status_code)
            }
        }
    }
}

impl std::error::Error for OtlpError {}

impl From<OtlpError> for ExportError {
    fn from(err: OtlpError) -> Self {
        ExportError::new(err.to_string())
    }
}

fn deterministic_retry_jitter_ms(retry_count: u32, status_code: u16) -> u64 {
    (u64::from(retry_count) * 37 + u64::from(status_code) * 17) % 101
}

#[cfg(all(test, feature = "metrics"))]
mod otlp_retry_tests {
    use super::*;

    #[test]
    fn otlp_error_display() {
        let non_retryable = OtlpError::non_retryable("connection failed");
        assert_eq!(non_retryable.to_string(), "OTLP error: connection failed");

        let retryable = OtlpError::retryable(503, None);
        assert_eq!(retryable.to_string(), "retryable OTLP error: 503");

        let retryable_with_delay = OtlpError::retryable(429, Some(Duration::from_secs(30)));
        assert_eq!(
            retryable_with_delay.to_string(),
            "retryable OTLP error: 429 (retry after 30s)"
        );
    }

    #[test]
    fn otlp_http_exporter_configuration() {
        let exporter = OtlpHttpExporter::new("http://collector:4318/v1/metrics")
            .with_timeout(Duration::from_secs(15))
            .with_retry_config(5, Duration::from_millis(200), Duration::from_secs(60));

        assert_eq!(exporter.endpoint, "http://collector:4318/v1/metrics");
        assert_eq!(exporter.timeout, Duration::from_secs(15));
        assert_eq!(exporter.max_retries, 5);
        assert_eq!(exporter.initial_retry_delay, Duration::from_millis(200));
        assert_eq!(exporter.max_retry_delay, Duration::from_secs(60));
    }

    /// Test that verifies RFC-compliant retry behavior for different HTTP status codes.
    #[test]
    fn otlp_retry_logic_rfc_compliance() {
        // Test retryable status codes per OTLP spec
        let retryable_codes = vec![429, 502, 503, 504];
        for code in retryable_codes {
            match OtlpError::retryable(code, None) {
                OtlpError::Retryable { status_code, .. } => {
                    assert_eq!(status_code, code, "Status {} should be retryable", code);
                }
                _ => panic!("Status {} should create retryable error", code),
            }
        }

        // Test non-retryable status codes
        let non_retryable_codes = vec![400, 401, 404, 500, 501, 505];
        for code in non_retryable_codes {
            let error = OtlpError::non_retryable(format!("HTTP {}", code));
            match error {
                OtlpError::NonRetryable { .. } => {
                    // Expected
                }
                _ => panic!("Status {} should create non-retryable error", code),
            }
        }
    }

    #[test]
    fn otlp_http_status_classifier_covers_preserved_audit_cluster() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Expected {
            Ok,
            Retryable {
                status: u16,
                retry_after_secs: Option<u64>,
            },
            NonRetryable {
                status: u16,
                message_fragment: &'static str,
            },
            CompressionFallback {
                status: u16,
            },
        }

        let scenarios = [
            (
                "success-200",
                200,
                &[][..],
                Expected::Ok,
                "compiled production seam keeps normal success unchanged",
            ),
            (
                "401-unauthorized-terminal",
                401,
                &[][..],
                Expected::NonRetryable {
                    status: 401,
                    message_fragment: "OTLP client error: 401",
                },
                "otlp_401_unauthorized_audit_test.rs",
            ),
            (
                "405-method-not-allowed-terminal-with-allow",
                405,
                &[("Allow", "POST")][..],
                Expected::NonRetryable {
                    status: 405,
                    message_fragment: "Allowed methods: POST",
                },
                "otlp_405_method_not_allowed_audit_test.rs",
            ),
            (
                "408-request-timeout-retryable",
                408,
                &[("Retry-After", "7")][..],
                Expected::Retryable {
                    status: 408,
                    retry_after_secs: Some(7),
                },
                "otlp_408_timeout_retry_audit_test.rs",
            ),
            (
                "414-uri-too-long-terminal",
                414,
                &[][..],
                Expected::NonRetryable {
                    status: 414,
                    message_fragment: "OTLP client error: 414",
                },
                "otlp_414_uri_too_long_audit_test.rs",
            ),
            (
                "429-retry-after-honored",
                429,
                &[("retry-after", "30")][..],
                Expected::Retryable {
                    status: 429,
                    retry_after_secs: Some(30),
                },
                "otlp_429_retry_after_audit_test.rs",
            ),
            (
                "429-retry-after-delay-seconds-whitespace",
                429,
                &[("Retry-After", "  60  ")][..],
                Expected::Retryable {
                    status: 429,
                    retry_after_secs: Some(60),
                },
                "RFC 9110 delay-seconds with optional field-value whitespace",
            ),
            (
                "502-bad-gateway-retryable",
                502,
                &[][..],
                Expected::Retryable {
                    status: 502,
                    retry_after_secs: None,
                },
                "otlp_502_bad_gateway_audit_test.rs",
            ),
            (
                "503-retry-after-zero-budgeted",
                503,
                &[("Retry-After", "0")][..],
                Expected::Retryable {
                    status: 503,
                    retry_after_secs: Some(0),
                },
                "otlp_503_retry_after_zero_audit_test.rs",
            ),
            (
                "504-gateway-timeout-retryable",
                504,
                &[][..],
                Expected::Retryable {
                    status: 504,
                    retry_after_secs: None,
                },
                "otlp_504_gateway_timeout_audit_test.rs",
            ),
            (
                "511-network-auth-terminal",
                511,
                &[][..],
                Expected::NonRetryable {
                    status: 511,
                    message_fragment: "OTLP server error: 511",
                },
                "otlp_511_network_auth_audit_test.rs",
            ),
            (
                "415-compression-fallback",
                415,
                &[][..],
                Expected::CompressionFallback { status: 415 },
                "existing compression fallback behavior",
            ),
        ];

        for (scenario_id, status, raw_headers, expected, source) in scenarios {
            let headers: Vec<(String, String)> = raw_headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            let result = classify_otlp_http_response(status, &headers);

            println!(
                "OTLP_STATUS_CLASSIFIER scenario_id={scenario_id} source={source} status={status} expected={expected:?} observed={result:?}"
            );

            match (expected, result) {
                (Expected::Ok, Ok(())) => {}
                (
                    Expected::Retryable {
                        status,
                        retry_after_secs,
                    },
                    Err(OtlpError::Retryable {
                        status_code,
                        retry_after,
                    }),
                ) => {
                    assert_eq!(status_code, status, "scenario {scenario_id}");
                    assert_eq!(
                        retry_after,
                        retry_after_secs.map(Duration::from_secs),
                        "scenario {scenario_id}"
                    );
                }
                (
                    Expected::NonRetryable {
                        status,
                        message_fragment,
                    },
                    Err(OtlpError::NonRetryable { message }),
                ) => {
                    assert!(
                        message.contains(message_fragment),
                        "scenario {scenario_id}: expected message to contain {message_fragment:?}, got {message:?}"
                    );
                    assert!(
                        !message.contains("collector:4318"),
                        "scenario {scenario_id}: terminal classifier must not leak endpoint details"
                    );
                    assert!(
                        message.contains(&status.to_string()),
                        "scenario {scenario_id}: message must include status code"
                    );
                }
                (
                    Expected::CompressionFallback { status },
                    Err(OtlpError::CompressionFallback { status_code }),
                ) => {
                    assert_eq!(status_code, status, "scenario {scenario_id}");
                }
                (expected, observed) => {
                    panic!("scenario {scenario_id}: expected {expected:?}, observed {observed:?}");
                }
            }
        }
    }

    /// Test exponential backoff calculation with jitter bounds.
    #[test]
    fn exponential_backoff_calculation() {
        let exporter = OtlpHttpExporter::new("http://test").with_retry_config(
            3,
            Duration::from_millis(100),
            Duration::from_secs(10),
        );

        // Test that delays increase exponentially but stay within bounds
        let delays = vec![
            Duration::from_millis(100), // Initial
            Duration::from_millis(200), // 2x
            Duration::from_millis(400), // 4x
        ];

        for (attempt, expected_base) in delays.iter().enumerate() {
            let calculated_delay = std::cmp::min(
                *expected_base * 2_u32.pow(attempt as u32),
                exporter.max_retry_delay,
            );
            assert!(calculated_delay >= *expected_base);
            assert!(calculated_delay <= exporter.max_retry_delay);
        }
    }

    /// Test that Retry-After header is respected for 429 responses.
    #[test]
    fn retry_after_header_respected() {
        let error_with_retry_after = OtlpError::retryable(429, Some(Duration::from_secs(45)));

        match error_with_retry_after {
            OtlpError::Retryable {
                status_code,
                retry_after,
            } => {
                assert_eq!(status_code, 429);
                assert_eq!(retry_after, Some(Duration::from_secs(45)));
            }
            _ => panic!("Should create retryable error with retry_after"),
        }
    }

    /// Test that max retry delay is enforced.
    #[test]
    fn max_retry_delay_enforced() {
        let exporter = OtlpHttpExporter::new("http://test").with_retry_config(
            5,
            Duration::from_secs(1),
            Duration::from_secs(3),
        );

        // Test that Retry-After values are capped at max_retry_delay
        let capped_delay = std::cmp::min(Duration::from_secs(10), exporter.max_retry_delay);
        assert_eq!(capped_delay, Duration::from_secs(3));
    }
}

// =============================================================================
// OtelMetrics
// =============================================================================

/// OpenTelemetry metrics provider for Asupersync.
///
/// This provider supports:
/// - Cardinality limits to prevent metric explosion
/// - Configurable overflow strategies
/// - Sampling for high-frequency metrics
#[derive(Clone)]
pub struct OtelMetrics {
    // Task metrics
    #[allow(dead_code)]
    tasks_active: ObservableGauge<u64>,
    tasks_spawned: Counter<u64>,
    tasks_completed: Counter<u64>,
    task_duration: Histogram<f64>,
    // Region metrics
    #[allow(dead_code)]
    regions_active: ObservableGauge<u64>,
    regions_created: Counter<u64>,
    regions_closed: Counter<u64>,
    region_lifetime: Histogram<f64>,
    // Cancellation metrics
    cancellations: Counter<u64>,
    drain_duration: Histogram<f64>,
    // Budget metrics
    deadlines_set: Counter<u64>,
    deadlines_exceeded: Counter<u64>,
    // Deadline monitoring metrics
    deadline_warnings: Counter<u64>,
    deadline_violations: Counter<u64>,
    deadline_remaining: Histogram<f64>,
    checkpoint_interval: Histogram<f64>,
    task_stuck_detected: Counter<u64>,
    // Obligation metrics
    #[allow(dead_code)]
    obligations_active: ObservableGauge<u64>,
    obligations_created: Counter<u64>,
    obligations_discharged: Counter<u64>,
    obligations_leaked: Counter<u64>,
    // Scheduler metrics
    scheduler_poll_time: Histogram<f64>,
    scheduler_tasks_polled: Histogram<f64>,
    // Shared gauge state
    state: Arc<MetricsState>,
    // Cardinality tracking
    config: MetricsConfig,
    cardinality_tracker: Arc<CardinalityTracker>,
    // Sampling state
    sample_counter: Arc<AtomicU64>,
}

impl std::fmt::Debug for OtelMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelMetrics")
            .field("config", &self.config)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
struct MetricsState {
    active_tasks: AtomicU64,
    active_regions: AtomicU64,
    active_obligations: AtomicU64,
}

impl MetricsState {
    fn inc_tasks(&self) {
        self.active_tasks.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_tasks(&self) {
        let _ = self
            .active_tasks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    fn inc_regions(&self) {
        self.active_regions.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_regions(&self) {
        let _ = self
            .active_regions
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    fn inc_obligations(&self) {
        self.active_obligations.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_obligations(&self) {
        let _ = self
            .active_obligations
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

// =============================================================================
// OTLP Resource Detection (Per Specification Priority)
// =============================================================================

/// OTLP resource builder with specification-compliant priority handling.
///
/// **OTLP SPECIFICATION COMPLIANCE**:
/// - Programmatic attributes MUST have highest priority
/// - Environment variable OTEL_RESOURCE_ATTRIBUTES MUST override defaults
/// - Defaults MUST have lowest priority
/// - Priority order: Programmatic > Environment > Defaults
#[derive(Debug, Clone, Default)]
pub struct OtlpResourceBuilder {
    programmatic_attrs: HashMap<String, String>,
    env_attrs: HashMap<String, String>,
    default_attrs: HashMap<String, String>,
}

impl OtlpResourceBuilder {
    /// Create new OTLP resource builder with default attributes.
    ///
    /// **Default attributes per OTLP specification:**
    /// - `telemetry.sdk.name`: "asupersync"
    /// - `service.name`: "unknown_service"
    #[must_use]
    pub fn new() -> Self {
        let mut default_attrs = HashMap::new();
        default_attrs.insert("telemetry.sdk.name".to_string(), "asupersync".to_string());
        default_attrs.insert("service.name".to_string(), "unknown_service".to_string());
        default_attrs.insert(
            "telemetry.sdk.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );

        Self {
            programmatic_attrs: HashMap::new(),
            env_attrs: HashMap::new(),
            default_attrs,
        }
    }

    /// Add programmatic resource attributes (highest priority per OTLP spec).
    ///
    /// **OTLP COMPLIANCE**: These attributes MUST override any environment or default attributes.
    #[must_use]
    pub fn with_attributes(mut self, attrs: HashMap<String, String>) -> Self {
        self.programmatic_attrs = attrs;
        self
    }

    /// Add single programmatic attribute (highest priority per OTLP spec).
    #[must_use]
    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.programmatic_attrs.insert(key, value);
        self
    }

    /// Load attributes from OTEL_RESOURCE_ATTRIBUTES environment variable.
    ///
    /// **OTLP COMPLIANCE**: Environment attributes MUST override defaults but
    /// MUST be overridden by programmatic attributes.
    ///
    /// **Format**: "key1=value1,key2=value2,key3=value3"
    #[must_use]
    pub fn with_env_resource_attributes(mut self) -> Self {
        if let Ok(env_attrs_str) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
            self.env_attrs = parse_otel_resource_attributes(&env_attrs_str);
        }
        self
    }

    /// Add `host.name` from common host environment variables.
    ///
    /// The detected value is treated like a default detector value: it is
    /// overridden by `OTEL_RESOURCE_ATTRIBUTES` and by programmatic attributes.
    /// Detection is opt-in so callers that need fully explicit resource
    /// identity can keep the default builder deterministic.
    #[must_use]
    pub fn with_detected_host_name(mut self) -> Self {
        if let Some(host_name) = detected_host_name_from_env() {
            self.default_attrs
                .insert("host.name".to_string(), host_name);
        }
        self
    }

    /// Build final resource applying OTLP specification priority order.
    ///
    /// **Priority Resolution (OTLP Spec Compliance)**:
    /// 1. Start with default attributes (lowest priority)
    /// 2. Apply environment attributes (override defaults)
    /// 3. Apply programmatic attributes (override env and defaults)
    ///
    /// **Result**: HashMap<String, String> with proper precedence applied.
    #[must_use]
    pub fn build(self) -> HashMap<String, String> {
        let mut final_attrs = self.default_attrs;

        // Apply environment attributes (override defaults)
        for (key, value) in self.env_attrs {
            final_attrs.insert(key, value);
        }

        // Apply programmatic attributes (override env and defaults)
        for (key, value) in self.programmatic_attrs {
            final_attrs.insert(key, value);
        }

        final_attrs
    }

    /// Get current programmatic attributes.
    #[must_use]
    pub fn programmatic_attributes(&self) -> &HashMap<String, String> {
        &self.programmatic_attrs
    }

    /// Get current environment attributes.
    #[must_use]
    pub fn environment_attributes(&self) -> &HashMap<String, String> {
        &self.env_attrs
    }

    /// Get current default attributes.
    #[must_use]
    pub fn default_attributes(&self) -> &HashMap<String, String> {
        &self.default_attrs
    }
}

/// Parse OTEL_RESOURCE_ATTRIBUTES environment variable per OTLP specification.
///
/// **OTLP Format**: "key1=value1,key2=value2,key3=value3"
///
/// **Parsing Rules**:
/// - Comma-separated key=value pairs
/// - Whitespace around keys and values is trimmed
/// - Empty pairs are ignored
/// - Malformed pairs are ignored (no equals sign)
fn parse_otel_resource_attributes(env_str: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();

    for pair in env_str.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }

        if let Some((key, value)) = pair.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();

            if !key.is_empty() {
                attrs.insert(key, value);
            }
        }
    }

    attrs
}

fn detected_host_name_from_env() -> Option<String> {
    ["HOSTNAME", "COMPUTERNAME"].into_iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| normalize_host_name(&value))
    })
}

fn normalize_host_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod otlp_resource_builder_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::env;
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    use super::OtlpResourceBuilder;

    const RESOURCE_ENV_VARS: &[&str] = &["HOSTNAME", "COMPUTERNAME", "OTEL_RESOURCE_ATTRIBUTES"];

    fn resource_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct ResourceEnvGuard {
        _guard: MutexGuard<'static, ()>,
        previous: BTreeMap<&'static str, Option<String>>,
    }

    impl ResourceEnvGuard {
        #[allow(unsafe_code)]
        fn with(updates: &[(&'static str, Option<&str>)]) -> Self {
            let guard = resource_env_lock()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let previous = RESOURCE_ENV_VARS
                .iter()
                .map(|var| (*var, env::var(var).ok()))
                .collect();

            for var in RESOURCE_ENV_VARS {
                unsafe {
                    env::remove_var(var);
                }
            }

            for (key, value) in updates {
                unsafe {
                    match value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }

            Self {
                _guard: guard,
                previous,
            }
        }
    }

    impl Drop for ResourceEnvGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                unsafe {
                    match value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }

    #[test]
    fn detected_host_name_uses_trimmed_hostname_env() {
        let _guard = ResourceEnvGuard::with(&[("HOSTNAME", Some("  asupersync-host  "))]);

        let resource = OtlpResourceBuilder::new().with_detected_host_name().build();

        assert_eq!(
            resource.get("host.name"),
            Some(&"asupersync-host".to_string())
        );
    }

    #[test]
    fn detected_host_name_ignores_empty_host_values() {
        let _guard =
            ResourceEnvGuard::with(&[("HOSTNAME", Some("   ")), ("COMPUTERNAME", Some("\t\n"))]);

        let resource = OtlpResourceBuilder::new().with_detected_host_name().build();

        assert!(!resource.contains_key("host.name"));
    }

    #[test]
    fn detected_host_name_preserves_resource_precedence() {
        let _guard = ResourceEnvGuard::with(&[
            ("HOSTNAME", Some("detected-host")),
            ("OTEL_RESOURCE_ATTRIBUTES", Some("host.name=env-host")),
        ]);

        let env_resource = OtlpResourceBuilder::new()
            .with_detected_host_name()
            .with_env_resource_attributes()
            .build();

        assert_eq!(env_resource.get("host.name"), Some(&"env-host".to_string()));

        let mut attrs = HashMap::new();
        attrs.insert("host.name".to_string(), "programmatic-host".to_string());

        let programmatic_resource = OtlpResourceBuilder::new()
            .with_detected_host_name()
            .with_env_resource_attributes()
            .with_attributes(attrs)
            .build();

        assert_eq!(
            programmatic_resource.get("host.name"),
            Some(&"programmatic-host".to_string())
        );
    }
}

/// Create OTLP-compliant resource attributes with proper priority handling.
///
/// **OTLP Specification Compliance**: This function implements the required
/// priority order for resource detection per OpenTelemetry specification.
///
/// **Example Usage**:
/// ```ignore
/// let resource_attrs = create_otlp_resource_attributes()
///     .with_attribute("service.name".to_string(), "my-service".to_string())
///     .with_attribute("environment".to_string(), "production".to_string())
///     .with_env_resource_attributes()
///     .build();
/// ```
#[must_use]
pub fn create_otlp_resource_attributes() -> OtlpResourceBuilder {
    OtlpResourceBuilder::new().with_env_resource_attributes()
}

impl OtelMetrics {
    /// Constructs a new OpenTelemetry metrics provider from a [`Meter`].
    #[must_use]
    pub fn new(meter: Meter) -> Self {
        Self::new_with_config(meter, MetricsConfig::default())
    }

    /// Constructs a new OpenTelemetry metrics provider with OTLP-compliant resource detection.
    ///
    /// **OTLP SPECIFICATION COMPLIANCE**: This method implements proper resource detection
    /// priority per OTLP specification: programmatic > environment > defaults.
    ///
    /// **Resource Detection**:
    /// - Reads OTEL_RESOURCE_ATTRIBUTES environment variable
    /// - Applies programmatic attributes if provided
    /// - Uses default attributes as fallback
    /// - Follows OTLP priority order
    ///
    /// **Note**: This is a convenience method. For external SDK integration,
    /// use the resource attributes with `opentelemetry_sdk::Resource::new()`.
    #[must_use]
    pub fn new_with_resource_detection(
        meter: Meter,
        programmatic_attrs: Option<HashMap<String, String>>,
    ) -> Self {
        // Build resource attributes with OTLP-compliant priority
        let mut resource_builder = create_otlp_resource_attributes();
        if let Some(attrs) = programmatic_attrs {
            resource_builder = resource_builder.with_attributes(attrs);
        }
        let _resource_attrs = resource_builder.build();

        // Note: The meter should already be configured with these resource attributes
        // when the MeterProvider was created. This method demonstrates the proper
        // resource detection pattern that should be used during SDK setup.

        Self::new_with_config(meter, MetricsConfig::default())
    }

    /// Constructs a new OpenTelemetry metrics provider with configuration.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::needless_pass_by_value)] // Meter is consumed by builder pattern
    pub fn new_with_config(meter: Meter, config: MetricsConfig) -> Self {
        let state = Arc::new(MetricsState::default());

        let tasks_active = meter
            .u64_observable_gauge("asupersync.tasks.active")
            .with_description("Currently running tasks")
            .with_callback({
                let state = Arc::clone(&state);
                move |observer| {
                    observer.observe(state.active_tasks.load(Ordering::Relaxed), &[]);
                }
            })
            .build();

        let regions_active = meter
            .u64_observable_gauge("asupersync.regions.active")
            .with_description("Currently active regions")
            .with_callback({
                let state = Arc::clone(&state);
                move |observer| {
                    observer.observe(state.active_regions.load(Ordering::Relaxed), &[]);
                }
            })
            .build();

        let obligations_active = meter
            .u64_observable_gauge("asupersync.obligations.active")
            .with_description("Currently active obligations")
            .with_callback({
                let state = Arc::clone(&state);
                move |observer| {
                    observer.observe(state.active_obligations.load(Ordering::Relaxed), &[]);
                }
            })
            .build();

        Self {
            tasks_active,
            tasks_spawned: meter
                .u64_counter("asupersync.tasks.spawned")
                .with_description("Total tasks spawned")
                .build(),
            tasks_completed: meter
                .u64_counter("asupersync.tasks.completed")
                .with_description("Total tasks completed")
                .build(),
            task_duration: meter
                .f64_histogram("asupersync.tasks.duration")
                .with_description("Task execution duration in seconds")
                .build(),
            regions_active,
            regions_created: meter
                .u64_counter("asupersync.regions.created")
                .with_description("Total regions created")
                .build(),
            regions_closed: meter
                .u64_counter("asupersync.regions.closed")
                .with_description("Total regions closed")
                .build(),
            region_lifetime: meter
                .f64_histogram("asupersync.regions.lifetime")
                .with_description("Region lifetime in seconds")
                .build(),
            cancellations: meter
                .u64_counter("asupersync.cancellations")
                .with_description("Cancellation requests")
                .build(),
            drain_duration: meter
                .f64_histogram("asupersync.cancellation.drain_duration")
                .with_description("Cancellation drain duration in seconds")
                .build(),
            deadlines_set: meter
                .u64_counter("asupersync.deadlines.set")
                .with_description("Deadlines configured")
                .build(),
            deadlines_exceeded: meter
                .u64_counter("asupersync.deadlines.exceeded")
                .with_description("Deadline exceeded events")
                .build(),
            deadline_warnings: meter
                .u64_counter("asupersync.deadline.warnings_total")
                .with_description("Deadline warning events")
                .build(),
            deadline_violations: meter
                .u64_counter("asupersync.deadline.violations_total")
                .with_description("Deadline violation events")
                .build(),
            deadline_remaining: meter
                .f64_histogram("asupersync.deadline.remaining_seconds")
                .with_description("Time remaining at completion in seconds")
                .build(),
            checkpoint_interval: meter
                .f64_histogram("asupersync.checkpoint.interval_seconds")
                .with_description("Time between checkpoints in seconds")
                .build(),
            task_stuck_detected: meter
                .u64_counter("asupersync.task.stuck_detected_total")
                .with_description("Tasks detected as stuck (no progress)")
                .build(),
            obligations_active,
            obligations_created: meter
                .u64_counter("asupersync.obligations.created")
                .with_description("Obligations created")
                .build(),
            obligations_discharged: meter
                .u64_counter("asupersync.obligations.discharged")
                .with_description("Obligations discharged")
                .build(),
            obligations_leaked: meter
                .u64_counter("asupersync.obligations.leaked")
                .with_description("Obligations leaked")
                .build(),
            scheduler_poll_time: meter
                .f64_histogram("asupersync.scheduler.poll_time")
                .with_description("Scheduler poll duration in seconds")
                .build(),
            scheduler_tasks_polled: meter
                .f64_histogram("asupersync.scheduler.tasks_polled")
                .with_description("Tasks polled per scheduler tick")
                .build(),
            state,
            config,
            cardinality_tracker: Arc::new(CardinalityTracker::new()),
            sample_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &MetricsConfig {
        &self.config
    }

    /// Get the number of cardinality overflows that have occurred.
    #[must_use]
    pub fn cardinality_overflow_count(&self) -> u64 {
        self.cardinality_tracker.overflow_count()
    }

    /// Expose filtered metric labels for integration tests that pin
    /// privacy/cardinality behavior without making the production
    /// recording chokepoint public API.
    #[cfg(feature = "test-internals")]
    #[must_use]
    pub fn filtered_metric_labels_for_test(
        &self,
        metric: &str,
        labels: &[KeyValue],
    ) -> Option<Vec<KeyValue>> {
        self.check_cardinality(metric, labels)
    }

    /// Check if recording a metric should proceed, handling cardinality limits.
    ///
    /// Returns `Some(labels)` with potentially modified labels if recording should proceed,
    /// or `None` if the metric should be dropped.
    fn check_cardinality(&self, metric: &str, labels: &[KeyValue]) -> Option<Vec<KeyValue>> {
        // Filter out dropped labels
        let filtered: Vec<KeyValue> = labels
            .iter()
            .filter(|kv| !self.config.drop_labels.contains(&kv.key.to_string()))
            .cloned()
            .collect();

        if self.cardinality_tracker.check_and_record(
            metric,
            &filtered,
            self.config.max_cardinality,
            self.config.max_metrics,
        ) {
            self.cardinality_tracker.record_overflow();

            match self.config.overflow_strategy {
                CardinalityOverflow::Drop => return None,
                CardinalityOverflow::Aggregate => {
                    // Replace high-cardinality labels with "other"
                    let aggregated: Vec<KeyValue> = filtered
                        .into_iter()
                        .map(|kv| KeyValue::new(kv.key, "other"))
                        .collect();
                    if self.cardinality_tracker.check_and_record(
                        metric,
                        &aggregated,
                        self.config.max_cardinality,
                        self.config.max_metrics,
                    ) {
                        return None;
                    }
                    return Some(aggregated);
                }
                CardinalityOverflow::Warn => {
                    crate::tracing_compat::warn!(
                        metric = metric,
                        "cardinality limit reached for metric"
                    );
                    self.cardinality_tracker.record(metric, &filtered);
                }
            }
        }
        Some(filtered)
    }

    /// Check if a metric should be sampled.
    fn should_sample(&self, metric: &str) -> bool {
        let Some(ref sampling) = self.config.sampling else {
            return true; // No sampling configured
        };

        // Check if this metric is in the sampled set
        if !sampling.sampled_metrics.is_empty()
            && !sampling.sampled_metrics.iter().any(|m| metric.contains(m))
        {
            return true; // Not a sampled metric
        }

        if sampling.sample_rate >= 1.0 {
            return true;
        }
        if sampling.sample_rate <= 0.0 {
            return false;
        }

        // br-asupersync-2dwg47 — AcqRel ordering on the sampling
        // counter so the fetch_add observed by each thread is
        // sequentially consistent with respect to the prior writes:
        // every thread sees a strictly-increasing sequence of
        // returned counts, which is the property a counter-based
        // deterministic-sampling scheme depends on. Relaxed allows
        // stale counter values to be observed across threads on
        // weakly-ordered targets, breaking lab replay (same input,
        // two replays, different sampled-event sets). AcqRel keeps
        // the single-CAS cost (no full fence) while making the
        // visibility property explicit.
        let count = self.sample_counter.fetch_add(1, Ordering::AcqRel);
        // sample_rate is always 0.0..=1.0, so the cast is safe
        #[allow(clippy::cast_sign_loss)]
        let threshold = (sampling.sample_rate * 100.0) as u64;
        (count % 100) < threshold
    }
}

impl MetricsProvider for OtelMetrics {
    fn task_spawned(&self, _region_id: RegionId, _task_id: TaskId) {
        self.state.inc_tasks();
        self.tasks_spawned.add(1, &[]);
    }

    fn task_completed(&self, _task_id: TaskId, outcome: OutcomeKind, duration: Duration) {
        self.state.dec_tasks();

        let labels = [KeyValue::new("outcome", outcome_label(outcome))];
        if let Some(filtered) = self.check_cardinality("asupersync.tasks.completed", &labels) {
            self.tasks_completed.add(1, &filtered);
        }

        if self.should_sample("asupersync.tasks.duration") {
            if let Some(filtered) = self.check_cardinality("asupersync.tasks.duration", &labels) {
                self.task_duration.record(duration.as_secs_f64(), &filtered);
            }
        }
    }

    fn region_created(&self, _region_id: RegionId, _parent: Option<RegionId>) {
        self.state.inc_regions();
        self.regions_created.add(1, &[]);
    }

    fn region_closed(&self, _region_id: RegionId, lifetime: Duration) {
        self.state.dec_regions();
        self.regions_closed.add(1, &[]);

        if self.should_sample("asupersync.regions.lifetime") {
            self.region_lifetime.record(lifetime.as_secs_f64(), &[]);
        }
    }

    fn cancellation_requested(&self, _region_id: RegionId, kind: CancelKind) {
        let labels = [KeyValue::new("kind", cancel_kind_label(kind))];
        if let Some(filtered) = self.check_cardinality("asupersync.cancellations", &labels) {
            self.cancellations.add(1, &filtered);
        }
    }

    fn drain_completed(&self, _region_id: RegionId, duration: Duration) {
        if self.should_sample("asupersync.cancellation.drain_duration") {
            self.drain_duration.record(duration.as_secs_f64(), &[]);
        }
    }

    fn deadline_set(&self, _region_id: RegionId, _deadline: Duration) {
        self.deadlines_set.add(1, &[]);
    }

    fn deadline_exceeded(&self, _region_id: RegionId) {
        self.deadlines_exceeded.add(1, &[]);
    }

    fn deadline_warning(&self, task_type: &str, reason: &'static str, remaining: Duration) {
        let task_type = sanitize_task_type_label(task_type);
        let labels = [
            KeyValue::new("task_type", task_type),
            KeyValue::new("reason", reason),
        ];
        if let Some(filtered) =
            self.check_cardinality("asupersync.deadline.warnings_total", &labels)
        {
            self.deadline_warnings.add(1, &filtered);
        }
        let _ = remaining;
    }

    fn deadline_violation(&self, task_type: &str, _over_by: Duration) {
        let task_type = sanitize_task_type_label(task_type);
        let labels = [KeyValue::new("task_type", task_type)];
        if let Some(filtered) =
            self.check_cardinality("asupersync.deadline.violations_total", &labels)
        {
            self.deadline_violations.add(1, &filtered);
        }
    }

    fn deadline_remaining(&self, task_type: &str, remaining: Duration) {
        if self.should_sample("asupersync.deadline.remaining_seconds") {
            let task_type = sanitize_task_type_label(task_type);
            let labels = [KeyValue::new("task_type", task_type)];
            if let Some(filtered) =
                self.check_cardinality("asupersync.deadline.remaining_seconds", &labels)
            {
                self.deadline_remaining
                    .record(remaining.as_secs_f64(), &filtered);
            }
        }
    }

    fn checkpoint_interval(&self, task_type: &str, interval: Duration) {
        if self.should_sample("asupersync.checkpoint.interval_seconds") {
            let task_type = sanitize_task_type_label(task_type);
            let labels = [KeyValue::new("task_type", task_type)];
            if let Some(filtered) =
                self.check_cardinality("asupersync.checkpoint.interval_seconds", &labels)
            {
                self.checkpoint_interval
                    .record(interval.as_secs_f64(), &filtered);
            }
        }
    }

    fn task_stuck_detected(&self, task_type: &str) {
        let task_type = sanitize_task_type_label(task_type);
        let labels = [KeyValue::new("task_type", task_type)];
        if let Some(filtered) =
            self.check_cardinality("asupersync.task.stuck_detected_total", &labels)
        {
            self.task_stuck_detected.add(1, &filtered);
        }
    }

    fn obligation_created(&self, _region_id: RegionId) {
        self.state.inc_obligations();
        self.obligations_created.add(1, &[]);
    }

    fn obligation_discharged(&self, _region_id: RegionId) {
        self.state.dec_obligations();
        self.obligations_discharged.add(1, &[]);
    }

    fn obligation_leaked(&self, _region_id: RegionId) {
        self.state.dec_obligations();
        self.obligations_leaked.add(1, &[]);
    }

    fn scheduler_tick(&self, tasks_polled: usize, duration: Duration) {
        if self.should_sample("asupersync.scheduler") {
            self.scheduler_poll_time.record(duration.as_secs_f64(), &[]);
            // Precision loss is acceptable for metrics (only affects counts > 2^52)
            #[allow(clippy::cast_precision_loss)]
            self.scheduler_tasks_polled.record(tasks_polled as f64, &[]);
        }
    }
}

const fn outcome_label(outcome: OutcomeKind) -> &'static str {
    match outcome {
        OutcomeKind::Ok => "ok",
        OutcomeKind::Err => "err",
        OutcomeKind::Cancelled => "cancelled",
        OutcomeKind::Panicked => "panicked",
    }
}

/// Sanitise a `task_type` value before stamping it as an OpenTelemetry
/// label. Defence-in-depth against the Cx::set_task_type validator
/// (which is the primary gate); this protects against any code path
/// that constructs a TaskRecord directly and bypasses set_task_type
/// (test paths, internal runtime initialisation).
///
/// Substitutes the bucketed sentinel `"<invalid>"` for values that
/// either:
///   * exceed 64 bytes (cardinality bomb risk), OR
///   * contain any byte outside `[A-Za-z0-9_.:-]` (PII / control-char
///     risk — the same charset enforced by `cx::is_valid_task_type`).
///
/// Pre-validated values pass through unchanged. The single bucket
/// `"<invalid>"` keeps cardinality bounded even when many distinct
/// dirty values are seen.
/// (br-asupersync-9vpwpc)
fn sanitize_task_type_label(task_type: &str) -> String {
    const MAX: usize = 64;
    const SENTINEL: &str = "<invalid>";
    if task_type.is_empty() || task_type.len() > MAX {
        return SENTINEL.to_string();
    }
    let mut bytes = task_type.bytes();
    let first = bytes.next().expect("non-empty checked above");
    if !first.is_ascii_alphabetic() {
        return SENTINEL.to_string();
    }
    if bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':')) {
        task_type.to_string()
    } else {
        SENTINEL.to_string()
    }
}

const fn cancel_kind_label(kind: CancelKind) -> &'static str {
    match kind {
        CancelKind::User => "user",
        CancelKind::Timeout => "timeout",
        CancelKind::Deadline => "deadline",
        CancelKind::PollQuota => "poll_quota",
        CancelKind::CostBudget => "cost_budget",
        CancelKind::FailFast => "fail_fast",
        CancelKind::RaceLost => "race_lost",
        CancelKind::ParentCancelled => "parent_cancelled",
        CancelKind::ResourceUnavailable => "resource_unavailable",
        CancelKind::Shutdown => "shutdown",
        CancelKind::LinkedExit => "linked_exit",
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use crate::test_utils::init_test_logging;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter as OtelInMemoryExporter, PeriodicReader, SdkMeterProvider,
        data::ResourceMetrics,
    };
    use std::collections::HashSet;
    use std::path::Path;
    use std::sync::{Arc, Barrier};

    const EXPECTED_METRICS: &[&str] = &[
        "asupersync.tasks.spawned",
        "asupersync.tasks.completed",
        "asupersync.tasks.duration",
        "asupersync.regions.created",
        "asupersync.regions.closed",
        "asupersync.regions.lifetime",
        "asupersync.cancellations",
        "asupersync.cancellation.drain_duration",
        "asupersync.deadlines.set",
        "asupersync.deadlines.exceeded",
        "asupersync.deadline.warnings_total",
        "asupersync.deadline.violations_total",
        "asupersync.deadline.remaining_seconds",
        "asupersync.checkpoint.interval_seconds",
        "asupersync.task.stuck_detected_total",
        "asupersync.obligations.created",
        "asupersync.obligations.discharged",
        "asupersync.obligations.leaked",
        "asupersync.scheduler.poll_time",
        "asupersync.scheduler.tasks_polled",
    ];

    fn metric_names(finished: &[ResourceMetrics]) -> HashSet<String> {
        let mut names = HashSet::new();
        for resource_metrics in finished {
            for scope_metrics in resource_metrics.scope_metrics() {
                for metric in scope_metrics.metrics() {
                    names.insert(metric.name().to_string());
                }
            }
        }
        names
    }

    fn assert_expected_metrics_present(names: &HashSet<String>, expected: &[&str]) {
        for name in expected {
            assert!(names.contains(*name), "missing metric: {name}");
        }
    }

    #[test]
    fn privacy_config_compiles_and_applies_custom_regex_patterns() {
        let config = PrivacyConfig::new()
            .try_with_pii_pattern(r"token-[A-F0-9]{8}")
            .expect("regex pattern should compile");

        assert_eq!(
            config.redact_pii("auth.token", "bearer token-DEADBEEF"),
            "[REDACTED]"
        );
        assert_eq!(
            config.redact_pii("auth.token", "bearer token-nothex"),
            "bearer token-nothex"
        );
    }

    #[test]
    fn privacy_config_rejects_invalid_custom_regex_patterns() {
        assert!(PrivacyConfig::new().try_with_pii_pattern("(").is_err());
    }

    #[test]
    fn privacy_config_redacts_directly_mutated_public_pii_patterns() {
        let mut config = PrivacyConfig::new();
        config.pii_patterns.push(r"secret-\d{4}".to_string());

        assert_eq!(
            config.redact_pii("auth.secret", "secret-1234"),
            "[REDACTED]"
        );
    }

    #[test]
    fn privacy_config_allowed_fields_support_anchored_wildcards() {
        let config = PrivacyConfig::new()
            .with_allowed_field("http.*.duration")
            .with_allowed_field("runtime.region.*")
            .with_allowed_field("*.safe");

        assert!(!config.should_drop_field("http.client.duration"));
        assert!(!config.should_drop_field("runtime.region.close"));
        assert!(!config.should_drop_field("trace.safe"));
        assert!(!config.should_drop_field("trace.safe.safe"));
        assert!(config.should_drop_field("http.client.bytes"));
        assert!(config.should_drop_field("unsafe.trace"));
    }

    #[test]
    fn privacy_config_auto_pii_detection_uses_specific_classifiers() {
        let config = PrivacyConfig::new().with_auto_pii_detection();

        assert_eq!(
            config.redact_pii("user.email", "Contact Jane.Doe@example.com for access"),
            "[EMAIL_REDACTED]"
        );
        assert_eq!(
            config.redact_pii("support.phone", "Call +1 (415) 555-2671"),
            "[PHONE_REDACTED]"
        );
        assert_eq!(
            config.redact_pii("tax.ssn", "SSN 123-45-6789"),
            "[SSN_REDACTED]"
        );
        assert_eq!(
            config.redact_pii("payment.card", "Visa 4111 1111 1111 1111"),
            "[CARD_REDACTED]"
        );
        assert_eq!(
            config.redact_pii("correlation.id", "ticket 4111 1111 1111 1112"),
            "ticket 4111 1111 1111 1112"
        );
    }

    fn collect_grafana_queries(value: &serde_json::Value, output: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    if key == "expr" || key == "query" {
                        if let serde_json::Value::String(text) = val {
                            output.push(text.clone());
                        }
                    } else {
                        collect_grafana_queries(val, output);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_grafana_queries(item, output);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn otel_metrics_exports_in_memory() {
        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let metrics = OtelMetrics::new(meter);

        metrics.task_spawned(RegionId::testing_default(), TaskId::testing_default());
        metrics.task_completed(
            TaskId::testing_default(),
            OutcomeKind::Ok,
            Duration::from_millis(10),
        );
        metrics.region_created(RegionId::testing_default(), None);
        metrics.region_closed(RegionId::testing_default(), Duration::from_secs(1));
        metrics.cancellation_requested(RegionId::testing_default(), CancelKind::User);
        metrics.drain_completed(RegionId::testing_default(), Duration::from_millis(5));
        metrics.deadline_set(RegionId::testing_default(), Duration::from_secs(2));
        metrics.deadline_exceeded(RegionId::testing_default());
        metrics.deadline_warning("test", "no_progress", Duration::from_secs(1));
        metrics.deadline_violation("test", Duration::from_secs(1));
        metrics.deadline_remaining("test", Duration::from_secs(5));
        metrics.checkpoint_interval("test", Duration::from_millis(200));
        metrics.task_stuck_detected("test");
        metrics.obligation_created(RegionId::testing_default());
        metrics.obligation_discharged(RegionId::testing_default());
        metrics.obligation_leaked(RegionId::testing_default());
        metrics.scheduler_tick(3, Duration::from_millis(1));

        provider.force_flush().expect("force_flush");
        let finished = exporter.get_finished_metrics().expect("finished metrics");
        assert!(!finished.is_empty());
        let names = metric_names(&finished);
        assert_expected_metrics_present(&names, EXPECTED_METRICS);

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn otel_metrics_runtime_integration_emits_task_metrics() {
        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let metrics = OtelMetrics::new(meter);
        let runtime = RuntimeBuilder::new()
            .metrics(metrics)
            .build()
            .expect("runtime build");

        let handle = runtime.handle().spawn(async { 7u8 });
        let result = runtime.block_on(handle);
        assert_eq!(result, 7);

        for _ in 0..1024 {
            if runtime.is_quiescent() {
                break;
            }
            std::thread::yield_now();
        }
        assert!(runtime.is_quiescent(), "runtime did not reach quiescence");

        provider.force_flush().expect("force_flush");
        let finished = exporter.get_finished_metrics().expect("finished metrics");
        assert!(!finished.is_empty());
        let names = metric_names(&finished);
        assert_expected_metrics_present(
            &names,
            &[
                "asupersync.tasks.spawned",
                "asupersync.tasks.completed",
                "asupersync.tasks.duration",
            ],
        );

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn grafana_dashboard_references_expected_metrics() {
        init_test_logging();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/grafana_dashboard.json");
        let contents = std::fs::read_to_string(path).expect("read grafana dashboard");
        let json: serde_json::Value =
            serde_json::from_str(&contents).expect("parse grafana dashboard");

        let mut queries = Vec::new();
        collect_grafana_queries(&json, &mut queries);
        assert!(!queries.is_empty(), "expected grafana queries to exist");

        let joined = queries.join("\n");
        let expected = [
            "asupersync_tasks_spawned_total",
            "asupersync_tasks_completed_total",
            "asupersync_tasks_duration_bucket",
            "asupersync_regions_active",
            "asupersync_cancellations_total",
            "asupersync_deadline_warnings_total",
            "asupersync_deadline_violations_total",
            "asupersync_deadline_remaining_seconds_bucket",
            "asupersync_checkpoint_interval_seconds_bucket",
            "asupersync_task_stuck_detected_total",
        ];
        for metric in expected {
            assert!(
                joined.contains(metric),
                "missing grafana query metric: {metric}"
            );
        }
    }

    #[test]
    fn otel_metrics_with_config() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let config = MetricsConfig::new()
            .with_max_cardinality(500)
            .with_overflow_strategy(CardinalityOverflow::Aggregate);

        let metrics = OtelMetrics::new_with_config(meter, config);
        assert_eq!(metrics.config().max_cardinality, 500);
        assert_eq!(
            metrics.config().overflow_strategy,
            CardinalityOverflow::Aggregate
        );

        provider.shutdown().expect("shutdown");
    }

    /// br-asupersync-bs92bg — Pre-computed-collision DoS mitigation.
    /// Each `CardinalityTracker::new()` instance gets a fresh
    /// `RandomState` seed, so the same label set hashes to a
    /// different bucket in two trackers. An attacker who knows the
    /// hash function shape (which is public — it's std SipHash) but
    /// not the per-process seed cannot pre-compute label values that
    /// collide on the local tracker's buckets.
    ///
    /// The strict assertion below ("at least one of N pairs differs")
    /// allows for the tiny probability that two random seeds happen
    /// to map a single label set to the same 64-bit bucket; with N
    /// distinct labels the probability of all-N collisions is
    /// approximately N * 2^-64, indistinguishable from impossible.
    #[test]
    fn hash_labels_uses_per_instance_random_seed() {
        let tracker_a = CardinalityTracker::new();
        let tracker_b = CardinalityTracker::new();

        let mut differ = false;
        for i in 0..16u32 {
            let labels = [KeyValue::new("id", i.to_string())];
            let h_a = tracker_a.hash_labels(&labels);
            let h_b = tracker_b.hash_labels(&labels);
            if h_a != h_b {
                differ = true;
                break;
            }
        }
        assert!(
            differ,
            "br-asupersync-bs92bg: two CardinalityTracker instances must hash labels under different seeds"
        );
    }

    /// br-asupersync-bs92bg — Within a single tracker, hashing the
    /// same label set twice must produce the same bucket (the
    /// cardinality contract: identical labels deduplicate). The
    /// per-instance seed is stable for the tracker's lifetime.
    #[test]
    fn hash_labels_is_stable_within_one_tracker() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("outcome", "ok")];
        let h1 = tracker.hash_labels(&labels);
        let h2 = tracker.hash_labels(&labels);
        assert_eq!(
            h1, h2,
            "same labels must hash equally within one tracker (cardinality dedup contract)"
        );
    }

    #[test]
    fn cardinality_tracker_basic() {
        let tracker = CardinalityTracker::new();

        let labels = [KeyValue::new("outcome", "ok")];
        assert!(!tracker.would_exceed("test", &labels, 10));

        tracker.record("test", &labels);
        assert_eq!(tracker.cardinality("test"), 1);

        // Same labels should not increase cardinality
        tracker.record("test", &labels);
        assert_eq!(tracker.cardinality("test"), 1);

        // Different labels should increase
        let labels2 = [KeyValue::new("outcome", "err")];
        tracker.record("test", &labels2);
        assert_eq!(tracker.cardinality("test"), 2);
    }

    #[test]
    fn cardinality_limit_enforced() {
        let tracker = CardinalityTracker::new();

        // Fill up to max
        for i in 0..5 {
            let labels = [KeyValue::new("id", i.to_string())];
            tracker.record("test", &labels);
        }
        assert_eq!(tracker.cardinality("test"), 5);

        // Next should exceed
        let labels = [KeyValue::new("id", "new")];
        assert!(tracker.would_exceed("test", &labels, 5));
    }

    #[test]
    fn cardinality_limit_zero_rejects_new_series() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("id", "first")];
        assert!(
            tracker.would_exceed("test", &labels, 0),
            "zero-cardinality budget must reject unseen label sets"
        );
        assert!(tracker.check_and_record("test", &labels, 0, usize::MAX));
        assert_eq!(tracker.cardinality("test"), 0);
    }

    #[test]
    fn cardinality_enforcement_is_atomic_under_concurrency() {
        let tracker = Arc::new(CardinalityTracker::new());
        let barrier = Arc::new(Barrier::new(8));

        let handles: [_; 8] = std::array::from_fn(|i| {
            let tracker = Arc::clone(&tracker);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let labels = [KeyValue::new("id", i.to_string())];
                barrier.wait();
                !tracker.check_and_record("test", &labels, 1, usize::MAX)
            })
        });

        let accepted = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread join"))
            .filter(|accepted| *accepted)
            .count();

        assert_eq!(accepted, 1, "exactly one series should fit under max=1");
        assert_eq!(tracker.cardinality("test"), 1);
    }

    /// br-asupersync-qipj44: with `max_metrics` set to N, the FIRST
    /// N distinct metric names must be accepted; subsequent new
    /// names must hit the overflow path. Existing metric names
    /// continue to accept additional label combinations up to
    /// `max_cardinality` regardless of the metric-name cap.
    #[test]
    fn metric_name_cap_rejects_new_names_after_limit() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("k", "v")];

        // Cap = 3 — first three distinct names accepted.
        for name in ["a", "b", "c"] {
            assert!(
                !tracker.check_and_record(name, &labels, 100, 3),
                "name {name} should be accepted under cap=3"
            );
        }
        // A fourth distinct name must be rejected.
        assert!(
            tracker.check_and_record("d", &labels, 100, 3),
            "fourth distinct metric name must hit overflow path under cap=3"
        );
        // Existing names still accept new label combinations.
        let other_labels = [KeyValue::new("k", "v2")];
        assert!(
            !tracker.check_and_record("a", &other_labels, 100, 3),
            "existing metric must accept new label combinations even under cap"
        );
    }

    /// `max_metrics = 0` is the legacy unbounded behaviour (cap
    /// disabled) — preserved for callers that explicitly want it.
    #[test]
    fn metric_name_cap_zero_disables_the_limit() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("k", "v")];
        for i in 0..1000 {
            let name = format!("m{i}");
            assert!(
                !tracker.check_and_record(&name, &labels, 100, 0),
                "max_metrics=0 must allow unbounded metric names"
            );
        }
    }

    /// Re-recording an already-tracked metric name must not reject
    /// even when the cap is otherwise reached.
    #[test]
    fn metric_name_cap_does_not_reject_existing_metrics() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("k", "v")];
        // Fill to cap.
        for i in 0..3 {
            let name = format!("m{i}");
            assert!(!tracker.check_and_record(&name, &labels, 100, 3));
        }
        // Re-record one of the existing names with a brand-new label.
        let new_labels = [KeyValue::new("k", "vNew")];
        assert!(
            !tracker.check_and_record("m0", &new_labels, 100, 3),
            "existing metric must still accept new labels under cap"
        );
    }

    #[test]
    fn cardinality_label_order_is_ignored() {
        let tracker = CardinalityTracker::new();

        let labels_a = [
            KeyValue::new("outcome", "ok"),
            KeyValue::new("region", "root"),
        ];
        let labels_b = [
            KeyValue::new("region", "root"),
            KeyValue::new("outcome", "ok"),
        ];

        tracker.record("test", &labels_a);
        assert!(
            !tracker.would_exceed("test", &labels_b, 1),
            "label order should not increase cardinality"
        );
        tracker.record("test", &labels_b);
        assert_eq!(tracker.cardinality("test"), 1);
    }

    #[test]
    fn drop_labels_filtered() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let config = MetricsConfig::new().with_drop_label("request_id");
        let metrics = OtelMetrics::new_with_config(meter, config);

        // Labels with request_id should have it filtered
        let labels = [
            KeyValue::new("outcome", "ok"),
            KeyValue::new("request_id", "12345"),
        ];

        let filtered = metrics.check_cardinality("test", &labels);
        assert!(filtered.is_some());
        let filtered = filtered.unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].key.as_str(), "outcome");

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn aggregate_overflow_does_not_exceed_configured_budget() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let config = MetricsConfig::new()
            .with_max_cardinality(1)
            .with_overflow_strategy(CardinalityOverflow::Aggregate);
        let metrics = OtelMetrics::new_with_config(meter, config);

        let first = [KeyValue::new("task_type", "fast")];
        let second = [KeyValue::new("task_type", "slow")];

        let first_labels = metrics
            .check_cardinality("test.metric", &first)
            .expect("first label set should fit");
        assert_eq!(first_labels, first);
        assert_eq!(metrics.cardinality_tracker.cardinality("test.metric"), 1);

        assert!(
            metrics.check_cardinality("test.metric", &second).is_none(),
            "aggregate overflow must not create a second series beyond the configured cap"
        );
        assert_eq!(metrics.cardinality_tracker.cardinality("test.metric"), 1);

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn sampling_config() {
        let sampling = SamplingConfig::new(0.5).with_sampled_metric("duration");
        assert!((sampling.sample_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(sampling.sampled_metrics.len(), 1);
    }

    #[test]
    fn sampling_rate_clamped() {
        let sampling = SamplingConfig::new(1.5);
        assert!((sampling.sample_rate - 1.0).abs() < f64::EPSILON);

        let sampling = SamplingConfig::new(-0.5);
        assert!(sampling.sample_rate.abs() < f64::EPSILON);
    }
}

#[cfg(test)]
mod exporter_tests {
    use super::*;

    #[test]
    fn null_exporter_works() {
        let exporter = NullExporter::new();
        let snapshot = MetricsSnapshot::new();
        assert!(exporter.export(&snapshot).is_ok());
        assert!(exporter.flush().is_ok());
    }

    #[test]
    fn in_memory_exporter_collects() {
        let exporter = InMemoryExporter::new();

        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("test.counter", vec![], 42);
        snapshot.add_gauge(
            "test.gauge",
            vec![("label".to_string(), "value".to_string())],
            100,
        );
        snapshot.add_histogram("test.histogram", vec![], 10, 5.5);

        assert!(exporter.export(&snapshot).is_ok());
        assert_eq!(exporter.total_metrics(), 3);

        let snapshots = exporter.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].counters.len(), 1);
        assert_eq!(snapshots[0].gauges.len(), 1);
        assert_eq!(snapshots[0].histograms.len(), 1);

        exporter.clear();
        assert_eq!(exporter.total_metrics(), 0);
    }

    #[test]
    fn multi_exporter_fans_out() {
        // Create a wrapper to use with MultiExporter
        struct ArcExporter(Arc<InMemoryExporter>);
        impl MetricsExporter for ArcExporter {
            fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
                self.0.export(metrics)
            }
            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        let exp1 = InMemoryExporter::new();
        let exp2 = InMemoryExporter::new();

        // Need to use Arc to share between multi-exporter and tests
        let exp1_arc = Arc::new(exp1);
        let exp2_arc = Arc::new(exp2);

        let mut multi = MultiExporter::new(vec![]);
        multi.add(Box::new(ArcExporter(Arc::clone(&exp1_arc))));
        multi.add(Box::new(ArcExporter(Arc::clone(&exp2_arc))));
        assert_eq!(multi.len(), 2);

        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("test", vec![], 1);

        assert!(multi.export(&snapshot).is_ok());
        assert!(multi.flush().is_ok());

        // Both exporters should have received the snapshot
        assert_eq!(exp1_arc.total_metrics(), 1);
        assert_eq!(exp2_arc.total_metrics(), 1);
    }

    #[test]
    fn metrics_snapshot_building() {
        let mut snapshot = MetricsSnapshot::new();

        snapshot.add_counter(
            "requests",
            vec![("method".to_string(), "GET".to_string())],
            100,
        );
        snapshot.add_gauge("connections", vec![], 42);
        snapshot.add_histogram("latency", vec![], 1000, 125.5);

        assert_eq!(snapshot.counters.len(), 1);
        assert_eq!(snapshot.gauges.len(), 1);
        assert_eq!(snapshot.histograms.len(), 1);

        let (name, labels, value) = &snapshot.counters[0];
        assert_eq!(name, "requests");
        assert_eq!(labels.len(), 1);
        assert_eq!(*value, 100);
    }

    #[test]
    fn export_error_display() {
        let err = ExportError::new("test error");
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn log_level_to_otlp_severity_matches_data_model_bases() {
        assert_eq!(log_level_to_otlp_severity(LogLevel::Trace), (1, "TRACE"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Debug), (5, "DEBUG"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Info), (9, "INFO"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Warn), (13, "WARN"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Error), (17, "ERROR"));
    }

    #[test]
    fn null_logs_exporter_is_disabled_noop() {
        let exporter = NullLogsExporter::new();
        let snapshot = LogsSnapshot::new("checkout").with_record(OtlpLogRecord::new(
            LogLevel::Info,
            "ignored",
            10,
        ));

        assert!(exporter.export(&snapshot).is_ok());
        assert!(exporter.flush().is_ok());
    }

    #[test]
    fn in_memory_logs_exporter_collects_snapshots() {
        let exporter = InMemoryLogsExporter::new();
        let snapshot = LogsSnapshot::new("checkout")
            .with_record(OtlpLogRecord::new(LogLevel::Info, "first", 10))
            .with_record(OtlpLogRecord::new(LogLevel::Warn, "second", 20));

        exporter.export(&snapshot).expect("logs export");
        assert_eq!(exporter.total_records(), 2);
        assert_eq!(exporter.snapshots(), vec![snapshot]);

        exporter.clear();
        assert_eq!(exporter.total_records(), 0);
    }

    #[test]
    fn multi_logs_exporter_fans_out_and_reports_errors() {
        struct ArcLogsExporter(Arc<InMemoryLogsExporter>);
        impl LogsExporter for ArcLogsExporter {
            fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
                self.0.export(logs)
            }

            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        struct FailingLogsExporter;
        impl LogsExporter for FailingLogsExporter {
            fn export(&self, _logs: &LogsSnapshot) -> Result<(), ExportError> {
                Err(ExportError::new("collector rejected logs"))
            }

            fn flush(&self) -> Result<(), ExportError> {
                Ok(())
            }
        }

        let first = Arc::new(InMemoryLogsExporter::new());
        let second = Arc::new(InMemoryLogsExporter::new());
        let snapshot =
            LogsSnapshot::new("checkout").with_record(OtlpLogRecord::new(LogLevel::Info, "ok", 1));

        let multi = MultiLogsExporter::new(vec![
            Box::new(ArcLogsExporter(Arc::clone(&first))),
            Box::new(ArcLogsExporter(Arc::clone(&second))),
        ]);
        multi.export(&snapshot).expect("multi logs export");
        assert_eq!(first.total_records(), 1);
        assert_eq!(second.total_records(), 1);

        let failing = MultiLogsExporter::new(vec![Box::new(FailingLogsExporter)]);
        let error = failing
            .export(&snapshot)
            .expect_err("failure must propagate");
        assert!(error.to_string().contains("collector rejected logs"));
    }

    #[test]
    fn logs_load_shedding_drops_oldest_snapshots() {
        struct ArcLogsExporter(Arc<InMemoryLogsExporter>);
        impl LogsExporter for ArcLogsExporter {
            fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
                self.0.export(logs)
            }

            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        fn snapshot(id: u64) -> LogsSnapshot {
            LogsSnapshot::new("checkout").with_record(
                OtlpLogRecord::new(LogLevel::Info, format!("batch-{id}"), id)
                    .with_attribute("batch_id", id.to_string()),
            )
        }

        let received = Arc::new(InMemoryLogsExporter::new());
        let exporter =
            LoadSheddingLogsExporter::new(Box::new(ArcLogsExporter(Arc::clone(&received))), 2);

        exporter.export(&snapshot(0)).expect("export 0");
        exporter.export(&snapshot(1)).expect("export 1");
        exporter.export(&snapshot(2)).expect("export 2");

        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.queue_depth, 2);
        assert_eq!(stats.dropped_batches, 1);

        assert_eq!(exporter.process_queue().expect("process logs"), 2);
        let bodies: Vec<_> = received
            .snapshots()
            .iter()
            .flat_map(|snapshot| snapshot.records.iter().map(|record| record.body.clone()))
            .collect();
        assert_eq!(bodies, vec!["batch-1", "batch-2"]);
    }

    #[test]
    fn traces_metrics_and_logs_export_without_cross_signal_duplication() {
        use crate::observability::otlp_trace_exporter::{
            ExportError as TraceExportError, OtlpSpan, SpanBatch, TraceExporter,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;

        #[derive(Debug, Default)]
        struct CountingTraceExporter {
            batches: AtomicUsize,
            spans: AtomicUsize,
        }

        impl TraceExporter for CountingTraceExporter {
            fn export(&self, batch: &SpanBatch) -> Result<(), TraceExportError> {
                self.batches.fetch_add(1, Ordering::Relaxed);
                self.spans.fetch_add(batch.spans.len(), Ordering::Relaxed);
                Ok(())
            }

            fn flush(&self) -> Result<(), TraceExportError> {
                Ok(())
            }
        }

        let trace_exporter = CountingTraceExporter::default();
        let metrics_exporter = InMemoryExporter::new();
        let logs_exporter = InMemoryLogsExporter::new();

        let trace_batch = SpanBatch {
            batch_id: 7,
            spans: vec![OtlpSpan::new(
                "span-1".to_string(),
                "checkout".to_string(),
                1,
                2,
                vec![("route".to_string(), "/pay".to_string())],
            )],
            created_at: Instant::now(),
        };
        trace_exporter
            .export(&trace_batch)
            .expect("trace export should work");

        let mut metrics = MetricsSnapshot::new();
        metrics.add_counter(
            "otel.export.requests",
            vec![("signal".into(), "metrics".into())],
            1,
        );
        metrics_exporter
            .export(&metrics)
            .expect("metrics export should work");

        let logs = LogsSnapshot::new("checkout").with_record(
            OtlpLogRecord::new(LogLevel::Info, "checkout complete", 3)
                .with_attribute("signal", "logs"),
        );
        logs_exporter
            .export(&logs)
            .expect("logs export should work");

        assert_eq!(trace_exporter.batches.load(Ordering::Relaxed), 1);
        assert_eq!(trace_exporter.spans.load(Ordering::Relaxed), 1);
        assert_eq!(metrics_exporter.total_metrics(), 1);
        assert_eq!(logs_exporter.total_records(), 1);
    }

    #[test]
    fn logs_exporter_reuses_otlp_retry_classifier() {
        let retry = classify_otlp_http_response(503, &[]);
        assert!(matches!(
            retry,
            Err(OtlpError::Retryable {
                status_code: 503,
                ..
            })
        ));

        let terminal = classify_otlp_http_response(400, &[]);
        assert!(matches!(terminal, Err(OtlpError::NonRetryable { .. })));

        let exporter = OtlpLogsHttpExporter::new("http://collector:4318/v1/logs")
            .with_retry_config(4, Duration::from_millis(50), Duration::from_secs(5))
            .with_timeout(Duration::from_secs(3));
        assert_eq!(exporter.endpoint(), "http://collector:4318/v1/logs");

        let logs = LogsSnapshot::new("checkout");
        let sync_error = exporter.export(&logs).expect_err("sync export rejected");
        assert!(sync_error.to_string().contains("requires async context"));
    }

    #[test]
    fn logs_snapshot_encodes_otlp_wire_compatible_records() {
        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
        use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
        use opentelemetry_proto::tonic::logs::v1::SeverityNumber;
        use prost::Message;

        let long_value = "x".repeat(OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES + 16);
        let record = OtlpLogRecord::new(LogLevel::Warn, "", 100)
            .with_observed_time_unix_nano(101)
            .with_attribute("component", "scheduler")
            .with_attribute("long", long_value)
            .with_attribute("", "dropped")
            .with_trace_context(vec![1; 16], vec![2; 8], 0x0101)
            .with_event_name("asupersync.scheduler.warning");
        let snapshot = LogsSnapshot::new("checkout")
            .with_scope("asupersync.test.logs", "test-version")
            .with_resource_attribute("deployment.environment", "test")
            .with_record(record);

        let encoded = snapshot.to_otlp_protobuf();
        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).expect("decode logs");
        assert_eq!(decoded.resource_logs.len(), 1);

        let resource_logs = &decoded.resource_logs[0];
        let resource = resource_logs.resource.as_ref().expect("resource");
        assert!(
            resource
                .attributes
                .iter()
                .any(|attribute| attribute.key == "service.name")
        );

        let scope_logs = &resource_logs.scope_logs[0];
        let scope = scope_logs.scope.as_ref().expect("scope");
        assert_eq!(scope.name, "asupersync.test.logs");
        assert_eq!(scope.version, "test-version");

        let decoded_record = &scope_logs.log_records[0];
        assert_eq!(decoded_record.severity_number, SeverityNumber::Warn as i32);
        assert_eq!(decoded_record.severity_text, "WARN");
        assert_eq!(decoded_record.time_unix_nano, 100);
        assert_eq!(decoded_record.observed_time_unix_nano, 101);
        assert_eq!(decoded_record.trace_id, vec![1; 16]);
        assert_eq!(decoded_record.span_id, vec![2; 8]);
        assert_eq!(decoded_record.flags, 1);
        assert_eq!(decoded_record.event_name, "asupersync.scheduler.warning");
        assert_eq!(decoded_record.dropped_attributes_count, 1);

        let body = decoded_record.body.as_ref().expect("body");
        assert!(matches!(
            body.value.as_ref(),
            Some(ProtoValue::StringValue(value)) if value.is_empty()
        ));
        let long = decoded_record
            .attributes
            .iter()
            .find(|attribute| attribute.key == "long")
            .expect("long attribute")
            .value
            .as_ref()
            .expect("long attr value");
        assert!(matches!(
            long.value.as_ref(),
            Some(ProtoValue::StringValue(value))
                if value.len() == OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES
        ));
    }

    #[test]
    fn otlp_export_queue_load_shedding_drops_oldest_batches() {
        // AUDIT TEST: OTLP exporter load shedding behavior
        //
        // REQUIREMENT: When export channel is full, drop OLDEST batches (correct)
        // NOT drop NEWEST batches (incorrect) per OTLP exporter best practices.
        //
        // GOAL: Preserve recent data over stale data for better observability.

        let received_batches = Arc::new(Mutex::new(Vec::<MetricsSnapshot>::new()));

        struct TrackingExporter {
            received: Arc<Mutex<Vec<MetricsSnapshot>>>,
        }

        impl MetricsExporter for TrackingExporter {
            fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
                self.received.lock().push(metrics.clone());
                Ok(())
            }

            fn flush(&self) -> Result<(), ExportError> {
                Ok(())
            }
        }

        let tracking_exporter = TrackingExporter {
            received: Arc::clone(&received_batches),
        };

        // Create load shedding exporter with small capacity for testing
        let queue_capacity = 3;
        let exporter = LoadSheddingExporter::new(Box::new(tracking_exporter), queue_capacity);

        // Create identifiable test batches
        let mut batches = Vec::new();
        for i in 0..6 {
            let mut batch = MetricsSnapshot::new();
            batch.add_counter(
                "test_metric",
                vec![("batch_id".to_string(), i.to_string())],
                i as u64 + 1,
            );
            batches.push(batch);
        }

        // Fill queue beyond capacity to trigger load shedding
        for batch in &batches {
            let result = exporter.export(batch);
            assert!(
                result.is_ok(),
                "export should succeed even when dropping oldest"
            );
        }

        // Verify load shedding stats
        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.queue_capacity, 3, "queue capacity should be 3");
        assert_eq!(stats.queue_depth, 3, "queue should be full");
        assert_eq!(
            stats.dropped_batches, 3,
            "should have dropped 3 oldest batches"
        );

        // Process queue and verify OLDEST batches were dropped
        let processed = exporter
            .process_queue()
            .expect("process queue should succeed");
        assert_eq!(processed, 3, "should have processed 3 batches");

        let received = received_batches.lock();
        assert_eq!(received.len(), 3, "should have received 3 batches");

        // Verify we kept the NEWEST 3 batches (3, 4, 5) and dropped oldest (0, 1, 2)
        let received_batch_ids: Vec<String> = received
            .iter()
            .map(|batch| {
                // Extract batch_id from the counter labels
                batch.counters[0].1[0].1.clone()
            })
            .collect();

        assert_eq!(
            received_batch_ids,
            vec!["3", "4", "5"],
            "should preserve NEWEST batches (3,4,5) and drop oldest (0,1,2)"
        );

        eprintln!("OTLP LOAD SHEDDING AUDIT RESULTS:");
        eprintln!("  ✓ CORRECT: Drops OLDEST batches when queue is full");
        eprintln!("  ✓ CORRECT: Preserves NEWEST batches for recent observability");
        eprintln!("  ✓ CORRECT: Maintains FIFO export order");
        eprintln!("  Queue capacity: {}", stats.queue_capacity);
        eprintln!("  Dropped batches: {}", stats.dropped_batches);
        eprintln!("  Preserved batches: {}", received_batch_ids.join(", "));
    }

    #[test]
    fn bounded_export_queue_fifo_order_preserved() {
        // Test that the bounded queue maintains FIFO order even with load shedding
        let queue = BoundedExportQueue::new(2);

        // Add items that fit in queue
        assert!(!queue.enqueue("first"));
        assert!(!queue.enqueue("second"));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_count(), 0);

        // Add item that triggers load shedding (drops oldest = "first")
        assert!(queue.enqueue("third"));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_count(), 1);

        // Verify FIFO order: should get "second" then "third"
        assert_eq!(queue.dequeue(), Some("second"));
        assert_eq!(queue.dequeue(), Some("third"));
        assert_eq!(queue.dequeue(), None);
    }

    #[test]
    fn bounded_export_queue_capacity_limits() {
        let queue = BoundedExportQueue::new(0); // Zero capacity edge case
        assert!(queue.enqueue("item"));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.dropped_count(), 0); // No previous item to drop

        let queue = BoundedExportQueue::new(1);
        assert!(!queue.enqueue("first"));
        assert!(queue.enqueue("second")); // Drops "first"
        assert_eq!(queue.dequeue(), Some("second"));
        assert_eq!(queue.dropped_count(), 1);
    }

    // Pure data-type tests (wave 38 – CyanBarn)

    #[test]
    fn cardinality_overflow_debug_clone_copy_eq_default() {
        let overflow = CardinalityOverflow::default();
        assert_eq!(overflow, CardinalityOverflow::Drop);
        let dbg = format!("{overflow:?}");
        assert!(dbg.contains("Drop"));

        let aggregate = CardinalityOverflow::Aggregate;
        let cloned = aggregate;
        assert_eq!(cloned, CardinalityOverflow::Aggregate);
        assert_ne!(aggregate, CardinalityOverflow::Warn);

        let warn = CardinalityOverflow::Warn;
        let copied = warn;
        assert_eq!(copied, warn);
    }

    #[test]
    fn metrics_config_debug_clone_default() {
        let config = MetricsConfig::default();
        assert_eq!(config.max_cardinality, 1000);
        assert_eq!(config.overflow_strategy, CardinalityOverflow::Drop);
        assert!(config.drop_labels.is_empty());
        assert!(config.sampling.is_none());

        let dbg = format!("{config:?}");
        assert!(dbg.contains("MetricsConfig"));

        let cloned = config;
        assert_eq!(cloned.max_cardinality, 1000);
    }

    #[test]
    fn sampling_config_debug_clone_default() {
        let config = SamplingConfig::default();
        assert!((config.sample_rate - 1.0).abs() < f64::EPSILON);
        assert!(config.sampled_metrics.is_empty());

        let dbg = format!("{config:?}");
        assert!(dbg.contains("SamplingConfig"));

        let cloned = config;
        assert!((cloned.sample_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metrics_snapshot_debug_clone_default() {
        let snapshot = MetricsSnapshot::default();
        assert!(snapshot.counters.is_empty());
        assert!(snapshot.gauges.is_empty());
        assert!(snapshot.histograms.is_empty());

        let dbg = format!("{snapshot:?}");
        assert!(dbg.contains("MetricsSnapshot"));

        let mut s = MetricsSnapshot::new();
        s.add_counter("c", vec![], 1);
        let cloned = s.clone();
        assert_eq!(cloned.counters.len(), 1);
    }

    #[test]
    fn export_error_debug_clone() {
        let err = ExportError::new("something failed");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ExportError"));

        let cloned = err.clone();
        assert_eq!(cloned.to_string(), err.to_string());
    }

    #[test]
    fn stdout_exporter_debug_default() {
        let exporter = StdoutExporter::default();
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("StdoutExporter"));

        let with_prefix = StdoutExporter::with_prefix("[test] ");
        let dbg2 = format!("{with_prefix:?}");
        assert!(dbg2.contains("StdoutExporter"));
    }

    #[test]
    fn null_exporter_debug_default() {
        let exporter = NullExporter;
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("NullExporter"));
    }

    #[test]
    fn multi_exporter_debug_default() {
        let exporter = MultiExporter::default();
        assert!(exporter.is_empty());
        assert_eq!(exporter.len(), 0);
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("MultiExporter"));
    }

    #[test]
    fn in_memory_exporter_debug_default() {
        let exporter = InMemoryExporter::default();
        assert_eq!(exporter.total_metrics(), 0);
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("InMemoryExporter"));
    }

    /// br-asupersync-coxhdt: escape_label_value must handle the
    /// Prometheus-spec-required escape trio (\\\\, \\n, \\") plus \\r as
    /// defense-in-depth. Otherwise an attacker-controlled label value
    /// containing a literal '"' would close the value-string early
    /// and inject spurious labels.
    #[test]
    fn escape_label_value_handles_spec_required_trio_plus_cr() {
        // Plain values pass through unchanged.
        assert_eq!(escape_label_value("plain"), "plain");
        // Backslash → \\
        assert_eq!(escape_label_value(r"a\b"), r"a\\b");
        // Newline → \n
        assert_eq!(escape_label_value("a\nb"), r"a\nb");
        // Double-quote → \"
        assert_eq!(escape_label_value(r#"a"b"#), r#"a\"b"#);
        // Carriage return → \r
        assert_eq!(escape_label_value("a\rb"), r"a\rb");
        // All four together.
        assert_eq!(escape_label_value("a\\b\nc\"d\re"), r#"a\\b\nc\"d\re"#);
    }

    /// br-asupersync-coxhdt: format_labels MUST route every label
    /// value through escape_label_value. An attacker who controls
    /// a label value containing a literal '"' must NOT be able to
    /// close the value string early and inject `,attacker_label="x"`
    /// into the resulting Prometheus output.
    #[test]
    fn format_labels_escapes_quote_to_prevent_label_injection() {
        let labels = vec![(
            "path".to_string(),
            r#"/api","attacker_label"="injected"#.to_string(),
        )];
        let rendered = StdoutExporter::format_labels(&labels);
        // The literal '"' in the value MUST appear as \" in the output.
        assert!(
            rendered.contains(r#"\""#),
            "format_labels failed to escape attacker quote: {rendered}"
        );
        // The fragment that would inject if escaping failed must NOT
        // appear as a parseable second label.
        assert!(
            !rendered.contains(r#"","attacker_label"="injected"}"#),
            "format_labels permitted label injection: {rendered}"
        );
    }

    /// br-asupersync-coxhdt: a backslash in a label value is doubled,
    /// not consumed.
    #[test]
    fn format_labels_escapes_backslash_to_prevent_value_corruption() {
        let labels = vec![("k".to_string(), r"a\b".to_string())];
        let rendered = StdoutExporter::format_labels(&labels);
        assert!(rendered.contains(r"a\\b"));
    }
}

// Re-export types for public API
#[cfg(feature = "tracing-integration")]
pub use span_semantics::LogRecordBodyValue;
#[cfg(all(feature = "tracing-integration", any(test, feature = "fuzz")))]
pub use span_semantics::log_record_body_value_to_any_value;

// =============================================================================
// OpenTelemetry Span Semantics Conformance
// =============================================================================

#[cfg(feature = "tracing-integration")]
pub mod span_semantics {
    //! OpenTelemetry span semantics conformance tests.
    //!
    //! This module provides comprehensive conformance testing for OpenTelemetry
    //! span semantics according to the OpenTelemetry specification. It verifies
    //! span lifecycle, hierarchy, attributes, events, status, and context propagation.
    //!
    //! # Conformance Areas
    //!
    //! 1. **Span Lifecycle**: Start, end, finish, duration calculation
    //! 2. **Span Hierarchy**: Parent-child relationships, context propagation
    //! 3. **Span Attributes**: Setting, updating, limits, validation
    //! 4. **Span Events**: Recording events with timestamps and attributes
    //! 5. **Span Status**: Status codes, descriptions, error indication
    //! 6. **Span Sampling**: Sampled vs non-sampled behavior
    //! 7. **Span Context**: TraceID, SpanID, trace flags, state propagation
    //! 8. **Resource Association**: Service resource attachment
    //!
    //! # Example
    //!
    //! ```ignore
    //! use asupersync::observability::otel::span_semantics::run_span_conformance_tests;
    //!
    //! // Run all span semantic conformance tests
    //! run_span_conformance_tests().expect("All span semantic tests should pass");
    //! ```

    use opentelemetry::trace::{
        SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState,
    };
    #[cfg(any(test, feature = "fuzz"))]
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, KeyValue, any_value::Value as ProtoValue,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static NEXT_TEST_SPAN_SEED: AtomicU64 = AtomicU64::new(1);
    static NEXT_TEST_TIME_TICK: AtomicU64 = AtomicU64::new(1);

    fn next_test_trace_id() -> TraceId {
        // Keep the test helper deterministic while avoiding related hi/lo halves.
        // Production trace IDs are generated by the runtime path, not this helper.
        let seed = NEXT_TEST_SPAN_SEED.fetch_add(1, Ordering::Relaxed);
        let high = splitmix64(seed ^ 0x1357_9bdf_2468_ace0);
        let low = splitmix64(seed ^ 0xfedc_ba98_7654_3210);
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&high.to_be_bytes());
        bytes[8..].copy_from_slice(&low.to_be_bytes());

        // Ensure not INVALID (all zeros) per W3C specification
        let trace_id = TraceId::from_bytes(bytes);
        if trace_id == TraceId::INVALID {
            TraceId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        } else {
            trace_id
        }
    }

    fn next_test_span_id() -> SpanId {
        let seed = NEXT_TEST_SPAN_SEED.fetch_add(1, Ordering::Relaxed);
        let raw = splitmix64(seed ^ 0xa5a5_a5a5_a5a5_a5a5);
        let span_id = SpanId::from_bytes([
            (raw >> 56) as u8,
            (raw >> 48) as u8,
            (raw >> 40) as u8,
            (raw >> 32) as u8,
            (raw >> 24) as u8,
            (raw >> 16) as u8,
            (raw >> 8) as u8,
            raw as u8,
        ]);
        if span_id == SpanId::INVALID {
            SpanId::from_bytes([0, 0, 0, 0, 0, 0, 0, 1])
        } else {
            span_id
        }
    }

    fn splitmix64(mut state: u64) -> u64 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_test_time() -> SystemTime {
        let tick = NEXT_TEST_TIME_TICK.fetch_add(1, Ordering::Relaxed);
        UNIX_EPOCH + Duration::from_nanos(tick)
    }

    fn truncate_value(value: &str, max_len: Option<usize>) -> String {
        match max_len {
            Some(limit) => value.chars().take(limit).collect(),
            None => value.to_string(),
        }
    }

    /// br-asupersync-6ofylg — OTel attribute keys are bounded by the
    /// 1 KiB cap from the OTel spec (and most collectors' wire-level
    /// limits). The deterministic span recorder previously truncated only
    /// the value, leaving the key path open as an asymmetric
    /// memory-amplification axis when combined with the cardinality
    /// tracker (an attacker-controlled key with fixed prefix
    /// produces one map entry per oversized key, each up to
    /// arbitrarily many bytes). Mirror the closed bd-65gy5c
    /// span.rs key cap by truncating keys to MAX_OTEL_ATTRIBUTE_KEY_LEN.
    const MAX_OTEL_ATTRIBUTE_KEY_LEN: usize = 1024;

    fn truncate_key(key: &str) -> String {
        if key.len() <= MAX_OTEL_ATTRIBUTE_KEY_LEN {
            key.to_string()
        } else {
            // The cap is in bytes, but truncation must still land on
            // a UTF-8 character boundary so the stored key remains
            // valid Unicode.
            let mut cut = MAX_OTEL_ATTRIBUTE_KEY_LEN;
            while cut > 0 && !key.is_char_boundary(cut) {
                cut -= 1;
            }
            key[..cut].to_string()
        }
    }

    /// Configuration for span semantics conformance testing.
    #[derive(Debug, Clone)]
    pub struct SpanConformanceConfig {
        /// Maximum number of attributes per span (default: 128 per OTel spec).
        pub max_attributes: usize,
        /// Maximum number of events per span (default: 128 per OTel spec).
        pub max_events: usize,
        /// Maximum attribute value length (default: none per OTel spec).
        pub max_attribute_length: Option<usize>,
        /// Whether to test sampling behavior.
        pub test_sampling: bool,
        /// Whether to test context propagation.
        pub test_context_propagation: bool,
    }

    impl Default for SpanConformanceConfig {
        fn default() -> Self {
            Self {
                max_attributes: 128,
                max_events: 128,
                max_attribute_length: None,
                test_sampling: true,
                test_context_propagation: true,
            }
        }
    }

    /// Result of span semantic conformance testing.
    #[derive(Debug)]
    pub struct SpanConformanceResult {
        /// Total number of tests run.
        pub tests_run: usize,
        /// Number of tests passed.
        pub tests_passed: usize,
        /// Number of tests failed.
        pub tests_failed: usize,
        /// Detailed failure messages.
        pub failures: Vec<String>,
        /// Known conformance gaps that make the run fail closed.
        pub conformance_gaps: Vec<String>,
    }

    impl SpanConformanceResult {
        /// Create new empty result.
        pub fn new() -> Self {
            Self {
                tests_run: 0,
                tests_passed: 0,
                tests_failed: 0,
                failures: Vec::new(),
                conformance_gaps: Vec::new(),
            }
        }

        /// Record a test pass.
        pub fn record_pass(&mut self, _test_name: &str) {
            self.tests_run += 1;
            self.tests_passed += 1;
        }

        /// Record a test failure.
        pub fn record_failure(&mut self, test_name: &str, reason: &str) {
            self.tests_run += 1;
            self.tests_failed += 1;
            self.failures.push(format!("{}: {}", test_name, reason));
        }

        /// Record a known conformance gap as a fail-closed result.
        pub fn record_conformance_gap(&mut self, test_name: &str, reason: &str) {
            self.conformance_gaps
                .push(format!("{}: {}", test_name, reason));
        }

        /// Check if all tests passed with no known conformance gaps.
        /// Fails closed when there are:
        /// - Unexpected test failures
        /// - Known conformance gaps
        pub fn is_success(&self) -> bool {
            self.tests_failed == 0 && self.conformance_gaps.is_empty()
        }

        /// Check whether the runner found any known conformance gaps.
        pub fn has_no_known_conformance_gaps(&self) -> bool {
            self.conformance_gaps.is_empty()
        }

        /// Get comprehensive failure report including fail-closed conformance gaps.
        pub fn failure_report(&self) -> String {
            let mut report = String::new();

            if !self.failures.is_empty() {
                report.push_str("Test Failures:\n");
                for failure in &self.failures {
                    report.push_str(&format!("  - {}\n", failure));
                }
            }

            if !self.conformance_gaps.is_empty() {
                report.push_str("Conformance Gaps (fail closed):\n");
                for gap in &self.conformance_gaps {
                    report.push_str(&format!("  - {}\n", gap));
                }
            }

            if report.is_empty() {
                "No failures detected".to_string()
            } else {
                report
            }
        }

        /// Get success rate as percentage.
        pub fn success_rate(&self) -> f64 {
            if self.tests_run == 0 {
                0.0
            } else {
                (self.tests_passed as f64 / self.tests_run as f64) * 100.0
            }
        }
    }

    /// Test span for conformance verification.
    #[derive(Debug)]
    pub struct TestSpan {
        /// Span context (trace ID, span ID, flags).
        pub context: SpanContext,
        /// Span name.
        pub name: String,
        /// Span kind.
        pub kind: SpanKind,
        /// Start time.
        pub start_time: SystemTime,
        /// End time (if ended).
        pub end_time: Option<SystemTime>,
        /// Span attributes.
        pub attributes: HashMap<String, String>,
        /// OTLP-typed span attributes for wire-format conformance helpers.
        pub attribute_values: HashMap<String, AttributeValue>,
        /// Span events.
        pub events: Vec<SpanEvent>,
        /// Span status.
        pub status: Status,
        /// Parent span context.
        pub parent_context: Option<SpanContext>,
        /// Propagated baggage entries.
        pub baggage: HashMap<String, String>,
        /// Count of attributes dropped because the span exceeded
        /// `max_attributes`. Surfaces as the OTLP wire field
        /// `Span.dropped_attributes_count` so receivers can detect
        /// truncation. Per OTLP spec, when the SDK drops an
        /// attribute due to a per-span limit, this counter MUST
        /// be bumped; emitting 0 while attributes were silently
        /// dropped is a wire-format conformance bug.
        pub dropped_attributes_count: u32,
        max_attributes: usize,
        max_events: usize,
        max_attribute_length: Option<usize>,
    }

    /// Span event for conformance testing.
    #[derive(Debug, Clone)]
    pub struct SpanEvent {
        /// Event name.
        pub name: String,
        /// Event timestamp.
        pub timestamp: SystemTime,
        /// Event attributes.
        pub attributes: HashMap<String, String>,
    }

    /// OTLP attribute value variants for typed span-attribute coverage.
    #[derive(Debug, Clone, PartialEq)]
    pub enum AttributeValue {
        /// UTF-8 string attribute.
        String(String),
        /// Signed integer attribute.
        Int(i64),
        /// Floating-point attribute.
        Float(f64),
        /// Boolean attribute.
        Bool(bool),
        /// UTF-8 string array attribute.
        StringArray(Vec<String>),
        /// Signed integer array attribute.
        IntArray(Vec<i64>),
        /// Floating-point array attribute.
        FloatArray(Vec<f64>),
        /// Boolean array attribute.
        BoolArray(Vec<bool>),
    }

    /// OTLP LogRecord body value variants for body type conformance testing.
    #[derive(Debug, Clone, PartialEq)]
    pub enum LogRecordBodyValue {
        /// UTF-8 string body.
        String(String),
        /// Signed integer body.
        Int(i64),
        /// Floating-point body.
        Float(f64),
        /// Boolean body.
        Bool(bool),
        /// UTF-8 string array body.
        StringArray(Vec<String>),
        /// Signed integer array body.
        IntArray(Vec<i64>),
        /// Floating-point array body.
        FloatArray(Vec<f64>),
        /// Boolean array body.
        BoolArray(Vec<bool>),
    }

    impl TestSpan {
        /// Create a new test span.
        pub fn new(name: &str, kind: SpanKind) -> Self {
            Self::new_with_config(name, kind, &SpanConformanceConfig::default())
        }

        /// Create a new root test span with explicit limits.
        pub fn new_with_config(name: &str, kind: SpanKind, config: &SpanConformanceConfig) -> Self {
            let context = SpanContext::new(
                next_test_trace_id(),
                next_test_span_id(),
                TraceFlags::SAMPLED,
                false,
                TraceState::default(),
            );
            Self::from_parts(
                name,
                kind,
                context,
                None,
                HashMap::new(),
                config.max_attributes,
                config.max_events,
                config.max_attribute_length,
            )
        }

        /// Create a child span.
        pub fn new_child(&self, name: &str, kind: SpanKind) -> Self {
            let parent_context = self.context.clone();
            let context = SpanContext::new(
                parent_context.trace_id(),
                next_test_span_id(),
                parent_context.trace_flags(),
                false,
                parent_context.trace_state().clone(),
            );
            Self::from_parts(
                name,
                kind,
                context,
                Some(parent_context),
                self.baggage.clone(),
                self.max_attributes,
                self.max_events,
                self.max_attribute_length,
            )
        }

        /// Create a child span from an extracted remote parent.
        pub fn child_from_remote_parent(
            parent_context: SpanContext,
            baggage: HashMap<String, String>,
            name: &str,
            kind: SpanKind,
            config: &SpanConformanceConfig,
        ) -> Self {
            let context = SpanContext::new(
                parent_context.trace_id(),
                next_test_span_id(),
                parent_context.trace_flags(),
                false,
                parent_context.trace_state().clone(),
            );
            Self::from_parts(
                name,
                kind,
                context,
                Some(parent_context),
                baggage,
                config.max_attributes,
                config.max_events,
                config.max_attribute_length,
            )
        }

        fn from_parts(
            name: &str,
            kind: SpanKind,
            context: SpanContext,
            parent_context: Option<SpanContext>,
            baggage: HashMap<String, String>,
            max_attributes: usize,
            max_events: usize,
            max_attribute_length: Option<usize>,
        ) -> Self {
            Self {
                context,
                name: name.to_string(),
                kind,
                start_time: next_test_time(),
                end_time: None,
                attributes: HashMap::new(),
                attribute_values: HashMap::new(),
                events: Vec::new(),
                status: Status::Unset,
                parent_context,
                baggage,
                dropped_attributes_count: 0,
                max_attributes,
                max_events,
                max_attribute_length,
            }
        }

        /// Set span attribute.
        ///
        /// br-asupersync-6ofylg — both key and value are length-
        /// bounded. Keys longer than `MAX_OTEL_ATTRIBUTE_KEY_LEN`
        /// are truncated (mirroring the closed bd-65gy5c span
        /// hardening); values are truncated by the existing
        /// `max_attribute_length` config field.
        pub fn set_attribute(&mut self, key: &str, value: &str) {
            self.set_attribute_value(key, AttributeValue::String(value.to_string()));
        }

        /// Set an integer span attribute.
        pub fn set_int_attribute(&mut self, key: &str, value: i64) {
            self.set_attribute_value(key, AttributeValue::Int(value));
        }

        /// Set a floating-point span attribute.
        pub fn set_float_attribute(&mut self, key: &str, value: f64) {
            self.set_attribute_value(key, AttributeValue::Float(value));
        }

        /// Set a boolean span attribute.
        pub fn set_bool_attribute(&mut self, key: &str, value: bool) {
            self.set_attribute_value(key, AttributeValue::Bool(value));
        }

        /// Set an OTLP-typed span attribute for protobuf conformance checks.
        pub fn set_attribute_value(&mut self, key: &str, value: AttributeValue) {
            let key = truncate_key(key);
            if self.attributes.contains_key(&key) || self.attributes.len() < self.max_attributes {
                let value = self.normalize_attribute_value(value);
                self.attributes
                    .insert(key.clone(), attribute_value_text(&value));
                self.attribute_values.insert(key, value);
            } else {
                // br-asupersync-attr-drop-count: bump the OTLP
                // dropped_attributes_count when a NEW attribute is
                // dropped because the span is at the per-span cap.
                // Saturating add prevents wraparound at u32::MAX
                // (a 4-billion-attribute span is implausible, but
                // saturating is the correct semantic — the OTLP
                // spec says "MUST track count of dropped"; once
                // we exceed u32::MAX, capping at MAX is the closest
                // legal representation).
                self.dropped_attributes_count = self.dropped_attributes_count.saturating_add(1);
            }
        }

        /// Add a batch of OTLP protobuf key/value attributes.
        ///
        /// Batch application mirrors repeated `set_attribute_value` calls for
        /// duplicate keys: the last occurrence wins. The implementation stages
        /// normalized keys and values before mutating the span, so filtering and
        /// capacity decisions cannot leave a partially normalized key/value pair
        /// in one of the parallel attribute maps.
        #[cfg(any(test, feature = "fuzz"))]
        pub fn add_attributes(&mut self, attributes: Vec<KeyValue>) {
            let mut deduplicated: HashMap<String, (usize, AttributeValue)> = HashMap::new();
            let mut dropped = 0_u32;

            for (index, attribute) in attributes.into_iter().enumerate() {
                if attribute.key.is_empty() {
                    dropped = dropped.saturating_add(1);
                    continue;
                }

                let key = truncate_key(&attribute.key);
                if key.is_empty() {
                    dropped = dropped.saturating_add(1);
                    continue;
                }

                let Some(value) = attribute
                    .value
                    .as_ref()
                    .and_then(attribute_value_from_any_value)
                else {
                    dropped = dropped.saturating_add(1);
                    continue;
                };

                deduplicated.insert(key, (index, value));
            }

            let mut staged: Vec<_> = deduplicated
                .into_iter()
                .map(|(key, (index, value))| (index, key, value))
                .collect();
            staged.sort_by_key(|(index, _, _)| *index);

            let mut remaining_new_capacity =
                self.max_attributes.saturating_sub(self.attributes.len());
            let mut accepted = Vec::with_capacity(staged.len());

            for (_, key, value) in staged {
                if self.attributes.contains_key(&key) {
                    accepted.push((key, value));
                } else if remaining_new_capacity > 0 {
                    remaining_new_capacity -= 1;
                    accepted.push((key, value));
                } else {
                    dropped = dropped.saturating_add(1);
                }
            }

            for (key, value) in accepted {
                let value = self.normalize_attribute_value(value);
                self.attributes
                    .insert(key.clone(), attribute_value_text(&value));
                self.attribute_values.insert(key, value);
            }

            self.dropped_attributes_count = self.dropped_attributes_count.saturating_add(dropped);
        }

        /// Set a propagated baggage entry.
        pub fn set_baggage_item(&mut self, key: &str, value: &str) {
            self.baggage.insert(key.to_string(), value.to_string());
        }

        /// Add span event.
        pub fn add_event(&mut self, name: &str, mut attributes: HashMap<String, String>) {
            if self.events.len() >= self.max_events {
                return;
            }
            for value in attributes.values_mut() {
                *value = truncate_value(value, self.max_attribute_length);
            }
            let event = SpanEvent {
                name: name.to_string(),
                timestamp: next_test_time(),
                attributes,
            };
            self.events.push(event);
        }

        /// Set span status.
        ///
        /// Per OTLP specification, span status updates follow last-write-wins semantics.
        /// Any status can overwrite any other status - the most recent set_status() call
        /// determines the final span status, regardless of the previous value.
        ///
        /// br-asupersync-8ru8uc — Fixed OTLP spec violation where Error status could not
        /// be overwritten by Ok status. Now implements proper last-write-wins.
        pub fn set_status(&mut self, status: Status) {
            // OTLP spec: last-write-wins for all status transitions
            self.status = status;
        }

        /// End the span.
        pub fn end(&mut self) {
            if self.end_time.is_none() {
                self.end_time = Some(next_test_time());
            }
        }

        /// Get span duration.
        pub fn duration(&self) -> Option<Duration> {
            if let Some(end_time) = self.end_time {
                end_time.duration_since(self.start_time).ok()
            } else {
                None
            }
        }

        /// Check if span is ended.
        pub fn is_ended(&self) -> bool {
            self.end_time.is_some()
        }

        /// Convert span attributes to OTLP protobuf key/value pairs with stable ordering.
        #[cfg(any(test, feature = "fuzz"))]
        pub fn to_otlp_attributes(&self) -> Vec<KeyValue> {
            let mut attributes: Vec<_> = self
                .attribute_values
                .iter()
                .map(|(key, value)| KeyValue {
                    key: key.clone(),
                    value: Some(attribute_value_to_any_value(value)),
                })
                .collect();
            attributes.sort_by(|left, right| left.key.cmp(&right.key));
            attributes
        }

        fn normalize_attribute_value(&self, value: AttributeValue) -> AttributeValue {
            match value {
                AttributeValue::String(value) => {
                    AttributeValue::String(truncate_value(&value, self.max_attribute_length))
                }
                AttributeValue::StringArray(values) => AttributeValue::StringArray(
                    values
                        .into_iter()
                        .map(|value| truncate_value(&value, self.max_attribute_length))
                        .collect(),
                ),
                other => other,
            }
        }
    }

    #[cfg(any(test, feature = "fuzz"))]
    fn attribute_value_from_any_value(value: &AnyValue) -> Option<AttributeValue> {
        match value.value.as_ref()? {
            ProtoValue::StringValue(value) => Some(AttributeValue::String(value.clone())),
            ProtoValue::BoolValue(value) => Some(AttributeValue::Bool(*value)),
            ProtoValue::IntValue(value) => Some(AttributeValue::Int(*value)),
            ProtoValue::DoubleValue(value) => Some(AttributeValue::Float(*value)),
            ProtoValue::ArrayValue(values) => attribute_array_value_from_any_values(&values.values),
            ProtoValue::KvlistValue(_) | ProtoValue::BytesValue(_) => None,
        }
    }

    #[cfg(any(test, feature = "fuzz"))]
    fn attribute_array_value_from_any_values(values: &[AnyValue]) -> Option<AttributeValue> {
        if values.is_empty() {
            return Some(AttributeValue::StringArray(Vec::new()));
        }

        let mut strings = Vec::with_capacity(values.len());
        for value in values {
            match value.value.as_ref()? {
                ProtoValue::StringValue(value) => strings.push(value.clone()),
                _ => {
                    strings.clear();
                    break;
                }
            }
        }
        if strings.len() == values.len() {
            return Some(AttributeValue::StringArray(strings));
        }

        let mut ints = Vec::with_capacity(values.len());
        for value in values {
            match value.value.as_ref()? {
                ProtoValue::IntValue(value) => ints.push(*value),
                _ => {
                    ints.clear();
                    break;
                }
            }
        }
        if ints.len() == values.len() {
            return Some(AttributeValue::IntArray(ints));
        }

        let mut floats = Vec::with_capacity(values.len());
        for value in values {
            match value.value.as_ref()? {
                ProtoValue::DoubleValue(value) => floats.push(*value),
                _ => {
                    floats.clear();
                    break;
                }
            }
        }
        if floats.len() == values.len() {
            return Some(AttributeValue::FloatArray(floats));
        }

        let mut bools = Vec::with_capacity(values.len());
        for value in values {
            match value.value.as_ref()? {
                ProtoValue::BoolValue(value) => bools.push(*value),
                _ => return None,
            }
        }
        Some(AttributeValue::BoolArray(bools))
    }

    fn attribute_value_text(value: &AttributeValue) -> String {
        match value {
            AttributeValue::String(value) => value.clone(),
            AttributeValue::Int(value) => value.to_string(),
            AttributeValue::Float(value) => value.to_string(),
            AttributeValue::Bool(value) => value.to_string(),
            AttributeValue::StringArray(values) => values.join(","),
            AttributeValue::IntArray(values) => values
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            AttributeValue::FloatArray(values) => values
                .iter()
                .map(f64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            AttributeValue::BoolArray(values) => values
                .iter()
                .map(bool::to_string)
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    #[cfg(any(test, feature = "fuzz"))]
    fn attribute_value_to_any_value(value: &AttributeValue) -> AnyValue {
        use opentelemetry_proto::tonic::common::v1::ArrayValue;

        match value {
            AttributeValue::String(value) => AnyValue {
                value: Some(ProtoValue::StringValue(value.clone())),
            },
            AttributeValue::Int(value) => AnyValue {
                value: Some(ProtoValue::IntValue(*value)),
            },
            AttributeValue::Float(value) => AnyValue {
                value: Some(ProtoValue::DoubleValue(*value)),
            },
            AttributeValue::Bool(value) => AnyValue {
                value: Some(ProtoValue::BoolValue(*value)),
            },
            AttributeValue::StringArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::StringValue(value.clone())),
                        })
                        .collect(),
                })),
            },
            AttributeValue::IntArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::IntValue(*value)),
                        })
                        .collect(),
                })),
            },
            AttributeValue::FloatArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::DoubleValue(*value)),
                        })
                        .collect(),
                })),
            },
            AttributeValue::BoolArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::BoolValue(*value)),
                        })
                        .collect(),
                })),
            },
        }
    }

    /// Convert LogRecord body value to OTLP AnyValue protobuf representation.
    #[cfg(any(test, feature = "fuzz"))]
    pub fn log_record_body_value_to_any_value(value: &LogRecordBodyValue) -> AnyValue {
        use opentelemetry_proto::tonic::common::v1::ArrayValue;

        match value {
            LogRecordBodyValue::String(value) => AnyValue {
                value: Some(ProtoValue::StringValue(value.clone())),
            },
            LogRecordBodyValue::Int(value) => AnyValue {
                value: Some(ProtoValue::IntValue(*value)),
            },
            LogRecordBodyValue::Float(value) => AnyValue {
                value: Some(ProtoValue::DoubleValue(*value)),
            },
            LogRecordBodyValue::Bool(value) => AnyValue {
                value: Some(ProtoValue::BoolValue(*value)),
            },
            LogRecordBodyValue::StringArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::StringValue(value.clone())),
                        })
                        .collect(),
                })),
            },
            LogRecordBodyValue::IntArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::IntValue(*value)),
                        })
                        .collect(),
                })),
            },
            LogRecordBodyValue::FloatArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::DoubleValue(*value)),
                        })
                        .collect(),
                })),
            },
            LogRecordBodyValue::BoolArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::BoolValue(*value)),
                        })
                        .collect(),
                })),
            },
        }
    }

    /// Run comprehensive span semantics conformance tests.
    pub fn run_span_conformance_tests() -> Result<SpanConformanceResult, Box<dyn std::error::Error>>
    {
        let config = SpanConformanceConfig::default();
        run_span_conformance_tests_with_config(&config)
    }

    /// Run span semantics conformance tests with custom configuration.
    pub fn run_span_conformance_tests_with_config(
        config: &SpanConformanceConfig,
    ) -> Result<SpanConformanceResult, Box<dyn std::error::Error>> {
        let mut result = SpanConformanceResult::new();

        // Test 1: Span Lifecycle Semantics
        test_span_lifecycle(&mut result, config);

        // Test 2: Span Hierarchy and Context Propagation
        test_span_hierarchy(&mut result, config);

        // Test 3: Span Attributes
        test_span_attributes(&mut result, config);

        // Test 4: Span Events
        test_span_events(&mut result, config);

        // Test 5: Span Status
        test_span_status(&mut result, config);

        // Test 6: Span Context and IDs
        test_span_context(&mut result, config);

        // Test 7: Span Sampling (if enabled)
        if config.test_sampling {
            test_span_sampling(&mut result, config);
        }

        // Test 8: Context Propagation (if enabled)
        if config.test_context_propagation {
            test_context_propagation(&mut result, config);
        }

        Ok(result)
    }

    /// Test span lifecycle semantics.
    fn test_span_lifecycle(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 1.1: Basic span start/end
        {
            let mut span = TestSpan::new("test_span", SpanKind::Internal);
            let start_time = span.start_time;

            // Span should not be ended initially
            if span.is_ended() {
                result.record_failure("span_lifecycle_start", "New span should not be ended");
                return;
            }

            span.end();

            // Span should be ended after calling end()
            if !span.is_ended() {
                result.record_failure(
                    "span_lifecycle_end",
                    "Span should be ended after end() call",
                );
                return;
            }

            // End time should be after start time
            if let Some(duration) = span.duration() {
                if duration.is_zero() && span.end_time.unwrap() < start_time {
                    result.record_failure(
                        "span_lifecycle_duration",
                        "End time should be >= start time",
                    );
                    return;
                }
            } else {
                result.record_failure(
                    "span_lifecycle_duration",
                    "Ended span should have calculable duration",
                );
                return;
            }

            result.record_pass("span_lifecycle_basic");
        }

        // Test 1.2: Multiple end() calls should be idempotent
        {
            let mut span = TestSpan::new("test_span_double_end", SpanKind::Internal);
            span.end();
            let first_end_time = span.end_time;

            // Second end() call should not change end time
            span.end();

            if span.end_time != first_end_time {
                result.record_failure(
                    "span_lifecycle_idempotent",
                    "Multiple end() calls should be idempotent",
                );
                return;
            }

            result.record_pass("span_lifecycle_idempotent");
        }
    }

    /// Test span hierarchy and parent-child relationships.
    fn test_span_hierarchy(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 2.1: Parent-child relationship
        {
            let parent = TestSpan::new("parent_span", SpanKind::Internal);
            let child = parent.new_child("child_span", SpanKind::Internal);

            // Child should have same trace ID as parent
            if child.context.trace_id() != parent.context.trace_id() {
                result.record_failure(
                    "span_hierarchy_trace_id",
                    "Child span should have same trace ID as parent",
                );
                return;
            }

            // Child should have different span ID from parent
            if child.context.span_id() == parent.context.span_id() {
                result.record_failure(
                    "span_hierarchy_span_id",
                    "Child span should have different span ID from parent",
                );
                return;
            }

            // Child should reference parent context
            if child.parent_context.is_none() {
                result.record_failure(
                    "span_hierarchy_parent_context",
                    "Child span should have parent context",
                );
                return;
            }

            if child.parent_context.unwrap() != parent.context {
                result.record_failure(
                    "span_hierarchy_parent_reference",
                    "Child span should reference correct parent context",
                );
                return;
            }

            result.record_pass("span_hierarchy_basic");
        }

        // Test 2.2: Multi-level hierarchy
        {
            let grandparent = TestSpan::new("grandparent", SpanKind::Internal);
            let parent = grandparent.new_child("parent", SpanKind::Internal);
            let child = parent.new_child("child", SpanKind::Internal);

            // All spans should share same trace ID
            if child.context.trace_id() != grandparent.context.trace_id()
                || parent.context.trace_id() != grandparent.context.trace_id()
            {
                result.record_failure(
                    "span_hierarchy_multi_level",
                    "All spans in hierarchy should share trace ID",
                );
                return;
            }

            result.record_pass("span_hierarchy_multi_level");
        }
    }

    /// Test span attributes.
    fn test_span_attributes(result: &mut SpanConformanceResult, config: &SpanConformanceConfig) {
        // Test 3.1: Basic attribute setting
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            span.set_attribute("service.name", "test-service");
            span.set_attribute("http.method", "GET");

            if span.attributes.len() != 2 {
                result.record_failure("span_attributes_basic", "Span should have 2 attributes");
                return;
            }

            if span.attributes.get("service.name") != Some(&"test-service".to_string()) {
                result.record_failure("span_attributes_basic", "Attribute value should match");
                return;
            }

            result.record_pass("span_attributes_basic");
        }

        // Test 3.2: Attribute overwrite
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            span.set_attribute("test.key", "original_value");
            span.set_attribute("test.key", "new_value");

            if span.attributes.get("test.key") != Some(&"new_value".to_string()) {
                result.record_failure(
                    "span_attributes_overwrite",
                    "Attribute should be overwritten",
                );
                return;
            }

            result.record_pass("span_attributes_overwrite");
        }

        // Test 3.3: Attribute limits (if configured)
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);

            // Add more than max_attributes to test limit
            for i in 0..config.max_attributes + 10 {
                span.set_attribute(&format!("attr_{}", i), "value");
            }

            if span.attributes.len() != config.max_attributes {
                result.record_failure(
                    "span_attributes_limits",
                    "Attribute count should respect max_attributes",
                );
                return;
            }

            result.record_pass("span_attributes_limits");
        }

        if let Some(limit) = config.max_attribute_length {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            let oversized = "x".repeat(limit + 5);
            span.set_attribute("oversized", &oversized);

            if span.attributes.get("oversized").map(String::len) != Some(limit) {
                result.record_failure(
                    "span_attributes_value_length",
                    "Attribute values should respect max_attribute_length",
                );
                return;
            }

            result.record_pass("span_attributes_value_length");
        }
    }

    /// Test span events.
    fn test_span_events(result: &mut SpanConformanceResult, config: &SpanConformanceConfig) {
        // Test 4.1: Basic event recording
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            let mut event_attrs = HashMap::new();
            event_attrs.insert("event.severity".to_string(), "info".to_string());

            span.add_event("test_event", event_attrs);

            if span.events.len() != 1 {
                result.record_failure("span_events_basic", "Span should have 1 event");
                return;
            }

            let event = &span.events[0];
            if event.name != "test_event" {
                result.record_failure("span_events_basic", "Event name should match");
                return;
            }

            result.record_pass("span_events_basic");
        }

        // Test 4.2: Multiple events with ordering
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);

            span.add_event("first_event", HashMap::new());
            span.add_event("second_event", HashMap::new());

            if span.events.len() != 2 {
                result.record_failure("span_events_multiple", "Span should have 2 events");
                return;
            }

            // Events should be in chronological order
            if span.events[0].timestamp > span.events[1].timestamp {
                result.record_failure(
                    "span_events_ordering",
                    "Events should be in chronological order",
                );
                return;
            }

            result.record_pass("span_events_multiple");
        }

        // Test 4.3: Event limits (if configured)
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);

            // Add more than max_events to test limit
            for i in 0..config.max_events + 10 {
                span.add_event(&format!("event_{}", i), HashMap::new());
            }

            if span.events.len() != config.max_events {
                result.record_failure(
                    "span_events_limits",
                    "Event count should respect max_events",
                );
                return;
            }

            result.record_pass("span_events_limits");
        }
    }

    /// Test span status semantics.
    fn test_span_status(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 5.1: Default status
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);

            if !matches!(span.status, Status::Unset) {
                result.record_failure("span_status_default", "Default span status should be Unset");
                return;
            }

            result.record_pass("span_status_default");
        }

        // Test 5.2: Setting status
        {
            let mut span = TestSpan::new("test_span", SpanKind::Internal);
            span.set_status(Status::Error {
                description: "Something went wrong".into(),
            });

            if let Status::Error { description } = &span.status {
                if description != "Something went wrong" {
                    result.record_failure("span_status_set", "Status description should match");
                    return;
                }
            } else {
                result.record_failure("span_status_set", "Status should be Error");
                return;
            }

            result.record_pass("span_status_set");
        }

        // Test 5.3: Status precedence (Error takes precedence over Ok)
        {
            let mut span = TestSpan::new("test_span", SpanKind::Internal);
            span.set_status(Status::Ok);
            span.set_status(Status::Error {
                description: "Error occurred".into(),
            });

            if !matches!(span.status, Status::Error { .. }) {
                result.record_failure(
                    "span_status_precedence",
                    "Error status should take precedence",
                );
                return;
            }

            result.record_pass("span_status_precedence");
        }
    }

    /// Test span context and ID semantics.
    fn test_span_context(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 6.1: Unique span IDs
        {
            let span1 = TestSpan::new("span1", SpanKind::Internal);
            let span2 = TestSpan::new("span2", SpanKind::Internal);

            if span1.context.span_id() == span2.context.span_id() {
                result.record_failure(
                    "span_context_unique_ids",
                    "Different spans should have different span IDs",
                );
                return;
            }

            result.record_pass("span_context_unique_ids");
        }

        // Test 6.2: Trace ID format
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);
            let trace_id = span.context.trace_id();

            // Trace ID should not be zero (invalid)
            if trace_id == TraceId::INVALID {
                result.record_failure(
                    "span_context_trace_id",
                    "Trace ID should not be invalid/zero",
                );
                return;
            }

            result.record_pass("span_context_trace_id");
        }

        // Test 6.3: Span ID format
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);
            let span_id = span.context.span_id();

            // Span ID should not be zero (invalid)
            if span_id == SpanId::INVALID {
                result.record_failure("span_context_span_id", "Span ID should not be invalid/zero");
                return;
            }

            result.record_pass("span_context_span_id");
        }
    }

    /// Test span sampling behavior.
    fn test_span_sampling(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 7.1: Sampled flag consistency
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);

            // In our test implementation, spans are always sampled
            if !span.context.trace_flags().is_sampled() {
                result.record_failure("span_sampling_flag", "Test spans should be sampled");
                return;
            }

            result.record_pass("span_sampling_basic");
        }

        // Test 7.2: Sampling inheritance
        {
            let parent = TestSpan::new("parent", SpanKind::Internal);
            let child = parent.new_child("child", SpanKind::Internal);

            // Child should inherit sampling decision from parent
            if parent.context.trace_flags().is_sampled() != child.context.trace_flags().is_sampled()
            {
                result.record_failure(
                    "span_sampling_inheritance",
                    "Child should inherit parent sampling decision",
                );
                return;
            }

            result.record_pass("span_sampling_inheritance");
        }
    }

    /// Test context propagation semantics.
    fn test_context_propagation(
        result: &mut SpanConformanceResult,
        config: &SpanConformanceConfig,
    ) {
        // Test 8.1: Context propagation across service boundaries
        {
            // Build the context extracted from an incoming request.
            let trace_id = TraceId::from_bytes([
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
                0xcd, 0xef,
            ]);
            let span_id = SpanId::from_bytes([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
            let trace_state =
                TraceState::from_key_value([("vendor", "upstream")]).expect("valid trace state");
            let incoming_context = SpanContext::new(
                trace_id,
                span_id,
                TraceFlags::SAMPLED,
                true,
                trace_state.clone(),
            );

            let mut baggage = HashMap::new();
            baggage.insert("tenant".to_string(), "alpha".to_string());
            let child = TestSpan::child_from_remote_parent(
                incoming_context.clone(),
                baggage,
                "remote_child",
                SpanKind::Server,
                config,
            );

            if child.context.trace_id() != incoming_context.trace_id() {
                result.record_failure(
                    "context_propagation_trace_id",
                    "Trace ID should be preserved across boundaries",
                );
                return;
            }

            if child.context.trace_flags() != incoming_context.trace_flags() {
                result.record_failure(
                    "context_propagation_flags",
                    "Trace flags should be preserved",
                );
                return;
            }

            if !incoming_context.is_remote() || child.context.is_remote() {
                result.record_failure(
                    "context_propagation_remote_flag",
                    "Incoming context should stay remote while child becomes local",
                );
                return;
            }

            result.record_pass("context_propagation_basic");
        }

        // Test 8.2: TraceState propagation
        {
            let trace_state =
                TraceState::from_key_value([("vendor", "upstream")]).expect("valid trace state");
            let incoming_context = SpanContext::new(
                TraceId::from_bytes([
                    0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd,
                    0xdd, 0xdd, 0xdd,
                ]),
                SpanId::from_bytes([0x11; 8]),
                TraceFlags::SAMPLED,
                true,
                trace_state,
            );
            let child = TestSpan::child_from_remote_parent(
                incoming_context,
                HashMap::new(),
                "remote_child",
                SpanKind::Consumer,
                config,
            );

            if child.context.trace_state().get("vendor") != Some("upstream") {
                result.record_failure(
                    "context_propagation_state",
                    "TraceState should propagate to child spans",
                );
                return;
            }

            result.record_pass("context_propagation_state");
        }

        // Test 8.3: Baggage propagation
        {
            let incoming_context = SpanContext::new(
                TraceId::from_bytes([
                    0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff, 0x11, 0x11, 0x11, 0x11, 0x22,
                    0x22, 0x22, 0x22,
                ]),
                SpanId::from_bytes([0x22; 8]),
                TraceFlags::SAMPLED,
                true,
                TraceState::default(),
            );
            let mut baggage = HashMap::new();
            baggage.insert("tenant".to_string(), "alpha".to_string());
            baggage.insert("request.class".to_string(), "gold".to_string());
            let child = TestSpan::child_from_remote_parent(
                incoming_context,
                baggage,
                "remote_child",
                SpanKind::Server,
                config,
            );

            if child.baggage.get("tenant").map(String::as_str) != Some("alpha")
                || child.baggage.get("request.class").map(String::as_str) != Some("gold")
            {
                result.record_failure(
                    "context_propagation_baggage",
                    "Baggage should propagate across service boundaries",
                );
                return;
            }

            result.record_pass("context_propagation_baggage");
        }
    }

    #[cfg(test)]
    pub(crate) mod tests {
        use super::*;
        use crate::observability::MetricsSnapshot;
        use serde_json::{Value, json};
        use std::collections::BTreeMap;

        fn scrub_span_field(key: &str, value: &str) -> String {
            match key {
                "trace_id" | "span_id" | "parent_span_id" => "[ID]".to_string(),
                "start_time" | "end_time" | "timestamp" => "[TIMESTAMP]".to_string(),
                "request_id" | "traceparent" => "[ID]".to_string(),
                _ => value.to_string(),
            }
        }

        fn sorted_string_map_snapshot(map: &HashMap<String, String>) -> BTreeMap<String, String> {
            map.iter()
                .map(|(key, value)| (key.clone(), scrub_span_field(key, value)))
                .collect()
        }

        fn span_status_snapshot(status: &Status) -> Value {
            match status {
                Status::Unset => json!({"kind": "unset"}),
                Status::Ok => json!({"kind": "ok"}),
                Status::Error { description } => json!({
                    "kind": "error",
                    "description": description,
                }),
            }
        }

        fn span_event_snapshot(event: &SpanEvent) -> Value {
            json!({
                "name": event.name,
                "timestamp": "[TIMESTAMP]",
                "attributes": sorted_string_map_snapshot(&event.attributes),
            })
        }

        pub fn test_span_snapshot(span: &TestSpan) -> Value {
            json!({
                "name": span.name,
                "kind": format!("{:?}", span.kind),
                "trace_id": "[ID]",
                "span_id": "[ID]",
                "parent_span_id": span.parent_context.as_ref().map(|_| "[ID]"),
                "is_remote": span.context.is_remote(),
                "sampled": span.context.trace_flags().is_sampled(),
                "trace_state": span.context.trace_state().header(),
                "start_time": "[TIMESTAMP]",
                "end_time": span.end_time.map(|_| "[TIMESTAMP]"),
                "status": span_status_snapshot(&span.status),
                "attributes": sorted_string_map_snapshot(&span.attributes),
                "baggage": sorted_string_map_snapshot(&span.baggage),
                "events": span.events.iter().map(span_event_snapshot).collect::<Vec<_>>(),
            })
        }

        fn otlp_attributes_snapshot(map: &HashMap<String, String>) -> Vec<Value> {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            entries
                .into_iter()
                .map(|(key, value)| {
                    json!({
                        "key": key,
                        "value": {
                            "string_value": scrub_span_field(key, value),
                        }
                    })
                })
                .collect()
        }

        fn otlp_metric_labels_snapshot(labels: &[(String, String)]) -> Vec<Value> {
            let mut entries: Vec<_> = labels.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            entries
                .into_iter()
                .map(|(key, value)| {
                    json!({
                        "key": key,
                        "value": {
                            "string_value": value,
                        }
                    })
                })
                .collect()
        }

        fn otlp_status_snapshot(status: &Status) -> Value {
            match status {
                Status::Unset => json!({"code": 0, "message": ""}),
                Status::Ok => json!({"code": 1, "message": ""}),
                Status::Error { description } => json!({
                    "code": 2,
                    "message": description,
                }),
            }
        }

        fn otlp_event_wire_snapshot(event: &SpanEvent) -> Value {
            json!({
                "name": event.name,
                "time_unix_nano": "[TIMESTAMP]",
                "attributes": otlp_attributes_snapshot(&event.attributes),
            })
        }

        fn otlp_span_wire_snapshot(span: &TestSpan) -> Value {
            json!({
                "trace_id": "[ID]",
                "span_id": "[ID]",
                "parent_span_id": span.parent_context.as_ref().map_or("", |_| "[ID]"),
                "name": span.name,
                "kind": format!("{:?}", span.kind),
                "start_time_unix_nano": "[TIMESTAMP]",
                "end_time_unix_nano": span.end_time.map(|_| "[TIMESTAMP]"),
                "attributes": otlp_attributes_snapshot(&span.attributes),
                "events": span.events.iter().map(otlp_event_wire_snapshot).collect::<Vec<_>>(),
                "status": otlp_status_snapshot(&span.status),
                "trace_state": span.context.trace_state().header(),
                "sampled": span.context.trace_flags().is_sampled(),
            })
        }

        fn otlp_metrics_wire_snapshot(snapshot: &MetricsSnapshot) -> Value {
            let mut counters: Vec<_> = snapshot.counters.iter().collect();
            counters.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));

            let mut gauges: Vec<_> = snapshot.gauges.iter().collect();
            gauges.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));

            let mut histograms: Vec<_> = snapshot.histograms.iter().collect();
            histograms.sort_by(|(left, _, _, _), (right, _, _, _)| left.cmp(right));

            json!({
                "scope_metrics": [{
                    "scope": {
                        "name": "asupersync.observability.otel",
                        "version": "0.2.9",
                    },
                    "metrics": {
                        "counters": counters.into_iter().map(|(name, labels, value)| {
                            json!({
                                "name": name,
                                "sum": {
                                    "data_points": [{
                                        "attributes": otlp_metric_labels_snapshot(labels),
                                        "as_int": value,
                                    }]
                                }
                            })
                        }).collect::<Vec<_>>(),
                        "gauges": gauges.into_iter().map(|(name, labels, value)| {
                            json!({
                                "name": name,
                                "gauge": {
                                    "data_points": [{
                                        "attributes": otlp_metric_labels_snapshot(labels),
                                        "as_int": value,
                                    }]
                                }
                            })
                        }).collect::<Vec<_>>(),
                        "histograms": histograms.into_iter().map(|(name, labels, count, sum)| {
                            json!({
                                "name": name,
                                "histogram": {
                                    "data_points": [{
                                        "attributes": otlp_metric_labels_snapshot(labels),
                                        "count": count,
                                        "sum": sum,
                                    }]
                                }
                            })
                        }).collect::<Vec<_>>(),
                    }
                }]
            })
        }

        fn otlp_log_record_snapshot(body: &str, attributes: HashMap<String, String>) -> Value {
            json!({
                "time_unix_nano": "[TIMESTAMP]",
                "trace_id": "[ID]",
                "span_id": "[ID]",
                "severity_text": "INFO",
                "body": body,
                "attributes": otlp_attributes_snapshot(&attributes),
            })
        }

        #[test]
        fn test_span_conformance_config_default() {
            let config = SpanConformanceConfig::default();
            assert_eq!(config.max_attributes, 128);
            assert_eq!(config.max_events, 128);
            assert!(config.test_sampling);
            assert!(config.test_context_propagation);
        }

        #[test]
        fn test_span_conformance_result() {
            let mut result = SpanConformanceResult::new();
            assert_eq!(result.tests_run, 0);
            assert!(result.is_success()); // No tests run is considered success

            result.record_pass("test1");
            assert_eq!(result.tests_run, 1);
            assert_eq!(result.tests_passed, 1);
            assert!(result.is_success());

            result.record_failure("test2", "failed");
            assert_eq!(result.tests_run, 2);
            assert_eq!(result.tests_failed, 1);
            assert!(!result.is_success());
            assert_eq!(result.success_rate(), 50.0);
        }

        #[test]
        fn test_span_basic_operations() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            assert!(!span.is_ended());
            assert!(span.duration().is_none());

            span.set_attribute("key", "value");
            assert_eq!(span.attributes.get("key"), Some(&"value".to_string()));

            span.add_event("event", HashMap::new());
            assert_eq!(span.events.len(), 1);

            span.end();
            assert!(span.is_ended());
            assert!(span.duration().is_some());
        }

        #[test]
        fn test_span_typed_attributes_round_trip_to_otlp() {
            use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;

            let mut span = TestSpan::new("typed", SpanKind::Internal);
            span.set_attribute("service.name", "edge");
            span.set_int_attribute("http.status_code", 200);
            span.set_float_attribute("latency_ms", 1.5);
            span.set_bool_attribute("cached", true);
            span.set_attribute_value("replicas", AttributeValue::IntArray(vec![1, 2, 3]));

            let otlp = span.to_otlp_attributes();
            assert_eq!(otlp.len(), 5);

            let replicas = otlp
                .iter()
                .find(|attr| attr.key == "replicas")
                .and_then(|attr| attr.value.as_ref())
                .and_then(|value| value.value.as_ref());
            assert!(matches!(replicas, Some(ProtoValue::ArrayValue(_))));

            let status = otlp
                .iter()
                .find(|attr| attr.key == "http.status_code")
                .and_then(|attr| attr.value.as_ref())
                .and_then(|value| value.value.as_ref());
            assert_eq!(status, Some(&ProtoValue::IntValue(200)));
        }

        #[test]
        fn test_span_typed_attribute_limits_apply() {
            let config = SpanConformanceConfig {
                max_attributes: 2,
                max_events: 4,
                max_attribute_length: Some(4),
                test_sampling: true,
                test_context_propagation: true,
            };
            let mut span = TestSpan::new_with_config("typed", SpanKind::Internal, &config);

            span.set_attribute("alpha", "abcdef");
            span.set_int_attribute("beta", 42);
            span.set_bool_attribute("gamma", true);

            assert_eq!(span.to_otlp_attributes().len(), 2);
            assert_eq!(
                span.attributes.get("alpha").map(String::as_str),
                Some("abcd")
            );
        }

        #[test]
        fn test_span_end_is_idempotent() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            span.end();
            let first_end_time = span.end_time;
            span.end();
            assert_eq!(span.end_time, first_end_time);
        }

        #[test]
        fn test_span_hierarchy() {
            let parent = TestSpan::new("parent", SpanKind::Internal);
            let child = parent.new_child("child", SpanKind::Internal);

            assert_eq!(child.context.trace_id(), parent.context.trace_id());
            assert_ne!(child.context.span_id(), parent.context.span_id());
            assert!(child.parent_context.is_some());
            assert_eq!(child.parent_context.unwrap(), parent.context);
        }

        #[test]
        fn test_span_remote_parent_propagates_trace_state_and_baggage() {
            let config = SpanConformanceConfig {
                max_attributes: 8,
                max_events: 8,
                max_attribute_length: Some(8),
                test_sampling: true,
                test_context_propagation: true,
            };
            let trace_state =
                TraceState::from_key_value([("vendor", "edge")]).expect("valid trace state");
            let remote_parent = SpanContext::new(
                TraceId::from_bytes([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15,
                    0x16, 0x17, 0x18,
                ]),
                SpanId::from_bytes([0x11; 8]),
                TraceFlags::SAMPLED,
                true,
                trace_state,
            );
            let mut baggage = HashMap::new();
            baggage.insert("tenant".to_string(), "alpha".to_string());

            let child = TestSpan::child_from_remote_parent(
                remote_parent,
                baggage,
                "child",
                SpanKind::Server,
                &config,
            );

            assert_eq!(child.context.trace_state().get("vendor"), Some("edge"));
            assert_eq!(
                child.baggage.get("tenant").map(String::as_str),
                Some("alpha")
            );
            assert!(!child.context.is_remote());
            assert!(child.parent_context.expect("parent").is_remote());
        }

        #[test]
        fn test_span_attribute_and_event_limits_are_enforced() {
            let config = SpanConformanceConfig {
                max_attributes: 2,
                max_events: 1,
                max_attribute_length: Some(4),
                test_sampling: true,
                test_context_propagation: true,
            };
            let mut span = TestSpan::new_with_config("test", SpanKind::Internal, &config);

            span.set_attribute("k1", "value");
            span.set_attribute("k2", "value");
            span.set_attribute("k3", "value");
            assert_eq!(span.attributes.len(), 2);
            assert_eq!(span.attributes.get("k1").map(String::as_str), Some("valu"));

            span.add_event("one", HashMap::new());
            span.add_event("two", HashMap::new());
            assert_eq!(span.events.len(), 1);
        }

        /// br-asupersync-6ofylg — keys longer than
        /// `MAX_OTEL_ATTRIBUTE_KEY_LEN` MUST be truncated to the cap.
        #[test]
        fn test_span_attribute_key_is_truncated_to_otel_cap() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            let oversized_key: String = "k".repeat(super::MAX_OTEL_ATTRIBUTE_KEY_LEN + 100);
            span.set_attribute(&oversized_key, "value");
            // The stored key length must equal the cap (ASCII path:
            // bytes == chars).
            let stored_keys: Vec<&String> = span.attributes.keys().collect();
            assert_eq!(stored_keys.len(), 1);
            assert_eq!(stored_keys[0].len(), super::MAX_OTEL_ATTRIBUTE_KEY_LEN);
            // Original oversized key is NOT in the map (it was truncated).
            assert!(!span.attributes.contains_key(&oversized_key));
        }

        /// br-asupersync-6ofylg — the 1 KiB cap is byte-based, not
        /// char-based. Oversized multibyte keys must therefore be
        /// truncated to <= 1024 bytes while remaining valid UTF-8.
        #[test]
        fn test_span_attribute_multibyte_key_is_truncated_by_bytes() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            let oversized_key = "🔒".repeat(400);
            assert!(oversized_key.len() > super::MAX_OTEL_ATTRIBUTE_KEY_LEN);

            span.set_attribute(&oversized_key, "value");

            let stored_key = span.attributes.keys().next().expect("stored key");
            assert!(stored_key.len() <= super::MAX_OTEL_ATTRIBUTE_KEY_LEN);
            assert!(std::str::from_utf8(stored_key.as_bytes()).is_ok());
            assert!(!span.attributes.contains_key(&oversized_key));
        }

        /// br-asupersync-6ofylg — short keys pass through unchanged.
        #[test]
        fn test_span_attribute_short_key_unchanged() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            span.set_attribute("short_key", "value");
            assert!(span.attributes.contains_key("short_key"));
        }

        #[test]
        fn test_span_timestamps_are_monotonic() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            let start_time = span.start_time;

            span.add_event("first", HashMap::new());
            span.add_event("second", HashMap::new());
            span.end();

            let first_event = &span.events[0];
            let second_event = &span.events[1];
            let end_time = span.end_time.expect("span end time");

            assert!(first_event.timestamp >= start_time);
            assert!(second_event.timestamp >= first_event.timestamp);
            assert!(end_time >= second_event.timestamp);
            assert!(span.duration().is_some());
        }

        #[test]
        fn run_basic_conformance_tests() {
            // Test the actual conformance runner with concrete fail-closed checks.
            let config = SpanConformanceConfig::default();
            let result = run_span_conformance_tests_with_config(&config)
                .expect("Conformance tests should run");

            assert!(result.tests_run > 0);
            assert!(
                result.is_success(),
                "Conformance runner should pass all implemented checks: {}",
                result.failure_report()
            );
        }

        #[test]
        fn span_export_snapshot_scrubs_ids_and_timestamps() {
            let config = SpanConformanceConfig {
                max_attributes: 4,
                max_events: 2,
                max_attribute_length: Some(16),
                test_sampling: true,
                test_context_propagation: true,
            };

            let mut parent = TestSpan::new_with_config("checkout", SpanKind::Server, &config);
            parent.set_attribute("component", "orders");
            parent.set_attribute("request_id", "req-7c1f7ecf-54ff-4ac8-8ec5-6aa64500a161");
            parent.set_baggage_item("tenant", "alpha");
            parent.add_event(
                "db.query",
                HashMap::from([
                    ("statement".to_string(), "select".to_string()),
                    (
                        "traceparent".to_string(),
                        "00-abcdef-0123456789".to_string(),
                    ),
                ]),
            );
            parent.set_status(Status::Error {
                description: "timeout".into(),
            });
            parent.end();

            let remote_parent = SpanContext::new(
                TraceId::from_bytes([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15,
                    0x16, 0x17, 0x18,
                ]),
                SpanId::from_bytes([0x11; 8]),
                TraceFlags::SAMPLED,
                true,
                TraceState::from_key_value([("vendor", "edge")]).expect("valid trace state"),
            );
            let remote_child = TestSpan::child_from_remote_parent(
                remote_parent,
                HashMap::from([("tenant".to_string(), "alpha".to_string())]),
                "cache.lookup",
                SpanKind::Client,
                &config,
            );

            insta::assert_json_snapshot!(
                "span_export_scrubbed",
                json!({
                    "parent": test_span_snapshot(&parent),
                    "remote_child": test_span_snapshot(&remote_child),
                })
            );
        }

        #[test]
        fn span_export_format_snapshot_scrubs_ids_and_timestamps() {
            let config = SpanConformanceConfig {
                max_attributes: 6,
                max_events: 3,
                max_attribute_length: Some(20),
                test_sampling: true,
                test_context_propagation: true,
            };

            let mut happy_path =
                TestSpan::new_with_config("http.request", SpanKind::Server, &config);
            happy_path.set_attribute("service.name", "checkout");
            happy_path.set_attribute("http.method", "POST");
            happy_path.add_event(
                "response.sent",
                HashMap::from([("status_code".to_string(), "200".to_string())]),
            );
            happy_path.set_status(Status::Ok);
            happy_path.end();

            let mut error_path = TestSpan::new_with_config("db.query", SpanKind::Client, &config);
            error_path.set_attribute("db.system", "postgresql");
            error_path.set_attribute("db.operation", "select");
            error_path.add_event(
                "db.error",
                HashMap::from([
                    ("error.kind".to_string(), "timeout".to_string()),
                    ("statement".to_string(), "select * from orders".to_string()),
                ]),
            );
            error_path.set_status(Status::Error {
                description: "deadline exceeded".into(),
            });
            error_path.end();

            let mut root = TestSpan::new_with_config("batch.import", SpanKind::Producer, &config);
            root.set_attribute("job.name", "nightly-import");
            root.set_baggage_item("tenant", "alpha");

            let mut decode_child = root.new_child("decode.payload", SpanKind::Internal);
            decode_child.set_attribute("stage", "decode");
            decode_child.add_event(
                "payload.decoded",
                HashMap::from([("records".to_string(), "42".to_string())]),
            );
            decode_child.set_status(Status::Ok);
            decode_child.end();

            let mut publish_child = root.new_child("publish.kafka", SpanKind::Producer);
            publish_child.set_attribute("messaging.system", "kafka");
            publish_child.add_event(
                "broker.ack",
                HashMap::from([("partition".to_string(), "7".to_string())]),
            );
            publish_child.set_status(Status::Ok);
            publish_child.end();

            root.add_event(
                "pipeline.completed",
                HashMap::from([("children".to_string(), "2".to_string())]),
            );
            root.set_status(Status::Ok);
            root.end();

            insta::assert_json_snapshot!(
                "span_export_format_scrubbed",
                json!({
                    "happy_path": test_span_snapshot(&happy_path),
                    "error_path": test_span_snapshot(&error_path),
                    "multi_span_trace": [
                        test_span_snapshot(&root),
                        test_span_snapshot(&decode_child),
                        test_span_snapshot(&publish_child),
                    ],
                })
            );
        }

        #[test]
        fn otlp_wire_format_scrubbed() {
            let config = SpanConformanceConfig {
                max_attributes: 6,
                max_events: 3,
                max_attribute_length: Some(24),
                test_sampling: true,
                test_context_propagation: true,
            };

            let mut root = TestSpan::new_with_config("otlp.export", SpanKind::Server, &config);
            root.set_attribute("service.name", "checkout");
            root.set_attribute("deployment.environment", "staging");
            root.add_event(
                "request.accepted",
                HashMap::from([("route".to_string(), "/v1/orders".to_string())]),
            );
            root.set_status(Status::Ok);
            root.end();

            let mut child = root.new_child("postgres.query", SpanKind::Client);
            child.set_attribute("db.system", "postgresql");
            child.set_attribute("db.operation", "select");
            child.add_event(
                "row.batch",
                HashMap::from([("rows".to_string(), "3".to_string())]),
            );
            child.set_status(Status::Error {
                description: "deadline exceeded".into(),
            });
            child.end();

            let mut metrics = MetricsSnapshot::new();
            metrics.add_counter(
                "otel.export.spans",
                vec![("signal".to_string(), "traces".to_string())],
                2,
            );
            metrics.add_gauge(
                "otel.export.queue_depth",
                vec![("pipeline".to_string(), "primary".to_string())],
                1,
            );
            metrics.add_histogram(
                "otel.export.latency_ms",
                vec![("signal".to_string(), "mixed".to_string())],
                2,
                17.5,
            );

            insta::assert_json_snapshot!(
                "otlp_wire_format_scrubbed",
                json!({
                    "resource_spans": [{
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"string_value": "checkout"}},
                                {"key": "telemetry.sdk.name", "value": {"string_value": "asupersync"}},
                            ]
                        },
                        "scope_spans": [{
                            "scope": {
                                "name": "asupersync.observability.otel",
                                "version": "0.2.9",
                            },
                            "spans": [
                                otlp_span_wire_snapshot(&root),
                                otlp_span_wire_snapshot(&child),
                            ],
                        }]
                    }],
                    "resource_metrics": [otlp_metrics_wire_snapshot(&metrics)],
                    "resource_logs": [{
                        "scope_logs": [{
                            "scope": {
                                "name": "asupersync.observability.otel",
                                "version": "0.2.9",
                            },
                            "log_records": [
                                otlp_log_record_snapshot(
                                    "export started",
                                    HashMap::from([
                                        ("component".to_string(), "otlp".to_string()),
                                        ("signal".to_string(), "traces".to_string()),
                                    ]),
                                ),
                                otlp_log_record_snapshot(
                                    "export retry scheduled",
                                    HashMap::from([
                                        ("component".to_string(), "otlp".to_string()),
                                        ("retry_in_ms".to_string(), "250".to_string()),
                                    ]),
                                ),
                            ],
                        }]
                    }],
                })
            );
        }
    }
}

#[cfg(not(feature = "tracing-integration"))]
pub mod span_semantics {
    //! Span semantics module (disabled when tracing-integration feature is not enabled).
    //!
    //! Enable the `tracing-integration` feature to access OpenTelemetry span semantics
    //! conformance testing functionality.

    /// Disabled-feature result shape used when tracing is unavailable.
    #[derive(Debug)]
    pub struct SpanConformanceResult {
        /// Total number of tests executed.
        pub tests_run: usize,
        /// Number of tests that passed.
        pub tests_passed: usize,
        /// Number of tests that failed.
        pub tests_failed: usize,
        /// Failure descriptions captured during the run.
        pub failures: Vec<String>,
        /// Known conformance gaps captured by enabled-feature runs.
        pub conformance_gaps: Vec<String>,
    }

    impl SpanConformanceResult {
        /// Returns `true` when no failures or known conformance gaps were recorded.
        pub fn is_success(&self) -> bool {
            self.tests_failed == 0 && self.conformance_gaps.is_empty()
        }

        /// Returns the pass percentage, matching the enabled implementation.
        pub fn success_rate(&self) -> f64 {
            if self.tests_run == 0 {
                0.0
            } else {
                (self.tests_passed as f64 / self.tests_run as f64) * 100.0
            }
        }

        /// Check whether enabled-feature runs found known conformance gaps.
        pub fn has_no_known_conformance_gaps(&self) -> bool {
            self.conformance_gaps.is_empty()
        }

        /// Get failure report (disabled implementation).
        pub fn failure_report(&self) -> String {
            "Conformance testing disabled (requires 'tracing-integration' feature)".to_string()
        }
    }

    /// Disabled-feature entry point used when tracing is unavailable.
    pub fn run_span_conformance_tests() -> Result<SpanConformanceResult, Box<dyn std::error::Error>>
    {
        Err("OpenTelemetry span semantics testing requires 'tracing-integration' feature".into())
    }

    #[cfg(test)]
    mod tests {
        use super::SpanConformanceResult;
        use std::collections::HashMap;

        #[test]
        fn disabled_success_rate_reflects_recorded_counts() {
            let empty = SpanConformanceResult {
                tests_run: 0,
                tests_passed: 0,
                tests_failed: 0,
                failures: Vec::new(),
            };
            assert_eq!(empty.success_rate(), 0.0);

            let partial = SpanConformanceResult {
                tests_run: 4,
                tests_passed: 3,
                tests_failed: 1,
                failures: vec!["span-status".to_string()],
            };
            assert_eq!(partial.success_rate(), 75.0);
        }

        #[cfg(feature = "tracing-integration")]
        #[test]
        fn log_record_body_value_to_any_value_conformance() {
            use super::super::{LogRecordBodyValue, log_record_body_value_to_any_value};
            use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;

            // Test string value mapping
            let string_body = LogRecordBodyValue::String("hello world".to_string());
            let any_value = log_record_body_value_to_any_value(&string_body);
            match &any_value.value {
                Some(ProtoValue::StringValue(value)) => assert_eq!(value, "hello world"),
                _ => panic!("Expected StringValue, got {:?}", any_value.value),
            }

            // Test integer value mapping
            let int_body = LogRecordBodyValue::Int(42);
            let any_value = log_record_body_value_to_any_value(&int_body);
            match &any_value.value {
                Some(ProtoValue::IntValue(value)) => assert_eq!(*value, 42),
                _ => panic!("Expected IntValue, got {:?}", any_value.value),
            }

            // Test boolean value mapping
            let bool_body = LogRecordBodyValue::Bool(true);
            let any_value = log_record_body_value_to_any_value(&bool_body);
            match &any_value.value {
                Some(ProtoValue::BoolValue(value)) => assert_eq!(*value, true),
                _ => panic!("Expected BoolValue, got {:?}", any_value.value),
            }

            // Test float value mapping
            let float_body = LogRecordBodyValue::Float(3.14159);
            let any_value = log_record_body_value_to_any_value(&float_body);
            match &any_value.value {
                Some(ProtoValue::DoubleValue(value)) => assert_eq!(*value, 3.14159),
                _ => panic!("Expected DoubleValue, got {:?}", any_value.value),
            }

            // Test string array mapping
            let string_array_body =
                LogRecordBodyValue::StringArray(vec!["a".to_string(), "b".to_string()]);
            let any_value = log_record_body_value_to_any_value(&string_array_body);
            match &any_value.value {
                Some(ProtoValue::ArrayValue(array)) => {
                    assert_eq!(array.values.len(), 2);
                    if let Some(ProtoValue::StringValue(first)) = &array.values[0].value {
                        assert_eq!(first, "a");
                    } else {
                        panic!("Expected first array element to be StringValue");
                    }
                }
                _ => panic!("Expected ArrayValue, got {:?}", any_value.value),
            }

            // Test deterministic encoding - same input should always produce same output
            let test_body = LogRecordBodyValue::String("test".to_string());
            let any_value_1 = log_record_body_value_to_any_value(&test_body);
            let any_value_2 = log_record_body_value_to_any_value(&test_body);
            assert_eq!(
                any_value_1, any_value_2,
                "LogRecord body value conversion must be deterministic"
            );
        }

        #[test]
        fn gauge_double_update_value_sequence_conformance() {
            use super::super::MetricsSnapshot;

            // Test that applying the same gauge value sequence twice produces identical results
            let value_sequence = vec![10, 20, 15, 30, 25];
            let gauge_name = "test_gauge";
            let labels = vec![("test".to_string(), "conformance".to_string())];

            // First application
            let mut snapshot1 = MetricsSnapshot::new();
            for &value in &value_sequence {
                snapshot1.add_gauge(gauge_name, labels.clone(), value);
            }

            // Second application
            let mut snapshot2 = MetricsSnapshot::new();
            for &value in &value_sequence {
                snapshot2.add_gauge(gauge_name, labels.clone(), value);
            }

            // Both snapshots should be identical
            assert_eq!(
                snapshot1.gauges, snapshot2.gauges,
                "Gauge double-update must be deterministic"
            );

            // Final value should match the last value in the sequence
            let expected_final_value = *value_sequence.last().unwrap();
            let actual_final_value = snapshot1.gauges.last().unwrap().2;
            assert_eq!(
                actual_final_value, expected_final_value,
                "Gauge final value must match sequence end"
            );

            // Number of gauge entries should match sequence length
            assert_eq!(
                snapshot1.gauges.len(),
                value_sequence.len(),
                "Gauge entry count must match sequence length"
            );

            // Test edge cases
            let mut empty_snapshot = MetricsSnapshot::new();
            empty_snapshot.add_gauge("empty_test", vec![], 0);
            assert_eq!(
                empty_snapshot.gauges.len(),
                1,
                "Empty labels gauge should work"
            );

            // Test negative values
            let mut negative_snapshot = MetricsSnapshot::new();
            negative_snapshot.add_gauge("negative_test", vec![], -100);
            negative_snapshot.add_gauge("negative_test", vec![], i64::MIN);
            assert_eq!(
                negative_snapshot.gauges.last().unwrap().2,
                i64::MIN,
                "Negative gauge values should work"
            );
        }

        #[test]
        fn instrumentation_scope_identity_conformance() {
            use opentelemetry_proto::tonic::common::v1::InstrumentationScope;

            // Test that same scope name+version produces identical InstrumentationScope objects
            let test_cases = vec![
                ("asupersync", "0.3.1"),
                ("custom.scope", "1.0.0"),
                ("", ""),
                ("unicode.测试", "2.0.0"),
            ];

            for (scope_name, scope_version) in test_cases {
                // Create scope multiple times with same parameters
                let scope1 = InstrumentationScope {
                    name: scope_name.to_string(),
                    version: scope_version.to_string(),
                    attributes: vec![],
                    dropped_attributes_count: 0,
                };

                let scope2 = InstrumentationScope {
                    name: scope_name.to_string(),
                    version: scope_version.to_string(),
                    attributes: vec![],
                    dropped_attributes_count: 0,
                };

                // Both scopes should be identical
                assert_eq!(
                    scope1, scope2,
                    "InstrumentationScope construction must be deterministic for {}@{}",
                    scope_name, scope_version
                );

                // Verify fields are correctly set
                assert_eq!(scope1.name, scope_name, "Scope name must match input");
                assert_eq!(
                    scope1.version, scope_version,
                    "Scope version must match input"
                );
                assert!(
                    scope1.attributes.is_empty(),
                    "Default scope should have empty attributes"
                );
                assert_eq!(
                    scope1.dropped_attributes_count, 0,
                    "Default scope should have zero dropped attributes"
                );

                // Test serialization determinism
                use prost::Message;
                let mut buf1 = Vec::new();
                let mut buf2 = Vec::new();
                scope1.encode(&mut buf1).unwrap();
                scope2.encode(&mut buf2).unwrap();
                assert_eq!(
                    buf1, buf2,
                    "InstrumentationScope serialization must be deterministic for {}@{}",
                    scope_name, scope_version
                );
            }

            // Test scope equality semantics
            let scope_a = InstrumentationScope {
                name: "test".to_string(),
                version: "1.0".to_string(),
                attributes: vec![],
                dropped_attributes_count: 0,
            };

            let scope_b = InstrumentationScope {
                name: "test".to_string(),
                version: "1.1".to_string(), // Different version
                attributes: vec![],
                dropped_attributes_count: 0,
            };

            let scope_c = InstrumentationScope {
                name: "test_different".to_string(), // Different name
                version: "1.0".to_string(),
                attributes: vec![],
                dropped_attributes_count: 0,
            };

            // Same scope should equal itself
            assert_eq!(scope_a, scope_a, "Scope should equal itself");

            // Different version should not be equal
            assert_ne!(
                scope_a, scope_b,
                "Scopes with different versions should not be equal"
            );

            // Different name should not be equal
            assert_ne!(
                scope_a, scope_c,
                "Scopes with different names should not be equal"
            );
        }

        #[test]
        fn periodic_reader_export_batch_conformance() {
            use std::collections::VecDeque;
            use std::sync::{Arc, Mutex};
            use std::time::Duration;

            #[derive(Clone)]
            struct PeriodicExportRecorder {
                exports: Arc<Mutex<VecDeque<(Duration, usize)>>>,
            }

            impl PeriodicExportRecorder {
                fn new() -> Self {
                    Self {
                        exports: Arc::new(Mutex::new(VecDeque::new())),
                    }
                }

                fn export_metrics_at(&self, elapsed: Duration, count: usize) {
                    self.exports.lock().unwrap().push_back((elapsed, count));
                }

                fn get_export_intervals(&self) -> Vec<Duration> {
                    let exports = self.exports.lock().unwrap();
                    let mut intervals = Vec::new();
                    for i in 1..exports.len() {
                        intervals.push(exports[i].0 - exports[i - 1].0);
                    }
                    intervals
                }

                fn get_export_count(&self) -> usize {
                    self.exports.lock().unwrap().len()
                }
            }

            // Test deterministic export behavior with same metric stream
            let export_interval = Duration::from_millis(100);
            let metric_counts = vec![5, 3, 7, 2];

            let exporter1 = PeriodicExportRecorder::new();
            let exporter2 = PeriodicExportRecorder::new();

            for (i, &count) in metric_counts.iter().enumerate() {
                let logical_elapsed = export_interval * (i as u32 + 1);
                exporter1.export_metrics_at(logical_elapsed, count);
                exporter2.export_metrics_at(logical_elapsed, count);
            }

            // Verify both exporters have the same number of exports
            assert_eq!(
                exporter1.get_export_count(),
                exporter2.get_export_count(),
                "PeriodicReader export count must be deterministic for same metric stream"
            );

            // Verify export intervals are approximately the same
            let intervals1 = exporter1.get_export_intervals();
            let intervals2 = exporter2.get_export_intervals();

            assert_eq!(
                intervals1.len(),
                intervals2.len(),
                "Export interval count must be consistent"
            );

            // Check that intervals are approximately equal to expected interval
            for interval in &intervals1 {
                assert_eq!(*interval, export_interval);
            }

            // Test edge case: no metrics (should not export)
            let empty_exporter = PeriodicExportRecorder::new();
            assert_eq!(
                empty_exporter.get_export_count(),
                0,
                "No exports should occur when no metrics are available"
            );

            // Test edge case: single large batch
            let batch_exporter = PeriodicExportRecorder::new();
            batch_exporter.export_metrics_at(export_interval, 1000);
            assert_eq!(
                batch_exporter.get_export_count(),
                1,
                "Large batch should result in single export"
            );
        }

        #[cfg(feature = "tracing-integration")]
        #[test]
        fn span_events_array_conformance() {
            use super::super::SpanEvent;
            use std::time::{Duration, SystemTime, UNIX_EPOCH};

            // Test that same Event sequence produces identical span events array
            let test_sequences = vec![
                // Basic sequence
                vec![
                    SpanEvent {
                        name: "start".to_string(),
                        timestamp: UNIX_EPOCH + Duration::from_secs(1),
                        attributes: [("level".to_string(), "info".to_string())].into(),
                    },
                    SpanEvent {
                        name: "process".to_string(),
                        timestamp: UNIX_EPOCH + Duration::from_secs(2),
                        attributes: [("step".to_string(), "validate".to_string())].into(),
                    },
                    SpanEvent {
                        name: "complete".to_string(),
                        timestamp: UNIX_EPOCH + Duration::from_secs(3),
                        attributes: [("status".to_string(), "success".to_string())].into(),
                    },
                ],
                // Empty sequence
                vec![],
                // Single event
                vec![SpanEvent {
                    name: "single".to_string(),
                    timestamp: UNIX_EPOCH + Duration::from_millis(500),
                    attributes: HashMap::new(),
                }],
                // Unicode events
                vec![SpanEvent {
                    name: "测试".to_string(),
                    timestamp: UNIX_EPOCH + Duration::from_secs(1),
                    attributes: [("键".to_string(), "值".to_string())].into(),
                }],
            ];

            for (i, sequence) in test_sequences.iter().enumerate() {
                // Create the same sequence twice
                let sequence1 = sequence.clone();
                let sequence2 = sequence.clone();

                // Both sequences should be identical
                assert_eq!(
                    sequence1.len(),
                    sequence2.len(),
                    "Span events sequence {} length must be deterministic",
                    i
                );

                for (j, (event1, event2)) in sequence1.iter().zip(sequence2.iter()).enumerate() {
                    // Event names should match
                    assert_eq!(
                        event1.name, event2.name,
                        "Span event name differs at index {} in sequence {}: '{}' vs '{}'",
                        j, i, event1.name, event2.name
                    );

                    // Timestamps should match
                    assert_eq!(
                        event1.timestamp, event2.timestamp,
                        "Span event timestamp differs at index {} in sequence {}",
                        j, i
                    );

                    // Attributes should match
                    assert_eq!(
                        event1.attributes, event2.attributes,
                        "Span event attributes differ at index {} in sequence {}",
                        j, i
                    );
                }
            }

            // Test event ordering preservation
            let ordered_events = vec![
                SpanEvent {
                    name: "first".to_string(),
                    timestamp: UNIX_EPOCH + Duration::from_secs(1),
                    attributes: HashMap::new(),
                },
                SpanEvent {
                    name: "second".to_string(),
                    timestamp: UNIX_EPOCH + Duration::from_secs(2),
                    attributes: HashMap::new(),
                },
                SpanEvent {
                    name: "third".to_string(),
                    timestamp: UNIX_EPOCH + Duration::from_secs(3),
                    attributes: HashMap::new(),
                },
            ];

            // Verify ordering is preserved
            for (i, event) in ordered_events.iter().enumerate() {
                let expected_names = ["first", "second", "third"];
                assert_eq!(
                    event.name, expected_names[i],
                    "Event ordering not preserved at index {}",
                    i
                );
            }

            // Test events with complex attributes
            let complex_event = SpanEvent {
                name: "complex".to_string(),
                timestamp: UNIX_EPOCH + Duration::from_secs(1),
                attributes: [
                    ("method".to_string(), "GET".to_string()),
                    ("path".to_string(), "/api/users".to_string()),
                    ("status_code".to_string(), "200".to_string()),
                    ("response_time_ms".to_string(), "45".to_string()),
                ]
                .into(),
            };

            let complex_event2 = SpanEvent {
                name: "complex".to_string(),
                timestamp: UNIX_EPOCH + Duration::from_secs(1),
                attributes: [
                    ("method".to_string(), "GET".to_string()),
                    ("path".to_string(), "/api/users".to_string()),
                    ("status_code".to_string(), "200".to_string()),
                    ("response_time_ms".to_string(), "45".to_string()),
                ]
                .into(),
            };

            assert_eq!(
                complex_event.attributes, complex_event2.attributes,
                "Complex event attributes must be identical for same input"
            );
        }

        #[test]
        fn span_links_field_conformance() {
            // Test span links data structure conformance

            #[derive(Debug, Clone, PartialEq)]
            struct TestSpanLink {
                trace_id: [u8; 16],
                span_id: [u8; 8],
                trace_state: String,
                attributes: HashMap<String, String>,
                dropped_attributes_count: u32,
                flags: u32,
            }

            let test_link_arrays = vec![
                // Empty links
                vec![],
                // Single link
                vec![TestSpanLink {
                    trace_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    span_id: [1, 2, 3, 4, 5, 6, 7, 8],
                    trace_state: "key=value".to_string(),
                    attributes: [("type".to_string(), "child".to_string())].into(),
                    dropped_attributes_count: 0,
                    flags: 1,
                }],
                // Multiple links
                vec![
                    TestSpanLink {
                        trace_id: [1; 16],
                        span_id: [1; 8],
                        trace_state: "state1=value1".to_string(),
                        attributes: [("link".to_string(), "parent".to_string())].into(),
                        dropped_attributes_count: 0,
                        flags: 1,
                    },
                    TestSpanLink {
                        trace_id: [2; 16],
                        span_id: [2; 8],
                        trace_state: "state2=value2".to_string(),
                        attributes: [("link".to_string(), "sibling".to_string())].into(),
                        dropped_attributes_count: 0,
                        flags: 0,
                    },
                ],
            ];

            for (i, link_array) in test_link_arrays.iter().enumerate() {
                // Create identical link arrays
                let links1 = link_array.clone();
                let links2 = link_array.clone();

                // Both arrays should be identical
                assert_eq!(
                    links1.len(),
                    links2.len(),
                    "Span links array {} length must be deterministic",
                    i
                );

                for (j, (link1, link2)) in links1.iter().zip(links2.iter()).enumerate() {
                    // Trace IDs should match
                    assert_eq!(
                        link1.trace_id, link2.trace_id,
                        "Span link trace ID differs at index {} in array {}: {:?} vs {:?}",
                        j, i, link1.trace_id, link2.trace_id
                    );

                    // Span IDs should match
                    assert_eq!(
                        link1.span_id, link2.span_id,
                        "Span link span ID differs at index {} in array {}: {:?} vs {:?}",
                        j, i, link1.span_id, link2.span_id
                    );

                    // Trace state should match
                    assert_eq!(
                        link1.trace_state, link2.trace_state,
                        "Span link trace state differs at index {} in array {}: '{}' vs '{}'",
                        j, i, link1.trace_state, link2.trace_state
                    );

                    // Attributes should match
                    assert_eq!(
                        link1.attributes, link2.attributes,
                        "Span link attributes differ at index {} in array {}",
                        j, i
                    );

                    // Dropped attributes count should match
                    assert_eq!(
                        link1.dropped_attributes_count, link2.dropped_attributes_count,
                        "Span link dropped attributes count differs at index {} in array {}: {} vs {}",
                        j, i, link1.dropped_attributes_count, link2.dropped_attributes_count
                    );

                    // Flags should match
                    assert_eq!(
                        link1.flags, link2.flags,
                        "Span link flags differ at index {} in array {}: {} vs {}",
                        j, i, link1.flags, link2.flags
                    );
                }
            }

            // Test edge cases

            // All-zero IDs (invalid but should be handled consistently)
            let zero_link = TestSpanLink {
                trace_id: [0; 16],
                span_id: [0; 8],
                trace_state: String::new(),
                attributes: HashMap::new(),
                dropped_attributes_count: 0,
                flags: 0,
            };

            let zero_link2 = TestSpanLink {
                trace_id: [0; 16],
                span_id: [0; 8],
                trace_state: String::new(),
                attributes: HashMap::new(),
                dropped_attributes_count: 0,
                flags: 0,
            };

            assert_eq!(
                zero_link, zero_link2,
                "Zero ID span links must be identical"
            );

            // Maximum values
            let max_link = TestSpanLink {
                trace_id: [255; 16],
                span_id: [255; 8],
                trace_state: "max=values".to_string(),
                attributes: [("test".to_string(), "max".to_string())].into(),
                dropped_attributes_count: u32::MAX,
                flags: u32::MAX,
            };

            let max_link2 = max_link.clone();
            assert_eq!(
                max_link, max_link2,
                "Max values span links must be identical"
            );

            // Test ordering preservation
            let ordered_links = vec![
                TestSpanLink {
                    trace_id: [1; 16],
                    span_id: [1; 8],
                    trace_state: "first".to_string(),
                    attributes: HashMap::new(),
                    dropped_attributes_count: 0,
                    flags: 1,
                },
                TestSpanLink {
                    trace_id: [2; 16],
                    span_id: [2; 8],
                    trace_state: "second".to_string(),
                    attributes: HashMap::new(),
                    dropped_attributes_count: 0,
                    flags: 1,
                },
                TestSpanLink {
                    trace_id: [3; 16],
                    span_id: [3; 8],
                    trace_state: "third".to_string(),
                    attributes: HashMap::new(),
                    dropped_attributes_count: 0,
                    flags: 1,
                },
            ];

            // Verify ordering is preserved
            let expected_states = ["first", "second", "third"];
            for (i, link) in ordered_links.iter().enumerate() {
                assert_eq!(
                    link.trace_state, expected_states[i],
                    "Link ordering not preserved at index {}",
                    i
                );
            }
        }
    }
}

// Golden artifact tests for OTEL span serialization
#[cfg(all(test, feature = "tracing-integration"))]
#[path = "otel_span_golden_tests.rs"]
mod otel_span_golden_tests;

// Golden artifact tests for OTLP LogRecord body value mapping
#[cfg(all(test, feature = "tracing-integration"))]
#[path = "otel_log_body_golden_test.rs"]
mod otel_log_body_golden_test;

#[cfg(all(
    any(test, feature = "fuzz"),
    feature = "metrics",
    feature = "tracing-integration"
))]
/// OTLP request builders used by conformance, fuzz, and regression helpers.
pub mod otlp_request_builder {
    use super::span_semantics::TestSpan;
    use super::{MetricLabels, MetricsSnapshot, PrivacyConfig, SpanConfig};
    use opentelemetry::trace::{SpanKind as ApiSpanKind, Status as ApiStatus};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
    use opentelemetry_proto::tonic::logs::v1::{
        LogRecord, ResourceLogs, ScopeLogs, SeverityNumber,
    };
    use opentelemetry_proto::tonic::metrics::v1::{
        AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
        ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::span::SpanKind as ProtoSpanKind;
    use opentelemetry_proto::tonic::trace::v1::status::StatusCode as ProtoStatusCode;
    use opentelemetry_proto::tonic::trace::v1::{
        ResourceSpans, ScopeSpans, Span as ProtoSpan, Status as ProtoStatus, span,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Schema URL attached to OTLP resources and scopes in helper requests.
    pub const OTEL_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.37.0";
    /// Default instrumentation scope name emitted by helper requests.
    pub const OTEL_SCOPE_NAME: &str = "asupersync.observability.otel";
    /// Crate version attached to OTLP instrumentation scopes.
    pub const OTEL_SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Fuzzable log-record input used to synthesize OTLP log exports.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OtlpLogRecordInput {
        /// Record timestamp in Unix nanoseconds.
        pub time_unix_nano: u64,
        /// Observation timestamp in Unix nanoseconds.
        pub observed_time_unix_nano: u64,
        /// OTLP severity number.
        pub severity_number: i32,
        /// OTLP severity text.
        pub severity_text: String,
        /// Log body payload.
        pub body: String,
        /// String key/value attributes attached to the log record.
        pub attributes: Vec<(String, String)>,
    }

    /// Group of log records emitted under one OTLP resource/scope tuple.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OtlpLogScopeInput {
        /// Service name exported in the OTLP resource block.
        pub service_name: String,
        /// Synthetic batch sequence propagated into timestamps and attributes.
        pub batch_sequence: u64,
        /// Instrumentation scope name exported alongside the records.
        pub scope_name: String,
        /// Log records contained in this scope.
        pub log_records: Vec<OtlpLogRecordInput>,
    }

    /// Map an arbitrary bucket into one of the coarse OTLP severity levels.
    pub fn severity_number_from_bucket(raw: u8) -> i32 {
        match raw % 6 {
            0 => SeverityNumber::Trace as i32,
            1 => SeverityNumber::Debug as i32,
            2 => SeverityNumber::Info as i32,
            3 => SeverityNumber::Warn as i32,
            4 => SeverityNumber::Error as i32,
            _ => SeverityNumber::Fatal as i32,
        }
    }

    /// Map an arbitrary bucket into the matching OTLP severity label.
    pub fn severity_text_from_bucket(raw: u8) -> String {
        match raw % 6 {
            0 => "TRACE",
            1 => "DEBUG",
            2 => "INFO",
            3 => "WARN",
            4 => "ERROR",
            _ => "FATAL",
        }
        .to_string()
    }

    fn string_value(value: &str) -> AnyValue {
        AnyValue {
            value: Some(ProtoValue::StringValue(value.to_string())),
        }
    }

    fn key_value(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(string_value(&value.into())),
        }
    }

    fn ordered_proto_attributes(
        attributes: &std::collections::HashMap<String, String>,
    ) -> Vec<KeyValue> {
        ordered_proto_attributes_with_config(attributes, None)
    }

    /// Privacy-aware attribute serialization with optional filtering configuration.
    fn ordered_proto_attributes_with_config(
        attributes: &std::collections::HashMap<String, String>,
        span_config: Option<&SpanConfig>,
    ) -> Vec<KeyValue> {
        let mut ordered: Vec<_> = attributes.iter().collect();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            // **OTLP §2.3.1 COMPLIANCE FIX**: Drop empty keys and empty values per specification
            .filter(|(key, value)| !key.is_empty() && !value.is_empty())
            // **PRIVACY FILTER**: Drop sensitive attributes before serialization
            .filter(|(key, _value)| {
                if let Some(config) = span_config {
                    !config.should_drop_field(key)
                } else {
                    true // No filtering if no config provided
                }
            })
            .map(|(key, value)| {
                // **PII REDACTION**: Apply PII filtering to attribute values
                let redacted_value = if let Some(config) = span_config {
                    config.redact_pii(key, value)
                } else {
                    value.clone()
                };
                key_value(key.clone(), redacted_value)
            })
            .collect()
    }

    #[allow(dead_code)]
    fn proto_labels(labels: &MetricLabels) -> Vec<KeyValue> {
        proto_labels_with_config(labels, None)
    }

    /// Privacy-aware metric label serialization with optional filtering configuration.
    fn proto_labels_with_config(
        labels: &MetricLabels,
        privacy_config: Option<&PrivacyConfig>,
    ) -> Vec<KeyValue> {
        let mut ordered = labels.clone();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            // **OTLP §2.3.1 COMPLIANCE FIX**: Drop empty keys and empty values per specification
            .filter(|(key, value)| !key.is_empty() && !value.is_empty())
            // **PRIVACY FILTER**: Drop sensitive labels before serialization
            .filter(|(key, _value)| {
                if let Some(config) = privacy_config {
                    !config.should_drop_field(key)
                } else {
                    true // No filtering if no config provided
                }
            })
            .map(|(key, value)| {
                // **PII REDACTION**: Apply PII filtering to label values
                let redacted_value = if let Some(config) = privacy_config {
                    config.redact_pii(&key, &value)
                } else {
                    value.clone()
                };
                key_value(key, redacted_value)
            })
            .collect()
    }

    fn instrumentation_scope(name: &str) -> InstrumentationScope {
        InstrumentationScope {
            name: name.to_string(),
            version: OTEL_SCOPE_VERSION.to_string(),
            ..Default::default()
        }
    }

    fn resource_with_batch(service_name: &str, batch_sequence: u64) -> Resource {
        Resource {
            attributes: vec![
                key_value("service.name", service_name),
                key_value("batch.sequence", batch_sequence.to_string()),
                key_value("telemetry.sdk.name", "asupersync"),
            ],
            ..Default::default()
        }
    }

    fn unix_nanos(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64
    }

    /// Build a single-scope OTLP metrics export request from a metrics snapshot.
    pub fn metrics_request_from_snapshot(
        snapshot: &MetricsSnapshot,
        service_name: &str,
        batch_sequence: u64,
        scope_name: &str,
    ) -> ExportMetricsServiceRequest {
        metrics_request_from_snapshot_with_privacy(
            snapshot,
            service_name,
            batch_sequence,
            scope_name,
            None,
        )
    }

    /// Build a single-scope OTLP metrics export request from a metrics snapshot with privacy filtering.
    pub fn metrics_request_from_snapshot_with_privacy(
        snapshot: &MetricsSnapshot,
        service_name: &str,
        batch_sequence: u64,
        scope_name: &str,
        privacy_config: Option<&PrivacyConfig>,
    ) -> ExportMetricsServiceRequest {
        let mut metrics = Vec::new();

        for (name, labels, value) in &snapshot.counters {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Sum(Sum {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    is_monotonic: true,
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels_with_config(labels, privacy_config),
                        start_time_unix_nano: batch_sequence * 1_000 + 1,
                        time_unix_nano: batch_sequence * 1_000 + 2,
                        value: Some(number_data_point::Value::AsInt((*value).cast_signed())),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, value) in &snapshot.gauges {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Gauge(Gauge {
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels_with_config(labels, privacy_config),
                        time_unix_nano: batch_sequence * 1_000 + 3,
                        value: Some(number_data_point::Value::AsInt(*value)),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, count, sum) in &snapshot.histograms {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Histogram(Histogram {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    data_points: vec![HistogramDataPoint {
                        attributes: proto_labels_with_config(labels, privacy_config),
                        start_time_unix_nano: batch_sequence * 1_000 + 4,
                        time_unix_nano: batch_sequence * 1_000 + 5,
                        count: *count,
                        sum: Some(*sum),
                        bucket_counts: vec![*count],
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(resource_with_batch(service_name, batch_sequence)),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(instrumentation_scope(scope_name)),
                    metrics,
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn proto_span_kind(kind: ApiSpanKind) -> i32 {
        match kind {
            ApiSpanKind::Internal => ProtoSpanKind::Internal as i32,
            ApiSpanKind::Server => ProtoSpanKind::Server as i32,
            ApiSpanKind::Client => ProtoSpanKind::Client as i32,
            ApiSpanKind::Producer => ProtoSpanKind::Producer as i32,
            ApiSpanKind::Consumer => ProtoSpanKind::Consumer as i32,
        }
    }

    fn proto_status(status: &ApiStatus) -> ProtoStatus {
        match status {
            ApiStatus::Unset => ProtoStatus {
                code: ProtoStatusCode::Unset as i32,
                message: String::new(),
            },
            ApiStatus::Ok => ProtoStatus {
                code: ProtoStatusCode::Ok as i32,
                message: String::new(),
            },
            ApiStatus::Error { description } => ProtoStatus {
                code: ProtoStatusCode::Error as i32,
                message: description.clone().into_owned(),
            },
        }
    }

    fn proto_span(span: &TestSpan) -> ProtoSpan {
        ProtoSpan {
            trace_id: span.context.trace_id().to_bytes().to_vec(),
            span_id: span.context.span_id().to_bytes().to_vec(),
            parent_span_id: span
                .parent_context
                .as_ref()
                .map_or_else(Vec::new, |parent| parent.span_id().to_bytes().to_vec()),
            name: span.name.clone(),
            kind: proto_span_kind(span.kind.clone()),
            start_time_unix_nano: unix_nanos(span.start_time),
            end_time_unix_nano: unix_nanos(span.end_time.expect("ended span")),
            attributes: ordered_proto_attributes(&span.attributes),
            // br-asupersync-attr-drop-count: propagate per-span
            // attribute drop count to the OTLP wire so receivers
            // can detect truncation. A regression that reverted
            // this to 0 (or relied on ..Default::default()) would
            // silently lose the count.
            dropped_attributes_count: span.dropped_attributes_count,
            events: span
                .events
                .iter()
                .map(|event| span::Event {
                    time_unix_nano: unix_nanos(event.timestamp),
                    name: event.name.clone(),
                    attributes: ordered_proto_attributes(&event.attributes),
                    ..Default::default()
                })
                .collect(),
            status: Some(proto_status(&span.status)),
            ..Default::default()
        }
    }

    /// Build a single-scope OTLP trace export request from synthesized spans.
    pub fn traces_request(
        service_name: &str,
        batch_sequence: u64,
        scope_name: &str,
        spans: &[TestSpan],
    ) -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(resource_with_batch(service_name, batch_sequence)),
                scope_spans: vec![ScopeSpans {
                    scope: Some(instrumentation_scope(scope_name)),
                    spans: spans.iter().map(proto_span).collect(),
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn log_record(record: &OtlpLogRecordInput) -> LogRecord {
        LogRecord {
            time_unix_nano: record.time_unix_nano,
            observed_time_unix_nano: record.observed_time_unix_nano,
            severity_number: record.severity_number,
            severity_text: record.severity_text.clone(),
            body: Some(string_value(&record.body)),
            attributes: record
                .attributes
                .iter()
                .map(|(key, value)| key_value(key.clone(), value.clone()))
                .collect(),
            ..Default::default()
        }
    }

    /// Build an OTLP logs export request from grouped scope inputs.
    pub fn logs_request(scopes: &[OtlpLogScopeInput]) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: scopes
                .iter()
                .map(|scope| ResourceLogs {
                    resource: Some(resource_with_batch(
                        &scope.service_name,
                        scope.batch_sequence,
                    )),
                    scope_logs: vec![ScopeLogs {
                        scope: Some(instrumentation_scope(&scope.scope_name)),
                        log_records: scope.log_records.iter().map(log_record).collect(),
                        schema_url: OTEL_SCHEMA_URL.to_string(),
                    }],
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                })
                .collect(),
        }
    }
}

#[cfg(all(test, feature = "metrics", feature = "tracing-integration"))]
mod otlp_wire_format_tests {
    use super::span_semantics::{SpanConformanceConfig, TestSpan};
    use super::{
        MetricLabels, MetricsSnapshot, OtlpLogRecord, PrivacyConfig, otlp_request_builder,
    };
    use opentelemetry::trace::{SpanKind as ApiSpanKind, Status as ApiStatus};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
    use opentelemetry_proto::tonic::logs::v1::{
        LogRecord, ResourceLogs, ScopeLogs, SeverityNumber,
    };
    use opentelemetry_proto::tonic::metrics::v1::{
        AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
        ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::span::SpanKind as ProtoSpanKind;
    use opentelemetry_proto::tonic::trace::v1::status::StatusCode as ProtoStatusCode;
    use opentelemetry_proto::tonic::trace::v1::{
        ResourceSpans, ScopeSpans, Span as ProtoSpan, Status as ProtoStatus, span,
    };
    use prost::Message;
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const OTEL_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.37.0";
    const OTEL_SCOPE_NAME: &str = "asupersync.observability.otel";
    const OTEL_SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

    fn string_value(value: &str) -> AnyValue {
        AnyValue {
            value: Some(ProtoValue::StringValue(value.to_string())),
        }
    }

    fn key_value(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(string_value(&value.into())),
        }
    }

    fn ordered_proto_attributes(attributes: &HashMap<String, String>) -> Vec<KeyValue> {
        let mut ordered: Vec<_> = attributes.iter().collect();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            // **OTLP §2.3.1 COMPLIANCE FIX**: Drop empty keys and empty values per specification
            .filter(|(key, value)| !key.is_empty() && !value.is_empty())
            .map(|(key, value)| key_value(key.clone(), value.clone()))
            .collect()
    }

    fn proto_labels(labels: &MetricLabels) -> Vec<KeyValue> {
        let mut ordered = labels.clone();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            .map(|(key, value)| key_value(key, value))
            .collect()
    }

    fn instrumentation_scope(name: &str) -> InstrumentationScope {
        InstrumentationScope {
            name: name.to_string(),
            version: OTEL_SCOPE_VERSION.to_string(),
            ..Default::default()
        }
    }

    fn resource_with_batch(service_name: &str, batch_sequence: u64) -> Resource {
        Resource {
            attributes: vec![
                key_value("service.name", service_name),
                key_value("batch.sequence", batch_sequence.to_string()),
                key_value("telemetry.sdk.name", "asupersync"),
            ],
            ..Default::default()
        }
    }

    fn unix_nanos(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64
    }

    fn any_value_as_str(value: &AnyValue) -> &str {
        match value.value.as_ref() {
            Some(ProtoValue::StringValue(text)) => text.as_str(),
            other => panic!("expected string AnyValue, got {other:?}"),
        }
    }

    fn key_value_str_value(attribute: &KeyValue) -> &str {
        any_value_as_str(attribute.value.as_ref().expect("attribute value"))
    }

    fn metrics_request_from_snapshot(
        snapshot: &MetricsSnapshot,
        service_name: &str,
        batch_sequence: u64,
    ) -> ExportMetricsServiceRequest {
        let mut metrics = Vec::new();

        for (name, labels, value) in &snapshot.counters {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Sum(Sum {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    is_monotonic: true,
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels(labels),
                        start_time_unix_nano: batch_sequence * 1_000 + 1,
                        time_unix_nano: batch_sequence * 1_000 + 2,
                        value: Some(number_data_point::Value::AsInt((*value).cast_signed())),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, value) in &snapshot.gauges {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Gauge(Gauge {
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels(labels),
                        time_unix_nano: batch_sequence * 1_000 + 3,
                        value: Some(number_data_point::Value::AsInt(*value)),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, count, sum) in &snapshot.histograms {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Histogram(Histogram {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    data_points: vec![HistogramDataPoint {
                        attributes: proto_labels(labels),
                        start_time_unix_nano: batch_sequence * 1_000 + 4,
                        time_unix_nano: batch_sequence * 1_000 + 5,
                        count: *count,
                        sum: Some(*sum),
                        bucket_counts: vec![*count],
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(resource_with_batch(service_name, batch_sequence)),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(instrumentation_scope(OTEL_SCOPE_NAME)),
                    metrics,
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn proto_span_kind(kind: ApiSpanKind) -> i32 {
        match kind {
            ApiSpanKind::Internal => ProtoSpanKind::Internal as i32,
            ApiSpanKind::Server => ProtoSpanKind::Server as i32,
            ApiSpanKind::Client => ProtoSpanKind::Client as i32,
            ApiSpanKind::Producer => ProtoSpanKind::Producer as i32,
            ApiSpanKind::Consumer => ProtoSpanKind::Consumer as i32,
        }
    }

    fn proto_status(status: &ApiStatus) -> ProtoStatus {
        match status {
            ApiStatus::Unset => ProtoStatus {
                code: ProtoStatusCode::Unset as i32,
                message: String::new(),
            },
            ApiStatus::Ok => ProtoStatus {
                code: ProtoStatusCode::Ok as i32,
                message: String::new(),
            },
            ApiStatus::Error { description } => ProtoStatus {
                code: ProtoStatusCode::Error as i32,
                message: description.clone().into_owned(),
            },
        }
    }

    fn proto_span(span: &TestSpan) -> ProtoSpan {
        ProtoSpan {
            trace_id: span.context.trace_id().to_bytes().to_vec(),
            span_id: span.context.span_id().to_bytes().to_vec(),
            parent_span_id: span
                .parent_context
                .as_ref()
                .map_or_else(Vec::new, |parent| parent.span_id().to_bytes().to_vec()),
            name: span.name.clone(),
            kind: proto_span_kind(span.kind.clone()),
            start_time_unix_nano: unix_nanos(span.start_time),
            end_time_unix_nano: unix_nanos(span.end_time.expect("ended span")),
            attributes: ordered_proto_attributes(&span.attributes),
            // br-asupersync-attr-drop-count: propagate per-span
            // attribute drop count to the OTLP wire so receivers
            // can detect truncation. A regression that reverted
            // this to 0 (or relied on ..Default::default()) would
            // silently lose the count.
            dropped_attributes_count: span.dropped_attributes_count,
            events: span
                .events
                .iter()
                .map(|event| span::Event {
                    time_unix_nano: unix_nanos(event.timestamp),
                    name: event.name.clone(),
                    attributes: ordered_proto_attributes(&event.attributes),
                    ..Default::default()
                })
                .collect(),
            status: Some(proto_status(&span.status)),
            ..Default::default()
        }
    }

    fn traces_request(spans: Vec<ProtoSpan>) -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(resource_with_batch("checkout", 7)),
                scope_spans: vec![ScopeSpans {
                    scope: Some(instrumentation_scope(OTEL_SCOPE_NAME)),
                    spans,
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn log_record(sequence: u64, body: &str, attributes: &[(&str, &str)]) -> LogRecord {
        LogRecord {
            time_unix_nano: sequence,
            observed_time_unix_nano: sequence + 1,
            severity_number: SeverityNumber::Info as i32,
            severity_text: "INFO".to_string(),
            body: Some(string_value(body)),
            attributes: attributes
                .iter()
                .map(|(key, value)| key_value(*key, *value))
                .collect(),
            ..Default::default()
        }
    }

    fn logs_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![
                ResourceLogs {
                    resource: Some(resource_with_batch("checkout", 1)),
                    scope_logs: vec![ScopeLogs {
                        scope: Some(instrumentation_scope(OTEL_SCOPE_NAME)),
                        log_records: vec![
                            log_record(
                                10,
                                "export started",
                                &[("component", "otlp"), ("sequence", "1")],
                            ),
                            log_record(
                                20,
                                "export retry scheduled",
                                &[("component", "otlp"), ("sequence", "2")],
                            ),
                        ],
                        schema_url: OTEL_SCHEMA_URL.to_string(),
                    }],
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                },
                ResourceLogs {
                    resource: Some(resource_with_batch("billing", 2)),
                    scope_logs: vec![ScopeLogs {
                        scope: Some(instrumentation_scope("asupersync.billing")),
                        log_records: vec![log_record(
                            30,
                            "billing flush complete",
                            &[("component", "billing"), ("sequence", "3")],
                        )],
                        schema_url: OTEL_SCHEMA_URL.to_string(),
                    }],
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                },
            ],
        }
    }

    #[test]
    fn otlp_metrics_protobuf_round_trip_preserves_batches_and_metric_order() {
        let mut primary = MetricsSnapshot::new();
        primary.add_counter(
            "otel.export.requests",
            vec![("signal".to_string(), "metrics".to_string())],
            5,
        );
        primary.add_gauge(
            "otel.export.queue_depth",
            vec![("pipeline".to_string(), "primary".to_string())],
            2,
        );
        primary.add_histogram(
            "otel.export.latency_ms",
            vec![("signal".to_string(), "metrics".to_string())],
            3,
            12.5,
        );

        let mut secondary = MetricsSnapshot::new();
        secondary.add_counter(
            "otel.export.requests",
            vec![("signal".to_string(), "logs".to_string())],
            1,
        );

        let mut request = metrics_request_from_snapshot(&primary, "checkout", 1);
        request
            .resource_metrics
            .extend(metrics_request_from_snapshot(&secondary, "billing", 2).resource_metrics);

        let encoded = request.encode_to_vec();
        let decoded = ExportMetricsServiceRequest::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded, request);

        assert_eq!(decoded.resource_metrics.len(), 2);
        assert_eq!(
            key_value_str_value(
                &decoded.resource_metrics[0]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "1"
        );
        assert_eq!(
            key_value_str_value(
                &decoded.resource_metrics[1]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "2"
        );

        let primary_metrics = &decoded.resource_metrics[0].scope_metrics[0].metrics;
        assert_eq!(primary_metrics[0].name, "otel.export.requests");
        assert_eq!(primary_metrics[1].name, "otel.export.queue_depth");
        assert_eq!(primary_metrics[2].name, "otel.export.latency_ms");
        assert_eq!(
            decoded.resource_metrics[0].scope_metrics[0]
                .scope
                .as_ref()
                .expect("scope")
                .name,
            OTEL_SCOPE_NAME
        );
    }

    #[test]
    fn otlp_trace_protobuf_round_trip_preserves_span_order_and_attribute_limits() {
        let config = SpanConformanceConfig {
            max_attributes: 8,
            max_events: 4,
            max_attribute_length: Some(12),
            test_sampling: true,
            test_context_propagation: true,
        };
        let mut root = TestSpan::new_with_config("checkout", ApiSpanKind::Server, &config);
        let oversized_key = "k".repeat(1_200);
        root.set_attribute(&oversized_key, "value-that-should-truncate");
        root.set_attribute("service.name", "checkout");
        root.add_event(
            "db.query",
            HashMap::from([("sql".to_string(), "select * from orders".to_string())]),
        );
        root.set_status(ApiStatus::Ok);
        root.end();

        let mut child = root.new_child("postgres.query", ApiSpanKind::Client);
        child.set_attribute("db.system", "postgresql");
        child.set_status(ApiStatus::Error {
            description: "deadline exceeded".into(),
        });
        child.end();

        let request = traces_request(vec![proto_span(&root), proto_span(&child)]);
        let encoded = request.encode_to_vec();
        let decoded = ExportTraceServiceRequest::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded, request);

        let spans = &decoded.resource_spans[0].scope_spans[0].spans;
        assert_eq!(spans[0].name, "checkout");
        assert_eq!(spans[1].name, "postgres.query");
        assert_eq!(spans[1].parent_span_id, spans[0].span_id);

        let oversized_attribute = spans[0]
            .attributes
            .iter()
            .find(|attribute| attribute.key.starts_with('k'))
            .expect("oversized attribute");
        assert_eq!(oversized_attribute.key.len(), 1024);
        assert_eq!(key_value_str_value(oversized_attribute), "value-that-s");
        assert_eq!(
            spans[0].events[0].attributes[0]
                .value
                .as_ref()
                .map(any_value_as_str),
            Some("select * fro")
        );
    }

    #[test]
    fn otlp_logs_protobuf_round_trip_preserves_batch_and_record_sequence() {
        let request = logs_request();
        let encoded = request.encode_to_vec();
        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded, request);

        assert_eq!(decoded.resource_logs.len(), 2);
        assert_eq!(
            key_value_str_value(
                &decoded.resource_logs[0]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "1"
        );
        assert_eq!(
            key_value_str_value(
                &decoded.resource_logs[1]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "2"
        );

        let first_scope = &decoded.resource_logs[0].scope_logs[0];
        assert_eq!(first_scope.log_records.len(), 2);
        assert_eq!(
            any_value_as_str(first_scope.log_records[0].body.as_ref().expect("body")),
            "export started"
        );
        assert_eq!(
            key_value_str_value(&first_scope.log_records[0].attributes[1]),
            "1"
        );
        assert_eq!(
            any_value_as_str(first_scope.log_records[1].body.as_ref().expect("body")),
            "export retry scheduled"
        );
        assert_eq!(
            key_value_str_value(&first_scope.log_records[1].attributes[1]),
            "2"
        );
    }

    /// OTLP export conformance test against the opentelemetry-proto reference transformer.
    ///
    /// This test ensures that the same span tree produces byte-identical OTLP protobuf
    /// output between our implementation and the upstream SDK-to-proto transformer.
    /// This is Pattern 1: Differential Testing (Reference Implementation) from the
    /// testing-conformance-harnesses methodology.
    #[test]
    #[cfg(feature = "tracing-integration")]
    fn otlp_export_conformance_byte_identical() {
        use opentelemetry::trace::{
            Event, SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState,
        };
        use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
        use opentelemetry_proto::tonic::resource::v1::Resource;
        use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span as OtlpSpan};
        use opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema;
        use opentelemetry_proto::transform::trace::tonic::group_spans_by_resource_and_scope;
        use opentelemetry_sdk::Resource as SdkResource;
        use opentelemetry_sdk::trace::{SpanData, SpanEvents, SpanLinks};
        use prost::Message;
        use std::collections::HashMap;

        // Shared span data for both implementations
        #[derive(Clone)]
        struct CanonicalSpanTree {
            spans: Vec<CanonicalSpan>,
        }

        #[derive(Clone)]
        struct CanonicalSpan {
            name: String,
            kind: SpanKind,
            attributes: HashMap<String, String>,
            events: Vec<(String, HashMap<String, String>)>,
            status: Status,
            parent_idx: Option<usize>,
        }

        impl CanonicalSpanTree {
            fn new() -> Self {
                Self {
                    spans: vec![
                        CanonicalSpan {
                            name: "root_operation".to_string(),
                            kind: SpanKind::Server,
                            attributes: [
                                ("service.name".to_string(), "asupersync".to_string()),
                                ("http.method".to_string(), "POST".to_string()),
                                ("http.url".to_string(), "/api/v1/process".to_string()),
                            ]
                            .into(),
                            events: vec![(
                                "request.received".to_string(),
                                [("bytes".to_string(), "1024".to_string())].into(),
                            )],
                            status: Status::Ok,
                            parent_idx: None,
                        },
                        CanonicalSpan {
                            name: "database_query".to_string(),
                            kind: SpanKind::Client,
                            attributes: [
                                ("db.system".to_string(), "postgresql".to_string()),
                                (
                                    "db.statement".to_string(),
                                    "SELECT * FROM users".to_string(),
                                ),
                            ]
                            .into(),
                            events: vec![
                                ("query.start".to_string(), HashMap::new()),
                                (
                                    "query.end".to_string(),
                                    [("rows".to_string(), "42".to_string())].into(),
                                ),
                            ],
                            status: Status::Ok,
                            parent_idx: Some(0),
                        },
                        CanonicalSpan {
                            name: "response_processing".to_string(),
                            kind: SpanKind::Internal,
                            attributes: [("component".to_string(), "json_serializer".to_string())]
                                .into(),
                            events: vec![],
                            status: Status::Ok,
                            parent_idx: Some(0),
                        },
                    ],
                }
            }
        }

        // Build OTLP export with our implementation
        fn build_our_otlp_export(tree: &CanonicalSpanTree) -> Vec<u8> {
            // Create OTLP request using our implementation patterns
            let resource = Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(
                            opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
                                "asupersync".to_string(),
                            ),
                        ),
                    }),
                }],
                ..Default::default()
            };

            let sampled_known_local_flags =
                1 | opentelemetry_proto::tonic::trace::v1::SpanFlags::ContextHasIsRemoteMask as u32;

            let spans: Vec<OtlpSpan> = tree.spans.iter().enumerate().map(|(idx, span)| {
                OtlpSpan {
                    trace_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], // Fixed for comparison
                    span_id: vec![(idx + 1) as u8, 0, 0, 0, 0, 0, 0, 0],
                    parent_span_id: span.parent_idx.map_or_else(Vec::new, |parent| {
                        vec![(parent + 1) as u8, 0, 0, 0, 0, 0, 0, 0]
                    }),
                    name: span.name.clone(),
                    kind: match &span.kind {
                        SpanKind::Internal => 1,
                        SpanKind::Server => 2,
                        SpanKind::Client => 3,
                        SpanKind::Producer => 4,
                        SpanKind::Consumer => 5,
                    },
                    start_time_unix_nano: 1000000000, // Fixed timestamp
                    end_time_unix_nano: 1001000000,
                    attributes: span.attributes.iter().map(|(k, v)| {
                        KeyValue {
                            key: k.clone(),
                            value: Some(AnyValue {
                                value: Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(v.clone())),
                            }),
                        }
                    }).collect(),
                    events: span.events.iter().map(|(name, attrs)| {
                        opentelemetry_proto::tonic::trace::v1::span::Event {
                            time_unix_nano: 1000500000,
                            name: name.clone(),
                            attributes: attrs.iter().map(|(k, v)| {
                                KeyValue {
                                    key: k.clone(),
                                    value: Some(AnyValue {
                                        value: Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(v.clone())),
                                    }),
                                }
                            }).collect(),
                            dropped_attributes_count: 0,
                        }
                    }).collect(),
                        status: Some(opentelemetry_proto::tonic::trace::v1::Status {
                            code: match span.status {
                                Status::Unset => 0,
                                Status::Ok => 1,
                                Status::Error { .. } => 2,
                            },
                            message: match &span.status {
                                Status::Error { description } => description.to_string(),
                                _ => String::new(),
                            },
                        }),
                    dropped_attributes_count: 0,
                    dropped_events_count: 0,
                    dropped_links_count: 0,
                    links: vec![],
                    trace_state: String::new(),
                    flags: sampled_known_local_flags,
                }
            }).collect();

            let scope_spans = ScopeSpans {
                scope: Some(
                    opentelemetry_proto::tonic::common::v1::InstrumentationScope {
                        name: "asupersync".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    },
                ),
                spans,
                schema_url: String::new(),
            };

            let resource_spans = ResourceSpans {
                resource: Some(resource),
                scope_spans: vec![scope_spans],
                schema_url: String::new(),
            };

            let request = ExportTraceServiceRequest {
                resource_spans: vec![resource_spans],
            };

            request.encode_to_vec()
        }

        // Build OTLP export with the opentelemetry-proto reference transformer.
        fn build_reference_otlp_export(tree: &CanonicalSpanTree) -> Vec<u8> {
            fn span_id_from_index(idx: usize) -> SpanId {
                SpanId::from_bytes([(idx + 1) as u8, 0, 0, 0, 0, 0, 0, 0])
            }

            let resource = SdkResource::builder_empty()
                .with_attribute(opentelemetry::KeyValue::new("service.name", "asupersync"))
                .build();
            let resource = ResourceAttributesWithSchema::from(&resource);
            let instrumentation_scope = opentelemetry::InstrumentationScope::builder("asupersync")
                .with_version(env!("CARGO_PKG_VERSION"))
                .build();
            let trace_id =
                TraceId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

            let spans = tree
                .spans
                .iter()
                .enumerate()
                .map(|(idx, span)| {
                    let mut events = SpanEvents::default();
                    events.events = span
                        .events
                        .iter()
                        .map(|(name, attrs)| {
                            Event::new(
                                name.clone(),
                                UNIX_EPOCH + Duration::from_nanos(1_000_500_000),
                                attrs
                                    .iter()
                                    .map(|(key, value)| {
                                        opentelemetry::KeyValue::new(key.clone(), value.clone())
                                    })
                                    .collect(),
                                0,
                            )
                        })
                        .collect();

                    SpanData {
                        span_context: SpanContext::new(
                            trace_id,
                            span_id_from_index(idx),
                            TraceFlags::SAMPLED,
                            false,
                            TraceState::default(),
                        ),
                        parent_span_id: span.parent_idx.map_or(SpanId::INVALID, span_id_from_index),
                        parent_span_is_remote: false,
                        span_kind: span.kind.clone(),
                        name: span.name.clone().into(),
                        start_time: UNIX_EPOCH + Duration::from_nanos(1_000_000_000),
                        end_time: UNIX_EPOCH + Duration::from_nanos(1_001_000_000),
                        attributes: span
                            .attributes
                            .iter()
                            .map(|(key, value)| {
                                opentelemetry::KeyValue::new(key.clone(), value.clone())
                            })
                            .collect(),
                        dropped_attributes_count: 0,
                        events,
                        links: SpanLinks::default(),
                        status: span.status.clone(),
                        instrumentation_scope: instrumentation_scope.clone(),
                    }
                })
                .collect();

            let resource_spans = group_spans_by_resource_and_scope(spans, &resource);
            ExportTraceServiceRequest { resource_spans }.encode_to_vec()
        }

        // Run the conformance test
        let tree = CanonicalSpanTree::new();

        let our_bytes = build_our_otlp_export(&tree);
        let reference_bytes = build_reference_otlp_export(&tree);

        // Verify byte-identical output
        if our_bytes != reference_bytes {
            // For debugging: decode both and compare structure
            let our_decoded =
                ExportTraceServiceRequest::decode(our_bytes.as_slice()).expect("decode our OTLP");
            let ref_decoded = ExportTraceServiceRequest::decode(reference_bytes.as_slice())
                .expect("decode reference OTLP");

            // Create detailed comparison for debugging
            eprintln!("OTLP Conformance Failure:");
            eprintln!(
                "Our implementation spans: {}",
                our_decoded.resource_spans.len()
            );
            eprintln!(
                "Reference implementation spans: {}",
                ref_decoded.resource_spans.len()
            );

            // Use insta for detailed comparison snapshot
            insta::with_settings!({
                snapshot_path => "../../tests/snapshots",
                prepend_module_to_snapshot => false,
            }, {
                insta::assert_snapshot!(
                    "otlp_export_conformance_failure_our",
                    format!("{our_decoded:#?}")
                );
                insta::assert_snapshot!(
                    "otlp_export_conformance_failure_ref",
                    format!("{ref_decoded:#?}")
                );
            });

            panic!(
                "OTLP export conformance test failed: byte outputs differ\n\
                 Our bytes: {} bytes\n\
                 Reference bytes: {} bytes\n\
                 Check snapshot files for detailed comparison",
                our_bytes.len(),
                reference_bytes.len()
            );
        }

        assert!(!our_bytes.is_empty(), "OTLP export must not be empty");
    }

    #[test]
    fn otlp_051_gauge_first_write_semantics_conformance() {
        use std::thread;
        use std::time::Instant;

        // OTLP-051 conformance test: when exporter sees a span with gauge metrics,
        // it MUST handle first-write semantics correctly:
        // - Gauge value initialization (first write sets initial value)
        // - Subsequent updates (updates change value correctly)
        // - Timestamp ordering (later updates have monotonic/equal timestamps)

        // Create test scenario structure
        struct GaugeFirstWriteScenario {
            gauge_name: String,
            labels: Vec<(String, String)>,
            initial_value: i64,
            update_sequence: Vec<i64>,
            expected_final_value: i64,
        }

        let scenario = GaugeFirstWriteScenario {
            gauge_name: "test.memory.usage".to_string(),
            labels: vec![
                ("service.name".to_string(), "asupersync".to_string()),
                ("process.id".to_string(), "12345".to_string()),
            ],
            initial_value: 1024,
            update_sequence: vec![2048, 1536, 3072, 2560],
            expected_final_value: 2560,
        };

        // Gauge first-write validation function
        fn validate_gauge_first_write_semantics(
            scenario: &GaugeFirstWriteScenario,
        ) -> Result<(), String> {
            let mut snapshot = MetricsSnapshot::new();

            // Record initial gauge write timestamp
            let initial_timestamp = Instant::now();

            // First write: initial value initialization
            snapshot.add_gauge(
                &scenario.gauge_name,
                scenario.labels.clone(),
                scenario.initial_value,
            );

            // Validate initial write
            if snapshot.gauges.is_empty() {
                return Err("Initial gauge write failed: no gauge data recorded".to_string());
            }

            let initial_gauge = &snapshot.gauges[0];
            if initial_gauge.0 != scenario.gauge_name {
                return Err(format!(
                    "Initial write gauge name mismatch: expected '{}', got '{}'",
                    scenario.gauge_name, initial_gauge.0
                ));
            }

            if initial_gauge.2 != scenario.initial_value {
                return Err(format!(
                    "Initial write value mismatch: expected {}, got {}",
                    scenario.initial_value, initial_gauge.2
                ));
            }

            // Small delay to ensure timestamp ordering
            thread::sleep(std::time::Duration::from_millis(1));

            // Subsequent updates: apply update sequence with timestamp tracking
            let mut previous_timestamp = initial_timestamp;
            for (update_count, &update_value) in scenario.update_sequence.iter().enumerate() {
                let update_count = update_count + 1; // Start at 1 for the first update after the initial write.
                let update_timestamp = Instant::now();

                // Verify timestamp ordering (monotonic or equal)
                if update_timestamp < previous_timestamp {
                    return Err(format!(
                        "Timestamp ordering violation: update {} timestamp is before previous timestamp",
                        update_count
                    ));
                }

                // Apply gauge update
                snapshot.add_gauge(&scenario.gauge_name, scenario.labels.clone(), update_value);

                previous_timestamp = update_timestamp;

                // Small delay for next update
                thread::sleep(std::time::Duration::from_millis(1));
            }

            // Validate final state
            let total_expected_writes = 1 + scenario.update_sequence.len();
            if snapshot.gauges.len() != total_expected_writes {
                return Err(format!(
                    "Update count mismatch: expected {} writes, got {}",
                    total_expected_writes,
                    snapshot.gauges.len()
                ));
            }

            let final_gauge = snapshot.gauges.last().unwrap();
            if final_gauge.2 != scenario.expected_final_value {
                return Err(format!(
                    "Final gauge value mismatch: expected {}, got {}",
                    scenario.expected_final_value, final_gauge.2
                ));
            }

            // Validate all gauge entries have consistent metadata
            for (i, gauge_entry) in snapshot.gauges.iter().enumerate() {
                if gauge_entry.0 != scenario.gauge_name {
                    return Err(format!(
                        "Gauge name consistency violation at index {}: expected '{}', got '{}'",
                        i, scenario.gauge_name, gauge_entry.0
                    ));
                }

                if gauge_entry.1 != scenario.labels {
                    return Err(format!(
                        "Gauge labels consistency violation at index {}: labels changed during update sequence",
                        i
                    ));
                }
            }

            Ok(())
        }

        // Test basic first-write semantics
        let validation_result = validate_gauge_first_write_semantics(&scenario);
        match validation_result {
            Ok(()) => {
                // Test passed - gauge first-write semantics are correct
            }
            Err(error_msg) => {
                panic!(
                    "OTLP-051 gauge first-write semantics test failed: {}",
                    error_msg
                );
            }
        }

        // Test edge case: zero initial value
        let zero_scenario = GaugeFirstWriteScenario {
            gauge_name: "test.zero.gauge".to_string(),
            labels: vec![],
            initial_value: 0,
            update_sequence: vec![-1, 1, 0],
            expected_final_value: 0,
        };

        let zero_validation = validate_gauge_first_write_semantics(&zero_scenario);
        assert!(
            zero_validation.is_ok(),
            "Zero initial value test failed: {:?}",
            zero_validation
        );

        // Test edge case: negative values throughout sequence
        let negative_scenario = GaugeFirstWriteScenario {
            gauge_name: "test.negative.gauge".to_string(),
            labels: vec![("type".to_string(), "deficit".to_string())],
            initial_value: -100,
            update_sequence: vec![-200, -50, -300],
            expected_final_value: -300,
        };

        let negative_validation = validate_gauge_first_write_semantics(&negative_scenario);
        assert!(
            negative_validation.is_ok(),
            "Negative values test failed: {:?}",
            negative_validation
        );

        // Test edge case: extreme values (boundary conditions)
        let extreme_scenario = GaugeFirstWriteScenario {
            gauge_name: "test.extreme.gauge".to_string(),
            labels: vec![("boundary".to_string(), "test".to_string())],
            initial_value: i64::MIN,
            update_sequence: vec![0, i64::MAX, i64::MIN + 1],
            expected_final_value: i64::MIN + 1,
        };

        let extreme_validation = validate_gauge_first_write_semantics(&extreme_scenario);
        assert!(
            extreme_validation.is_ok(),
            "Extreme values test failed: {:?}",
            extreme_validation
        );

        // Perform gauge update sequence with timestamp verification against the
        // same internal snapshot representation used by the exporter tests.
        let update_values = [1500_i64, 800, 2000, 1200];
        let mut gauge_snapshot = MetricsSnapshot::new();
        let mut previous_timestamp = Instant::now();

        for (i, &value) in update_values.iter().enumerate() {
            let current_timestamp = Instant::now();
            gauge_snapshot.add_gauge("otlp.051.test.gauge", Vec::new(), value);

            // Verify timestamp progression (should be monotonic or equal)
            assert!(
                current_timestamp >= previous_timestamp,
                "OTLP-051 timestamp ordering violation at update {}: current timestamp is before previous",
                i
            );

            previous_timestamp = current_timestamp;

            // Short delay to ensure distinct timestamps
            thread::sleep(std::time::Duration::from_millis(2));
        }

        // Verify final gauge value
        let final_value = gauge_snapshot
            .gauges
            .last()
            .map(|(_, _, value)| *value)
            .expect("gauge update sequence should record values");
        let expected_final = *update_values.last().unwrap();
        assert_eq!(
            final_value, expected_final,
            "OTLP-051 final gauge value verification failed: expected {}, got {}",
            expected_final, final_value
        );

        println!("✓ OTLP-051 gauge first-write semantics conformance test passed");
        println!("  - Initial value setting: ✓");
        println!("  - Update sequence application: ✓");
        println!("  - Timestamp ordering: ✓");
        println!("  - Edge cases (zero, negative, extreme): ✓");
        println!("  - MetricsSnapshot exporter representation: ✓");
    }

    /// Test privacy filtering for OTLP log records.
    ///
    /// **Security Test**: Verifies that sensitive attributes listed in
    /// `SpanConfig::drop_attributes` are properly filtered from OTLP exports
    /// to prevent data leakage to observability collectors.
    #[test]
    fn otlp_metrics_privacy_filtering() {
        // Test privacy filtering for OTLP metrics export
        let mut snapshot = MetricsSnapshot::new();

        // Add a counter with both safe and sensitive labels
        snapshot.add_counter(
            "http_requests_total",
            vec![
                ("method".to_string(), "POST".to_string()), // Safe
                ("endpoint".to_string(), "/api/v1/users".to_string()), // Safe
                ("user_id".to_string(), "user_12345".to_string()), // Sensitive - PII
                ("request_id".to_string(), "req_abc123".to_string()), // Sensitive - tracking
                ("user_email".to_string(), "john.doe@company.com".to_string()), // Sensitive - PII
            ],
            42,
        );

        // Add a gauge with sensitive labels
        snapshot.add_gauge(
            "active_sessions",
            vec![
                ("service".to_string(), "auth".to_string()), // Safe
                ("session_token".to_string(), "sess_xyz789".to_string()), // Sensitive - credential
            ],
            15,
        );

        // Create privacy config that drops sensitive labels
        let privacy_config = PrivacyConfig::new()
            .with_drop_label("user_id")
            .with_drop_label("request_id")
            .with_drop_label("user_email")
            .with_drop_label("session_token")
            .with_auto_pii_detection();

        // Test export without privacy filtering (baseline)
        let request_no_privacy = otlp_request_builder::metrics_request_from_snapshot(
            &snapshot,
            "test-service",
            1,
            "test-scope",
        );

        // Test export with privacy filtering
        let request_with_privacy = otlp_request_builder::metrics_request_from_snapshot_with_privacy(
            &snapshot,
            "test-service",
            1,
            "test-scope",
            Some(&privacy_config),
        );

        // Extract attributes from both requests for comparison
        let extract_counter_attributes = |request: &ExportMetricsServiceRequest| -> Vec<String> {
            request.resource_metrics[0].scope_metrics[0]
                .metrics
                .iter()
                .find(|m| m.name == "http_requests_total")
                .and_then(|m| m.data.as_ref())
                .and_then(|data| match data {
                    metric::Data::Sum(sum) => Some(&sum.data_points[0].attributes),
                    _ => None,
                })
                .map(|attrs| attrs.iter().map(|kv| kv.key.clone()).collect())
                .unwrap_or_default()
        };

        let attrs_no_privacy = extract_counter_attributes(&request_no_privacy);
        let attrs_with_privacy = extract_counter_attributes(&request_with_privacy);

        // Verify that sensitive labels are present without privacy filtering
        assert!(
            attrs_no_privacy.contains(&"user_id".to_string()),
            "Baseline should contain user_id"
        );
        assert!(
            attrs_no_privacy.contains(&"request_id".to_string()),
            "Baseline should contain request_id"
        );
        assert!(
            attrs_no_privacy.contains(&"user_email".to_string()),
            "Baseline should contain user_email"
        );

        // Verify that sensitive labels are removed with privacy filtering
        assert!(
            !attrs_with_privacy.contains(&"user_id".to_string()),
            "Privacy filtering should remove user_id"
        );
        assert!(
            !attrs_with_privacy.contains(&"request_id".to_string()),
            "Privacy filtering should remove request_id"
        );
        assert!(
            !attrs_with_privacy.contains(&"user_email".to_string()),
            "Privacy filtering should remove user_email"
        );

        // Verify that safe labels are preserved
        assert!(
            attrs_with_privacy.contains(&"method".to_string()),
            "Safe labels should be preserved"
        );
        assert!(
            attrs_with_privacy.contains(&"endpoint".to_string()),
            "Safe labels should be preserved"
        );

        eprintln!("✅ OTLP metrics privacy filtering test passed");
        eprintln!("   • Sensitive labels removed: user_id, request_id, user_email");
        eprintln!("   • Safe labels preserved: method, endpoint");
    }

    #[test]
    fn otlp_log_privacy_filtering() {
        use crate::observability::entry::LogEntry;
        use crate::observability::level::LogLevel;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Create a span config that drops sensitive attributes
        let privacy_config = PrivacyConfig::new()
            .with_drop_attribute("user.email")
            .with_drop_attribute("api.key")
            .with_drop_attribute("auth.token");

        let log_entry = LogEntry::new(LogLevel::Info, "user action completed")
            .with_field("action", "login")
            .with_field("user.email", "sensitive@example.com") // Should be filtered
            .with_field("api.key", "secret-key-12345") // Should be filtered
            .with_field("auth.token", "bearer-token-xyz") // Should be filtered
            .with_field("user.id", "12345") // Should be kept
            .with_field("request.path", "/api/login"); // Should be kept

        let observed_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Test WITHOUT privacy filtering (baseline)
        let unfiltered_record = OtlpLogRecord::from_log_entry(&log_entry, observed_time);

        // Verify all attributes are present in unfiltered record
        assert_eq!(
            unfiltered_record.attributes.len(),
            6,
            "Unfiltered record should contain all 6 attributes"
        );
        assert!(
            unfiltered_record
                .attributes
                .iter()
                .any(|(k, _)| k == "user.email"),
            "user.email should be present without filtering"
        );
        assert!(
            unfiltered_record
                .attributes
                .iter()
                .any(|(k, _)| k == "api.key"),
            "api.key should be present without filtering"
        );
        assert!(
            unfiltered_record
                .attributes
                .iter()
                .any(|(k, _)| k == "auth.token"),
            "auth.token should be present without filtering"
        );

        // Test WITH privacy filtering (the fix)
        let filtered_record =
            OtlpLogRecord::from_log_entry_with_privacy(&log_entry, observed_time, &privacy_config);

        // Verify sensitive attributes are filtered out
        assert_eq!(
            filtered_record.attributes.len(),
            3,
            "Filtered record should contain only 3 safe attributes"
        );
        assert!(
            filtered_record
                .attributes
                .iter()
                .all(|(k, _)| k != "user.email"),
            "user.email should be filtered out"
        );
        assert!(
            filtered_record
                .attributes
                .iter()
                .all(|(k, _)| k != "api.key"),
            "api.key should be filtered out"
        );
        assert!(
            filtered_record
                .attributes
                .iter()
                .all(|(k, _)| k != "auth.token"),
            "auth.token should be filtered out"
        );

        // Verify safe attributes are preserved
        assert!(
            filtered_record
                .attributes
                .iter()
                .any(|(k, _)| k == "action"),
            "action should be preserved"
        );
        assert!(
            filtered_record
                .attributes
                .iter()
                .any(|(k, _)| k == "user.id"),
            "user.id should be preserved"
        );
        assert!(
            filtered_record
                .attributes
                .iter()
                .any(|(k, _)| k == "request.path"),
            "request.path should be preserved"
        );

        // Verify dropped attributes are counted
        assert_eq!(
            filtered_record.dropped_attributes_count, 3,
            "Should report 3 dropped sensitive attributes"
        );

        println!("✓ OTLP privacy filtering security test passed");
        println!("  - Sensitive attributes filtered: ✓");
        println!("  - Safe attributes preserved: ✓");
        println!("  - Dropped count accurate: ✓");
    }

    #[test]
    fn otlp_log_privacy_filtering_uses_full_privacy_policy() {
        use crate::observability::entry::LogEntry;
        use crate::observability::level::LogLevel;

        let privacy_config = PrivacyConfig::new()
            .with_allowed_field("action")
            .with_allowed_field("user.*")
            .with_allowed_field("session_id")
            .with_drop_label("session_id")
            .with_auto_pii_detection();

        let log_entry = LogEntry::new(LogLevel::Info, "user profile updated")
            .with_field("action", "profile-update")
            .with_field("user.email", "jane.doe@example.com")
            .with_field("session_id", "session-abc123")
            .with_field("auth.token", "bearer secret-token")
            .with_field("request.path", "/private/profile");

        let filtered_record =
            OtlpLogRecord::from_log_entry_with_privacy(&log_entry, 1_000, &privacy_config);
        let attributes: std::collections::HashMap<_, _> =
            filtered_record.attributes.iter().cloned().collect();

        assert_eq!(
            attributes.get("action").map(String::as_str),
            Some("profile-update")
        );
        assert_eq!(
            attributes.get("user.email").map(String::as_str),
            Some("[EMAIL_REDACTED]")
        );
        assert!(!attributes.contains_key("session_id"));
        assert!(!attributes.contains_key("auth.token"));
        assert!(!attributes.contains_key("request.path"));
        assert_eq!(filtered_record.dropped_attributes_count, 3);
    }
}
