//! Conservative ATP transfer autotuning model.
//!
//! The policy in this module is intentionally deterministic and side-effect
//! free. Runtime, CLI, and lab harnesses can feed it observed path, disk, CPU,
//! and repair telemetry, then apply the returned settings through their own
//! capability-checked control paths.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Stable metric names emitted by ATP pressure/autotune telemetry.
///
/// Keep these names stable; downstream proof bundles and operator diagnostics
/// use them as durable keys.
pub const ATP_AUTOTUNE_METRIC_NAMES: [AtpAutotuneMetric; 14] = [
    AtpAutotuneMetric::RttMicros,
    AtpAutotuneMetric::LossPermille,
    AtpAutotuneMetric::PtoMicros,
    AtpAutotuneMetric::CongestionWindowBytes,
    AtpAutotuneMetric::InFlightBytes,
    AtpAutotuneMetric::SendBufferQueuedBytes,
    AtpAutotuneMetric::ReceiveBufferQueuedBytes,
    AtpAutotuneMetric::DiskReadLagMicros,
    AtpAutotuneMetric::DiskWriteLagMicros,
    AtpAutotuneMetric::EncodeBacklogSymbols,
    AtpAutotuneMetric::DecodeBacklogSymbols,
    AtpAutotuneMetric::RepairRoiPermille,
    AtpAutotuneMetric::RelayCostMicrosPerMiB,
    AtpAutotuneMetric::MigrationEvents,
];

/// Metric keys accepted by [`AtpAutotuneTelemetry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AtpAutotuneMetric {
    /// Smoothed round-trip time in microseconds.
    RttMicros,
    /// Observed loss rate in packets per thousand.
    LossPermille,
    /// Probe timeout in microseconds.
    PtoMicros,
    /// Congestion window in bytes.
    CongestionWindowBytes,
    /// Bytes currently in flight.
    InFlightBytes,
    /// Bytes queued in the send buffer.
    SendBufferQueuedBytes,
    /// Bytes queued in the receive buffer.
    ReceiveBufferQueuedBytes,
    /// Disk read lag in microseconds.
    DiskReadLagMicros,
    /// Disk write lag in microseconds.
    DiskWriteLagMicros,
    /// Pending encoder work in symbols.
    EncodeBacklogSymbols,
    /// Pending decoder work in symbols.
    DecodeBacklogSymbols,
    /// Repair benefit in useful repair symbols per thousand sent repair symbols.
    RepairRoiPermille,
    /// Relay cost in microseconds per MiB transferred.
    RelayCostMicrosPerMiB,
    /// Number of path migration events in the current decision window.
    MigrationEvents,
}

impl AtpAutotuneMetric {
    /// Return the stable metric name used in logs and proof artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RttMicros => "atp.autotune.rtt_micros",
            Self::LossPermille => "atp.autotune.loss_permille",
            Self::PtoMicros => "atp.autotune.pto_micros",
            Self::CongestionWindowBytes => "atp.autotune.congestion_window_bytes",
            Self::InFlightBytes => "atp.autotune.in_flight_bytes",
            Self::SendBufferQueuedBytes => "atp.autotune.send_buffer_queued_bytes",
            Self::ReceiveBufferQueuedBytes => "atp.autotune.receive_buffer_queued_bytes",
            Self::DiskReadLagMicros => "atp.autotune.disk_read_lag_micros",
            Self::DiskWriteLagMicros => "atp.autotune.disk_write_lag_micros",
            Self::EncodeBacklogSymbols => "atp.autotune.encode_backlog_symbols",
            Self::DecodeBacklogSymbols => "atp.autotune.decode_backlog_symbols",
            Self::RepairRoiPermille => "atp.autotune.repair_roi_permille",
            Self::RelayCostMicrosPerMiB => "atp.autotune.relay_cost_micros_per_mib",
            Self::MigrationEvents => "atp.autotune.migration_events",
        }
    }

    /// Parse a stable metric name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "atp.autotune.rtt_micros" => Some(Self::RttMicros),
            "atp.autotune.loss_permille" => Some(Self::LossPermille),
            "atp.autotune.pto_micros" => Some(Self::PtoMicros),
            "atp.autotune.congestion_window_bytes" => Some(Self::CongestionWindowBytes),
            "atp.autotune.in_flight_bytes" => Some(Self::InFlightBytes),
            "atp.autotune.send_buffer_queued_bytes" => Some(Self::SendBufferQueuedBytes),
            "atp.autotune.receive_buffer_queued_bytes" => Some(Self::ReceiveBufferQueuedBytes),
            "atp.autotune.disk_read_lag_micros" => Some(Self::DiskReadLagMicros),
            "atp.autotune.disk_write_lag_micros" => Some(Self::DiskWriteLagMicros),
            "atp.autotune.encode_backlog_symbols" => Some(Self::EncodeBacklogSymbols),
            "atp.autotune.decode_backlog_symbols" => Some(Self::DecodeBacklogSymbols),
            "atp.autotune.repair_roi_permille" => Some(Self::RepairRoiPermille),
            "atp.autotune.relay_cost_micros_per_mib" => Some(Self::RelayCostMicrosPerMiB),
            "atp.autotune.migration_events" => Some(Self::MigrationEvents),
            _ => None,
        }
    }
}

impl Serialize for AtpAutotuneMetric {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AtpAutotuneMetric {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::from_name(&name).ok_or_else(|| {
            serde::de::Error::unknown_variant(
                &name,
                &[
                    "atp.autotune.rtt_micros",
                    "atp.autotune.loss_permille",
                    "atp.autotune.pto_micros",
                    "atp.autotune.congestion_window_bytes",
                    "atp.autotune.in_flight_bytes",
                    "atp.autotune.send_buffer_queued_bytes",
                    "atp.autotune.receive_buffer_queued_bytes",
                    "atp.autotune.disk_read_lag_micros",
                    "atp.autotune.disk_write_lag_micros",
                    "atp.autotune.encode_backlog_symbols",
                    "atp.autotune.decode_backlog_symbols",
                    "atp.autotune.repair_roi_permille",
                    "atp.autotune.relay_cost_micros_per_mib",
                    "atp.autotune.migration_events",
                ],
            )
        })
    }
}

/// One collected ATP autotune metric sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneMetricSample {
    /// Stable metric key.
    pub metric: AtpAutotuneMetric,
    /// Observed metric value.
    pub value: u64,
}

impl AtpAutotuneMetricSample {
    /// Construct a metric sample with a stable metric key.
    #[must_use]
    pub const fn new(metric: AtpAutotuneMetric, value: u64) -> Self {
        Self { metric, value }
    }
}

/// Stable trace-scoped ATP autotune metric report.
///
/// This format is useful for runtime and lab collection paths that naturally
/// emit metric rows rather than a fully aggregated telemetry window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneTelemetryReport {
    /// Stable trace id linking every sample to path/proof logs.
    pub trace_id: String,
    /// Stable workload or transfer id.
    pub workload_id: String,
    /// Samples represented by this report. If zero, the sample vector length is used.
    pub sample_count: u32,
    /// Stable-name metric samples.
    pub samples: Vec<AtpAutotuneMetricSample>,
}

impl AtpAutotuneTelemetryReport {
    /// Create an empty trace-scoped telemetry report.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, workload_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            workload_id: workload_id.into(),
            sample_count: 0,
            samples: Vec::new(),
        }
    }

    /// Set the represented sample count.
    #[must_use]
    pub const fn with_sample_count(mut self, sample_count: u32) -> Self {
        self.sample_count = sample_count;
        self
    }

    /// Add one metric sample.
    #[must_use]
    pub fn with_sample(mut self, metric: AtpAutotuneMetric, value: u64) -> Self {
        self.samples
            .push(AtpAutotuneMetricSample::new(metric, value));
        self
    }

    /// Export an aggregated telemetry window as stable metric samples.
    #[must_use]
    pub fn from_telemetry(telemetry: &AtpAutotuneTelemetry) -> Self {
        telemetry.to_report()
    }

    /// Aggregate this report into one decision window.
    ///
    /// Repeated metrics use the latest sample in report order. Out-of-range
    /// values for narrow fields fail before producing a telemetry window.
    pub fn into_telemetry(self) -> Result<AtpAutotuneTelemetry, AtpAutotuneTelemetryError> {
        let sample_count = if self.sample_count == 0 {
            u32::try_from(self.samples.len()).unwrap_or(u32::MAX)
        } else {
            self.sample_count
        };
        let mut telemetry = AtpAutotuneTelemetry::new(self.trace_id, self.workload_id)
            .with_sample_count(sample_count);
        for sample in self.samples {
            telemetry.record_metric(sample.metric, sample.value)?;
        }
        Ok(telemetry)
    }
}

/// Error returned while aggregating ATP autotune metric samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpAutotuneTelemetryError {
    /// Metric value does not fit the telemetry field type.
    MetricValueOutOfRange {
        /// Metric being collected.
        metric: AtpAutotuneMetric,
        /// Observed value.
        value: u64,
        /// Maximum accepted value.
        max: u64,
    },
}

impl fmt::Display for AtpAutotuneTelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetricValueOutOfRange { metric, value, max } => write!(
                f,
                "ATP autotune metric {} value {} exceeds maximum {}",
                metric.as_str(),
                value,
                max
            ),
        }
    }
}

impl std::error::Error for AtpAutotuneTelemetryError {}

/// Current transfer knobs that the autotuner may adjust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneSettings {
    /// Maximum bytes allowed in flight for this transfer.
    pub in_flight_bytes: u64,
    /// Maximum concurrent streams for this transfer.
    pub stream_count: u16,
    /// Target chunk size in bytes.
    pub chunk_size_bytes: u32,
    /// Repair symbols allowed per second.
    pub repair_symbols_per_second: u32,
}

impl AtpAutotuneSettings {
    /// Construct settings with explicit nonzero values.
    #[must_use]
    pub const fn new(
        in_flight_bytes: u64,
        stream_count: u16,
        chunk_size_bytes: u32,
        repair_symbols_per_second: u32,
    ) -> Self {
        Self {
            in_flight_bytes,
            stream_count,
            chunk_size_bytes,
            repair_symbols_per_second,
        }
    }
}

impl Default for AtpAutotuneSettings {
    fn default() -> Self {
        Self {
            in_flight_bytes: 8 * 1_048_576,
            stream_count: 4,
            chunk_size_bytes: 256 * 1_024,
            repair_symbols_per_second: 256,
        }
    }
}

/// Hard bounds for autotune decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneLimits {
    /// Minimum in-flight byte limit.
    pub min_in_flight_bytes: u64,
    /// Maximum in-flight byte limit.
    pub max_in_flight_bytes: u64,
    /// Minimum stream count.
    pub min_stream_count: u16,
    /// Maximum stream count.
    pub max_stream_count: u16,
    /// Minimum chunk size in bytes.
    pub min_chunk_size_bytes: u32,
    /// Maximum chunk size in bytes.
    pub max_chunk_size_bytes: u32,
    /// Minimum repair-symbol rate.
    pub min_repair_symbols_per_second: u32,
    /// Maximum repair-symbol rate.
    pub max_repair_symbols_per_second: u32,
}

impl Default for AtpAutotuneLimits {
    fn default() -> Self {
        Self {
            min_in_flight_bytes: 1_048_576,
            max_in_flight_bytes: 512 * 1_048_576,
            min_stream_count: 1,
            max_stream_count: 64,
            min_chunk_size_bytes: 64 * 1_024,
            max_chunk_size_bytes: 8 * 1_048_576,
            min_repair_symbols_per_second: 0,
            max_repair_symbols_per_second: 16_384,
        }
    }
}

impl AtpAutotuneLimits {
    /// Clamp settings into this bounds envelope.
    #[must_use]
    pub fn clamp(self, settings: AtpAutotuneSettings) -> AtpAutotuneSettings {
        AtpAutotuneSettings {
            in_flight_bytes: settings
                .in_flight_bytes
                .clamp(self.min_in_flight_bytes, self.max_in_flight_bytes),
            stream_count: settings
                .stream_count
                .clamp(self.min_stream_count, self.max_stream_count),
            chunk_size_bytes: settings
                .chunk_size_bytes
                .clamp(self.min_chunk_size_bytes, self.max_chunk_size_bytes),
            repair_symbols_per_second: settings.repair_symbols_per_second.clamp(
                self.min_repair_symbols_per_second,
                self.max_repair_symbols_per_second,
            ),
        }
    }
}

/// Telemetry window used for one autotune decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneTelemetry {
    /// Stable trace id linking this decision to path/proof logs.
    pub trace_id: String,
    /// Stable workload or transfer id.
    pub workload_id: String,
    /// Samples represented by this telemetry window.
    pub sample_count: u32,
    /// Smoothed RTT in microseconds.
    pub rtt_micros: Option<u64>,
    /// Loss rate in packets per thousand.
    pub loss_permille: Option<u16>,
    /// Probe timeout in microseconds.
    pub pto_micros: Option<u64>,
    /// Congestion window in bytes.
    pub congestion_window_bytes: Option<u64>,
    /// Current in-flight bytes.
    pub in_flight_bytes: Option<u64>,
    /// Queued send-buffer bytes.
    pub send_buffer_queued_bytes: Option<u64>,
    /// Queued receive-buffer bytes.
    pub receive_buffer_queued_bytes: Option<u64>,
    /// Disk read lag in microseconds.
    pub disk_read_lag_micros: Option<u64>,
    /// Disk write lag in microseconds.
    pub disk_write_lag_micros: Option<u64>,
    /// Encoder backlog in symbols.
    pub encode_backlog_symbols: Option<u32>,
    /// Decoder backlog in symbols.
    pub decode_backlog_symbols: Option<u32>,
    /// Repair ROI in useful symbols per thousand repair symbols.
    pub repair_roi_permille: Option<u16>,
    /// Relay cost in microseconds per MiB.
    pub relay_cost_micros_per_mib: Option<u64>,
    /// Migration events during the window.
    pub migration_events: Option<u32>,
}

impl AtpAutotuneTelemetry {
    /// Create a telemetry window with only stable identifiers populated.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, workload_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            workload_id: workload_id.into(),
            sample_count: 0,
            rtt_micros: None,
            loss_permille: None,
            pto_micros: None,
            congestion_window_bytes: None,
            in_flight_bytes: None,
            send_buffer_queued_bytes: None,
            receive_buffer_queued_bytes: None,
            disk_read_lag_micros: None,
            disk_write_lag_micros: None,
            encode_backlog_symbols: None,
            decode_backlog_symbols: None,
            repair_roi_permille: None,
            relay_cost_micros_per_mib: None,
            migration_events: None,
        }
    }

    /// Set the sample count.
    #[must_use]
    pub const fn with_sample_count(mut self, sample_count: u32) -> Self {
        self.sample_count = sample_count;
        self
    }

    /// Export this telemetry window as a trace-scoped metric sample report.
    ///
    /// Samples are emitted in [`ATP_AUTOTUNE_METRIC_NAMES`] order and omitted
    /// when the corresponding telemetry field is absent. If this window has a
    /// zero `sample_count`, the report keeps zero so aggregation can infer the
    /// represented count from the exported samples.
    #[must_use]
    pub fn to_report(&self) -> AtpAutotuneTelemetryReport {
        let mut report =
            AtpAutotuneTelemetryReport::new(self.trace_id.clone(), self.workload_id.clone())
                .with_sample_count(self.sample_count);

        if let Some(value) = self.rtt_micros {
            report = report.with_sample(AtpAutotuneMetric::RttMicros, value);
        }
        if let Some(value) = self.loss_permille {
            report = report.with_sample(AtpAutotuneMetric::LossPermille, u64::from(value));
        }
        if let Some(value) = self.pto_micros {
            report = report.with_sample(AtpAutotuneMetric::PtoMicros, value);
        }
        if let Some(value) = self.congestion_window_bytes {
            report = report.with_sample(AtpAutotuneMetric::CongestionWindowBytes, value);
        }
        if let Some(value) = self.in_flight_bytes {
            report = report.with_sample(AtpAutotuneMetric::InFlightBytes, value);
        }
        if let Some(value) = self.send_buffer_queued_bytes {
            report = report.with_sample(AtpAutotuneMetric::SendBufferQueuedBytes, value);
        }
        if let Some(value) = self.receive_buffer_queued_bytes {
            report = report.with_sample(AtpAutotuneMetric::ReceiveBufferQueuedBytes, value);
        }
        if let Some(value) = self.disk_read_lag_micros {
            report = report.with_sample(AtpAutotuneMetric::DiskReadLagMicros, value);
        }
        if let Some(value) = self.disk_write_lag_micros {
            report = report.with_sample(AtpAutotuneMetric::DiskWriteLagMicros, value);
        }
        if let Some(value) = self.encode_backlog_symbols {
            report = report.with_sample(AtpAutotuneMetric::EncodeBacklogSymbols, u64::from(value));
        }
        if let Some(value) = self.decode_backlog_symbols {
            report = report.with_sample(AtpAutotuneMetric::DecodeBacklogSymbols, u64::from(value));
        }
        if let Some(value) = self.repair_roi_permille {
            report = report.with_sample(AtpAutotuneMetric::RepairRoiPermille, u64::from(value));
        }
        if let Some(value) = self.relay_cost_micros_per_mib {
            report = report.with_sample(AtpAutotuneMetric::RelayCostMicrosPerMiB, value);
        }
        if let Some(value) = self.migration_events {
            report = report.with_sample(AtpAutotuneMetric::MigrationEvents, u64::from(value));
        }

        report
    }

    /// Record one stable-name metric sample into this telemetry window.
    pub fn record_metric(
        &mut self,
        metric: AtpAutotuneMetric,
        value: u64,
    ) -> Result<(), AtpAutotuneTelemetryError> {
        match metric {
            AtpAutotuneMetric::RttMicros => self.rtt_micros = Some(value),
            AtpAutotuneMetric::LossPermille => {
                self.loss_permille = Some(narrow_u16_metric(metric, value)?);
            }
            AtpAutotuneMetric::PtoMicros => self.pto_micros = Some(value),
            AtpAutotuneMetric::CongestionWindowBytes => {
                self.congestion_window_bytes = Some(value);
            }
            AtpAutotuneMetric::InFlightBytes => self.in_flight_bytes = Some(value),
            AtpAutotuneMetric::SendBufferQueuedBytes => {
                self.send_buffer_queued_bytes = Some(value);
            }
            AtpAutotuneMetric::ReceiveBufferQueuedBytes => {
                self.receive_buffer_queued_bytes = Some(value);
            }
            AtpAutotuneMetric::DiskReadLagMicros => self.disk_read_lag_micros = Some(value),
            AtpAutotuneMetric::DiskWriteLagMicros => self.disk_write_lag_micros = Some(value),
            AtpAutotuneMetric::EncodeBacklogSymbols => {
                self.encode_backlog_symbols = Some(narrow_u32_metric(metric, value)?);
            }
            AtpAutotuneMetric::DecodeBacklogSymbols => {
                self.decode_backlog_symbols = Some(narrow_u32_metric(metric, value)?);
            }
            AtpAutotuneMetric::RepairRoiPermille => {
                self.repair_roi_permille = Some(narrow_u16_metric(metric, value)?);
            }
            AtpAutotuneMetric::RelayCostMicrosPerMiB => {
                self.relay_cost_micros_per_mib = Some(value);
            }
            AtpAutotuneMetric::MigrationEvents => {
                self.migration_events = Some(narrow_u32_metric(metric, value)?);
            }
        }
        Ok(())
    }
}

fn narrow_u16_metric(
    metric: AtpAutotuneMetric,
    value: u64,
) -> Result<u16, AtpAutotuneTelemetryError> {
    u16::try_from(value).map_err(|_| AtpAutotuneTelemetryError::MetricValueOutOfRange {
        metric,
        value,
        max: u64::from(u16::MAX),
    })
}

fn narrow_u32_metric(
    metric: AtpAutotuneMetric,
    value: u64,
) -> Result<u32, AtpAutotuneTelemetryError> {
    u32::try_from(value).map_err(|_| AtpAutotuneTelemetryError::MetricValueOutOfRange {
        metric,
        value,
        max: u64::from(u32::MAX),
    })
}

/// Bottleneck class selected by the autotune policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpBottleneckKind {
    /// Not enough telemetry to safely increase throughput.
    InsufficientTelemetry,
    /// Telemetry contains contradictory values.
    ContradictoryTelemetry,
    /// Loss or PTO signals imply network pressure.
    NetworkLoss,
    /// RTT is high enough to avoid aggressive growth.
    NetworkLatency,
    /// Current in-flight bytes exceed the observed congestion window.
    CongestionWindow,
    /// Sender buffering is backing up.
    SendBufferPressure,
    /// Receiver buffering is backing up.
    ReceiveBufferPressure,
    /// Disk reads are lagging.
    DiskReadLag,
    /// Disk writes are lagging.
    DiskWriteLag,
    /// Encoding work is backing up.
    EncodeBacklog,
    /// Decoding work is backing up.
    DecodeBacklog,
    /// Repair traffic is not paying for itself.
    RepairLowRoi,
    /// Relay path is materially expensive.
    RelayCost,
    /// Frequent migration means the path is unstable.
    MigrationInstability,
}

/// One human-readable bottleneck signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpBottleneckSignal {
    /// Bottleneck class.
    pub kind: AtpBottleneckKind,
    /// Stable metric that produced this signal.
    pub metric: Option<AtpAutotuneMetric>,
    /// Observed value.
    pub observed: u64,
    /// Threshold used by the policy.
    pub threshold: u64,
}

impl AtpBottleneckSignal {
    fn new(
        kind: AtpBottleneckKind,
        metric: Option<AtpAutotuneMetric>,
        observed: u64,
        threshold: u64,
    ) -> Self {
        Self {
            kind,
            metric,
            observed,
            threshold,
        }
    }
}

/// Decision returned by [`AtpAutotunePolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneDecision {
    /// Settings to apply for the next window.
    pub settings: AtpAutotuneSettings,
    /// Signals explaining why the decision was made.
    pub bottlenecks: Vec<AtpBottleneckSignal>,
    /// Whether the decision held or reduced throughput because confidence was low.
    pub fail_closed: bool,
    /// Short stable reason suitable for logs and proof artifacts.
    pub reason_code: String,
}

/// Deterministic conservative autotune policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotunePolicy {
    /// Hard decision limits.
    pub limits: AtpAutotuneLimits,
    /// Minimum samples before the policy may grow throughput.
    pub min_growth_samples: u32,
    /// Loss threshold that starts backing off in-flight bytes.
    pub loss_backoff_permille: u16,
    /// RTT threshold that blocks growth.
    pub latency_hold_micros: u64,
    /// Buffer pressure threshold in bytes.
    pub buffer_pressure_bytes: u64,
    /// Disk lag threshold in microseconds.
    pub disk_lag_micros: u64,
    /// CPU backlog threshold in symbols.
    pub cpu_backlog_symbols: u32,
    /// Repair ROI floor for keeping repair rate elevated.
    pub repair_roi_floor_permille: u16,
    /// Relay cost threshold in microseconds per MiB.
    pub relay_cost_micros_per_mib: u64,
}

impl Default for AtpAutotunePolicy {
    fn default() -> Self {
        Self {
            limits: AtpAutotuneLimits::default(),
            min_growth_samples: 8,
            loss_backoff_permille: 25,
            latency_hold_micros: 250_000,
            buffer_pressure_bytes: 8 * 1_048_576,
            disk_lag_micros: 100_000,
            cpu_backlog_symbols: 4_096,
            repair_roi_floor_permille: 350,
            relay_cost_micros_per_mib: 500_000,
        }
    }
}

impl AtpAutotunePolicy {
    /// Produce a conservative decision for the next transfer window.
    #[must_use]
    pub fn decide(
        self,
        current: AtpAutotuneSettings,
        telemetry: &AtpAutotuneTelemetry,
    ) -> AtpAutotuneDecision {
        let mut settings = self.limits.clamp(current);
        let mut bottlenecks = Vec::new();

        self.detect_bottlenecks(telemetry, &mut bottlenecks);

        if telemetry.sample_count < self.min_growth_samples {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::InsufficientTelemetry,
                None,
                u64::from(telemetry.sample_count),
                u64::from(self.min_growth_samples),
            ));
        }

        let fail_closed = !bottlenecks.is_empty();
        if fail_closed {
            settings = self.backoff(settings, telemetry, &bottlenecks);
            return AtpAutotuneDecision {
                settings: self.limits.clamp(settings),
                bottlenecks,
                fail_closed,
                reason_code: String::from("hold_or_backoff_on_pressure"),
            };
        }

        AtpAutotuneDecision {
            settings: self.limits.clamp(self.grow(settings)),
            bottlenecks,
            fail_closed,
            reason_code: String::from("conservative_growth"),
        }
    }

    fn detect_bottlenecks(
        self,
        telemetry: &AtpAutotuneTelemetry,
        bottlenecks: &mut Vec<AtpBottleneckSignal>,
    ) {
        if telemetry.trace_id.trim().is_empty() || telemetry.workload_id.trim().is_empty() {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::ContradictoryTelemetry,
                None,
                0,
                1,
            ));
        }

        if let Some(loss) = telemetry.loss_permille
            && loss > self.loss_backoff_permille
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::NetworkLoss,
                Some(AtpAutotuneMetric::LossPermille),
                u64::from(loss),
                u64::from(self.loss_backoff_permille),
            ));
        }

        if let Some(rtt) = telemetry.rtt_micros
            && rtt > self.latency_hold_micros
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::NetworkLatency,
                Some(AtpAutotuneMetric::RttMicros),
                rtt,
                self.latency_hold_micros,
            ));
        }

        if let (Some(in_flight), Some(cwnd)) =
            (telemetry.in_flight_bytes, telemetry.congestion_window_bytes)
            && in_flight > cwnd
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::CongestionWindow,
                Some(AtpAutotuneMetric::InFlightBytes),
                in_flight,
                cwnd,
            ));
        }

        self.detect_queue_bottleneck(
            telemetry.send_buffer_queued_bytes,
            AtpBottleneckKind::SendBufferPressure,
            AtpAutotuneMetric::SendBufferQueuedBytes,
            bottlenecks,
        );
        self.detect_queue_bottleneck(
            telemetry.receive_buffer_queued_bytes,
            AtpBottleneckKind::ReceiveBufferPressure,
            AtpAutotuneMetric::ReceiveBufferQueuedBytes,
            bottlenecks,
        );
        self.detect_lag_bottleneck(
            telemetry.disk_read_lag_micros,
            AtpBottleneckKind::DiskReadLag,
            AtpAutotuneMetric::DiskReadLagMicros,
            bottlenecks,
        );
        self.detect_lag_bottleneck(
            telemetry.disk_write_lag_micros,
            AtpBottleneckKind::DiskWriteLag,
            AtpAutotuneMetric::DiskWriteLagMicros,
            bottlenecks,
        );
        self.detect_cpu_bottleneck(
            telemetry.encode_backlog_symbols,
            AtpBottleneckKind::EncodeBacklog,
            AtpAutotuneMetric::EncodeBacklogSymbols,
            bottlenecks,
        );
        self.detect_cpu_bottleneck(
            telemetry.decode_backlog_symbols,
            AtpBottleneckKind::DecodeBacklog,
            AtpAutotuneMetric::DecodeBacklogSymbols,
            bottlenecks,
        );

        if let Some(roi) = telemetry.repair_roi_permille
            && roi < self.repair_roi_floor_permille
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::RepairLowRoi,
                Some(AtpAutotuneMetric::RepairRoiPermille),
                u64::from(roi),
                u64::from(self.repair_roi_floor_permille),
            ));
        }

        if let Some(cost) = telemetry.relay_cost_micros_per_mib
            && cost > self.relay_cost_micros_per_mib
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::RelayCost,
                Some(AtpAutotuneMetric::RelayCostMicrosPerMiB),
                cost,
                self.relay_cost_micros_per_mib,
            ));
        }

        if let Some(events) = telemetry.migration_events
            && events > 0
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::MigrationInstability,
                Some(AtpAutotuneMetric::MigrationEvents),
                u64::from(events),
                0,
            ));
        }
    }

    fn detect_queue_bottleneck(
        self,
        observed: Option<u64>,
        kind: AtpBottleneckKind,
        metric: AtpAutotuneMetric,
        bottlenecks: &mut Vec<AtpBottleneckSignal>,
    ) {
        if let Some(bytes) = observed
            && bytes > self.buffer_pressure_bytes
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                kind,
                Some(metric),
                bytes,
                self.buffer_pressure_bytes,
            ));
        }
    }

    fn detect_lag_bottleneck(
        self,
        observed: Option<u64>,
        kind: AtpBottleneckKind,
        metric: AtpAutotuneMetric,
        bottlenecks: &mut Vec<AtpBottleneckSignal>,
    ) {
        if let Some(micros) = observed
            && micros > self.disk_lag_micros
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                kind,
                Some(metric),
                micros,
                self.disk_lag_micros,
            ));
        }
    }

    fn detect_cpu_bottleneck(
        self,
        observed: Option<u32>,
        kind: AtpBottleneckKind,
        metric: AtpAutotuneMetric,
        bottlenecks: &mut Vec<AtpBottleneckSignal>,
    ) {
        if let Some(symbols) = observed
            && symbols > self.cpu_backlog_symbols
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                kind,
                Some(metric),
                u64::from(symbols),
                u64::from(self.cpu_backlog_symbols),
            ));
        }
    }

    fn backoff(
        self,
        mut settings: AtpAutotuneSettings,
        telemetry: &AtpAutotuneTelemetry,
        bottlenecks: &[AtpBottleneckSignal],
    ) -> AtpAutotuneSettings {
        let reduce_transport = bottlenecks.iter().any(|signal| {
            matches!(
                signal.kind,
                AtpBottleneckKind::NetworkLoss
                    | AtpBottleneckKind::NetworkLatency
                    | AtpBottleneckKind::CongestionWindow
                    | AtpBottleneckKind::SendBufferPressure
                    | AtpBottleneckKind::ReceiveBufferPressure
                    | AtpBottleneckKind::MigrationInstability
            )
        });
        if reduce_transport {
            settings.in_flight_bytes = decrease_by_quarter(settings.in_flight_bytes);
            settings.stream_count = settings.stream_count.saturating_sub(1).max(1);
        }

        let reduce_chunk = bottlenecks.iter().any(|signal| {
            matches!(
                signal.kind,
                AtpBottleneckKind::DiskReadLag
                    | AtpBottleneckKind::DiskWriteLag
                    | AtpBottleneckKind::EncodeBacklog
                    | AtpBottleneckKind::DecodeBacklog
            )
        });
        if reduce_chunk {
            settings.chunk_size_bytes = decrease_by_quarter_u32(settings.chunk_size_bytes);
        }

        if bottlenecks
            .iter()
            .any(|signal| signal.kind == AtpBottleneckKind::RepairLowRoi)
        {
            settings.repair_symbols_per_second =
                decrease_by_quarter_u32(settings.repair_symbols_per_second);
        } else if telemetry
            .loss_permille
            .is_some_and(|loss| loss > self.loss_backoff_permille)
        {
            settings.repair_symbols_per_second = increase_by_quarter_u32(
                settings.repair_symbols_per_second.max(1),
                self.limits.max_repair_symbols_per_second,
            );
        }

        settings
    }

    fn grow(self, mut settings: AtpAutotuneSettings) -> AtpAutotuneSettings {
        settings.in_flight_bytes =
            increase_by_eighth(settings.in_flight_bytes, self.limits.max_in_flight_bytes);
        settings.stream_count = settings
            .stream_count
            .saturating_add(1)
            .min(self.limits.max_stream_count);
        settings.chunk_size_bytes =
            increase_by_eighth_u32(settings.chunk_size_bytes, self.limits.max_chunk_size_bytes);
        settings
    }
}

fn decrease_by_quarter(value: u64) -> u64 {
    value.saturating_sub(value / 4).max(1)
}

fn decrease_by_quarter_u32(value: u32) -> u32 {
    value.saturating_sub(value / 4).max(1)
}

fn increase_by_eighth(value: u64, max: u64) -> u64 {
    value.saturating_add(value / 8).min(max)
}

fn increase_by_eighth_u32(value: u32, max: u32) -> u32 {
    value.saturating_add(value / 8).min(max)
}

fn increase_by_quarter_u32(value: u32, max: u32) -> u32 {
    value.saturating_add(value / 4).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_telemetry() -> AtpAutotuneTelemetry {
        AtpAutotuneTelemetry::new("trace-a", "workload-a").with_sample_count(16)
    }

    #[test]
    fn metric_names_are_stable_and_namespaced() {
        let names: Vec<_> = ATP_AUTOTUNE_METRIC_NAMES
            .iter()
            .map(|metric| metric.as_str())
            .collect();

        assert_eq!(names.len(), 14);
        assert!(names.iter().all(|name| name.starts_with("atp.autotune.")));
        assert_eq!(names[0], "atp.autotune.rtt_micros");
        assert_eq!(names[13], "atp.autotune.migration_events");
    }

    #[test]
    fn metric_json_uses_stable_names() -> serde_json::Result<()> {
        let encoded = serde_json::to_string(&AtpAutotuneMetric::LossPermille)?;
        assert_eq!(encoded, r#""atp.autotune.loss_permille""#);

        let decoded: AtpAutotuneMetric = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, AtpAutotuneMetric::LossPermille);
        Ok(())
    }

    #[test]
    fn telemetry_report_collects_stable_metric_samples() -> Result<(), Box<dyn std::error::Error>> {
        let report = AtpAutotuneTelemetryReport::new("trace-report", "workload-report")
            .with_sample_count(16)
            .with_sample(AtpAutotuneMetric::RttMicros, 42_000)
            .with_sample(AtpAutotuneMetric::LossPermille, 7)
            .with_sample(AtpAutotuneMetric::EncodeBacklogSymbols, 128)
            .with_sample(AtpAutotuneMetric::RelayCostMicrosPerMiB, 250_000);

        let encoded = serde_json::to_string(&report)?;
        assert!(encoded.contains("atp.autotune.rtt_micros"));

        let decoded: AtpAutotuneTelemetryReport = serde_json::from_str(&encoded)?;
        let telemetry = decoded.into_telemetry()?;

        assert_eq!(telemetry.trace_id, "trace-report");
        assert_eq!(telemetry.workload_id, "workload-report");
        assert_eq!(telemetry.sample_count, 16);
        assert_eq!(telemetry.rtt_micros, Some(42_000));
        assert_eq!(telemetry.loss_permille, Some(7));
        assert_eq!(telemetry.encode_backlog_symbols, Some(128));
        assert_eq!(telemetry.relay_cost_micros_per_mib, Some(250_000));
        Ok(())
    }

    #[test]
    fn telemetry_report_rejects_out_of_range_metric_samples() {
        let report = AtpAutotuneTelemetryReport::new("trace-report", "workload-report")
            .with_sample(AtpAutotuneMetric::LossPermille, u64::from(u16::MAX) + 1);

        let error = report.into_telemetry();

        assert_eq!(
            error,
            Err(AtpAutotuneTelemetryError::MetricValueOutOfRange {
                metric: AtpAutotuneMetric::LossPermille,
                value: u64::from(u16::MAX) + 1,
                max: u64::from(u16::MAX),
            })
        );
    }

    #[test]
    fn telemetry_window_exports_stable_sample_report_order() {
        let mut telemetry =
            AtpAutotuneTelemetry::new("trace-window", "workload-window").with_sample_count(32);
        telemetry.loss_permille = Some(5);
        telemetry.rtt_micros = Some(40_000);
        telemetry.congestion_window_bytes = Some(64 * 1_048_576);
        telemetry.migration_events = Some(2);

        let report = telemetry.to_report();

        assert_eq!(report.trace_id, "trace-window");
        assert_eq!(report.workload_id, "workload-window");
        assert_eq!(report.sample_count, 32);
        assert_eq!(
            report.samples,
            vec![
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RttMicros, 40_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::LossPermille, 5),
                AtpAutotuneMetricSample::new(
                    AtpAutotuneMetric::CongestionWindowBytes,
                    64 * 1_048_576,
                ),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::MigrationEvents, 2),
            ]
        );
    }

    #[test]
    fn telemetry_window_roundtrips_through_sample_report() -> Result<(), Box<dyn std::error::Error>>
    {
        let telemetry = AtpAutotuneTelemetry {
            trace_id: String::from("trace-roundtrip"),
            workload_id: String::from("workload-roundtrip"),
            sample_count: 16,
            rtt_micros: Some(41_000),
            loss_permille: Some(3),
            pto_micros: Some(125_000),
            congestion_window_bytes: Some(96 * 1_048_576),
            in_flight_bytes: Some(32 * 1_048_576),
            send_buffer_queued_bytes: Some(2 * 1_048_576),
            receive_buffer_queued_bytes: Some(1_048_576),
            disk_read_lag_micros: Some(10_000),
            disk_write_lag_micros: Some(12_000),
            encode_backlog_symbols: Some(128),
            decode_backlog_symbols: Some(64),
            repair_roi_permille: Some(800),
            relay_cost_micros_per_mib: Some(250_000),
            migration_events: Some(1),
        };

        let report = AtpAutotuneTelemetryReport::from_telemetry(&telemetry);

        assert_eq!(report.samples.len(), ATP_AUTOTUNE_METRIC_NAMES.len());
        assert_eq!(
            report.samples[0],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::RttMicros, 41_000)
        );
        assert_eq!(
            report.samples[13],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::MigrationEvents, 1)
        );
        assert_eq!(report.into_telemetry()?, telemetry);
        Ok(())
    }

    #[test]
    fn telemetry_window_zero_sample_count_roundtrip_uses_exported_sample_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut telemetry = AtpAutotuneTelemetry::new("trace-inferred", "workload-inferred");
        telemetry.rtt_micros = Some(25_000);
        telemetry.loss_permille = Some(1);

        let roundtrip = telemetry.to_report().into_telemetry()?;

        assert_eq!(roundtrip.trace_id, telemetry.trace_id);
        assert_eq!(roundtrip.workload_id, telemetry.workload_id);
        assert_eq!(roundtrip.sample_count, 2);
        assert_eq!(roundtrip.rtt_micros, Some(25_000));
        assert_eq!(roundtrip.loss_permille, Some(1));
        Ok(())
    }

    #[test]
    fn healthy_window_grows_conservatively() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let decision = policy.decide(current, &healthy_telemetry());

        assert!(!decision.fail_closed);
        assert_eq!(decision.reason_code, "conservative_growth");
        assert_eq!(
            decision.settings.in_flight_bytes,
            current.in_flight_bytes + current.in_flight_bytes / 8
        );
        assert_eq!(decision.settings.stream_count, current.stream_count + 1);
        assert_eq!(
            decision.settings.chunk_size_bytes,
            current.chunk_size_bytes + current.chunk_size_bytes / 8
        );
        assert_eq!(
            decision.settings.repair_symbols_per_second,
            current.repair_symbols_per_second
        );
    }

    #[test]
    fn insufficient_samples_hold_existing_settings() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let telemetry = AtpAutotuneTelemetry::new("trace-a", "workload-a").with_sample_count(2);
        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert_eq!(decision.settings, current);
        assert_eq!(
            decision.bottlenecks[0].kind,
            AtpBottleneckKind::InsufficientTelemetry
        );
    }

    #[test]
    fn loss_backs_off_transport_and_raises_repair_rate() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::NetworkLoss)
        );
        assert!(decision.settings.in_flight_bytes < current.in_flight_bytes);
        assert_eq!(decision.settings.stream_count, current.stream_count - 1);
        assert!(decision.settings.repair_symbols_per_second > current.repair_symbols_per_second);
    }

    #[test]
    fn low_repair_roi_reduces_repair_rate_without_transport_backoff() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.repair_roi_permille = Some(100);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert_eq!(decision.settings.in_flight_bytes, current.in_flight_bytes);
        assert_eq!(decision.settings.stream_count, current.stream_count);
        assert!(decision.settings.repair_symbols_per_second < current.repair_symbols_per_second);
    }

    #[test]
    fn buffer_and_disk_pressure_reduce_different_knobs() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.send_buffer_queued_bytes = Some(policy.buffer_pressure_bytes + 1);
        telemetry.disk_write_lag_micros = Some(policy.disk_lag_micros + 1);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(decision.settings.in_flight_bytes < current.in_flight_bytes);
        assert!(decision.settings.chunk_size_bytes < current.chunk_size_bytes);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::SendBufferPressure)
        );
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::DiskWriteLag)
        );
    }

    #[test]
    fn empty_ids_fail_closed() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let telemetry = AtpAutotuneTelemetry::new("", " ").with_sample_count(16);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::ContradictoryTelemetry)
        );
    }

    #[test]
    fn limits_are_enforced_on_growth_and_backoff() {
        let policy = AtpAutotunePolicy {
            limits: AtpAutotuneLimits {
                min_in_flight_bytes: 4,
                max_in_flight_bytes: 10,
                min_stream_count: 2,
                max_stream_count: 3,
                min_chunk_size_bytes: 8,
                max_chunk_size_bytes: 12,
                min_repair_symbols_per_second: 2,
                max_repair_symbols_per_second: 4,
            },
            ..AtpAutotunePolicy::default()
        };
        let current = AtpAutotuneSettings::new(100, 99, 100, 99);
        let decision = policy.decide(current, &healthy_telemetry());

        assert_eq!(decision.settings.in_flight_bytes, 10);
        assert_eq!(decision.settings.stream_count, 3);
        assert_eq!(decision.settings.chunk_size_bytes, 12);
        assert_eq!(decision.settings.repair_symbols_per_second, 4);
    }
}
