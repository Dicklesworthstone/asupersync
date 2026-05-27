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

/// Runtime pressure observations for one ATP transfer decision window.
///
/// Transfer code can fill this snapshot from path, disk, CPU, repair, and relay
/// counters without depending directly on the policy implementation. The
/// snapshot then exports stable metric names through
/// [`AtpAutotuneTelemetryReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpTransferPressureSnapshot {
    /// Stable trace id linking every sample to path/proof logs.
    pub trace_id: String,
    /// Stable transfer or workload id.
    pub transfer_id: String,
    /// Samples represented by this snapshot.
    pub sample_count: u32,
    /// Smoothed round-trip time in microseconds.
    pub rtt_micros: Option<u64>,
    /// Observed loss rate in packets per thousand.
    pub loss_permille: Option<u16>,
    /// Probe timeout in microseconds.
    pub pto_micros: Option<u64>,
    /// Congestion window in bytes.
    pub congestion_window_bytes: Option<u64>,
    /// Bytes currently in flight.
    pub in_flight_bytes: Option<u64>,
    /// Bytes queued in the send buffer.
    pub send_buffer_queued_bytes: Option<u64>,
    /// Bytes queued in the receive buffer.
    pub receive_buffer_queued_bytes: Option<u64>,
    /// Disk read lag in microseconds.
    pub disk_read_lag_micros: Option<u64>,
    /// Disk write lag in microseconds.
    pub disk_write_lag_micros: Option<u64>,
    /// Pending encoder work in symbols.
    pub encode_backlog_symbols: Option<u32>,
    /// Pending decoder work in symbols.
    pub decode_backlog_symbols: Option<u32>,
    /// Repair symbols sent during this window.
    pub repair_symbols_sent: Option<u32>,
    /// Repair symbols that helped decoding during this window.
    pub useful_repair_symbols: Option<u32>,
    /// Relay path cost observed during this window.
    pub relay_cost_micros: Option<u64>,
    /// Payload bytes forwarded through the relay during this window.
    pub relay_bytes: Option<u64>,
    /// Number of path migration events in the current decision window.
    pub migration_events: Option<u32>,
}

impl AtpTransferPressureSnapshot {
    /// Create an empty pressure snapshot for one transfer.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, transfer_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            transfer_id: transfer_id.into(),
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
            repair_symbols_sent: None,
            useful_repair_symbols: None,
            relay_cost_micros: None,
            relay_bytes: None,
            migration_events: None,
        }
    }

    /// Set the represented sample count.
    #[must_use]
    pub const fn with_sample_count(mut self, sample_count: u32) -> Self {
        self.sample_count = sample_count;
        self
    }

    /// Derived repair ROI in useful repair symbols per thousand sent symbols.
    #[must_use]
    pub fn repair_roi_permille(&self) -> Option<u16> {
        let sent = self.repair_symbols_sent?;
        if sent == 0 {
            return None;
        }
        let useful = u64::from(self.useful_repair_symbols.unwrap_or(0));
        let roi = useful.saturating_mul(1_000) / u64::from(sent);
        Some(roi.min(u64::from(u16::MAX)) as u16)
    }

    /// Derived relay cost in microseconds per MiB.
    #[must_use]
    pub fn relay_cost_micros_per_mib(&self) -> Option<u64> {
        let bytes = self.relay_bytes?;
        if bytes == 0 {
            return None;
        }
        let cost = self.relay_cost_micros?;
        Some(cost.saturating_mul(1_048_576) / bytes)
    }

    /// Export this snapshot as stable metric samples.
    #[must_use]
    pub fn to_report(&self) -> AtpAutotuneTelemetryReport {
        let mut report =
            AtpAutotuneTelemetryReport::new(self.trace_id.clone(), self.transfer_id.clone())
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
        if let Some(value) = self.repair_roi_permille() {
            report = report.with_sample(AtpAutotuneMetric::RepairRoiPermille, u64::from(value));
        }
        if let Some(value) = self.relay_cost_micros_per_mib() {
            report = report.with_sample(AtpAutotuneMetric::RelayCostMicrosPerMiB, value);
        }
        if let Some(value) = self.migration_events {
            report = report.with_sample(AtpAutotuneMetric::MigrationEvents, u64::from(value));
        }

        report
    }

    /// Aggregate this snapshot into one autotune decision window.
    pub fn into_telemetry(self) -> Result<AtpAutotuneTelemetry, AtpAutotuneTelemetryError> {
        self.to_report().into_telemetry()
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

/// Repair path surface available for a coordinator decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpRepairPathMode {
    /// Direct retransmit or parity repair can use the primary path.
    Direct,
    /// Only a relay path is currently admissible.
    RelayOnly,
    /// Both direct and relay repair paths are currently admissible.
    DirectAndRelay,
}

impl AtpRepairPathMode {
    /// Return the stable path-mode name used in status and proof output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::RelayOnly => "relay_only",
            Self::DirectAndRelay => "direct_and_relay",
        }
    }

    const fn relay_available(self) -> bool {
        matches!(self, Self::RelayOnly | Self::DirectAndRelay)
    }
}

/// Repair action selected by [`AtpRepairCoordinator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpRepairAction {
    /// Avoid repair overhead and rely on the normal transfer path.
    NoRepair,
    /// Request the missing bytes through exact retransmission.
    ExactRetransmit,
    /// Send low-rate parity symbols while the transfer continues.
    ParityTrickle,
    /// Send a bounded burst of parity symbols to recover a lossy tail quickly.
    BurstRepair,
    /// Use multiple admitted peers for repair symbols.
    MultiPeerRepair,
    /// Use only the relay path for repair traffic.
    RelayOnlyRepair,
}

impl AtpRepairAction {
    /// Return the stable action name used in status and proof output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRepair => "no_repair",
            Self::ExactRetransmit => "exact_retransmit",
            Self::ParityTrickle => "parity_trickle",
            Self::BurstRepair => "burst_repair",
            Self::MultiPeerRepair => "multi_peer_repair",
            Self::RelayOnlyRepair => "relay_only_repair",
        }
    }
}

/// Practical repair mode selected by the repair coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpRepairMode {
    /// Repair is disabled for this decision.
    Off,
    /// Sparse tail chunks should be repaired directly.
    Tail,
    /// Lossy paths should use parity before exact retransmit chatter grows.
    Lossy,
    /// Resume after disconnect should prioritize known missing ranges.
    ResumeRepair,
    /// Relay cost is high, so repair should minimize relay bytes.
    RelayExpensive,
    /// Path churn is high, so repair should favor robust progress.
    MobileUnstable,
    /// High-RTT/high-BDP paths should use steady parity to hide long feedback loops.
    SatelliteHighBdp,
    /// Broadcast fanout is available and useful.
    Broadcast,
    /// Multi-source peer repair is available and useful.
    Swarm,
}

impl AtpRepairMode {
    /// Return the stable mode name used in status and proof output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Tail => "tail",
            Self::Lossy => "lossy",
            Self::ResumeRepair => "resume_repair",
            Self::RelayExpensive => "relay_expensive",
            Self::MobileUnstable => "mobile_unstable",
            Self::SatelliteHighBdp => "satellite_high_bdp",
            Self::Broadcast => "broadcast",
            Self::Swarm => "swarm",
        }
    }
}

/// Input vector for deterministic repair ROI decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpRepairRoiInputs {
    /// Stable trace id linking this decision to path/proof logs.
    pub trace_id: String,
    /// Stable workload or transfer id.
    pub workload_id: String,
    /// Expected wall-clock time saved by repair.
    pub expected_time_saved_micros: u64,
    /// Encoder CPU cost expected for the repair symbols.
    pub encode_cpu_micros: u64,
    /// Decoder CPU cost expected for the repair symbols.
    pub decode_cpu_micros: u64,
    /// Additional bytes expected for repair traffic.
    pub bandwidth_overhead_bytes: u64,
    /// Memory pressure in permille, where 1000 is saturated.
    pub memory_pressure_permille: u16,
    /// Stream contention in permille, where 1000 is saturated.
    pub stream_contention_permille: u16,
    /// Relay cost in microseconds per MiB.
    pub relay_cost_micros_per_mib: u64,
    /// Path stability in permille, where 1000 is stable.
    pub path_stability_permille: u16,
    /// Value of resume/tail recovery in permille.
    pub resume_value_permille: u16,
    /// Observed loss in packets per thousand.
    pub loss_permille: u16,
    /// Number of admitted repair peers available for this transfer.
    pub available_peer_count: u16,
    /// Repair path surface currently available.
    pub path_mode: AtpRepairPathMode,
    /// Optional operator-selected mode. Budget gates still apply.
    pub requested_mode: Option<AtpRepairMode>,
    /// Sparse missing chunks near the transfer tail.
    pub missing_tail_chunks: u16,
    /// Smoothed path RTT.
    pub rtt_micros: u64,
    /// Path migrations observed during the telemetry window.
    pub path_migration_events: u16,
    /// Peers available for broadcast-style repair fanout.
    pub broadcast_peer_count: u16,
}

impl AtpRepairRoiInputs {
    /// Build conservative coordinator inputs from an autotune telemetry window.
    #[must_use]
    pub fn from_autotune_telemetry(telemetry: &AtpAutotuneTelemetry) -> Self {
        let loss_permille = telemetry.loss_permille.unwrap_or(0);
        let rtt_micros = telemetry.rtt_micros.unwrap_or(0);
        let pto_micros = telemetry
            .pto_micros
            .unwrap_or_else(|| rtt_micros.saturating_mul(2));
        let migration_events = telemetry.migration_events.unwrap_or(0);
        let loss_wait = permille_of(pto_micros, loss_permille);
        let migration_wait = rtt_micros.saturating_mul(u64::from(migration_events));
        let repair_roi = telemetry.repair_roi_permille.unwrap_or(0);
        let expected_time_saved_micros = loss_wait
            .max(migration_wait)
            .saturating_add(permille_of(rtt_micros, repair_roi.min(1_000)));
        let encode_cpu_micros = u64::from(telemetry.encode_backlog_symbols.unwrap_or(0)) * 32;
        let decode_cpu_micros = u64::from(telemetry.decode_backlog_symbols.unwrap_or(0)) * 48;
        let bandwidth_overhead_bytes = u64::from(loss_permille)
            .saturating_mul(16 * 1_024)
            .min(4 * 1_048_576);
        let queued_bytes = telemetry
            .send_buffer_queued_bytes
            .unwrap_or(0)
            .saturating_add(telemetry.receive_buffer_queued_bytes.unwrap_or(0));
        let memory_pressure_permille = ratio_permille(queued_bytes, 64 * 1_048_576);
        let stream_contention_permille =
            match (telemetry.in_flight_bytes, telemetry.congestion_window_bytes) {
                (Some(in_flight), Some(cwnd)) => ratio_permille(in_flight, cwnd),
                _ => 0,
            };
        let instability = u64::from(loss_permille)
            .saturating_mul(4)
            .saturating_add(u64::from(migration_events).saturating_mul(250))
            .min(1_000);
        let path_stability_permille = u16::try_from(1_000 - instability).unwrap_or(0);
        let resume_value_permille = repair_roi
            .max(if telemetry.decode_backlog_symbols.unwrap_or(0) > 0 {
                400
            } else {
                0
            })
            .min(1_000);
        let path_mode = if migration_events > 0 {
            AtpRepairPathMode::DirectAndRelay
        } else {
            AtpRepairPathMode::Direct
        };
        let missing_tail_chunks =
            u16::try_from(telemetry.decode_backlog_symbols.unwrap_or(0)).unwrap_or(u16::MAX);
        let path_migration_events = u16::try_from(migration_events).unwrap_or(u16::MAX);

        Self {
            trace_id: telemetry.trace_id.clone(),
            workload_id: telemetry.workload_id.clone(),
            expected_time_saved_micros,
            encode_cpu_micros,
            decode_cpu_micros,
            bandwidth_overhead_bytes,
            memory_pressure_permille,
            stream_contention_permille,
            relay_cost_micros_per_mib: telemetry.relay_cost_micros_per_mib.unwrap_or(u64::MAX),
            path_stability_permille,
            resume_value_permille,
            loss_permille,
            available_peer_count: 1,
            path_mode,
            requested_mode: None,
            missing_tail_chunks,
            rtt_micros,
            path_migration_events,
            broadcast_peer_count: 0,
        }
    }
}

/// Factor class recorded for an explainable repair decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpRepairDecisionFactorKind {
    /// Net ROI after cost accounting.
    NetRoi,
    /// Memory pressure cost gate.
    MemoryPressure,
    /// Stream contention cost gate.
    StreamContention,
    /// Relay path cost gate.
    RelayCost,
    /// Primary path stability gate.
    PathStability,
    /// Resume/tail value signal.
    ResumeValue,
    /// Loss signal.
    Loss,
    /// Peer diversity signal.
    PeerDiversity,
    /// Repair path mode signal.
    PathMode,
    /// Selected repair mode signal.
    RepairMode,
}

impl AtpRepairDecisionFactorKind {
    /// Return the stable factor name used in status and proof output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetRoi => "net_roi",
            Self::MemoryPressure => "memory_pressure",
            Self::StreamContention => "stream_contention",
            Self::RelayCost => "relay_cost",
            Self::PathStability => "path_stability",
            Self::ResumeValue => "resume_value",
            Self::Loss => "loss",
            Self::PeerDiversity => "peer_diversity",
            Self::PathMode => "path_mode",
            Self::RepairMode => "repair_mode",
        }
    }
}

/// Directional effect of one repair decision factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpRepairDecisionFactorEffect {
    /// The factor supports enabling repair.
    SupportsRepair,
    /// The factor blocks repair or selects a fail-closed path.
    BlocksRepair,
    /// The factor contributes cost but does not independently block repair.
    Cost,
}

impl AtpRepairDecisionFactorEffect {
    /// Return the stable effect name used in status and proof output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SupportsRepair => "supports_repair",
            Self::BlocksRepair => "blocks_repair",
            Self::Cost => "cost",
        }
    }
}

/// One traceable factor in a repair coordinator decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpRepairDecisionFactor {
    /// Factor class.
    pub kind: AtpRepairDecisionFactorKind,
    /// Observed value for the factor.
    pub observed: u64,
    /// Policy threshold used for the factor.
    pub threshold: u64,
    /// Directional effect on the decision.
    pub effect: AtpRepairDecisionFactorEffect,
}

impl AtpRepairDecisionFactor {
    const fn new(
        kind: AtpRepairDecisionFactorKind,
        observed: u64,
        threshold: u64,
        effect: AtpRepairDecisionFactorEffect,
    ) -> Self {
        Self {
            kind,
            observed,
            threshold,
            effect,
        }
    }
}

/// Deterministic, explainable repair coordinator decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpRepairCoordinatorDecision {
    /// Selected repair mode.
    pub mode: AtpRepairMode,
    /// Selected repair action.
    pub action: AtpRepairAction,
    /// Stable mode activation reason suitable for proof artifacts.
    pub mode_reason_code: String,
    /// Cooldown before the same mode should reactivate after deactivation.
    pub mode_cooldown_micros: u64,
    /// Stable reason suitable for logs and proof artifacts.
    pub reason_code: String,
    /// Whether the coordinator avoided repair because a conservative gate fired.
    pub fail_closed: bool,
    /// Expected gross benefit before cost accounting.
    pub gross_benefit_micros: u64,
    /// Total modeled repair cost.
    pub total_cost_micros: u64,
    /// Net ROI after subtracting modeled costs from gross benefit.
    pub net_roi_micros: i64,
    /// Traceable decision factors in stable order.
    pub factors: Vec<AtpRepairDecisionFactor>,
}

impl AtpRepairCoordinatorDecision {
    /// Build stable human status lines for `atp status --explain`.
    #[must_use]
    pub fn human_summary_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Repair mode: {}", self.mode.as_str()),
            format!("Repair action: {}", self.action.as_str()),
            format!("Repair mode reason: {}", self.mode_reason_code),
            format!("Repair mode cooldown micros: {}", self.mode_cooldown_micros),
            format!("Repair reason: {}", self.reason_code),
            format!("Repair fail closed: {}", self.fail_closed),
            format!(
                "Repair ROI: gross_benefit_micros={}, total_cost_micros={}, net_roi_micros={}",
                self.gross_benefit_micros, self.total_cost_micros, self.net_roi_micros
            ),
        ];
        for factor in &self.factors {
            lines.push(format!(
                "- repair {}: effect={}, observed={}, threshold={}",
                factor.kind.as_str(),
                factor.effect.as_str(),
                factor.observed,
                factor.threshold
            ));
        }
        lines
    }
}

/// Conservative thresholds for repair ROI coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpRepairCoordinatorPolicy {
    /// Minimum net ROI required before any repair action is enabled.
    pub min_positive_roi_micros: u64,
    /// Minimum net ROI for parity trickle.
    pub parity_trickle_min_roi_micros: u64,
    /// Minimum net ROI for burst repair.
    pub burst_repair_min_roi_micros: u64,
    /// Minimum net ROI for multi-peer repair.
    pub multi_peer_min_roi_micros: u64,
    /// Default direct bandwidth cost in microseconds per MiB.
    pub bandwidth_cost_micros_per_mib: u64,
    /// Maximum relay cost accepted for relay-only repair.
    pub max_relay_cost_micros_per_mib: u64,
    /// Memory pressure that blocks repair unless resume value is high.
    pub high_memory_pressure_permille: u16,
    /// Stream contention that blocks repair unless resume value is high.
    pub high_stream_contention_permille: u16,
    /// Path stability below this threshold prefers relay-only repair when cheap.
    pub unstable_path_permille: u16,
    /// Loss threshold for parity trickle.
    pub parity_loss_permille: u16,
    /// Loss threshold for burst repair.
    pub burst_loss_permille: u16,
    /// Minimum peers for multi-peer repair.
    pub multi_peer_min_peers: u16,
    /// Resume value that can override local pressure gates.
    pub resume_value_floor_permille: u16,
    /// Minimum missing tail chunks for tail repair mode.
    pub tail_min_missing_chunks: u16,
    /// Minimum RTT for satellite/high-BDP repair mode.
    pub satellite_high_bdp_min_rtt_micros: u64,
    /// Path migrations that activate mobile-unstable repair mode.
    pub mobile_unstable_min_migrations: u16,
    /// Broadcast peers required for broadcast repair mode.
    pub broadcast_min_peers: u16,
    /// Cooldown for tail repair mode.
    pub tail_cooldown_micros: u64,
    /// Cooldown for lossy repair mode.
    pub lossy_cooldown_micros: u64,
    /// Cooldown for resume repair mode.
    pub resume_cooldown_micros: u64,
    /// Cooldown for relay-expensive repair mode.
    pub relay_expensive_cooldown_micros: u64,
    /// Cooldown for mobile-unstable repair mode.
    pub mobile_unstable_cooldown_micros: u64,
    /// Cooldown for satellite/high-BDP repair mode.
    pub satellite_high_bdp_cooldown_micros: u64,
    /// Cooldown for broadcast repair mode.
    pub broadcast_cooldown_micros: u64,
    /// Cooldown for swarm repair mode.
    pub swarm_cooldown_micros: u64,
}

impl Default for AtpRepairCoordinatorPolicy {
    fn default() -> Self {
        Self {
            min_positive_roi_micros: 50_000,
            parity_trickle_min_roi_micros: 150_000,
            burst_repair_min_roi_micros: 1_000_000,
            multi_peer_min_roi_micros: 1_500_000,
            bandwidth_cost_micros_per_mib: 30_000,
            max_relay_cost_micros_per_mib: 500_000,
            high_memory_pressure_permille: 850,
            high_stream_contention_permille: 900,
            unstable_path_permille: 500,
            parity_loss_permille: 10,
            burst_loss_permille: 80,
            multi_peer_min_peers: 2,
            resume_value_floor_permille: 600,
            tail_min_missing_chunks: 1,
            satellite_high_bdp_min_rtt_micros: 500_000,
            mobile_unstable_min_migrations: 1,
            broadcast_min_peers: 8,
            tail_cooldown_micros: 100_000,
            lossy_cooldown_micros: 250_000,
            resume_cooldown_micros: 200_000,
            relay_expensive_cooldown_micros: 500_000,
            mobile_unstable_cooldown_micros: 750_000,
            satellite_high_bdp_cooldown_micros: 1_000_000,
            broadcast_cooldown_micros: 1_000_000,
            swarm_cooldown_micros: 500_000,
        }
    }
}

/// Deterministic repair ROI coordinator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpRepairCoordinator {
    /// Policy thresholds used by the coordinator.
    pub policy: AtpRepairCoordinatorPolicy,
}

impl AtpRepairCoordinator {
    /// Create a coordinator with explicit policy thresholds.
    #[must_use]
    pub const fn new(policy: AtpRepairCoordinatorPolicy) -> Self {
        Self { policy }
    }

    /// Decide the repair action for one traceable input vector.
    #[must_use]
    pub fn decide(self, inputs: &AtpRepairRoiInputs) -> AtpRepairCoordinatorDecision {
        let gross_benefit_micros = inputs
            .expected_time_saved_micros
            .saturating_add(permille_of(
                inputs.expected_time_saved_micros,
                inputs.resume_value_permille,
            ));
        let bandwidth_cost_micros = mul_div_u64(
            inputs.bandwidth_overhead_bytes,
            self.policy.bandwidth_cost_micros_per_mib,
            1_048_576,
        );
        let memory_cost_micros = permille_of(gross_benefit_micros, inputs.memory_pressure_permille);
        let stream_cost_micros =
            permille_of(gross_benefit_micros, inputs.stream_contention_permille);
        let total_cost_micros = inputs
            .encode_cpu_micros
            .saturating_add(inputs.decode_cpu_micros)
            .saturating_add(bandwidth_cost_micros)
            .saturating_add(memory_cost_micros)
            .saturating_add(stream_cost_micros);
        let net_roi_micros = signed_diff_to_i64(gross_benefit_micros, total_cost_micros);
        let mut factors = self.base_factors(inputs, net_roi_micros);

        if inputs.memory_pressure_permille >= self.policy.high_memory_pressure_permille
            && inputs.resume_value_permille < self.policy.resume_value_floor_permille
        {
            factors.push(AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::MemoryPressure,
                u64::from(inputs.memory_pressure_permille),
                u64::from(self.policy.high_memory_pressure_permille),
                AtpRepairDecisionFactorEffect::BlocksRepair,
            ));
            return build_repair_decision(
                AtpRepairMode::Off,
                AtpRepairAction::NoRepair,
                "repair_mode_blocked_by_memory_pressure",
                0,
                "blocked_by_memory_pressure",
                true,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        if inputs.stream_contention_permille >= self.policy.high_stream_contention_permille
            && inputs.resume_value_permille < self.policy.resume_value_floor_permille
        {
            factors.push(AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::StreamContention,
                u64::from(inputs.stream_contention_permille),
                u64::from(self.policy.high_stream_contention_permille),
                AtpRepairDecisionFactorEffect::BlocksRepair,
            ));
            return build_repair_decision(
                AtpRepairMode::Off,
                AtpRepairAction::NoRepair,
                "repair_mode_blocked_by_stream_contention",
                0,
                "blocked_by_stream_contention",
                true,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        if net_roi_micros < i64_from_u64(self.policy.min_positive_roi_micros) {
            return build_repair_decision(
                AtpRepairMode::Off,
                AtpRepairAction::NoRepair,
                "repair_mode_roi_not_positive",
                0,
                "repair_roi_not_positive",
                true,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        let relay_viable = inputs.path_mode.relay_available()
            && inputs.relay_cost_micros_per_mib <= self.policy.max_relay_cost_micros_per_mib;
        if let Some(requested_mode) = inputs.requested_mode {
            let action = self.action_for_manual_mode(requested_mode, inputs, relay_viable);
            factors.push(AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::RepairMode,
                repair_mode_rank(requested_mode),
                repair_mode_rank(requested_mode),
                AtpRepairDecisionFactorEffect::SupportsRepair,
            ));
            return build_repair_decision(
                requested_mode,
                action,
                "manual_repair_mode_requested",
                self.mode_cooldown_micros(requested_mode),
                Self::reason_for_action(action, requested_mode),
                false,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        if matches!(inputs.path_mode, AtpRepairPathMode::RelayOnly)
            || (relay_viable && inputs.path_stability_permille < self.policy.unstable_path_permille)
        {
            let (action, reason, fail_closed) = if relay_viable {
                (
                    AtpRepairAction::RelayOnlyRepair,
                    "relay_only_repair_roi_positive",
                    false,
                )
            } else {
                (AtpRepairAction::NoRepair, "relay_cost_not_viable", true)
            };
            let (mode, mode_reason) = if fail_closed {
                (AtpRepairMode::Off, "repair_mode_relay_cost_not_viable")
            } else {
                (
                    AtpRepairMode::MobileUnstable,
                    "auto_mobile_unstable_path_churn",
                )
            };
            return build_repair_decision(
                mode,
                action,
                mode_reason,
                self.mode_cooldown_micros(mode),
                reason,
                fail_closed,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        if inputs.available_peer_count >= self.policy.multi_peer_min_peers
            && net_roi_micros >= i64_from_u64(self.policy.multi_peer_min_roi_micros)
            && inputs.loss_permille >= self.policy.burst_loss_permille
        {
            return build_repair_decision(
                AtpRepairMode::Swarm,
                AtpRepairAction::MultiPeerRepair,
                "auto_swarm_high_loss_peer_diversity",
                self.mode_cooldown_micros(AtpRepairMode::Swarm),
                "multi_peer_repair_roi_positive",
                false,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        if inputs.loss_permille >= self.policy.burst_loss_permille
            && net_roi_micros >= i64_from_u64(self.policy.burst_repair_min_roi_micros)
        {
            return build_repair_decision(
                AtpRepairMode::Lossy,
                AtpRepairAction::BurstRepair,
                "auto_lossy_burst_loss",
                self.mode_cooldown_micros(AtpRepairMode::Lossy),
                "burst_repair_roi_positive",
                false,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        let (mode, mode_reason) = self.select_auto_mode(inputs);
        if (inputs.loss_permille >= self.policy.parity_loss_permille
            || inputs.resume_value_permille >= self.policy.resume_value_floor_permille)
            && net_roi_micros >= i64_from_u64(self.policy.parity_trickle_min_roi_micros)
        {
            return build_repair_decision(
                mode,
                AtpRepairAction::ParityTrickle,
                mode_reason,
                self.mode_cooldown_micros(mode),
                "parity_trickle_roi_positive",
                false,
                gross_benefit_micros,
                total_cost_micros,
                net_roi_micros,
                factors,
            );
        }

        build_repair_decision(
            mode,
            AtpRepairAction::ExactRetransmit,
            mode_reason,
            self.mode_cooldown_micros(mode),
            "exact_retransmit_roi_positive",
            false,
            gross_benefit_micros,
            total_cost_micros,
            net_roi_micros,
            factors,
        )
    }

    fn base_factors(
        self,
        inputs: &AtpRepairRoiInputs,
        net_roi_micros: i64,
    ) -> Vec<AtpRepairDecisionFactor> {
        vec![
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::NetRoi,
                u64_from_nonnegative_i64(net_roi_micros),
                self.policy.min_positive_roi_micros,
                if net_roi_micros >= i64_from_u64(self.policy.min_positive_roi_micros) {
                    AtpRepairDecisionFactorEffect::SupportsRepair
                } else {
                    AtpRepairDecisionFactorEffect::BlocksRepair
                },
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::MemoryPressure,
                u64::from(inputs.memory_pressure_permille),
                u64::from(self.policy.high_memory_pressure_permille),
                AtpRepairDecisionFactorEffect::Cost,
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::StreamContention,
                u64::from(inputs.stream_contention_permille),
                u64::from(self.policy.high_stream_contention_permille),
                AtpRepairDecisionFactorEffect::Cost,
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::RelayCost,
                inputs.relay_cost_micros_per_mib,
                self.policy.max_relay_cost_micros_per_mib,
                if inputs.path_mode.relay_available()
                    && inputs.relay_cost_micros_per_mib <= self.policy.max_relay_cost_micros_per_mib
                {
                    AtpRepairDecisionFactorEffect::SupportsRepair
                } else {
                    AtpRepairDecisionFactorEffect::Cost
                },
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::PathStability,
                u64::from(inputs.path_stability_permille),
                u64::from(self.policy.unstable_path_permille),
                if inputs.path_stability_permille < self.policy.unstable_path_permille {
                    AtpRepairDecisionFactorEffect::BlocksRepair
                } else {
                    AtpRepairDecisionFactorEffect::SupportsRepair
                },
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::ResumeValue,
                u64::from(inputs.resume_value_permille),
                u64::from(self.policy.resume_value_floor_permille),
                if inputs.resume_value_permille >= self.policy.resume_value_floor_permille {
                    AtpRepairDecisionFactorEffect::SupportsRepair
                } else {
                    AtpRepairDecisionFactorEffect::Cost
                },
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::Loss,
                u64::from(inputs.loss_permille),
                u64::from(self.policy.parity_loss_permille),
                if inputs.loss_permille >= self.policy.parity_loss_permille {
                    AtpRepairDecisionFactorEffect::SupportsRepair
                } else {
                    AtpRepairDecisionFactorEffect::Cost
                },
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::PeerDiversity,
                u64::from(inputs.available_peer_count),
                u64::from(self.policy.multi_peer_min_peers),
                if inputs.available_peer_count >= self.policy.multi_peer_min_peers {
                    AtpRepairDecisionFactorEffect::SupportsRepair
                } else {
                    AtpRepairDecisionFactorEffect::Cost
                },
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::PathMode,
                path_mode_rank(inputs.path_mode),
                path_mode_rank(AtpRepairPathMode::DirectAndRelay),
                AtpRepairDecisionFactorEffect::Cost,
            ),
            AtpRepairDecisionFactor::new(
                AtpRepairDecisionFactorKind::RepairMode,
                0,
                repair_mode_rank(AtpRepairMode::Swarm),
                AtpRepairDecisionFactorEffect::Cost,
            ),
        ]
    }

    fn select_auto_mode(self, inputs: &AtpRepairRoiInputs) -> (AtpRepairMode, &'static str) {
        if inputs.broadcast_peer_count >= self.policy.broadcast_min_peers {
            return (AtpRepairMode::Broadcast, "auto_broadcast_peer_fanout");
        }
        if inputs.available_peer_count >= self.policy.multi_peer_min_peers
            && inputs.loss_permille >= self.policy.burst_loss_permille
        {
            return (AtpRepairMode::Swarm, "auto_swarm_peer_diversity");
        }
        if inputs.path_migration_events >= self.policy.mobile_unstable_min_migrations
            || inputs.path_stability_permille < self.policy.unstable_path_permille
        {
            return (
                AtpRepairMode::MobileUnstable,
                "auto_mobile_unstable_path_churn",
            );
        }
        if inputs.path_mode.relay_available()
            && inputs.relay_cost_micros_per_mib > self.policy.max_relay_cost_micros_per_mib
        {
            return (
                AtpRepairMode::RelayExpensive,
                "auto_relay_expensive_cost_gate",
            );
        }
        if inputs.resume_value_permille >= self.policy.resume_value_floor_permille {
            return (AtpRepairMode::ResumeRepair, "auto_resume_value");
        }
        if inputs.rtt_micros >= self.policy.satellite_high_bdp_min_rtt_micros {
            return (
                AtpRepairMode::SatelliteHighBdp,
                "auto_satellite_high_bdp_rtt",
            );
        }
        if inputs.missing_tail_chunks >= self.policy.tail_min_missing_chunks {
            return (AtpRepairMode::Tail, "auto_tail_missing_chunks");
        }
        if inputs.loss_permille >= self.policy.parity_loss_permille {
            return (AtpRepairMode::Lossy, "auto_lossy_packet_loss");
        }
        (AtpRepairMode::Tail, "auto_tail_exact_retransmit")
    }

    fn action_for_manual_mode(
        self,
        mode: AtpRepairMode,
        inputs: &AtpRepairRoiInputs,
        relay_viable: bool,
    ) -> AtpRepairAction {
        match mode {
            AtpRepairMode::Off => AtpRepairAction::NoRepair,
            AtpRepairMode::Tail | AtpRepairMode::RelayExpensive => AtpRepairAction::ExactRetransmit,
            AtpRepairMode::Lossy | AtpRepairMode::SatelliteHighBdp => {
                if inputs.loss_permille >= self.policy.burst_loss_permille {
                    AtpRepairAction::BurstRepair
                } else {
                    AtpRepairAction::ParityTrickle
                }
            }
            AtpRepairMode::ResumeRepair => AtpRepairAction::ParityTrickle,
            AtpRepairMode::MobileUnstable => {
                if relay_viable {
                    AtpRepairAction::RelayOnlyRepair
                } else {
                    AtpRepairAction::BurstRepair
                }
            }
            AtpRepairMode::Broadcast | AtpRepairMode::Swarm => AtpRepairAction::MultiPeerRepair,
        }
    }

    const fn mode_cooldown_micros(self, mode: AtpRepairMode) -> u64 {
        match mode {
            AtpRepairMode::Off => 0,
            AtpRepairMode::Tail => self.policy.tail_cooldown_micros,
            AtpRepairMode::Lossy => self.policy.lossy_cooldown_micros,
            AtpRepairMode::ResumeRepair => self.policy.resume_cooldown_micros,
            AtpRepairMode::RelayExpensive => self.policy.relay_expensive_cooldown_micros,
            AtpRepairMode::MobileUnstable => self.policy.mobile_unstable_cooldown_micros,
            AtpRepairMode::SatelliteHighBdp => self.policy.satellite_high_bdp_cooldown_micros,
            AtpRepairMode::Broadcast => self.policy.broadcast_cooldown_micros,
            AtpRepairMode::Swarm => self.policy.swarm_cooldown_micros,
        }
    }

    const fn reason_for_action(action: AtpRepairAction, mode: AtpRepairMode) -> &'static str {
        match (action, mode) {
            (AtpRepairAction::NoRepair, _) => "manual_repair_mode_off",
            (AtpRepairAction::ExactRetransmit, AtpRepairMode::RelayExpensive) => {
                "manual_relay_expensive_exact_retransmit"
            }
            (AtpRepairAction::ExactRetransmit, _) => "manual_tail_exact_retransmit",
            (AtpRepairAction::ParityTrickle, AtpRepairMode::ResumeRepair) => {
                "manual_resume_parity_trickle"
            }
            (AtpRepairAction::ParityTrickle, _) => "manual_parity_trickle",
            (AtpRepairAction::BurstRepair, AtpRepairMode::MobileUnstable) => {
                "manual_mobile_unstable_burst_repair"
            }
            (AtpRepairAction::BurstRepair, _) => "manual_burst_repair",
            (AtpRepairAction::MultiPeerRepair, AtpRepairMode::Broadcast) => {
                "manual_broadcast_repair"
            }
            (AtpRepairAction::MultiPeerRepair, _) => "manual_swarm_repair",
            (AtpRepairAction::RelayOnlyRepair, _) => "manual_relay_only_repair",
        }
    }
}

fn build_repair_decision(
    mode: AtpRepairMode,
    action: AtpRepairAction,
    mode_reason_code: &str,
    mode_cooldown_micros: u64,
    reason_code: &str,
    fail_closed: bool,
    gross_benefit_micros: u64,
    total_cost_micros: u64,
    net_roi_micros: i64,
    factors: Vec<AtpRepairDecisionFactor>,
) -> AtpRepairCoordinatorDecision {
    AtpRepairCoordinatorDecision {
        mode,
        action,
        mode_reason_code: mode_reason_code.to_string(),
        mode_cooldown_micros,
        reason_code: reason_code.to_string(),
        fail_closed,
        gross_benefit_micros,
        total_cost_micros,
        net_roi_micros,
        factors,
    }
}

fn repair_mode_rank(mode: AtpRepairMode) -> u64 {
    match mode {
        AtpRepairMode::Off => 0,
        AtpRepairMode::Tail => 1,
        AtpRepairMode::Lossy => 2,
        AtpRepairMode::ResumeRepair => 3,
        AtpRepairMode::RelayExpensive => 4,
        AtpRepairMode::MobileUnstable => 5,
        AtpRepairMode::SatelliteHighBdp => 6,
        AtpRepairMode::Broadcast => 7,
        AtpRepairMode::Swarm => 8,
    }
}

fn path_mode_rank(path_mode: AtpRepairPathMode) -> u64 {
    match path_mode {
        AtpRepairPathMode::Direct => 1,
        AtpRepairPathMode::RelayOnly => 2,
        AtpRepairPathMode::DirectAndRelay => 3,
    }
}

fn permille_of(value: u64, permille: u16) -> u64 {
    mul_div_u64(value, u64::from(permille), 1_000)
}

fn ratio_permille(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 1_000;
    }
    let ratio = mul_div_u64(numerator, 1_000, denominator).min(1_000);
    u16::try_from(ratio).unwrap_or(1_000)
}

fn mul_div_u64(value: u64, multiplier: u64, divisor: u64) -> u64 {
    let divisor = u128::from(divisor.max(1));
    let divided = u128::from(value).saturating_mul(u128::from(multiplier)) / divisor;
    u64::try_from(divided).unwrap_or(u64::MAX)
}

fn signed_diff_to_i64(benefit: u64, cost: u64) -> i64 {
    let diff = i128::from(benefit) - i128::from(cost);
    let clamped = diff.clamp(i128::from(i64::MIN), i128::from(i64::MAX));
    i64::try_from(clamped).unwrap_or(if diff.is_negative() {
        i64::MIN
    } else {
        i64::MAX
    })
}

fn i64_from_u64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_from_nonnegative_i64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
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

impl AtpBottleneckKind {
    /// Return the stable bottleneck name used in receipts and status output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InsufficientTelemetry => "insufficient_telemetry",
            Self::ContradictoryTelemetry => "contradictory_telemetry",
            Self::NetworkLoss => "network_loss",
            Self::NetworkLatency => "network_latency",
            Self::CongestionWindow => "congestion_window",
            Self::SendBufferPressure => "send_buffer_pressure",
            Self::ReceiveBufferPressure => "receive_buffer_pressure",
            Self::DiskReadLag => "disk_read_lag",
            Self::DiskWriteLag => "disk_write_lag",
            Self::EncodeBacklog => "encode_backlog",
            Self::DecodeBacklog => "decode_backlog",
            Self::RepairLowRoi => "repair_low_roi",
            Self::RelayCost => "relay_cost",
            Self::MigrationInstability => "migration_instability",
        }
    }
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

/// Stable schema version for ATP autotune decision receipts.
pub const ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION: &str = "atp-autotune-decision-receipt-v1";

/// High-level outcome class for one autotune decision receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpAutotuneDecisionOutcome {
    /// Inputs were healthy enough for conservative growth.
    ConservativeGrowth,
    /// Pressure signals forced at least one throughput or repair knob change.
    PressureBackoff,
    /// The policy held bounded settings because no safe improvement was available.
    HoldNoWin,
    /// Missing or malformed identity evidence made the telemetry unsafe to apply.
    MalformedTelemetry,
}

/// Consumer-facing ATP autotune receipt status.
///
/// This is intentionally coarser than the internal policy outcome so status,
/// preflight, and proof consumers do not each re-classify raw metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpAutotuneReceiptStatus {
    /// Inputs were accepted and the selected settings are safe to report as passing.
    Pass,
    /// Pressure was accepted but the policy intentionally degraded throughput or repair knobs.
    Degraded,
    /// No bounded improvement was available, so the explicit no-win path was selected.
    NoWin,
    /// Work was not admitted because required evidence is incomplete.
    Blocked,
    /// The receipt or its telemetry evidence is malformed.
    Malformed,
    /// The receipt does not match current transfer-owned state.
    StaleEvidence,
}

impl AtpAutotuneReceiptStatus {
    /// Return the stable status string used in JSON and human output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Degraded => "degraded",
            Self::NoWin => "no_win",
            Self::Blocked => "blocked",
            Self::Malformed => "malformed",
            Self::StaleEvidence => "stale_evidence",
        }
    }
}

/// Confidence class for an explainable ATP autotune receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpAutotuneReceiptConfidence {
    /// Healthy evidence allowed conservative policy progress.
    Conservative,
    /// Evidence was accepted, but pressure forced fail-closed behavior.
    FailClosed,
    /// Evidence was incomplete, so the decision is blocked.
    InsufficientEvidence,
    /// Evidence was rejected as malformed or stale.
    Rejected,
}

impl AtpAutotuneReceiptConfidence {
    /// Return the stable confidence string used in JSON and human output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::FailClosed => "fail_closed",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::Rejected => "rejected",
        }
    }
}

/// Transfer knob described by an autotune decision receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpAutotuneKnob {
    /// Maximum bytes allowed in flight for this transfer.
    InFlightBytes,
    /// Maximum concurrent streams for this transfer.
    StreamCount,
    /// Target chunk size in bytes.
    ChunkSizeBytes,
    /// Repair symbols allowed per second.
    RepairSymbolsPerSecond,
}

impl AtpAutotuneKnob {
    /// Return the stable knob name used in receipt JSON and status output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlightBytes => "in_flight_bytes",
            Self::StreamCount => "stream_count",
            Self::ChunkSizeBytes => "chunk_size_bytes",
            Self::RepairSymbolsPerSecond => "repair_symbols_per_second",
        }
    }
}

/// Direction of a knob change in a decision receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpAutotuneKnobDirection {
    /// The knob value increased.
    Increase,
    /// The knob value decreased.
    Decrease,
    /// The knob value stayed unchanged.
    Hold,
}

/// Per-knob evidence for a decision receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneKnobChange {
    /// Knob being described.
    pub knob: AtpAutotuneKnob,
    /// Bounded value before the decision.
    pub previous: u64,
    /// Bounded value after the decision.
    pub next: u64,
    /// Direction selected by the decision.
    pub direction: AtpAutotuneKnobDirection,
    /// Absolute value delta.
    pub delta: u64,
}

impl AtpAutotuneKnobChange {
    fn new(knob: AtpAutotuneKnob, previous: u64, next: u64) -> Self {
        let direction = match next.cmp(&previous) {
            std::cmp::Ordering::Greater => AtpAutotuneKnobDirection::Increase,
            std::cmp::Ordering::Less => AtpAutotuneKnobDirection::Decrease,
            std::cmp::Ordering::Equal => AtpAutotuneKnobDirection::Hold,
        };
        Self {
            knob,
            previous,
            next,
            direction,
            delta: previous.abs_diff(next),
        }
    }
}

/// Replay/proof pointer embedded in an autotune receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneReceiptProofPointer {
    /// Receipt schema version that owns this proof pointer.
    pub receipt_schema_version: String,
    /// Stable trace id for joining status, preflight, and proof artifacts.
    pub trace_id: String,
    /// Stable workload or transfer id.
    pub workload_id: String,
    /// Samples represented by this receipt.
    pub sample_count: u32,
}

impl AtpAutotuneReceiptProofPointer {
    fn from_receipt_fields(trace_id: &str, workload_id: &str, sample_count: u32) -> Self {
        Self {
            receipt_schema_version: String::from(ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION),
            trace_id: trace_id.to_string(),
            workload_id: workload_id.to_string(),
            sample_count,
        }
    }
}

/// Error returned when a receipt cannot be consumed by status/preflight/proof code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpAutotuneReceiptValidationError {
    /// Receipt schema is unsupported.
    UnsupportedSchemaVersion {
        /// Expected schema version.
        expected: String,
        /// Actual schema version.
        actual: String,
    },
    /// Trace id is missing or blank.
    MissingTraceId,
    /// Workload id is missing or blank.
    MissingWorkloadId,
    /// Embedded proof pointer does not match the receipt identity.
    ProofPointerMismatch {
        /// Mismatched field name.
        field: String,
    },
}

impl fmt::Display for AtpAutotuneReceiptValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported ATP autotune receipt schema {actual}, expected {expected}"
                )
            }
            Self::MissingTraceId => write!(f, "ATP autotune receipt trace_id is missing"),
            Self::MissingWorkloadId => write!(f, "ATP autotune receipt workload_id is missing"),
            Self::ProofPointerMismatch { field } => {
                write!(f, "ATP autotune receipt proof pointer mismatches {field}")
            }
        }
    }
}

impl std::error::Error for AtpAutotuneReceiptValidationError {}

/// Deterministic, replay-friendly receipt for one ATP autotune decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneDecisionReceipt {
    /// Receipt schema version.
    pub schema_version: String,
    /// Stable trace id linking this decision to path/proof logs.
    pub trace_id: String,
    /// Stable workload or transfer id.
    pub workload_id: String,
    /// Samples represented by the decision window.
    pub sample_count: u32,
    /// Bounded settings before the decision was applied.
    pub current_settings: AtpAutotuneSettings,
    /// Full policy decision.
    pub decision: AtpAutotuneDecision,
    /// High-level outcome class.
    pub outcome: AtpAutotuneDecisionOutcome,
    /// Consumer-facing status for status, preflight, and proof code.
    pub consumer_status: AtpAutotuneReceiptStatus,
    /// Confidence/certainty class for this decision.
    pub confidence: AtpAutotuneReceiptConfidence,
    /// Stable caveats explaining why this status was selected.
    pub caveats: Vec<String>,
    /// Metric sources omitted from this decision window.
    pub omitted_sources: Vec<AtpAutotuneMetric>,
    /// Evidence sources rejected as stale while building this decision receipt.
    pub stale_sources: Vec<String>,
    /// Stable replay/proof pointer for downstream artifact joins.
    pub proof_pointer: AtpAutotuneReceiptProofPointer,
    /// Stable per-knob changes in a fixed order.
    pub changes: Vec<AtpAutotuneKnobChange>,
}

impl AtpAutotuneDecisionReceipt {
    /// Build a receipt from a policy decision and telemetry identifiers.
    #[must_use]
    pub fn from_decision(
        telemetry: &AtpAutotuneTelemetry,
        current_settings: AtpAutotuneSettings,
        decision: AtpAutotuneDecision,
    ) -> Self {
        let changes = knob_changes(current_settings, decision.settings);
        let outcome = classify_decision_outcome(&decision, &changes);
        let consumer_status = classify_receipt_status(&decision, outcome);
        let confidence = receipt_confidence(&decision, consumer_status);
        let caveats = receipt_caveats(&decision, consumer_status);
        let omitted_sources = omitted_metric_sources(telemetry);
        let proof_pointer = AtpAutotuneReceiptProofPointer::from_receipt_fields(
            &telemetry.trace_id,
            &telemetry.workload_id,
            telemetry.sample_count,
        );
        Self {
            schema_version: String::from(ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION),
            trace_id: telemetry.trace_id.clone(),
            workload_id: telemetry.workload_id.clone(),
            sample_count: telemetry.sample_count,
            current_settings,
            decision,
            outcome,
            consumer_status,
            confidence,
            caveats,
            omitted_sources,
            stale_sources: Vec::new(),
            proof_pointer,
            changes,
        }
    }

    /// Validate this receipt before a downstream consumer trusts it.
    pub fn validate_for_consumers(&self) -> Result<(), AtpAutotuneReceiptValidationError> {
        if self.schema_version != ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION {
            return Err(
                AtpAutotuneReceiptValidationError::UnsupportedSchemaVersion {
                    expected: String::from(ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION),
                    actual: self.schema_version.clone(),
                },
            );
        }
        if self.trace_id.trim().is_empty() {
            return Err(AtpAutotuneReceiptValidationError::MissingTraceId);
        }
        if self.workload_id.trim().is_empty() {
            return Err(AtpAutotuneReceiptValidationError::MissingWorkloadId);
        }
        if self.proof_pointer.receipt_schema_version != ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION
        {
            return Err(AtpAutotuneReceiptValidationError::ProofPointerMismatch {
                field: String::from("receipt_schema_version"),
            });
        }
        if self.proof_pointer.trace_id != self.trace_id {
            return Err(AtpAutotuneReceiptValidationError::ProofPointerMismatch {
                field: String::from("trace_id"),
            });
        }
        if self.proof_pointer.workload_id != self.workload_id {
            return Err(AtpAutotuneReceiptValidationError::ProofPointerMismatch {
                field: String::from("workload_id"),
            });
        }
        if self.proof_pointer.sample_count != self.sample_count {
            return Err(AtpAutotuneReceiptValidationError::ProofPointerMismatch {
                field: String::from("sample_count"),
            });
        }
        Ok(())
    }

    /// Return knobs that changed, in stable receipt order.
    #[must_use]
    pub fn selected_knobs(&self) -> Vec<AtpAutotuneKnob> {
        self.changes
            .iter()
            .filter(|change| change.direction != AtpAutotuneKnobDirection::Hold)
            .map(|change| change.knob)
            .collect()
    }

    /// Render a terse, stable human receipt for CLI/status output.
    #[must_use]
    pub fn render_human_summary(&self, explain: bool) -> String {
        self.human_summary_lines(explain).join("\n")
    }

    /// Build stable human receipt lines for callers that add their own heading.
    #[must_use]
    pub fn human_summary_lines(&self, explain: bool) -> Vec<String> {
        let mut lines = vec![
            format!("Trace ID: {}", self.trace_id),
            format!("Workload ID: {}", self.workload_id),
            format!("Samples: {}", self.sample_count),
            format!("Status: {}", self.consumer_status.as_str()),
            format!("Outcome: {:?}", self.outcome),
            format!("Reason: {}", self.decision.reason_code),
            format!("Confidence: {}", self.confidence.as_str()),
            format!("Fail closed: {}", self.decision.fail_closed),
            format!(
                "Next settings: in_flight_bytes={}, stream_count={}, chunk_size_bytes={}, repair_symbols_per_second={}",
                self.decision.settings.in_flight_bytes,
                self.decision.settings.stream_count,
                self.decision.settings.chunk_size_bytes,
                self.decision.settings.repair_symbols_per_second
            ),
            format!("Bottlenecks: {}", self.decision.bottlenecks.len()),
        ];

        if !self.caveats.is_empty() {
            lines.push(format!("Caveats: {}", self.caveats.join(",")));
        }
        if !self.stale_sources.is_empty() {
            lines.push(format!("Stale sources: {}", self.stale_sources.join(",")));
        }

        if explain {
            for change in &self.changes {
                if change.direction != AtpAutotuneKnobDirection::Hold {
                    lines.push(format!(
                        "- knob {}: {:?} {} -> {} (delta={})",
                        change.knob.as_str(),
                        change.direction,
                        change.previous,
                        change.next,
                        change.delta
                    ));
                }
            }
            for signal in &self.decision.bottlenecks {
                let metric = signal.metric.map_or("none", AtpAutotuneMetric::as_str);
                lines.push(format!(
                    "- {}: metric={}, observed={}, threshold={}",
                    signal.kind.as_str(),
                    metric,
                    signal.observed,
                    signal.threshold
                ));
            }
        }

        lines
    }
}

/// Stable schema version for ATP autotune decision-application receipts.
pub const ATP_AUTOTUNE_APPLICATION_RECEIPT_SCHEMA_VERSION: &str =
    "atp-autotune-application-receipt-v1";

/// Outcome for applying a policy decision to transfer-owned state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpAutotuneApplicationOutcome {
    /// Pressure backoff was applied immediately.
    AppliedPressureBackoff,
    /// Conservative growth was applied after enough consecutive clean windows.
    AppliedConfirmedGrowth,
    /// Conservative growth was deferred until the hysteresis threshold is met.
    DeferredGrowthHysteresis,
    /// No safe improvement was available, so existing settings were held.
    HeldNoWin,
    /// Malformed or contradictory telemetry was rejected without mutation.
    RejectedMalformedTelemetry,
    /// A receipt for stale transfer state was rejected without mutation.
    RejectedStaleReceipt,
    /// A receipt with an unsupported schema was rejected without mutation.
    RejectedSchemaVersion,
}

/// Replay-friendly evidence for applying one autotune decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneApplicationReceipt {
    /// Application receipt schema version.
    pub schema_version: String,
    /// Stable trace id linked to the source decision.
    pub trace_id: String,
    /// Stable workload or transfer id linked to the source decision.
    pub workload_id: String,
    /// Samples represented by the decision window.
    pub sample_count: u32,
    /// Bounded settings before the application step.
    pub previous_settings: AtpAutotuneSettings,
    /// Bounded candidate settings selected by the policy.
    pub candidate_settings: AtpAutotuneSettings,
    /// Settings visible after the application step.
    pub applied_settings: AtpAutotuneSettings,
    /// Whether transfer-owned settings changed.
    pub applied: bool,
    /// Stable outcome for logs, status, and proof artifacts.
    pub outcome: AtpAutotuneApplicationOutcome,
    /// Consumer-facing status after application/hysteresis checks.
    pub consumer_status: AtpAutotuneReceiptStatus,
    /// Consecutive clean-growth windows observed after this application step.
    pub consecutive_growth_windows: u8,
    /// Number of clean-growth windows required before applying growth.
    pub growth_confirmations_required: u8,
    /// Stable reason suitable for status and proof artifacts.
    pub reason_code: String,
    /// Original deterministic policy receipt.
    pub decision_receipt: AtpAutotuneDecisionReceipt,
}

/// Error returned when an application receipt cannot be consumed by status,
/// preflight, or proof code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpAutotuneApplicationReceiptValidationError {
    /// Application receipt schema is unsupported.
    UnsupportedSchemaVersion {
        /// Expected schema version.
        expected: String,
        /// Actual schema version.
        actual: String,
    },
    /// Nested decision receipt is not consumer-safe.
    DecisionReceiptInvalid {
        /// Nested decision receipt validation error.
        reason: AtpAutotuneReceiptValidationError,
    },
    /// Nested decision receipt identity does not match the application receipt.
    DecisionReceiptMismatch {
        /// Mismatched field name.
        field: String,
    },
    /// The `applied` flag does not match the before/after settings.
    AppliedFlagMismatch,
}

impl fmt::Display for AtpAutotuneApplicationReceiptValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { expected, actual } => write!(
                f,
                "unsupported ATP autotune application receipt schema {actual}, expected {expected}"
            ),
            Self::DecisionReceiptInvalid { reason } => {
                write!(
                    f,
                    "ATP autotune application receipt embeds invalid decision receipt: {reason}"
                )
            }
            Self::DecisionReceiptMismatch { field } => {
                write!(
                    f,
                    "ATP autotune application receipt decision receipt mismatches {field}"
                )
            }
            Self::AppliedFlagMismatch => {
                write!(
                    f,
                    "ATP autotune application receipt applied flag mismatches settings"
                )
            }
        }
    }
}

impl std::error::Error for AtpAutotuneApplicationReceiptValidationError {}

impl AtpAutotuneApplicationReceipt {
    fn from_parts(
        previous_settings: AtpAutotuneSettings,
        candidate_settings: AtpAutotuneSettings,
        applied_settings: AtpAutotuneSettings,
        outcome: AtpAutotuneApplicationOutcome,
        consecutive_growth_windows: u8,
        growth_confirmations_required: u8,
        decision_receipt: AtpAutotuneDecisionReceipt,
    ) -> Self {
        let consumer_status = application_consumer_status(outcome);
        let reason_code = match outcome {
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff => "applied_pressure_backoff",
            AtpAutotuneApplicationOutcome::AppliedConfirmedGrowth => "applied_confirmed_growth",
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis => "deferred_growth_hysteresis",
            AtpAutotuneApplicationOutcome::HeldNoWin => "held_no_win",
            AtpAutotuneApplicationOutcome::RejectedMalformedTelemetry => {
                "rejected_malformed_telemetry"
            }
            AtpAutotuneApplicationOutcome::RejectedStaleReceipt => "rejected_stale_receipt",
            AtpAutotuneApplicationOutcome::RejectedSchemaVersion => "rejected_schema_version",
        };
        let applied = previous_settings != applied_settings;
        Self {
            schema_version: String::from(ATP_AUTOTUNE_APPLICATION_RECEIPT_SCHEMA_VERSION),
            trace_id: decision_receipt.trace_id.clone(),
            workload_id: decision_receipt.workload_id.clone(),
            sample_count: decision_receipt.sample_count,
            previous_settings,
            candidate_settings,
            applied_settings,
            applied,
            outcome,
            consumer_status,
            consecutive_growth_windows,
            growth_confirmations_required,
            reason_code: String::from(reason_code),
            decision_receipt,
        }
    }

    /// Validate this application receipt before downstream consumers trust it.
    pub fn validate_for_consumers(
        &self,
    ) -> Result<(), AtpAutotuneApplicationReceiptValidationError> {
        if self.schema_version != ATP_AUTOTUNE_APPLICATION_RECEIPT_SCHEMA_VERSION {
            return Err(
                AtpAutotuneApplicationReceiptValidationError::UnsupportedSchemaVersion {
                    expected: String::from(ATP_AUTOTUNE_APPLICATION_RECEIPT_SCHEMA_VERSION),
                    actual: self.schema_version.clone(),
                },
            );
        }
        self.decision_receipt
            .validate_for_consumers()
            .map_err(|reason| {
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptInvalid { reason }
            })?;
        if self.decision_receipt.trace_id != self.trace_id {
            return Err(
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptMismatch {
                    field: String::from("trace_id"),
                },
            );
        }
        if self.decision_receipt.workload_id != self.workload_id {
            return Err(
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptMismatch {
                    field: String::from("workload_id"),
                },
            );
        }
        if self.decision_receipt.sample_count != self.sample_count {
            return Err(
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptMismatch {
                    field: String::from("sample_count"),
                },
            );
        }
        if self.applied != (self.previous_settings != self.applied_settings) {
            return Err(AtpAutotuneApplicationReceiptValidationError::AppliedFlagMismatch);
        }
        Ok(())
    }
}

/// Transfer-owned state for safely applying autotune decisions.
///
/// The state applies backoff immediately, but requires consecutive clean
/// windows before growth is visible to a transfer. That hysteresis keeps noisy
/// pressure from oscillating knobs while preserving fail-closed behavior for
/// stale or malformed decision receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAutotuneApplicationState {
    /// Current bounded transfer settings.
    pub settings: AtpAutotuneSettings,
    /// Hard bounds enforced at every application step.
    pub limits: AtpAutotuneLimits,
    /// Consecutive clean-growth windows required before applying growth.
    pub growth_confirmations_required: u8,
    /// Consecutive clean-growth windows observed so far.
    pub consecutive_growth_windows: u8,
}

impl Default for AtpAutotuneApplicationState {
    fn default() -> Self {
        Self::new(AtpAutotuneSettings::default(), AtpAutotuneLimits::default())
    }
}

impl AtpAutotuneApplicationState {
    /// Create transfer-owned application state with default two-window growth hysteresis.
    #[must_use]
    pub fn new(settings: AtpAutotuneSettings, limits: AtpAutotuneLimits) -> Self {
        Self {
            settings: limits.clamp(settings),
            limits,
            growth_confirmations_required: 2,
            consecutive_growth_windows: 0,
        }
    }

    /// Override the number of consecutive clean windows required for growth.
    #[must_use]
    pub fn with_growth_confirmations_required(mut self, required: u8) -> Self {
        self.growth_confirmations_required = required.max(1);
        self
    }

    /// Compute and apply one policy decision from a telemetry window.
    #[must_use]
    pub fn apply_policy_window(
        &mut self,
        policy: AtpAutotunePolicy,
        telemetry: &AtpAutotuneTelemetry,
    ) -> AtpAutotuneApplicationReceipt {
        let bounded_policy = AtpAutotunePolicy {
            limits: self.limits,
            ..policy
        };
        let receipt = bounded_policy.decide_with_receipt(self.settings, telemetry);
        self.apply_decision_receipt(receipt)
    }

    /// Apply a precomputed policy receipt if it still matches transfer-owned state.
    #[must_use]
    pub fn apply_decision_receipt(
        &mut self,
        receipt: AtpAutotuneDecisionReceipt,
    ) -> AtpAutotuneApplicationReceipt {
        let previous = self.limits.clamp(self.settings);
        self.settings = previous;

        if let Err(validation) = receipt.validate_for_consumers() {
            let candidate = self.limits.clamp(receipt.decision.settings);
            self.consecutive_growth_windows = 0;
            let outcome = match validation {
                AtpAutotuneReceiptValidationError::UnsupportedSchemaVersion { .. } => {
                    AtpAutotuneApplicationOutcome::RejectedSchemaVersion
                }
                AtpAutotuneReceiptValidationError::MissingTraceId
                | AtpAutotuneReceiptValidationError::MissingWorkloadId
                | AtpAutotuneReceiptValidationError::ProofPointerMismatch { .. } => {
                    AtpAutotuneApplicationOutcome::RejectedMalformedTelemetry
                }
            };
            return AtpAutotuneApplicationReceipt::from_parts(
                previous,
                candidate,
                previous,
                outcome,
                self.consecutive_growth_windows,
                self.growth_confirmations_required,
                receipt,
            );
        }

        if receipt.current_settings != previous {
            self.consecutive_growth_windows = 0;
            return AtpAutotuneApplicationReceipt::from_parts(
                previous,
                self.limits.clamp(receipt.decision.settings),
                previous,
                AtpAutotuneApplicationOutcome::RejectedStaleReceipt,
                self.consecutive_growth_windows,
                self.growth_confirmations_required,
                receipt,
            );
        }

        let candidate = self.limits.clamp(receipt.decision.settings);
        let outcome = match receipt.outcome {
            AtpAutotuneDecisionOutcome::PressureBackoff => {
                self.consecutive_growth_windows = 0;
                self.settings = candidate;
                AtpAutotuneApplicationOutcome::AppliedPressureBackoff
            }
            AtpAutotuneDecisionOutcome::ConservativeGrowth => {
                self.consecutive_growth_windows = self.consecutive_growth_windows.saturating_add(1);
                if self.consecutive_growth_windows >= self.growth_confirmations_required {
                    self.settings = candidate;
                    self.consecutive_growth_windows = 0;
                    AtpAutotuneApplicationOutcome::AppliedConfirmedGrowth
                } else {
                    AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
                }
            }
            AtpAutotuneDecisionOutcome::HoldNoWin => {
                self.consecutive_growth_windows = 0;
                AtpAutotuneApplicationOutcome::HeldNoWin
            }
            AtpAutotuneDecisionOutcome::MalformedTelemetry => {
                self.consecutive_growth_windows = 0;
                AtpAutotuneApplicationOutcome::RejectedMalformedTelemetry
            }
        };

        AtpAutotuneApplicationReceipt::from_parts(
            previous,
            candidate,
            self.settings,
            outcome,
            self.consecutive_growth_windows,
            self.growth_confirmations_required,
            receipt,
        )
    }
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

    /// Produce a conservative decision plus a deterministic receipt.
    #[must_use]
    pub fn decide_with_receipt(
        self,
        current: AtpAutotuneSettings,
        telemetry: &AtpAutotuneTelemetry,
    ) -> AtpAutotuneDecisionReceipt {
        let current_settings = self.limits.clamp(current);
        let decision = self.decide(current, telemetry);
        AtpAutotuneDecisionReceipt::from_decision(telemetry, current_settings, decision)
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

        if let Some(pto) = telemetry.pto_micros
            && pto > self.latency_hold_micros
        {
            bottlenecks.push(AtpBottleneckSignal::new(
                AtpBottleneckKind::NetworkLatency,
                Some(AtpAutotuneMetric::PtoMicros),
                pto,
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
                    | AtpBottleneckKind::RelayCost
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

fn knob_changes(
    current: AtpAutotuneSettings,
    next: AtpAutotuneSettings,
) -> Vec<AtpAutotuneKnobChange> {
    vec![
        AtpAutotuneKnobChange::new(
            AtpAutotuneKnob::InFlightBytes,
            current.in_flight_bytes,
            next.in_flight_bytes,
        ),
        AtpAutotuneKnobChange::new(
            AtpAutotuneKnob::StreamCount,
            u64::from(current.stream_count),
            u64::from(next.stream_count),
        ),
        AtpAutotuneKnobChange::new(
            AtpAutotuneKnob::ChunkSizeBytes,
            u64::from(current.chunk_size_bytes),
            u64::from(next.chunk_size_bytes),
        ),
        AtpAutotuneKnobChange::new(
            AtpAutotuneKnob::RepairSymbolsPerSecond,
            u64::from(current.repair_symbols_per_second),
            u64::from(next.repair_symbols_per_second),
        ),
    ]
}

fn classify_decision_outcome(
    decision: &AtpAutotuneDecision,
    changes: &[AtpAutotuneKnobChange],
) -> AtpAutotuneDecisionOutcome {
    if decision
        .bottlenecks
        .iter()
        .any(|signal| signal.kind == AtpBottleneckKind::ContradictoryTelemetry)
    {
        return AtpAutotuneDecisionOutcome::MalformedTelemetry;
    }

    if changes
        .iter()
        .any(|change| change.direction == AtpAutotuneKnobDirection::Decrease)
    {
        return AtpAutotuneDecisionOutcome::PressureBackoff;
    }

    if !decision.fail_closed
        && changes
            .iter()
            .any(|change| change.direction == AtpAutotuneKnobDirection::Increase)
    {
        return AtpAutotuneDecisionOutcome::ConservativeGrowth;
    }

    AtpAutotuneDecisionOutcome::HoldNoWin
}

fn classify_receipt_status(
    decision: &AtpAutotuneDecision,
    outcome: AtpAutotuneDecisionOutcome,
) -> AtpAutotuneReceiptStatus {
    if decision
        .bottlenecks
        .iter()
        .any(|signal| signal.kind == AtpBottleneckKind::ContradictoryTelemetry)
    {
        return AtpAutotuneReceiptStatus::Malformed;
    }
    if decision
        .bottlenecks
        .iter()
        .any(|signal| signal.kind == AtpBottleneckKind::InsufficientTelemetry)
    {
        return AtpAutotuneReceiptStatus::Blocked;
    }

    match outcome {
        AtpAutotuneDecisionOutcome::ConservativeGrowth => AtpAutotuneReceiptStatus::Pass,
        AtpAutotuneDecisionOutcome::PressureBackoff => AtpAutotuneReceiptStatus::Degraded,
        AtpAutotuneDecisionOutcome::HoldNoWin => AtpAutotuneReceiptStatus::NoWin,
        AtpAutotuneDecisionOutcome::MalformedTelemetry => AtpAutotuneReceiptStatus::Malformed,
    }
}

fn receipt_confidence(
    decision: &AtpAutotuneDecision,
    status: AtpAutotuneReceiptStatus,
) -> AtpAutotuneReceiptConfidence {
    match status {
        AtpAutotuneReceiptStatus::Pass => AtpAutotuneReceiptConfidence::Conservative,
        AtpAutotuneReceiptStatus::NoWin if !decision.fail_closed => {
            AtpAutotuneReceiptConfidence::Conservative
        }
        AtpAutotuneReceiptStatus::Degraded | AtpAutotuneReceiptStatus::NoWin => {
            AtpAutotuneReceiptConfidence::FailClosed
        }
        AtpAutotuneReceiptStatus::Blocked => AtpAutotuneReceiptConfidence::InsufficientEvidence,
        AtpAutotuneReceiptStatus::Malformed | AtpAutotuneReceiptStatus::StaleEvidence => {
            AtpAutotuneReceiptConfidence::Rejected
        }
    }
}

fn receipt_caveats(
    decision: &AtpAutotuneDecision,
    status: AtpAutotuneReceiptStatus,
) -> Vec<String> {
    match status {
        AtpAutotuneReceiptStatus::Pass => {
            vec![String::from("growth_requires_application_hysteresis")]
        }
        AtpAutotuneReceiptStatus::NoWin => vec![String::from("bounded_no_win")],
        AtpAutotuneReceiptStatus::Blocked => vec![String::from("insufficient_evidence")],
        AtpAutotuneReceiptStatus::Malformed => vec![String::from("malformed_evidence")],
        AtpAutotuneReceiptStatus::StaleEvidence => vec![String::from("stale_evidence")],
        AtpAutotuneReceiptStatus::Degraded => decision
            .bottlenecks
            .iter()
            .map(|signal| signal.kind.as_str().to_string())
            .collect(),
    }
}

fn omitted_metric_sources(telemetry: &AtpAutotuneTelemetry) -> Vec<AtpAutotuneMetric> {
    ATP_AUTOTUNE_METRIC_NAMES
        .iter()
        .copied()
        .filter(|metric| !telemetry_has_metric(telemetry, *metric))
        .collect()
}

fn telemetry_has_metric(telemetry: &AtpAutotuneTelemetry, metric: AtpAutotuneMetric) -> bool {
    match metric {
        AtpAutotuneMetric::RttMicros => telemetry.rtt_micros.is_some(),
        AtpAutotuneMetric::LossPermille => telemetry.loss_permille.is_some(),
        AtpAutotuneMetric::PtoMicros => telemetry.pto_micros.is_some(),
        AtpAutotuneMetric::CongestionWindowBytes => telemetry.congestion_window_bytes.is_some(),
        AtpAutotuneMetric::InFlightBytes => telemetry.in_flight_bytes.is_some(),
        AtpAutotuneMetric::SendBufferQueuedBytes => telemetry.send_buffer_queued_bytes.is_some(),
        AtpAutotuneMetric::ReceiveBufferQueuedBytes => {
            telemetry.receive_buffer_queued_bytes.is_some()
        }
        AtpAutotuneMetric::DiskReadLagMicros => telemetry.disk_read_lag_micros.is_some(),
        AtpAutotuneMetric::DiskWriteLagMicros => telemetry.disk_write_lag_micros.is_some(),
        AtpAutotuneMetric::EncodeBacklogSymbols => telemetry.encode_backlog_symbols.is_some(),
        AtpAutotuneMetric::DecodeBacklogSymbols => telemetry.decode_backlog_symbols.is_some(),
        AtpAutotuneMetric::RepairRoiPermille => telemetry.repair_roi_permille.is_some(),
        AtpAutotuneMetric::RelayCostMicrosPerMiB => telemetry.relay_cost_micros_per_mib.is_some(),
        AtpAutotuneMetric::MigrationEvents => telemetry.migration_events.is_some(),
    }
}

fn application_consumer_status(outcome: AtpAutotuneApplicationOutcome) -> AtpAutotuneReceiptStatus {
    match outcome {
        AtpAutotuneApplicationOutcome::AppliedPressureBackoff => AtpAutotuneReceiptStatus::Degraded,
        AtpAutotuneApplicationOutcome::AppliedConfirmedGrowth => AtpAutotuneReceiptStatus::Pass,
        AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis => {
            AtpAutotuneReceiptStatus::Blocked
        }
        AtpAutotuneApplicationOutcome::HeldNoWin => AtpAutotuneReceiptStatus::NoWin,
        AtpAutotuneApplicationOutcome::RejectedMalformedTelemetry
        | AtpAutotuneApplicationOutcome::RejectedSchemaVersion => {
            AtpAutotuneReceiptStatus::Malformed
        }
        AtpAutotuneApplicationOutcome::RejectedStaleReceipt => {
            AtpAutotuneReceiptStatus::StaleEvidence
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_telemetry() -> AtpAutotuneTelemetry {
        AtpAutotuneTelemetry::new("trace-a", "workload-a").with_sample_count(16)
    }

    fn repair_inputs() -> AtpRepairRoiInputs {
        AtpRepairRoiInputs {
            trace_id: String::from("trace-repair"),
            workload_id: String::from("workload-repair"),
            expected_time_saved_micros: 400_000,
            encode_cpu_micros: 10_000,
            decode_cpu_micros: 10_000,
            bandwidth_overhead_bytes: 64 * 1_024,
            memory_pressure_permille: 50,
            stream_contention_permille: 25,
            relay_cost_micros_per_mib: 100_000,
            path_stability_permille: 950,
            resume_value_permille: 0,
            loss_permille: 1,
            available_peer_count: 1,
            path_mode: AtpRepairPathMode::Direct,
            requested_mode: None,
            missing_tail_chunks: 0,
            rtt_micros: 50_000,
            path_migration_events: 0,
            broadcast_peer_count: 0,
        }
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
    fn transfer_pressure_snapshot_exports_runtime_metrics_and_derived_costs()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot =
            AtpTransferPressureSnapshot::new("trace-transfer", "transfer-42").with_sample_count(12);
        snapshot.rtt_micros = Some(44_000);
        snapshot.loss_permille = Some(9);
        snapshot.pto_micros = Some(120_000);
        snapshot.congestion_window_bytes = Some(96 * 1_048_576);
        snapshot.in_flight_bytes = Some(32 * 1_048_576);
        snapshot.send_buffer_queued_bytes = Some(512 * 1_024);
        snapshot.receive_buffer_queued_bytes = Some(256 * 1_024);
        snapshot.disk_read_lag_micros = Some(8_000);
        snapshot.disk_write_lag_micros = Some(9_000);
        snapshot.encode_backlog_symbols = Some(64);
        snapshot.decode_backlog_symbols = Some(32);
        snapshot.repair_symbols_sent = Some(400);
        snapshot.useful_repair_symbols = Some(250);
        snapshot.relay_cost_micros = Some(300_000);
        snapshot.relay_bytes = Some(2 * 1_048_576);
        snapshot.migration_events = Some(1);

        assert_eq!(snapshot.repair_roi_permille(), Some(625));
        assert_eq!(snapshot.relay_cost_micros_per_mib(), Some(150_000));

        let report = snapshot.to_report();
        assert_eq!(report.trace_id, "trace-transfer");
        assert_eq!(report.workload_id, "transfer-42");
        assert_eq!(report.sample_count, 12);
        assert_eq!(report.samples.len(), ATP_AUTOTUNE_METRIC_NAMES.len());
        assert_eq!(
            report.samples[11],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::RepairRoiPermille, 625)
        );
        assert_eq!(
            report.samples[12],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::RelayCostMicrosPerMiB, 150_000)
        );

        let telemetry = report.into_telemetry()?;
        assert_eq!(telemetry.trace_id, "trace-transfer");
        assert_eq!(telemetry.workload_id, "transfer-42");
        assert_eq!(telemetry.sample_count, 12);
        assert_eq!(telemetry.loss_permille, Some(9));
        assert_eq!(telemetry.repair_roi_permille, Some(625));
        assert_eq!(telemetry.relay_cost_micros_per_mib, Some(150_000));
        assert_eq!(telemetry.migration_events, Some(1));
        Ok(())
    }

    #[test]
    fn transfer_pressure_snapshot_omits_denominator_based_metrics_when_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot = AtpTransferPressureSnapshot::new("trace-empty", "transfer-empty");
        snapshot.repair_symbols_sent = Some(0);
        snapshot.useful_repair_symbols = Some(10);
        snapshot.relay_cost_micros = Some(1_000);
        snapshot.relay_bytes = Some(0);
        snapshot.migration_events = Some(2);

        assert_eq!(snapshot.repair_roi_permille(), None);
        assert_eq!(snapshot.relay_cost_micros_per_mib(), None);

        let report = snapshot.to_report();
        assert_eq!(
            report.samples,
            vec![AtpAutotuneMetricSample::new(
                AtpAutotuneMetric::MigrationEvents,
                2,
            )]
        );

        let telemetry = report.into_telemetry()?;
        assert_eq!(telemetry.sample_count, 1);
        assert_eq!(telemetry.repair_roi_permille, None);
        assert_eq!(telemetry.relay_cost_micros_per_mib, None);
        assert_eq!(telemetry.migration_events, Some(2));
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
    fn relay_cost_backs_off_transport_without_repair_backoff() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.relay_cost_micros_per_mib = Some(policy.relay_cost_micros_per_mib + 1);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::RelayCost)
        );
        assert!(decision.settings.in_flight_bytes < current.in_flight_bytes);
        assert_eq!(decision.settings.stream_count, current.stream_count - 1);
        assert_eq!(
            decision.settings.repair_symbols_per_second,
            current.repair_symbols_per_second
        );
    }

    #[test]
    fn repair_coordinator_clean_path_defaults_to_no_repair() {
        let coordinator = AtpRepairCoordinator::default();
        let mut inputs = repair_inputs();
        inputs.expected_time_saved_micros = 20_000;
        inputs.bandwidth_overhead_bytes = 0;

        let decision = coordinator.decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::NoRepair);
        assert_eq!(decision.mode, AtpRepairMode::Off);
        assert!(decision.fail_closed);
        assert_eq!(decision.reason_code, "repair_roi_not_positive");
        assert!(
            decision
                .factors
                .iter()
                .any(|factor| factor.kind == AtpRepairDecisionFactorKind::NetRoi)
        );
    }

    #[test]
    fn repair_coordinator_selects_exact_retransmit_for_low_loss_positive_roi() {
        let decision = AtpRepairCoordinator::default().decide(&repair_inputs());

        assert_eq!(decision.action, AtpRepairAction::ExactRetransmit);
        assert_eq!(decision.mode, AtpRepairMode::Tail);
        assert!(!decision.fail_closed);
        assert_eq!(decision.reason_code, "exact_retransmit_roi_positive");
        assert!(decision.net_roi_micros > 0);
    }

    #[test]
    fn repair_coordinator_selects_parity_trickle_for_moderate_loss() {
        let mut inputs = repair_inputs();
        inputs.loss_permille = 25;
        inputs.expected_time_saved_micros = 700_000;
        inputs.resume_value_permille = 200;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::ParityTrickle);
        assert_eq!(decision.mode, AtpRepairMode::Lossy);
        assert_eq!(decision.reason_code, "parity_trickle_roi_positive");
    }

    #[test]
    fn repair_coordinator_selects_burst_and_multi_peer_for_high_loss() {
        let coordinator = AtpRepairCoordinator::default();
        let mut burst = repair_inputs();
        burst.loss_permille = 120;
        burst.expected_time_saved_micros = 2_000_000;
        burst.resume_value_permille = 500;

        let burst_decision = coordinator.decide(&burst);
        assert_eq!(burst_decision.action, AtpRepairAction::BurstRepair);
        assert_eq!(burst_decision.mode, AtpRepairMode::Lossy);

        let mut multi_peer = burst;
        multi_peer.available_peer_count = 4;
        let multi_peer_decision = coordinator.decide(&multi_peer);
        assert_eq!(multi_peer_decision.action, AtpRepairAction::MultiPeerRepair);
        assert_eq!(multi_peer_decision.mode, AtpRepairMode::Swarm);
        assert_eq!(
            multi_peer_decision.reason_code,
            "multi_peer_repair_roi_positive"
        );
    }

    #[test]
    fn repair_coordinator_selects_relay_only_when_direct_path_is_unstable() {
        let mut inputs = repair_inputs();
        inputs.path_mode = AtpRepairPathMode::DirectAndRelay;
        inputs.path_stability_permille = 200;
        inputs.loss_permille = 40;
        inputs.expected_time_saved_micros = 1_000_000;
        inputs.relay_cost_micros_per_mib = 100_000;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::RelayOnlyRepair);
        assert_eq!(decision.mode, AtpRepairMode::MobileUnstable);
        assert_eq!(decision.reason_code, "relay_only_repair_roi_positive");
        assert!(
            decision
                .human_summary_lines()
                .join("\n")
                .contains("Repair mode: mobile_unstable")
        );
    }

    #[test]
    fn repair_coordinator_blocks_repair_under_high_memory_pressure() {
        let mut inputs = repair_inputs();
        inputs.expected_time_saved_micros = 2_000_000;
        inputs.memory_pressure_permille = 950;
        inputs.resume_value_permille = 100;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::NoRepair);
        assert_eq!(decision.mode, AtpRepairMode::Off);
        assert_eq!(decision.reason_code, "blocked_by_memory_pressure");
        assert!(decision.fail_closed);
    }

    #[test]
    fn repair_coordinator_honors_manual_resume_mode_after_budget_gates() {
        let mut inputs = repair_inputs();
        inputs.requested_mode = Some(AtpRepairMode::ResumeRepair);
        inputs.resume_value_permille = 700;
        inputs.expected_time_saved_micros = 900_000;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.mode, AtpRepairMode::ResumeRepair);
        assert_eq!(decision.action, AtpRepairAction::ParityTrickle);
        assert_eq!(decision.mode_reason_code, "manual_repair_mode_requested");
        assert_eq!(
            decision.mode_cooldown_micros,
            AtpRepairCoordinatorPolicy::default().resume_cooldown_micros
        );
    }

    #[test]
    fn repair_coordinator_auto_selects_relay_expensive_mode() {
        let mut inputs = repair_inputs();
        inputs.path_mode = AtpRepairPathMode::DirectAndRelay;
        inputs.relay_cost_micros_per_mib =
            AtpRepairCoordinatorPolicy::default().max_relay_cost_micros_per_mib + 1;
        inputs.expected_time_saved_micros = 800_000;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.mode, AtpRepairMode::RelayExpensive);
        assert_eq!(decision.action, AtpRepairAction::ExactRetransmit);
        assert_eq!(decision.mode_reason_code, "auto_relay_expensive_cost_gate");
    }

    #[test]
    fn repair_coordinator_auto_selects_satellite_broadcast_and_tail_modes() {
        let coordinator = AtpRepairCoordinator::default();
        let mut satellite = repair_inputs();
        satellite.rtt_micros =
            AtpRepairCoordinatorPolicy::default().satellite_high_bdp_min_rtt_micros;
        satellite.expected_time_saved_micros = 900_000;
        satellite.loss_permille = 20;
        assert_eq!(
            coordinator.decide(&satellite).mode,
            AtpRepairMode::SatelliteHighBdp
        );

        let mut broadcast = repair_inputs();
        broadcast.broadcast_peer_count = AtpRepairCoordinatorPolicy::default().broadcast_min_peers;
        broadcast.expected_time_saved_micros = 2_000_000;
        assert_eq!(
            coordinator.decide(&broadcast).mode,
            AtpRepairMode::Broadcast
        );

        let mut tail = repair_inputs();
        tail.missing_tail_chunks = AtpRepairCoordinatorPolicy::default().tail_min_missing_chunks;
        tail.expected_time_saved_micros = 300_000;
        assert_eq!(coordinator.decide(&tail).mode, AtpRepairMode::Tail);
    }

    #[test]
    fn repair_roi_inputs_derive_traceable_status_values_from_autotune() {
        let mut telemetry = healthy_telemetry();
        telemetry.rtt_micros = Some(50_000);
        telemetry.pto_micros = Some(300_000);
        telemetry.loss_permille = Some(100);
        telemetry.decode_backlog_symbols = Some(32);
        telemetry.repair_roi_permille = Some(700);
        telemetry.migration_events = Some(1);
        telemetry.relay_cost_micros_per_mib = Some(100_000);

        let inputs = AtpRepairRoiInputs::from_autotune_telemetry(&telemetry);
        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(inputs.trace_id, "trace-a");
        assert_eq!(inputs.workload_id, "workload-a");
        assert_eq!(inputs.path_mode, AtpRepairPathMode::DirectAndRelay);
        assert_eq!(inputs.missing_tail_chunks, 32);
        assert_eq!(inputs.path_migration_events, 1);
        assert_eq!(inputs.rtt_micros, 50_000);
        assert!(inputs.expected_time_saved_micros > 0);
        assert_ne!(decision.action, AtpRepairAction::NoRepair);
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

    #[test]
    fn decision_receipt_records_stable_knob_changes_and_outcome() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let receipt = policy.decide_with_receipt(current, &telemetry);

        assert_eq!(
            receipt.schema_version,
            ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION
        );
        assert_eq!(receipt.trace_id, "trace-a");
        assert_eq!(receipt.workload_id, "workload-a");
        assert_eq!(receipt.sample_count, 16);
        assert_eq!(receipt.current_settings, current);
        assert_eq!(receipt.outcome, AtpAutotuneDecisionOutcome::PressureBackoff);
        assert_eq!(receipt.consumer_status, AtpAutotuneReceiptStatus::Degraded);
        assert_eq!(receipt.confidence, AtpAutotuneReceiptConfidence::FailClosed);
        assert_eq!(receipt.caveats, vec![String::from("network_loss")]);
        assert!(receipt.stale_sources.is_empty());
        assert_eq!(
            receipt.proof_pointer,
            AtpAutotuneReceiptProofPointer {
                receipt_schema_version: String::from(ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION),
                trace_id: String::from("trace-a"),
                workload_id: String::from("workload-a"),
                sample_count: 16,
            }
        );
        assert!(receipt.validate_for_consumers().is_ok());
        assert!(
            receipt
                .omitted_sources
                .contains(&AtpAutotuneMetric::RttMicros)
        );
        assert!(
            !receipt
                .omitted_sources
                .contains(&AtpAutotuneMetric::LossPermille)
        );
        assert_eq!(receipt.changes.len(), 4);
        assert_eq!(receipt.changes[0].knob, AtpAutotuneKnob::InFlightBytes);
        assert_eq!(
            receipt.changes[0].direction,
            AtpAutotuneKnobDirection::Decrease
        );
        assert_eq!(receipt.changes[1].knob.as_str(), "stream_count");
        assert_eq!(
            receipt.changes[3].direction,
            AtpAutotuneKnobDirection::Increase
        );
        assert_eq!(
            receipt.selected_knobs(),
            vec![
                AtpAutotuneKnob::InFlightBytes,
                AtpAutotuneKnob::StreamCount,
                AtpAutotuneKnob::RepairSymbolsPerSecond,
            ]
        );

        let encoded = serde_json::to_string(&receipt).expect("receipt JSON");
        assert!(encoded.contains(r#""consumer_status":"degraded""#));
        assert!(encoded.contains(r#""confidence":"fail_closed""#));
        let decoded: AtpAutotuneDecisionReceipt =
            serde_json::from_str(&encoded).expect("roundtrip receipt JSON");
        assert_eq!(decoded, receipt);

        let human = receipt.render_human_summary(true);
        assert!(human.contains("Status: degraded"));
        assert!(human.contains("Confidence: fail_closed"));
        assert!(human.contains("- network_loss: metric=atp.autotune.loss_permille"));
    }

    #[test]
    fn decision_receipt_classifies_malformed_and_no_win_outcomes() {
        let policy = AtpAutotunePolicy {
            limits: AtpAutotuneLimits {
                min_in_flight_bytes: 8 * 1_048_576,
                max_in_flight_bytes: 8 * 1_048_576,
                min_stream_count: 4,
                max_stream_count: 4,
                min_chunk_size_bytes: 256 * 1_024,
                max_chunk_size_bytes: 256 * 1_024,
                min_repair_symbols_per_second: 256,
                max_repair_symbols_per_second: 256,
            },
            ..AtpAutotunePolicy::default()
        };

        let malformed = policy.decide_with_receipt(
            AtpAutotuneSettings::default(),
            &AtpAutotuneTelemetry::new("", "workload-a").with_sample_count(16),
        );
        assert_eq!(
            malformed.outcome,
            AtpAutotuneDecisionOutcome::MalformedTelemetry
        );
        assert_eq!(
            malformed.consumer_status,
            AtpAutotuneReceiptStatus::Malformed
        );
        assert_eq!(
            malformed.validate_for_consumers(),
            Err(AtpAutotuneReceiptValidationError::MissingTraceId)
        );

        let bounded =
            policy.decide_with_receipt(AtpAutotuneSettings::default(), &healthy_telemetry());
        assert_eq!(bounded.outcome, AtpAutotuneDecisionOutcome::HoldNoWin);
        assert_eq!(bounded.consumer_status, AtpAutotuneReceiptStatus::NoWin);
        assert_eq!(
            bounded.confidence,
            AtpAutotuneReceiptConfidence::Conservative
        );
        assert_eq!(bounded.caveats, vec![String::from("bounded_no_win")]);
        assert!(
            bounded
                .changes
                .iter()
                .all(|change| change.direction == AtpAutotuneKnobDirection::Hold)
        );
    }

    #[test]
    fn decision_receipt_status_distinguishes_blocked_and_malformed_consumers() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let blocked = policy.decide_with_receipt(
            current,
            &AtpAutotuneTelemetry::new("trace-blocked", "workload-blocked").with_sample_count(2),
        );

        assert_eq!(blocked.outcome, AtpAutotuneDecisionOutcome::HoldNoWin);
        assert_eq!(blocked.consumer_status, AtpAutotuneReceiptStatus::Blocked);
        assert_eq!(
            blocked.confidence,
            AtpAutotuneReceiptConfidence::InsufficientEvidence
        );
        assert_eq!(blocked.caveats, vec![String::from("insufficient_evidence")]);
        assert!(blocked.validate_for_consumers().is_ok());

        let mut unsupported = blocked.clone();
        unsupported.schema_version = String::from("atp-autotune-decision-receipt-v0");
        assert_eq!(
            unsupported.validate_for_consumers(),
            Err(
                AtpAutotuneReceiptValidationError::UnsupportedSchemaVersion {
                    expected: String::from(ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION),
                    actual: String::from("atp-autotune-decision-receipt-v0"),
                },
            )
        );

        let mut bad_pointer = blocked;
        bad_pointer.proof_pointer.trace_id = String::from("other-trace");
        assert_eq!(
            bad_pointer.validate_for_consumers(),
            Err(AtpAutotuneReceiptValidationError::ProofPointerMismatch {
                field: String::from("trace_id"),
            })
        );
    }

    #[test]
    fn application_state_defers_growth_until_hysteresis_is_satisfied() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let initial = state.settings;

        let first = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            first.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert_eq!(first.consumer_status, AtpAutotuneReceiptStatus::Blocked);
        assert!(!first.applied);
        assert_eq!(state.settings, initial);
        assert_eq!(state.consecutive_growth_windows, 1);

        let second = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            second.outcome,
            AtpAutotuneApplicationOutcome::AppliedConfirmedGrowth
        );
        assert_eq!(second.consumer_status, AtpAutotuneReceiptStatus::Pass);
        assert!(second.applied);
        assert!(state.settings.in_flight_bytes > initial.in_flight_bytes);
        assert_eq!(state.consecutive_growth_windows, 0);
    }

    #[test]
    fn application_state_applies_pressure_backoff_immediately() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let initial = state.settings;
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let receipt = state.apply_policy_window(policy, &telemetry);

        assert_eq!(
            receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert_eq!(receipt.consumer_status, AtpAutotuneReceiptStatus::Degraded);
        assert!(receipt.applied);
        assert!(state.settings.in_flight_bytes < initial.in_flight_bytes);
        assert!(state.settings.repair_symbols_per_second > initial.repair_symbols_per_second);
        assert_eq!(state.consecutive_growth_windows, 0);
    }

    #[test]
    fn application_receipt_validates_consumer_identity_and_applied_flag() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let receipt = state.apply_policy_window(policy, &telemetry);

        assert!(receipt.validate_for_consumers().is_ok());

        let mut unsupported_schema = receipt.clone();
        unsupported_schema.schema_version = String::from("atp-autotune-application-receipt-v0");
        assert_eq!(
            unsupported_schema.validate_for_consumers(),
            Err(
                AtpAutotuneApplicationReceiptValidationError::UnsupportedSchemaVersion {
                    expected: String::from(ATP_AUTOTUNE_APPLICATION_RECEIPT_SCHEMA_VERSION),
                    actual: String::from("atp-autotune-application-receipt-v0"),
                },
            )
        );

        let mut mismatched_trace = receipt.clone();
        mismatched_trace.trace_id = String::from("other-trace");
        assert_eq!(
            mismatched_trace.validate_for_consumers(),
            Err(
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptMismatch {
                    field: String::from("trace_id"),
                },
            )
        );

        let mut mismatched_applied = receipt;
        mismatched_applied.applied = false;
        assert_eq!(
            mismatched_applied.validate_for_consumers(),
            Err(AtpAutotuneApplicationReceiptValidationError::AppliedFlagMismatch)
        );
    }

    #[test]
    fn application_state_resets_pending_growth_after_noisy_pressure() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let first = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            first.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert_eq!(state.consecutive_growth_windows, 1);

        let mut telemetry = healthy_telemetry();
        telemetry.send_buffer_queued_bytes = Some(policy.buffer_pressure_bytes + 1);
        let noisy = state.apply_policy_window(policy, &telemetry);

        assert_eq!(
            noisy.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert_eq!(state.consecutive_growth_windows, 0);

        let next_clean = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            next_clean.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert_eq!(state.consecutive_growth_windows, 1);
    }

    #[test]
    fn application_state_rejects_stale_receipts_without_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let stale_current = AtpAutotuneSettings::new(1, 1, 64 * 1_024, 0);
        let stale_receipt = policy.decide_with_receipt(stale_current, &healthy_telemetry());
        let before = state.settings;

        let applied = state.apply_decision_receipt(stale_receipt);

        assert_eq!(
            applied.outcome,
            AtpAutotuneApplicationOutcome::RejectedStaleReceipt
        );
        assert_eq!(
            applied.consumer_status,
            AtpAutotuneReceiptStatus::StaleEvidence
        );
        assert!(!applied.applied);
        assert_eq!(state.settings, before);
        assert_eq!(state.consecutive_growth_windows, 0);
    }

    #[test]
    fn application_state_rejects_malformed_receipts_without_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let malformed = policy.decide_with_receipt(
            state.settings,
            &AtpAutotuneTelemetry::new("", "workload-a").with_sample_count(16),
        );
        let before = state.settings;

        let applied = state.apply_decision_receipt(malformed);

        assert_eq!(
            applied.outcome,
            AtpAutotuneApplicationOutcome::RejectedMalformedTelemetry
        );
        assert_eq!(applied.consumer_status, AtpAutotuneReceiptStatus::Malformed);
        assert!(!applied.applied);
        assert_eq!(state.settings, before);
        assert_eq!(state.consecutive_growth_windows, 0);
        assert!(matches!(
            applied.validate_for_consumers(),
            Err(
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptInvalid {
                    reason: AtpAutotuneReceiptValidationError::MissingTraceId,
                },
            )
        ));
    }
}
