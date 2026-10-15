//! ATP network truth instrumentation and pressure model.
//!
//! Provides practical network metrics from observations: RTT, ACK delay, loss,
//! PTO, congestion window, send/recv buffer pressure, disk lag, CPU pressure,
//! relay/direct delta, and path migration events.
//!
//! Exposes evidence with uncertainty, not omniscience.

use crate::observability::metrics::{Counter, Gauge, Histogram};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Custom serde module for SystemTime serialization.
mod system_time_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration_since_epoch = time
            .duration_since(UNIX_EPOCH)
            .map_err(serde::ser::Error::custom)?;
        duration_since_epoch.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + std::time::Duration::from_secs(secs))
    }
}

/// Network truth metrics schema covering RTT, loss, congestion, and pressure signals.
#[derive(Debug, Clone)]
pub struct NetworkTruthMetrics {
    /// Round-trip time measurements
    pub rtt: Arc<Histogram>,
    /// ACK delay observations
    pub ack_delay: Arc<Histogram>,
    /// Packet loss events counter
    pub loss_events: Arc<Counter>,
    /// Probe timeout events counter
    pub pto_events: Arc<Counter>,
    /// Congestion window size (bytes)
    pub congestion_window: Arc<Gauge>,
    /// Bytes in flight
    pub bytes_in_flight: Arc<Gauge>,
    /// Send buffer pressure (0.0-1.0)
    pub send_buffer_pressure: Arc<Gauge>,
    /// Receive buffer pressure (0.0-1.0)
    pub recv_buffer_pressure: Arc<Gauge>,
    /// Disk I/O latency
    pub disk_latency: Arc<Histogram>,
    /// CPU encoding pressure
    pub cpu_encode_pressure: Arc<Gauge>,
    /// CPU decoding pressure
    pub cpu_decode_pressure: Arc<Gauge>,
    /// Repair return on investment
    pub repair_roi: Arc<Histogram>,
    /// Relay vs direct path delta
    pub relay_direct_delta: Arc<Histogram>,
    /// Path migration event counter
    pub migration_events: Arc<Counter>,
    /// Cancellation pressure
    pub cancellation_pressure: Arc<Gauge>,
    /// Obligation drain latency
    pub obligation_drain_latency: Arc<Histogram>,
}

impl NetworkTruthMetrics {
    /// Creates a new network truth metrics instance with default buckets.
    pub fn new() -> Self {
        // RTT buckets: 0.1ms to 5s
        let rtt_buckets = vec![
            0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ];

        // Latency buckets: 10μs to 1s
        let latency_buckets = vec![
            0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
        ];

        // Delta buckets: -90% to +1000% (relay worse/better than direct)
        let delta_buckets = vec![
            -0.9, -0.5, -0.2, -0.1, -0.05, 0.0, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0,
        ];

        // ROI buckets: 0.1x to 100x
        let roi_buckets = vec![
            0.1, 0.2, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0, 100.0,
        ];

        Self {
            rtt: Arc::new(Histogram::new("atp_network_rtt_seconds", rtt_buckets)),
            ack_delay: Arc::new(Histogram::new(
                "atp_network_ack_delay_seconds",
                latency_buckets.clone(),
            )),
            loss_events: Arc::new(Counter::new("atp_network_loss_events_total")),
            pto_events: Arc::new(Counter::new("atp_network_pto_events_total")),
            congestion_window: Arc::new(Gauge::new("atp_network_cwnd_bytes")),
            bytes_in_flight: Arc::new(Gauge::new("atp_network_bytes_in_flight")),
            send_buffer_pressure: Arc::new(Gauge::new("atp_network_send_buffer_pressure_ratio")),
            recv_buffer_pressure: Arc::new(Gauge::new("atp_network_recv_buffer_pressure_ratio")),
            disk_latency: Arc::new(Histogram::new(
                "atp_disk_latency_seconds",
                latency_buckets.clone(),
            )),
            cpu_encode_pressure: Arc::new(Gauge::new("atp_cpu_encode_pressure_ratio")),
            cpu_decode_pressure: Arc::new(Gauge::new("atp_cpu_decode_pressure_ratio")),
            repair_roi: Arc::new(Histogram::new("atp_repair_roi_ratio", roi_buckets)),
            relay_direct_delta: Arc::new(Histogram::new(
                "atp_relay_direct_delta_ratio",
                delta_buckets,
            )),
            migration_events: Arc::new(Counter::new("atp_path_migration_events_total")),
            cancellation_pressure: Arc::new(Gauge::new("atp_cancellation_pressure_ratio")),
            obligation_drain_latency: Arc::new(Histogram::new(
                "atp_obligation_drain_latency_seconds",
                latency_buckets,
            )),
        }
    }
}

impl Default for NetworkTruthMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Path quality assessment based on observed metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathQuality {
    /// Path identifier
    pub path_id: String,
    /// RTT estimate with confidence interval
    pub rtt_estimate: MetricEstimate,
    /// Loss rate estimate
    pub loss_rate: MetricEstimate,
    /// Available bandwidth estimate (bytes/sec)
    pub bandwidth_estimate: MetricEstimate,
    /// Path stability score (0.0-1.0)
    pub stability_score: f64,
    /// Timestamp of last update (seconds since Unix epoch)
    #[serde(with = "system_time_serde")]
    pub last_updated: SystemTime,
}

/// Metric estimate with uncertainty bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricEstimate {
    /// Point estimate
    pub value: f64,
    /// Lower bound (95% confidence)
    pub lower_bound: f64,
    /// Upper bound (95% confidence)
    pub upper_bound: f64,
    /// Number of observations
    pub sample_count: u64,
}

/// Pressure model combining multiple signal sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureModel {
    /// Network pressure (0.0-1.0)
    pub network: f64,
    /// Disk I/O pressure (0.0-1.0)
    pub disk: f64,
    /// CPU pressure (0.0-1.0)
    pub cpu: f64,
    /// Memory pressure (0.0-1.0)
    pub memory: f64,
    /// Overall pressure score (0.0-1.0)
    pub overall: f64,
    /// Hysteresis threshold to prevent oscillation
    pub hysteresis_threshold: f64,
}

impl PressureModel {
    /// Creates a new pressure model with default thresholds.
    pub fn new() -> Self {
        Self {
            network: 0.0,
            disk: 0.0,
            cpu: 0.0,
            memory: 0.0,
            overall: 0.0,
            hysteresis_threshold: 0.1, // 10% change required to update
        }
    }

    /// Updates the pressure model with hysteresis to prevent oscillation.
    pub fn update(&mut self, new_network: f64, new_disk: f64, new_cpu: f64, new_memory: f64) {
        let new_overall = (new_network + new_disk + new_cpu + new_memory) / 4.0;

        // Apply hysteresis: only update if change is significant
        if (new_overall - self.overall).abs() > self.hysteresis_threshold {
            self.network = new_network;
            self.disk = new_disk;
            self.cpu = new_cpu;
            self.memory = new_memory;
            self.overall = new_overall;
        }
    }

    /// Returns true if the system is under significant pressure.
    pub fn is_stressed(&self) -> bool {
        self.overall > 0.7 // 70% threshold
    }
}

impl Default for PressureModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Network truth collector that aggregates observations.
#[derive(Debug)]
pub struct NetworkTruthCollector {
    metrics: NetworkTruthMetrics,
    path_qualities: Arc<Mutex<BTreeMap<String, PathQuality>>>,
    pressure_model: Arc<Mutex<PressureModel>>,
}

impl NetworkTruthCollector {
    /// Creates a new network truth collector.
    pub fn new() -> Self {
        Self {
            metrics: NetworkTruthMetrics::new(),
            path_qualities: Arc::new(Mutex::new(BTreeMap::new())),
            pressure_model: Arc::new(Mutex::new(PressureModel::new())),
        }
    }

    /// Records an RTT observation.
    pub fn record_rtt(&self, rtt: Duration) {
        self.metrics.rtt.observe(rtt.as_secs_f64());
    }

    /// Records an ACK delay observation.
    pub fn record_ack_delay(&self, delay: Duration) {
        self.metrics.ack_delay.observe(delay.as_secs_f64());
    }

    /// Records a packet loss event.
    pub fn record_loss_event(&self) {
        self.metrics.loss_events.increment();
    }

    /// Records a probe timeout event.
    pub fn record_pto_event(&self) {
        self.metrics.pto_events.increment();
    }

    /// Updates congestion window size.
    pub fn update_congestion_window(&self, bytes: u64) {
        self.metrics.congestion_window.set(bytes.cast_signed());
    }

    /// Updates bytes in flight.
    pub fn update_bytes_in_flight(&self, bytes: u64) {
        self.metrics.bytes_in_flight.set(bytes.cast_signed());
    }

    /// Updates buffer pressure (0.0-1.0).
    pub fn update_buffer_pressure(&self, send_pressure: f64, recv_pressure: f64) {
        let send_percent = (send_pressure * 100.0) as i64;
        let recv_percent = (recv_pressure * 100.0) as i64;

        self.metrics.send_buffer_pressure.set(send_percent);
        self.metrics.recv_buffer_pressure.set(recv_percent);
    }

    /// Records disk I/O latency.
    pub fn record_disk_latency(&self, latency: Duration) {
        self.metrics.disk_latency.observe(latency.as_secs_f64());
    }

    /// Updates CPU pressure (0.0-1.0).
    pub fn update_cpu_pressure(&self, encode_pressure: f64, decode_pressure: f64) {
        let encode_percent = (encode_pressure * 100.0) as i64;
        let decode_percent = (decode_pressure * 100.0) as i64;

        self.metrics.cpu_encode_pressure.set(encode_percent);
        self.metrics.cpu_decode_pressure.set(decode_percent);
    }

    /// Records repair return on investment.
    pub fn record_repair_roi(&self, roi: f64) {
        self.metrics.repair_roi.observe(roi);
    }

    /// Records relay vs direct path performance delta.
    pub fn record_relay_direct_delta(&self, delta_ratio: f64) {
        self.metrics.relay_direct_delta.observe(delta_ratio);
    }

    /// Records a path migration event.
    pub fn record_migration_event(&self) {
        self.metrics.migration_events.increment();
    }

    /// Updates cancellation pressure (0.0-1.0).
    pub fn update_cancellation_pressure(&self, pressure: f64) {
        let pressure_percent = (pressure * 100.0) as i64;
        self.metrics.cancellation_pressure.set(pressure_percent);
    }

    /// Records obligation drain latency.
    pub fn record_obligation_drain_latency(&self, latency: Duration) {
        self.metrics
            .obligation_drain_latency
            .observe(latency.as_secs_f64());
    }

    /// Updates path quality assessment.
    pub fn update_path_quality(&self, path_id: String, quality: PathQuality) {
        if let Ok(mut qualities) = self.path_qualities.lock() {
            qualities.insert(path_id, quality);
        }
    }

    /// Gets current path quality for a given path.
    pub fn get_path_quality(&self, path_id: &str) -> Option<PathQuality> {
        self.path_qualities.lock().ok()?.get(path_id).cloned()
    }

    /// Returns a point-in-time snapshot of all known path quality assessments.
    #[must_use]
    pub fn path_qualities(&self) -> BTreeMap<String, PathQuality> {
        self.path_qualities
            .lock()
            .map(|qualities| qualities.clone())
            .unwrap_or_default()
    }

    /// Updates the pressure model.
    pub fn update_pressure_model(&self, network: f64, disk: f64, cpu: f64, memory: f64) {
        if let Ok(mut model) = self.pressure_model.lock() {
            model.update(network, disk, cpu, memory);
        }
    }

    /// Gets the current pressure model.
    pub fn get_pressure_model(&self) -> Option<PressureModel> {
        self.pressure_model.lock().ok().map(|model| model.clone())
    }

    /// Gets access to the underlying metrics for integration with scheduler/diagnostics.
    pub fn metrics(&self) -> &NetworkTruthMetrics {
        &self.metrics
    }
}

impl Default for NetworkTruthCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_network_truth_collector() {
        let collector = NetworkTruthCollector::new();

        // Record some observations
        collector.record_rtt(Duration::from_millis(50));
        collector.record_ack_delay(Duration::from_millis(5));
        collector.record_loss_event();
        collector.record_pto_event();

        // Verify metrics were updated
        assert_eq!(collector.metrics().rtt.count(), 1);
        assert_eq!(collector.metrics().ack_delay.count(), 1);
        assert_eq!(collector.metrics().loss_events.get(), 1);
        assert_eq!(collector.metrics().pto_events.get(), 1);
    }

    #[test]
    fn test_pressure_model_hysteresis() {
        let mut model = PressureModel::new();

        // Initial update should work
        model.update(0.5, 0.3, 0.2, 0.1);
        assert_eq!(model.overall, 0.275);

        // Small change should not update due to hysteresis
        let old_overall = model.overall;
        model.update(0.52, 0.31, 0.21, 0.11);
        assert_eq!(model.overall, old_overall);

        // Large change should update
        model.update(0.8, 0.7, 0.6, 0.5);
        assert!(model.overall > old_overall);
    }

    #[test]
    fn test_path_quality_estimate() {
        let estimate = MetricEstimate {
            value: 50.0,
            lower_bound: 45.0,
            upper_bound: 55.0,
            sample_count: 100,
        };

        // Verify confidence interval makes sense
        assert!(estimate.lower_bound <= estimate.value);
        assert!(estimate.value <= estimate.upper_bound);
        assert!(estimate.sample_count > 0);
    }

    #[test]
    fn test_buffer_pressure_bounds() {
        let collector = NetworkTruthCollector::new();

        // Test boundary values
        collector.update_buffer_pressure(0.0, 0.0);
        assert_eq!(collector.metrics().send_buffer_pressure.get(), 0);
        assert_eq!(collector.metrics().recv_buffer_pressure.get(), 0);

        collector.update_buffer_pressure(1.0, 1.0);
        assert_eq!(collector.metrics().send_buffer_pressure.get(), 100);
        assert_eq!(collector.metrics().recv_buffer_pressure.get(), 100);
    }

    #[test]
    fn test_metric_estimates_serialization() {
        let estimate = MetricEstimate {
            value: 42.0,
            lower_bound: 40.0,
            upper_bound: 44.0,
            sample_count: 1000,
        };

        // Test that serialization works (for CLI/JSON output)
        let json = serde_json::to_string(&estimate).unwrap();
        let deserialized: MetricEstimate = serde_json::from_str(&json).unwrap();

        assert_eq!(estimate.value, deserialized.value);
        assert_eq!(estimate.sample_count, deserialized.sample_count);
    }
}
