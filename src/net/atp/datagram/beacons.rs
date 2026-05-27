//! Path Quality Beacons via DATAGRAM
//!
//! Implements periodic path quality measurement using DATAGRAM frames.

use crate::bytes::Bytes;
use crate::net::atp::datagram::frame::{DatagramFrame, DatagramMetadata, DatagramPriority};
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Path quality beacon payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathBeacon {
    /// Beacon sequence number
    pub sequence: u64,
    /// Timestamp when beacon was sent (microseconds since Unix epoch)
    pub send_timestamp: u64,
    /// Path identifier
    pub path_id: u64,
    /// Beacon type
    pub beacon_type: BeaconType,
    /// Additional measurement data
    pub measurement_data: BeaconMeasurement,
}

/// Types of path beacons
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BeaconType {
    /// Regular periodic beacon
    Periodic,
    /// Response to received beacon
    Response,
    /// Path quality probe
    Probe,
    /// NAT keepalive beacon
    Keepalive,
    /// Migration signal beacon
    Migration,
}

/// Beacon measurement data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMeasurement {
    /// Congestion window size (bytes)
    pub cwnd_bytes: Option<u32>,
    /// Smoothed RTT (microseconds)
    pub srtt_us: Option<u32>,
    /// RTT variance (microseconds)
    pub rttvar_us: Option<u32>,
    /// Bytes in flight
    pub bytes_in_flight: Option<u32>,
    /// Loss rate (packets per 1000)
    pub loss_rate_per_1000: Option<u16>,
    /// Bandwidth estimate (bytes per second)
    pub bandwidth_bps: Option<u64>,
    /// Path MTU estimate
    pub mtu_estimate: Option<u16>,
}

impl BeaconMeasurement {
    /// Create empty measurement
    pub fn empty() -> Self {
        Self {
            cwnd_bytes: None,
            srtt_us: None,
            rttvar_us: None,
            bytes_in_flight: None,
            loss_rate_per_1000: None,
            bandwidth_bps: None,
            mtu_estimate: None,
        }
    }

    /// Create measurement with basic RTT data
    pub fn with_rtt(srtt_us: u32, rttvar_us: u32) -> Self {
        Self {
            cwnd_bytes: None,
            srtt_us: Some(srtt_us),
            rttvar_us: Some(rttvar_us),
            bytes_in_flight: None,
            loss_rate_per_1000: None,
            bandwidth_bps: None,
            mtu_estimate: None,
        }
    }
}

impl Default for BeaconMeasurement {
    fn default() -> Self {
        Self::empty()
    }
}

impl PathBeacon {
    /// Create a new path beacon
    pub fn new(
        sequence: u64,
        path_id: u64,
        beacon_type: BeaconType,
        measurement_data: BeaconMeasurement,
    ) -> Self {
        let send_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            sequence,
            send_timestamp,
            path_id,
            beacon_type,
            measurement_data,
        }
    }

    /// Create periodic beacon
    pub fn periodic(sequence: u64, path_id: u64) -> Self {
        Self::new(
            sequence,
            path_id,
            BeaconType::Periodic,
            BeaconMeasurement::empty(),
        )
    }

    /// Create response beacon
    pub fn response(sequence: u64, path_id: u64, measurement: BeaconMeasurement) -> Self {
        Self::new(sequence, path_id, BeaconType::Response, measurement)
    }

    /// Create keepalive beacon
    pub fn keepalive(sequence: u64, path_id: u64) -> Self {
        Self::new(
            sequence,
            path_id,
            BeaconType::Keepalive,
            BeaconMeasurement::empty(),
        )
    }

    /// Encode beacon to bytes
    pub fn encode(&self) -> Outcome<Bytes, Box<dyn std::error::Error>> {
        let json = match serde_json::to_vec(self) {
            Ok(data) => data,
            Err(e) => return Outcome::err(Box::new(e) as Box<dyn std::error::Error>),
        };
        Outcome::ok(Bytes::from(json))
    }

    /// Decode beacon from bytes
    pub fn decode(data: &[u8]) -> Outcome<Self, Box<dyn std::error::Error>> {
        let beacon: Self = match serde_json::from_slice(data) {
            Ok(b) => b,
            Err(e) => return Outcome::err(Box::new(e) as Box<dyn std::error::Error>),
        };
        Outcome::ok(beacon)
    }

    /// Create DATAGRAM frame for this beacon
    pub fn to_datagram_frame(&self) -> Outcome<DatagramFrame, Box<dyn std::error::Error>> {
        let payload = match self.encode() {
            Outcome::Ok(p) => p,
            Outcome::Err(e) => return Outcome::err(e),
            Outcome::Cancelled(r) => return Outcome::cancelled(r),
            Outcome::Panicked(p) => return Outcome::panicked(p),
        };
        Outcome::ok(DatagramFrame::with_length(payload))
    }

    /// Get beacon age since creation
    pub fn age(&self) -> Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Duration::from_micros(now.saturating_sub(self.send_timestamp))
    }

    /// Create metadata for this beacon
    pub fn metadata(&self) -> DatagramMetadata {
        let priority = match self.beacon_type {
            BeaconType::Probe => DatagramPriority::High,
            BeaconType::Response => DatagramPriority::High,
            BeaconType::Periodic => DatagramPriority::Normal,
            BeaconType::Keepalive => DatagramPriority::Low,
            BeaconType::Migration => DatagramPriority::High,
        };

        DatagramMetadata::new(format!("beacon_{:?}", self.beacon_type).to_lowercase())
            .with_priority(priority)
            .with_correlation_id(self.sequence)
            .with_path_id(self.path_id)
    }
}

/// Path beacon statistics
#[derive(Debug, Clone)]
pub struct BeaconStats {
    /// Path ID
    pub path_id: u64,
    /// Total beacons sent
    pub sent_count: u64,
    /// Total beacons received
    pub received_count: u64,
    /// Total beacon responses received
    pub response_count: u64,
    /// Average round-trip time
    pub avg_rtt: Option<Duration>,
    /// Recent RTT measurements (circular buffer)
    pub recent_rtts: Vec<Duration>,
    /// Last beacon sequence sent
    pub last_sent_sequence: u64,
    /// Last beacon sequence received
    pub last_received_sequence: u64,
    /// Estimated loss rate
    pub loss_rate: f64,
    /// Last update timestamp
    pub last_update: Instant,
}

impl BeaconStats {
    /// Create new beacon statistics
    pub fn new(path_id: u64) -> Self {
        Self {
            path_id,
            sent_count: 0,
            received_count: 0,
            response_count: 0,
            avg_rtt: None,
            recent_rtts: Vec::new(),
            last_sent_sequence: 0,
            last_received_sequence: 0,
            loss_rate: 0.0,
            last_update: Instant::now(),
        }
    }

    /// Record sent beacon
    pub fn record_sent(&mut self, sequence: u64) {
        self.sent_count += 1;
        self.last_sent_sequence = sequence;
        self.last_update = Instant::now();
    }

    /// Record received beacon
    pub fn record_received(&mut self, sequence: u64) {
        self.received_count += 1;
        self.last_received_sequence = sequence;
        self.last_update = Instant::now();
    }

    /// Record beacon response with RTT
    pub fn record_response(&mut self, rtt: Duration) {
        self.response_count += 1;

        // Update RTT measurements
        self.recent_rtts.push(rtt);
        if self.recent_rtts.len() > 10 {
            self.recent_rtts.remove(0);
        }

        // Calculate average RTT
        if !self.recent_rtts.is_empty() {
            let total: Duration = self.recent_rtts.iter().sum();
            self.avg_rtt = Some(total / self.recent_rtts.len() as u32);
        }

        // Update loss rate estimation
        if self.sent_count > 0 {
            self.loss_rate = 1.0 - (self.response_count as f64 / self.sent_count as f64);
        }

        self.last_update = Instant::now();
    }

    /// Get current RTT estimate
    pub fn current_rtt(&self) -> Option<Duration> {
        self.avg_rtt
    }

    /// Get loss rate percentage
    pub fn loss_rate_percent(&self) -> f64 {
        self.loss_rate * 100.0
    }
}

/// Path beacon manager
#[derive(Debug)]
pub struct BeaconManager {
    /// Beacon statistics by path ID
    path_stats: HashMap<u64, BeaconStats>,
    /// Next sequence number
    next_sequence: u64,
    /// Beacon interval
    beacon_interval: Duration,
    /// Maximum beacon age before expiration
    #[allow(dead_code)]
    max_beacon_age: Duration,
    /// Last beacon send time by path
    last_beacon_time: HashMap<u64, Instant>,
    /// Enabled beacon types
    enabled_types: HashMap<BeaconType, bool>,
}

impl BeaconManager {
    /// Create new beacon manager
    pub fn new(beacon_interval: Duration) -> Self {
        let mut enabled_types = HashMap::new();
        enabled_types.insert(BeaconType::Periodic, true);
        enabled_types.insert(BeaconType::Response, true);
        enabled_types.insert(BeaconType::Probe, true);
        enabled_types.insert(BeaconType::Keepalive, true);
        enabled_types.insert(BeaconType::Migration, false); // Disabled by default

        Self {
            path_stats: HashMap::new(),
            next_sequence: 1,
            beacon_interval,
            max_beacon_age: Duration::from_secs(30),
            last_beacon_time: HashMap::new(),
            enabled_types,
        }
    }

    /// Create beacon manager with defaults
    pub fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }

    /// Enable/disable beacon type
    pub fn set_beacon_type_enabled(&mut self, beacon_type: BeaconType, enabled: bool) {
        self.enabled_types.insert(beacon_type, enabled);
    }

    /// Check if beacon type is enabled
    pub fn is_beacon_type_enabled(&self, beacon_type: BeaconType) -> bool {
        self.enabled_types
            .get(&beacon_type)
            .copied()
            .unwrap_or(false)
    }

    /// Check if it's time to send a beacon on a path
    pub fn should_send_beacon(&self, path_id: u64) -> bool {
        if !self.is_beacon_type_enabled(BeaconType::Periodic) {
            return false;
        }

        match self.last_beacon_time.get(&path_id) {
            Some(last_time) => last_time.elapsed() >= self.beacon_interval,
            None => true, // Never sent a beacon on this path
        }
    }

    /// Create periodic beacon for path
    pub fn create_beacon(&mut self, path_id: u64, measurement: BeaconMeasurement) -> PathBeacon {
        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let beacon = PathBeacon::new(sequence, path_id, BeaconType::Periodic, measurement);

        // Update stats
        let stats = self
            .path_stats
            .entry(path_id)
            .or_insert_with(|| BeaconStats::new(path_id));
        stats.record_sent(sequence);

        // Update last beacon time
        self.last_beacon_time.insert(path_id, Instant::now());

        beacon
    }

    /// Create response beacon
    pub fn create_response_beacon(
        &mut self,
        path_id: u64,
        measurement: BeaconMeasurement,
    ) -> Option<PathBeacon> {
        if !self.is_beacon_type_enabled(BeaconType::Response) {
            return None;
        }

        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let beacon = PathBeacon::new(sequence, path_id, BeaconType::Response, measurement);

        // Update stats
        let stats = self
            .path_stats
            .entry(path_id)
            .or_insert_with(|| BeaconStats::new(path_id));
        stats.record_sent(sequence);

        Some(beacon)
    }

    /// Process received beacon
    pub fn process_received_beacon(&mut self, beacon: PathBeacon) -> Option<PathBeacon> {
        let path_id = beacon.path_id;

        // Update receive stats
        let stats = self
            .path_stats
            .entry(path_id)
            .or_insert_with(|| BeaconStats::new(path_id));
        stats.record_received(beacon.sequence);

        match beacon.beacon_type {
            BeaconType::Periodic | BeaconType::Probe => {
                // Send response beacon if enabled
                let measurement = BeaconMeasurement::empty(); // Would populate with actual measurements
                self.create_response_beacon(path_id, measurement)
            }
            BeaconType::Response => {
                // Calculate RTT and update stats
                let rtt = beacon.age();
                stats.record_response(rtt);
                None
            }
            BeaconType::Keepalive | BeaconType::Migration => {
                // No response needed
                None
            }
        }
    }

    /// Get beacon statistics for path
    pub fn get_path_stats(&self, path_id: u64) -> Option<&BeaconStats> {
        self.path_stats.get(&path_id)
    }

    /// Get all path statistics
    pub fn get_all_stats(&self) -> &HashMap<u64, BeaconStats> {
        &self.path_stats
    }

    /// Clean up old statistics
    pub fn cleanup_old_stats(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.path_stats
            .retain(|_, stats| now.duration_since(stats.last_update) < max_age);
        self.last_beacon_time
            .retain(|path_id, _| self.path_stats.contains_key(path_id));
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> BeaconSummary {
        let mut summary = BeaconSummary::default();

        for stats in self.path_stats.values() {
            summary.total_paths += 1;
            summary.total_sent += stats.sent_count;
            summary.total_received += stats.received_count;
            summary.total_responses += stats.response_count;

            if let Some(rtt) = stats.avg_rtt {
                summary.avg_rtt_samples.push(rtt);
            }

            if stats.loss_rate > 0.0 {
                summary.loss_rate_samples.push(stats.loss_rate);
            }
        }

        // Calculate overall averages
        if !summary.avg_rtt_samples.is_empty() {
            let total: Duration = summary.avg_rtt_samples.iter().sum();
            summary.overall_avg_rtt = Some(total / summary.avg_rtt_samples.len() as u32);
        }

        if !summary.loss_rate_samples.is_empty() {
            summary.overall_loss_rate = summary.loss_rate_samples.iter().sum::<f64>()
                / summary.loss_rate_samples.len() as f64;
        }

        summary
    }
}

/// Beacon summary statistics
#[derive(Debug, Clone, Default)]
pub struct BeaconSummary {
    /// Total number of paths
    pub total_paths: u64,
    /// Total beacons sent across all paths
    pub total_sent: u64,
    /// Total beacons received across all paths
    pub total_received: u64,
    /// Total responses received across all paths
    pub total_responses: u64,
    /// Overall average RTT
    pub overall_avg_rtt: Option<Duration>,
    /// Overall loss rate
    pub overall_loss_rate: f64,
    /// RTT samples for averaging
    avg_rtt_samples: Vec<Duration>,
    /// Loss rate samples for averaging
    loss_rate_samples: Vec<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_beacon_creation() {
        let measurement = BeaconMeasurement::with_rtt(50000, 5000);
        let beacon = PathBeacon::new(1, 42, BeaconType::Periodic, measurement);

        assert_eq!(beacon.sequence, 1);
        assert_eq!(beacon.path_id, 42);
        assert_eq!(beacon.beacon_type, BeaconType::Periodic);
        assert_eq!(beacon.measurement_data.srtt_us, Some(50000));
    }

    #[test]
    fn test_beacon_encoding() {
        let beacon = PathBeacon::periodic(1, 42);
        let encoded = beacon.encode().unwrap();
        let decoded = PathBeacon::decode(&encoded).unwrap();

        assert_eq!(decoded.sequence, beacon.sequence);
        assert_eq!(decoded.path_id, beacon.path_id);
        assert_eq!(decoded.beacon_type, beacon.beacon_type);
    }

    #[test]
    fn test_beacon_metadata() {
        let beacon = PathBeacon::periodic(1, 42);
        let metadata = beacon.metadata();

        assert_eq!(metadata.correlation_id, Some(1));
        assert_eq!(metadata.path_id, Some(42));
        assert_eq!(metadata.priority, DatagramPriority::Normal);
        assert_eq!(metadata.payload_class, "beacon_periodic");
    }

    #[test]
    fn test_beacon_stats() {
        let mut stats = BeaconStats::new(42);

        assert_eq!(stats.path_id, 42);
        assert_eq!(stats.sent_count, 0);
        assert_eq!(stats.received_count, 0);

        stats.record_sent(1);
        stats.record_sent(2);
        assert_eq!(stats.sent_count, 2);
        assert_eq!(stats.last_sent_sequence, 2);

        stats.record_received(1);
        assert_eq!(stats.received_count, 1);

        stats.record_response(Duration::from_millis(50));
        stats.record_response(Duration::from_millis(60));

        assert_eq!(stats.response_count, 2);
        assert_eq!(stats.avg_rtt, Some(Duration::from_millis(55)));
        assert_eq!(stats.loss_rate, 0.0); // 2 responses / 2 sent = 0% loss
    }

    #[test]
    fn test_beacon_manager() {
        let mut manager = BeaconManager::new(Duration::from_secs(1));

        // Should send initial beacon
        assert!(manager.should_send_beacon(1));

        let measurement = BeaconMeasurement::empty();
        let beacon = manager.create_beacon(1, measurement);
        assert_eq!(beacon.path_id, 1);
        assert_eq!(beacon.sequence, 1);

        // Should not send again immediately
        assert!(!manager.should_send_beacon(1));

        // Process a beacon response.
        let response_beacon =
            PathBeacon::response(beacon.sequence, beacon.path_id, BeaconMeasurement::empty());
        let response = manager.process_received_beacon(response_beacon);
        assert!(response.is_none()); // Response beacons don't generate responses

        // Check stats
        let stats = manager.get_path_stats(1).unwrap();
        assert_eq!(stats.sent_count, 1);
        assert_eq!(stats.received_count, 1);
    }

    #[test]
    fn test_beacon_type_enabling() {
        let mut manager = BeaconManager::default();

        assert!(manager.is_beacon_type_enabled(BeaconType::Periodic));
        assert!(!manager.is_beacon_type_enabled(BeaconType::Migration));

        manager.set_beacon_type_enabled(BeaconType::Migration, true);
        assert!(manager.is_beacon_type_enabled(BeaconType::Migration));

        manager.set_beacon_type_enabled(BeaconType::Periodic, false);
        assert!(!manager.is_beacon_type_enabled(BeaconType::Periodic));
        assert!(!manager.should_send_beacon(1)); // No beacon when disabled
    }
}
