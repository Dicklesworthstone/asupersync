//! QUIC DATAGRAM Path Probes
//!
//! Implements path discovery and quality measurement via unreliable DATAGRAM frames.
//! Probes are used to discover alternative paths, measure RTT/bandwidth, and detect
//! path failures without affecting critical data flows.

use crate::bytes::Bytes;
use crate::net::atp::datagram::frame::{
    DatagramError, DatagramFrame, DatagramMetadata, DatagramPriority,
};
use crate::net::atp::datagram::transport::DatagramTransport;
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Path probe types for different discovery scenarios
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeType {
    /// Initial path discovery probe
    Discovery,
    /// RTT measurement probe
    Rtt,
    /// Bandwidth estimation probe
    Bandwidth,
    /// Path validation probe
    Validation,
    /// Keep-alive probe for established paths
    KeepAlive,
}

impl ProbeType {
    /// Get recommended timeout for probe type
    pub fn timeout(&self) -> Duration {
        match self {
            Self::Discovery => Duration::from_secs(5),
            Self::Rtt => Duration::from_secs(2),
            Self::Bandwidth => Duration::from_secs(3),
            Self::Validation => Duration::from_secs(1),
            Self::KeepAlive => Duration::from_secs(10),
        }
    }

    /// Get recommended probe payload size
    pub fn payload_size(&self) -> usize {
        match self {
            Self::Discovery => 32,
            Self::Rtt => 16,
            Self::Bandwidth => 64,
            Self::Validation => 24,
            Self::KeepAlive => 8,
        }
    }

    /// Get probe priority for congestion control
    pub fn priority(&self) -> DatagramPriority {
        match self {
            Self::Discovery | Self::Validation => DatagramPriority::High,
            Self::Rtt | Self::KeepAlive => DatagramPriority::Normal,
            Self::Bandwidth => DatagramPriority::Low,
        }
    }
}

/// Path probe request/response packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathProbe {
    /// Probe identifier for request/response matching
    pub probe_id: u64,
    /// Probe type
    pub probe_type: ProbeType,
    /// Timestamp when probe was sent (microseconds since epoch)
    pub timestamp: u64,
    /// Path identifier being probed
    pub path_id: u64,
    /// Sequence number for this probe type
    pub sequence: u32,
    /// Response flag (true for responses)
    pub is_response: bool,
    /// Optional challenge data for validation
    pub challenge: Option<Vec<u8>>,
    /// Optional payload for bandwidth testing
    pub payload: Option<Vec<u8>>,
}

impl PathProbe {
    /// Create new probe request
    pub fn new_request(probe_id: u64, probe_type: ProbeType, path_id: u64, sequence: u32) -> Self {
        Self {
            probe_id,
            probe_type,
            timestamp: Self::current_timestamp(),
            path_id,
            sequence,
            is_response: false,
            challenge: None,
            payload: None,
        }
    }

    /// Create response to probe request
    pub fn new_response(&self) -> Self {
        Self {
            probe_id: self.probe_id,
            probe_type: self.probe_type,
            timestamp: Self::current_timestamp(),
            path_id: self.path_id,
            sequence: self.sequence,
            is_response: true,
            challenge: self.challenge.clone(),
            payload: None, // Don't echo payload
        }
    }

    /// Add challenge data for validation probes
    pub fn with_challenge(mut self, challenge: Vec<u8>) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// Add payload data for bandwidth probes
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Encode probe to JSON bytes
    pub fn encode(&self) -> Outcome<Bytes, DatagramError> {
        match serde_json::to_vec(self) {
            Ok(bytes) => Outcome::ok(Bytes::from(bytes)),
            Err(e) => Outcome::err(DatagramError::EncodingFailed(format!(
                "probe encoding: {}",
                e
            ))),
        }
    }

    /// Decode probe from JSON bytes
    pub fn decode(data: &[u8]) -> Outcome<Self, DatagramError> {
        match serde_json::from_slice(data) {
            Ok(probe) => Outcome::ok(probe),
            Err(e) => Outcome::err(DatagramError::InvalidFrame(format!(
                "probe decoding: {}",
                e
            ))),
        }
    }

    /// Get current timestamp in microseconds
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }

    /// Calculate RTT from response
    pub fn calculate_rtt(&self, response: &PathProbe) -> Option<Duration> {
        if !response.is_response || response.probe_id != self.probe_id {
            return None;
        }

        response
            .timestamp
            .checked_sub(self.timestamp)
            .map(Duration::from_micros)
    }
}

/// Path probe statistics
#[derive(Debug, Clone, Default)]
pub struct ProbeStats {
    /// Total probes sent
    pub probes_sent: u64,
    /// Total responses received
    pub responses_received: u64,
    /// Average RTT in microseconds
    pub avg_rtt_us: f64,
    /// Minimum RTT in microseconds
    pub min_rtt_us: u64,
    /// Maximum RTT in microseconds
    pub max_rtt_us: u64,
    /// Packet loss ratio (0.0 - 1.0)
    pub loss_ratio: f64,
    /// Last successful probe timestamp
    pub last_success: Option<Instant>,
    /// Bandwidth estimate in bytes per second
    pub bandwidth_bps: Option<u64>,
}

impl ProbeStats {
    /// Update stats with new probe result
    pub fn update_probe_sent(&mut self) {
        self.probes_sent += 1;
        self.update_loss_ratio();
    }

    /// Update stats with probe response
    pub fn update_response_received(&mut self, rtt: Duration) {
        self.responses_received += 1;
        self.last_success = Some(Instant::now());

        let rtt_us = rtt.as_micros() as u64;

        // Update RTT statistics
        if self.responses_received == 1 {
            self.min_rtt_us = rtt_us;
            self.max_rtt_us = rtt_us;
            self.avg_rtt_us = rtt_us as f64;
        } else {
            self.min_rtt_us = self.min_rtt_us.min(rtt_us);
            self.max_rtt_us = self.max_rtt_us.max(rtt_us);

            // Exponential moving average
            let alpha = 0.1;
            self.avg_rtt_us = alpha * (rtt_us as f64) + (1.0 - alpha) * self.avg_rtt_us;
        }

        self.update_loss_ratio();
    }

    /// Update bandwidth estimate
    pub fn update_bandwidth(&mut self, bytes: usize, duration: Duration) {
        if duration.as_secs_f64() > 0.0 {
            let bps = (bytes as f64 / duration.as_secs_f64()) as u64;
            self.bandwidth_bps = Some(match self.bandwidth_bps {
                Some(old_bps) => {
                    // Exponential moving average
                    let alpha = 0.2;
                    ((1.0 - alpha) * old_bps as f64 + alpha * bps as f64) as u64
                }
                None => bps,
            });
        }
    }

    /// Calculate current loss ratio
    fn update_loss_ratio(&mut self) {
        if self.probes_sent > 0 {
            self.loss_ratio = 1.0 - (self.responses_received as f64 / self.probes_sent as f64);
        }
    }

    /// Check if path appears healthy
    pub fn is_healthy(&self) -> bool {
        self.loss_ratio < 0.1 && // Less than 10% loss
        self.last_success.is_some_and(|t| t.elapsed() < Duration::from_secs(60))
    }
}

/// Path probe manager
#[derive(Debug)]
pub struct ProbeManager {
    /// Next probe ID
    next_probe_id: u64,
    /// Active probes awaiting responses
    pending_probes: HashMap<u64, (PathProbe, Instant)>,
    /// Per-path statistics
    path_stats: HashMap<u64, ProbeStats>,
    /// Sequence counters per probe type
    sequences: HashMap<ProbeType, u32>,
    /// Datagram transport handler
    transport: DatagramTransport,
}

impl ProbeManager {
    /// Create new probe manager
    pub fn new(transport: DatagramTransport) -> Self {
        Self {
            next_probe_id: 1,
            pending_probes: HashMap::new(),
            path_stats: HashMap::new(),
            sequences: HashMap::new(),
            transport,
        }
    }

    /// Generate next probe ID
    fn next_probe_id(&mut self) -> u64 {
        let id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);
        id
    }

    /// Generate next sequence number for probe type
    fn next_sequence(&mut self, probe_type: ProbeType) -> u32 {
        let seq = self.sequences.entry(probe_type).or_insert(0);
        *seq = seq.wrapping_add(1);
        *seq
    }

    /// Create probe request
    pub fn create_probe(
        &mut self,
        probe_type: ProbeType,
        path_id: u64,
    ) -> Outcome<DatagramFrame, DatagramError> {
        let probe_id = self.next_probe_id();
        let sequence = self.next_sequence(probe_type);

        let mut probe = PathProbe::new_request(probe_id, probe_type, path_id, sequence);

        // Add type-specific data
        match probe_type {
            ProbeType::Discovery | ProbeType::Validation => {
                // Add challenge for validation
                let challenge = (0..16).map(|_| rand::random::<u8>()).collect();
                probe = probe.with_challenge(challenge);
            }
            ProbeType::Bandwidth => {
                // Add payload for bandwidth testing
                let payload = vec![0xAB; probe_type.payload_size()];
                probe = probe.with_payload(payload);
            }
            ProbeType::Rtt | ProbeType::KeepAlive => {
                // Minimal payload
            }
        }

        let probe_data = match probe.encode() {
            Outcome::Ok(bytes) => bytes,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Validate local frame construction size. The actual send path still
        // validates against negotiated peer DATAGRAM support.
        match Self::validate_local_datagram_size(&self.transport, probe_data.len()) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Track pending probe
        self.pending_probes
            .insert(probe_id, (probe.clone(), Instant::now()));

        // Update statistics
        self.path_stats
            .entry(path_id)
            .or_default()
            .update_probe_sent();

        // Create datagram frame
        let _metadata = DatagramMetadata::new("path_probe")
            .with_priority(probe_type.priority())
            .with_correlation_id(probe_id)
            .with_path_id(path_id)
            .with_expiration(Instant::now() + probe_type.timeout());

        Outcome::ok(DatagramFrame::with_length(probe_data))
    }

    /// Process incoming probe (request or response)
    pub fn process_probe(&mut self, data: &[u8]) -> Outcome<Option<DatagramFrame>, DatagramError> {
        let probe = match PathProbe::decode(data) {
            Outcome::Ok(probe) => probe,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        if probe.is_response {
            // Handle probe response
            self.handle_probe_response(probe)
        } else {
            // Handle probe request - generate response
            self.handle_probe_request(probe)
        }
    }

    /// Handle probe response
    fn handle_probe_response(
        &mut self,
        response: PathProbe,
    ) -> Outcome<Option<DatagramFrame>, DatagramError> {
        if let Some((request, _sent_at)) = self.pending_probes.remove(&response.probe_id) {
            // Calculate RTT
            if let Some(rtt) = request.calculate_rtt(&response) {
                let stats = self.path_stats.entry(response.path_id).or_default();
                stats.update_response_received(rtt);

                // Update bandwidth if applicable
                if response.probe_type == ProbeType::Bandwidth {
                    if let Some(ref payload) = request.payload {
                        stats.update_bandwidth(payload.len(), rtt);
                    }
                }
            }
        }

        Outcome::ok(None) // No response frame needed
    }

    /// Handle probe request - generate response
    fn handle_probe_request(
        &mut self,
        request: PathProbe,
    ) -> Outcome<Option<DatagramFrame>, DatagramError> {
        let response = request.new_response();
        let response_data = match response.encode() {
            Outcome::Ok(bytes) => bytes,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Validate local frame construction size. The actual send path still
        // validates against negotiated peer DATAGRAM support.
        match Self::validate_local_datagram_size(&self.transport, response_data.len()) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        let _metadata = DatagramMetadata::new("path_probe_response")
            .with_priority(DatagramPriority::High)
            .with_correlation_id(response.probe_id)
            .with_path_id(response.path_id);

        Outcome::ok(Some(DatagramFrame::with_length(response_data)))
    }

    fn validate_local_datagram_size(
        transport: &DatagramTransport,
        size: usize,
    ) -> Outcome<(), DatagramError> {
        let local_max_size = transport.local_max_size();
        if local_max_size == 0 {
            return Outcome::err(DatagramError::NotSupported);
        }

        let max = local_max_size as usize;
        if size > max {
            return Outcome::err(DatagramError::PayloadTooLarge { size, max });
        }

        Outcome::ok(())
    }

    /// Clean up expired pending probes
    pub fn cleanup_expired_probes(&mut self, now: Instant) {
        let timeout = Duration::from_secs(30); // Global timeout for pending probes

        self.pending_probes
            .retain(|_probe_id, (_probe, sent_at)| now.duration_since(*sent_at) < timeout);
    }

    /// Get statistics for a path
    pub fn get_path_stats(&self, path_id: u64) -> Option<&ProbeStats> {
        self.path_stats.get(&path_id)
    }

    /// Get all path statistics
    pub fn get_all_stats(&self) -> &HashMap<u64, ProbeStats> {
        &self.path_stats
    }

    /// Check if probing is enabled
    pub fn is_enabled(&self) -> bool {
        self.transport.is_enabled()
    }

    /// Get number of pending probes
    pub fn pending_count(&self) -> usize {
        self.pending_probes.len()
    }
}

// Dummy rand implementation for challenge generation
mod rand {
    pub fn random<T>() -> T
    where
        T: From<u8>,
    {
        // Simple PRNG for demo - replace with proper implementation
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEED: AtomicU64 = AtomicU64::new(1);
        let mut x = SEED.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        SEED.store(x, Ordering::Relaxed);
        T::from((x & 0xFF) as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::datagram::transport::DatagramTransport;

    #[test]
    fn test_probe_creation() {
        let probe = PathProbe::new_request(123, ProbeType::Rtt, 1, 42);
        assert_eq!(probe.probe_id, 123);
        assert_eq!(probe.probe_type, ProbeType::Rtt);
        assert_eq!(probe.path_id, 1);
        assert_eq!(probe.sequence, 42);
        assert!(!probe.is_response);

        let response = probe.new_response();
        assert_eq!(response.probe_id, 123);
        assert!(response.is_response);
    }

    #[test]
    fn test_probe_encoding_decoding() {
        let probe = PathProbe::new_request(456, ProbeType::Discovery, 2, 100)
            .with_challenge(vec![1, 2, 3, 4]);

        let encoded = probe.encode().unwrap();
        let decoded = PathProbe::decode(&encoded).unwrap();

        assert_eq!(decoded.probe_id, probe.probe_id);
        assert_eq!(decoded.probe_type, probe.probe_type);
        assert_eq!(decoded.challenge, probe.challenge);
    }

    #[test]
    fn test_probe_manager() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);

        // Create probe
        let _frame = manager.create_probe(ProbeType::Rtt, 1).unwrap();
        assert_eq!(manager.pending_count(), 1);

        // Verify stats updated
        let stats = manager.get_path_stats(1).unwrap();
        assert_eq!(stats.probes_sent, 1);
        assert_eq!(stats.responses_received, 0);
    }

    #[test]
    fn test_probe_stats() {
        let mut stats = ProbeStats::default();

        // Send probe
        stats.update_probe_sent();
        assert_eq!(stats.probes_sent, 1);
        assert_eq!(stats.loss_ratio, 1.0);

        // Receive response
        stats.update_response_received(Duration::from_millis(50));
        assert_eq!(stats.responses_received, 1);
        assert_eq!(stats.loss_ratio, 0.0);
        assert_eq!(stats.min_rtt_us, 50_000);
        assert_eq!(stats.avg_rtt_us, 50_000.0);

        // Check health
        assert!(stats.is_healthy());
    }

    #[test]
    fn test_probe_types() {
        assert_eq!(ProbeType::Discovery.priority(), DatagramPriority::High);
        assert_eq!(ProbeType::Bandwidth.priority(), DatagramPriority::Low);
        assert!(ProbeType::Discovery.timeout() > ProbeType::Validation.timeout());
        assert!(ProbeType::Bandwidth.payload_size() > ProbeType::Rtt.payload_size());
    }

    #[test]
    fn test_rtt_calculation() {
        let request = PathProbe::new_request(1, ProbeType::Rtt, 1, 1);
        let mut response = request.new_response();
        response.timestamp = request.timestamp + 10_000;

        let rtt = request.calculate_rtt(&response);
        assert_eq!(rtt, Some(Duration::from_millis(10)));
    }

    #[test]
    fn test_cleanup_expired_probes() {
        let transport = DatagramTransport::default_enabled();
        let mut manager = ProbeManager::new(transport);

        // Create probe
        manager.create_probe(ProbeType::Rtt, 1).unwrap();
        assert_eq!(manager.pending_count(), 1);

        // Cleanup with recent timestamp - should retain
        manager.cleanup_expired_probes(Instant::now());
        assert_eq!(manager.pending_count(), 1);

        // Cleanup with old timestamp - should remove
        manager.cleanup_expired_probes(Instant::now() + Duration::from_secs(60));
        assert_eq!(manager.pending_count(), 0);
    }
}
