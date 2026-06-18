//! Path Quality Beacons via DATAGRAM
//!
//! Implements periodic path quality measurement using DATAGRAM frames.

use crate::bytes::Bytes;
use crate::net::atp::datagram::frame::{DatagramFrame, DatagramMetadata, DatagramPriority};
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// Default interval for path RTT probes.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Default idle interval before emitting a keepalive decision.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Default missed probe budget before a path is treated as liveness-expired.
pub const DEFAULT_MAX_MISSED_PROBES: u8 = 3;

/// Path quality beacon payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathBeacon {
    /// Beacon sequence number
    pub sequence: u64,
    /// Reliable-control round sequence. Zero means legacy/disabled control.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub control_round_seq: u64,
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
            control_round_seq: 0,
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

    /// Create a response beacon that echoes the original probe identity.
    pub fn response_to(request: &Self, measurement: BeaconMeasurement) -> Self {
        let mut response = Self::new(
            request.sequence,
            request.path_id,
            BeaconType::Response,
            measurement,
        );
        response.control_round_seq = request.control_round_seq;
        response.send_timestamp = request.send_timestamp;
        response
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

    /// Create path-quality probe beacon
    pub fn probe(sequence: u64, path_id: u64, measurement_data: BeaconMeasurement) -> Self {
        Self::new(sequence, path_id, BeaconType::Probe, measurement_data)
    }

    /// Attach a reliable-control round sequence to this beacon.
    #[must_use]
    pub fn with_control_round_seq(mut self, control_round_seq: u64) -> Self {
        self.control_round_seq = control_round_seq;
        self
    }

    /// Whether this beacon participates in WIRE-5 reliable-control handling.
    #[must_use]
    pub fn has_control_round(&self) -> bool {
        self.control_round_seq != 0
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

    /// Create a response beacon that preserves the request correlation fields.
    pub fn create_response_for_beacon(
        &mut self,
        request: &PathBeacon,
        measurement: BeaconMeasurement,
    ) -> Option<PathBeacon> {
        if !self.is_beacon_type_enabled(BeaconType::Response) {
            return None;
        }

        let beacon = PathBeacon::response_to(request, measurement);

        let stats = self
            .path_stats
            .entry(request.path_id)
            .or_insert_with(|| BeaconStats::new(request.path_id));
        stats.record_sent(beacon.sequence);

        Some(beacon)
    }

    /// Create path probe beacon
    pub fn create_probe_beacon(
        &mut self,
        path_id: u64,
        measurement: BeaconMeasurement,
    ) -> Option<PathBeacon> {
        if !self.is_beacon_type_enabled(BeaconType::Probe) {
            return None;
        }

        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let beacon = PathBeacon::probe(sequence, path_id, measurement);

        let stats = self
            .path_stats
            .entry(path_id)
            .or_insert_with(|| BeaconStats::new(path_id));
        stats.record_sent(sequence);

        self.last_beacon_time.insert(path_id, Instant::now());

        Some(beacon)
    }

    /// Create NAT/liveness keepalive beacon
    pub fn create_keepalive_beacon(&mut self, path_id: u64) -> Option<PathBeacon> {
        if !self.is_beacon_type_enabled(BeaconType::Keepalive) {
            return None;
        }

        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let beacon = PathBeacon::keepalive(sequence, path_id);

        let stats = self
            .path_stats
            .entry(path_id)
            .or_insert_with(|| BeaconStats::new(path_id));
        stats.record_sent(sequence);

        self.last_beacon_time.insert(path_id, Instant::now());

        Some(beacon)
    }

    /// Record a path RTT sample observed by a transport-level probe.
    pub fn record_path_rtt(&mut self, path_id: u64, rtt: Duration) {
        let stats = self
            .path_stats
            .entry(path_id)
            .or_insert_with(|| BeaconStats::new(path_id));
        stats.record_response(rtt);
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
                self.create_response_for_beacon(&beacon, measurement)
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

/// Scheduled beacon action for one path.
#[derive(Debug, Clone)]
pub struct BeaconScheduleAction {
    /// Beacon to send or account for.
    pub beacon: PathBeacon,
    /// How long the peer had been idle when the action was selected.
    pub idle_for: Duration,
    /// Consecutive probe intervals that elapsed without peer activity.
    pub missed_probes: u8,
}

/// Peer liveness state inferred from beacon/probe progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconPeerHealth {
    /// Recent peer activity or a successful probe was observed.
    Active,
    /// At least one probe interval elapsed without peer activity.
    Suspect,
    /// The miss budget is exhausted; callers should fail closed.
    Expired,
}

/// Keepalive/probe scheduler for unreliable DATAGRAM-capable paths.
///
/// The scheduler is transport-neutral: callers may send the returned beacon on
/// a DATAGRAM path, or account for an existing protocol exchange as the probe
/// carrier when adding a new wire frame would break byte-isomorphism.
#[derive(Debug)]
pub struct BeaconScheduler {
    manager: BeaconManager,
    path_id: u64,
    keepalive_interval: Duration,
    probe_interval: Duration,
    next_control_round_seq: u64,
    last_received_beacon_round_seq: u64,
    last_received_response_round_seq: u64,
    last_peer_activity: Instant,
    last_keepalive: Option<Instant>,
    last_probe: Option<Instant>,
    pending_probe_since: Option<Instant>,
    latest_rtt: Option<Duration>,
    missed_probes: u8,
    max_missed_probes: u8,
}

impl BeaconScheduler {
    /// Create a scheduler with RQ/QUIC-safe defaults.
    #[must_use]
    pub fn new(path_id: u64, now: Instant) -> Self {
        Self::with_intervals(
            path_id,
            now,
            DEFAULT_KEEPALIVE_INTERVAL,
            DEFAULT_PROBE_INTERVAL,
        )
    }

    /// Create a scheduler with explicit keepalive and probe intervals.
    #[must_use]
    pub fn with_intervals(
        path_id: u64,
        now: Instant,
        keepalive_interval: Duration,
        probe_interval: Duration,
    ) -> Self {
        Self {
            manager: BeaconManager::new(probe_interval),
            path_id,
            keepalive_interval,
            probe_interval,
            next_control_round_seq: 1,
            last_received_beacon_round_seq: 0,
            last_received_response_round_seq: 0,
            last_peer_activity: now,
            last_keepalive: None,
            last_probe: None,
            pending_probe_since: None,
            latest_rtt: None,
            missed_probes: 0,
            max_missed_probes: DEFAULT_MAX_MISSED_PROBES,
        }
    }

    /// Override the consecutive missed-probe budget.
    #[must_use]
    pub fn with_missed_probe_budget(mut self, max_missed_probes: u8) -> Self {
        self.max_missed_probes = max_missed_probes.max(1);
        self
    }

    /// Path ID tracked by this scheduler.
    #[must_use]
    pub fn path_id(&self) -> u64 {
        self.path_id
    }

    /// Whether this scheduler emits and accepts WIRE-5 control beacons.
    #[must_use]
    pub fn control_enabled(&self) -> bool {
        self.next_control_round_seq != 0
    }

    /// Disable WIRE-5 control beacons. This mirrors seq=0 legacy peers.
    pub fn disable_control(&mut self) {
        self.next_control_round_seq = 0;
    }

    /// Latest observed probe RTT.
    #[must_use]
    pub fn latest_rtt(&self) -> Option<Duration> {
        self.latest_rtt
    }

    /// Consecutive probe intervals without peer activity.
    #[must_use]
    pub fn missed_probes(&self) -> u8 {
        self.missed_probes
    }

    /// Current peer liveness state.
    #[must_use]
    pub fn peer_health(&self) -> BeaconPeerHealth {
        if self.missed_probes == 0 {
            BeaconPeerHealth::Active
        } else if self.missed_probes >= self.max_missed_probes {
            BeaconPeerHealth::Expired
        } else {
            BeaconPeerHealth::Suspect
        }
    }

    /// Whether callers should fail closed instead of committing data.
    #[must_use]
    pub fn peer_liveness_expired(&self) -> bool {
        self.peer_health() == BeaconPeerHealth::Expired
    }

    /// Beacon accounting for this path.
    #[must_use]
    pub fn manager(&self) -> &BeaconManager {
        &self.manager
    }

    /// Mark inbound peer activity, suppressing idle keepalives.
    pub fn mark_peer_activity(&mut self, now: Instant) {
        self.last_peer_activity = now;
        self.pending_probe_since = None;
        self.missed_probes = 0;
    }

    fn allocate_control_round_seq(&mut self) -> Option<u64> {
        let round_seq = self.next_control_round_seq;
        if round_seq == 0 {
            return None;
        }
        self.next_control_round_seq = round_seq.saturating_add(1);
        Some(round_seq)
    }

    /// Return the next due keepalive/probe action, if any.
    pub fn next_action(
        &mut self,
        now: Instant,
        measurement: BeaconMeasurement,
    ) -> Option<BeaconScheduleAction> {
        if !self.control_enabled() {
            return None;
        }

        self.record_missed_probe_if_due(now);

        let idle_for = elapsed_since(now, self.last_peer_activity);
        let keepalive_due = idle_for >= self.keepalive_interval
            && self
                .last_keepalive
                .is_none_or(|last| elapsed_since(now, last) >= self.keepalive_interval);
        if keepalive_due {
            let round_seq = self.allocate_control_round_seq()?;
            let beacon = self
                .manager
                .create_keepalive_beacon(self.path_id)?
                .with_control_round_seq(round_seq);
            self.last_keepalive = Some(now);
            return Some(BeaconScheduleAction {
                beacon,
                idle_for,
                missed_probes: self.missed_probes,
            });
        }

        let probe_due = self
            .last_probe
            .is_none_or(|last| elapsed_since(now, last) >= self.probe_interval);
        if probe_due {
            let round_seq = self.allocate_control_round_seq()?;
            let beacon = self
                .manager
                .create_probe_beacon(self.path_id, measurement)?
                .with_control_round_seq(round_seq);
            self.last_probe = Some(now);
            self.pending_probe_since = Some(now);
            return Some(BeaconScheduleAction {
                beacon,
                idle_for,
                missed_probes: self.missed_probes,
            });
        }

        None
    }

    /// Record a received peer response and update path RTT statistics.
    pub fn observe_probe_result(&mut self, now: Instant, rtt: Duration) {
        self.last_probe = Some(now);
        self.pending_probe_since = None;
        self.latest_rtt = Some(rtt);
        self.mark_peer_activity(now);
        self.manager.record_path_rtt(self.path_id, rtt);
    }

    /// Process an inbound WIRE-5 beacon and return a response action if needed.
    ///
    /// Legacy peers serialize `control_round_seq=0`; those beacons are ignored
    /// here so reliable-control admission is fail-closed instead of ambiguous.
    pub fn process_inbound_beacon(
        &mut self,
        now: Instant,
        beacon: PathBeacon,
    ) -> Option<BeaconScheduleAction> {
        if !beacon.has_control_round() {
            return None;
        }

        let last_seen = match beacon.beacon_type {
            BeaconType::Response => &mut self.last_received_response_round_seq,
            BeaconType::Periodic
            | BeaconType::Probe
            | BeaconType::Keepalive
            | BeaconType::Migration => &mut self.last_received_beacon_round_seq,
        };
        if beacon.control_round_seq <= *last_seen {
            return None;
        }
        *last_seen = beacon.control_round_seq;

        let rtt = (beacon.beacon_type == BeaconType::Response).then(|| beacon.age());
        let response = self.manager.process_received_beacon(beacon);
        self.mark_peer_activity(now);

        if let Some(rtt) = rtt {
            self.latest_rtt = Some(rtt);
            self.last_probe = Some(now);
        }

        response.map(|beacon| BeaconScheduleAction {
            beacon,
            idle_for: Duration::ZERO,
            missed_probes: self.missed_probes,
        })
    }

    fn record_missed_probe_if_due(&mut self, now: Instant) {
        let Some(pending_since) = self.pending_probe_since else {
            return;
        };
        if elapsed_since(now, pending_since) < self.probe_interval {
            return;
        }

        self.pending_probe_since = None;
        self.missed_probes = self
            .missed_probes
            .saturating_add(1)
            .min(self.max_missed_probes);
    }
}

fn elapsed_since(now: Instant, then: Instant) -> Duration {
    now.checked_duration_since(then).unwrap_or_default()
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
        assert_eq!(decoded.control_round_seq, 0);
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
    fn test_probe_beacon_creation() {
        let measurement = BeaconMeasurement::with_rtt(50_000, 5_000);
        let beacon = PathBeacon::probe(7, 42, measurement);

        assert_eq!(beacon.sequence, 7);
        assert_eq!(beacon.path_id, 42);
        assert_eq!(beacon.beacon_type, BeaconType::Probe);
        assert_eq!(beacon.metadata().priority, DatagramPriority::High);
    }

    #[test]
    fn test_response_to_preserves_request_correlation() {
        let mut request =
            PathBeacon::probe(7, 42, BeaconMeasurement::empty()).with_control_round_seq(9);
        request.send_timestamp = 1234;

        let response = PathBeacon::response_to(&request, BeaconMeasurement::with_rtt(50_000, 5_000));

        assert_eq!(response.sequence, request.sequence);
        assert_eq!(response.path_id, request.path_id);
        assert_eq!(response.control_round_seq, 9);
        assert_eq!(response.send_timestamp, 1234);
        assert_eq!(response.beacon_type, BeaconType::Response);
        assert_eq!(response.measurement_data.srtt_us, Some(50_000));
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

    #[test]
    fn test_beacon_scheduler_probe_and_keepalive() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            42,
            now,
            Duration::from_secs(10),
            Duration::from_secs(2),
        );

        let first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        assert_eq!(first.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(first.beacon.control_round_seq, 1);
        assert_eq!(first.idle_for, Duration::ZERO);
        assert_eq!(first.missed_probes, 0);

        let reply_at = now + Duration::from_millis(50);
        scheduler.observe_probe_result(reply_at, Duration::from_millis(50));
        assert_eq!(scheduler.latest_rtt(), Some(Duration::from_millis(50)));
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);
        assert!(
            scheduler
                .next_action(
                    reply_at + Duration::from_secs(1),
                    BeaconMeasurement::empty(),
                )
                .is_none()
        );

        let keepalive = scheduler
            .next_action(
                reply_at + Duration::from_secs(11),
                BeaconMeasurement::empty(),
            )
            .expect("idle keepalive is due");
        assert_eq!(keepalive.beacon.beacon_type, BeaconType::Keepalive);
        assert_eq!(keepalive.beacon.control_round_seq, 2);
        assert!(keepalive.idle_for >= Duration::from_secs(10));
    }

    #[test]
    fn test_beacon_scheduler_tracks_missed_probe_budget_and_recovery() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            9,
            now,
            Duration::from_secs(30),
            Duration::from_secs(2),
        )
        .with_missed_probe_budget(2);

        let first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        assert_eq!(first.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);

        let second = scheduler
            .next_action(now + Duration::from_secs(2), BeaconMeasurement::empty())
            .expect("missed probe should schedule a replacement probe");
        assert_eq!(second.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(second.missed_probes, 1);
        assert_eq!(scheduler.missed_probes(), 1);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Suspect);

        let third = scheduler
            .next_action(now + Duration::from_secs(4), BeaconMeasurement::empty())
            .expect("second miss should schedule a replacement probe");
        assert_eq!(third.beacon.beacon_type, BeaconType::Probe);
        assert_eq!(third.missed_probes, 2);
        assert!(scheduler.peer_liveness_expired());

        let recovered_at = now + Duration::from_secs(4) + Duration::from_millis(75);
        scheduler.observe_probe_result(recovered_at, Duration::from_millis(75));
        assert_eq!(scheduler.latest_rtt(), Some(Duration::from_millis(75)));
        assert_eq!(scheduler.missed_probes(), 0);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);
    }

    #[test]
    fn test_beacon_scheduler_ignores_disabled_and_stale_control_beacons() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            42,
            now,
            Duration::from_secs(10),
            Duration::from_secs(2),
        );

        let legacy = PathBeacon::probe(1, 42, BeaconMeasurement::empty());
        assert!(scheduler.process_inbound_beacon(now, legacy).is_none());

        let fresh = PathBeacon::probe(2, 42, BeaconMeasurement::empty()).with_control_round_seq(3);
        let response = scheduler
            .process_inbound_beacon(now, fresh.clone())
            .expect("fresh control beacon should be answered");
        assert_eq!(response.beacon.beacon_type, BeaconType::Response);
        assert_eq!(response.beacon.control_round_seq, 3);
        assert!(scheduler.process_inbound_beacon(now, fresh).is_none());

        let stale = PathBeacon::keepalive(3, 42).with_control_round_seq(2);
        assert!(scheduler.process_inbound_beacon(now, stale).is_none());
    }

    #[test]
    fn test_beacon_scheduler_can_disable_control_output() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::new(42, now);
        scheduler.disable_control();

        assert!(!scheduler.control_enabled());
        assert!(
            scheduler
                .next_action(now + DEFAULT_PROBE_INTERVAL, BeaconMeasurement::empty())
                .is_none()
        );
    }

    #[test]
    fn test_beacon_scheduler_peer_activity_resets_liveness_and_idle_window() {
        let now = Instant::now();
        let mut scheduler = BeaconScheduler::with_intervals(
            11,
            now,
            Duration::from_secs(5),
            Duration::from_secs(10),
        );

        let _first = scheduler
            .next_action(now, BeaconMeasurement::empty())
            .expect("initial probe is due");
        let _second = scheduler
            .next_action(now + Duration::from_secs(10), BeaconMeasurement::empty())
            .expect("missed probe is due");
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Suspect);

        let peer_activity_at = now + Duration::from_secs(11);
        scheduler.mark_peer_activity(peer_activity_at);
        assert_eq!(scheduler.peer_health(), BeaconPeerHealth::Active);
        assert!(
            scheduler
                .next_action(
                    peer_activity_at + Duration::from_secs(4),
                    BeaconMeasurement::empty(),
                )
                .is_none(),
            "recent peer activity should suppress keepalive and replacement probe"
        );

        let keepalive = scheduler
            .next_action(
                peer_activity_at + Duration::from_secs(6),
                BeaconMeasurement::empty(),
            )
            .expect("idle keepalive is due after the reset window");
        assert_eq!(keepalive.beacon.beacon_type, BeaconType::Keepalive);
        assert!(keepalive.idle_for >= Duration::from_secs(5));
    }
}
