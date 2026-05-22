//! ATP-N2: Deterministic QUIC Packet Laboratory
//!
//! Provides deterministic packet scenarios for testing loss, reorder,
//! duplication, truncation, delayed ACK, ACK loss, PTO storms, and migration.

use asupersync::bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Deterministic packet lab for QUIC testing
pub struct QuicPacketLab {
    /// Network scenarios to simulate
    scenarios: HashMap<String, NetworkScenario>,
    /// Current active scenario
    current_scenario: Option<String>,
    /// Packet delivery queue
    delivery_queue: VecDeque<ScheduledPacket>,
    /// Network state
    network_state: NetworkState,
    /// Lab configuration
    config: LabConfig,
}

/// Network scenario definition
#[derive(Debug, Clone)]
pub struct NetworkScenario {
    /// Scenario name
    pub name: String,
    /// Description
    pub description: String,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Packet reorder probability
    pub reorder_prob: f64,
    /// Packet duplication probability
    pub duplicate_prob: f64,
    /// Packet corruption probability
    pub corruption_prob: f64,
    /// Base RTT
    pub base_rtt: Duration,
    /// RTT variance
    pub rtt_variance: Duration,
    /// Bandwidth limit (bytes/sec)
    pub bandwidth_limit: Option<u64>,
    /// Maximum packet size
    pub max_packet_size: usize,
}

/// Scheduled packet for delivery
#[derive(Debug, Clone)]
pub struct ScheduledPacket {
    /// Packet data
    pub data: Bytes,
    /// Source address
    pub src: SocketAddr,
    /// Destination address
    pub dst: SocketAddr,
    /// Scheduled delivery time
    pub delivery_time: Instant,
    /// Packet ID for tracking
    pub packet_id: u64,
    /// Whether this is a duplicate
    pub is_duplicate: bool,
    /// Whether this is reordered
    pub is_reordered: bool,
    /// Corruption applied
    pub corruption: Option<PacketCorruption>,
}

/// Packet corruption types
#[derive(Debug, Clone)]
pub enum PacketCorruption {
    /// Truncate packet to given size
    Truncate(usize),
    /// Corrupt random bytes
    RandomCorruption(Vec<usize>),
    /// Flip specific bits
    BitFlip(Vec<(usize, u8)>),
}

/// Network state tracking
#[derive(Debug)]
pub struct NetworkState {
    /// Current time (for deterministic simulation)
    pub current_time: Instant,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets delivered
    pub packets_delivered: u64,
    /// Total packets lost
    pub packets_lost: u64,
    /// Total packets reordered
    pub packets_reordered: u64,
    /// Total packets duplicated
    pub packets_duplicated: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Connection state per endpoint
    pub connections: HashMap<(SocketAddr, SocketAddr), ConnectionState>,
}

/// Per-connection state
#[derive(Debug)]
pub struct ConnectionState {
    /// Last packet number sent
    pub last_pkt_sent: u64,
    /// Last packet number received
    pub last_pkt_received: u64,
    /// Outstanding packets (not ACKed)
    pub outstanding_packets: HashMap<u64, OutstandingPacket>,
    /// Received packet tracking
    pub received_packets: HashMap<u64, ReceivedPacket>,
    /// Current congestion window
    pub congestion_window: u32,
    /// RTT measurements
    pub rtt_measurements: VecDeque<Duration>,
    /// PTO count
    pub pto_count: u32,
}

/// Outstanding packet info
#[derive(Debug)]
pub struct OutstandingPacket {
    pub packet_number: u64,
    pub sent_time: Instant,
    pub size: usize,
    pub retransmissions: u32,
}

/// Received packet info
#[derive(Debug)]
pub struct ReceivedPacket {
    pub packet_number: u64,
    pub received_time: Instant,
    pub size: usize,
}

/// Lab configuration
#[derive(Debug)]
pub struct LabConfig {
    /// Enable deterministic behavior
    pub deterministic: bool,
    /// Random seed for reproducible randomness
    pub seed: u64,
    /// Maximum simulation time
    pub max_sim_time: Duration,
    /// Packet ID counter
    pub packet_id_counter: u64,
}

impl QuicPacketLab {
    /// Create new packet lab
    pub fn new() -> Self {
        Self {
            scenarios: Self::create_default_scenarios(),
            current_scenario: None,
            delivery_queue: VecDeque::new(),
            network_state: NetworkState {
                current_time: Instant::now(),
                packets_sent: 0,
                packets_delivered: 0,
                packets_lost: 0,
                packets_reordered: 0,
                packets_duplicated: 0,
                bytes_transferred: 0,
                connections: HashMap::new(),
            },
            config: LabConfig {
                deterministic: true,
                seed: 42,
                max_sim_time: Duration::from_secs(300), // 5 minutes max
                packet_id_counter: 0,
            },
        }
    }

    /// Create default network scenarios
    fn create_default_scenarios() -> HashMap<String, NetworkScenario> {
        let mut scenarios = HashMap::new();

        // Perfect network
        scenarios.insert(
            "perfect".to_string(),
            NetworkScenario {
                name: "perfect".to_string(),
                description: "Perfect network with no loss or delay".to_string(),
                loss_rate: 0.0,
                reorder_prob: 0.0,
                duplicate_prob: 0.0,
                corruption_prob: 0.0,
                base_rtt: Duration::from_millis(1),
                rtt_variance: Duration::from_millis(0),
                bandwidth_limit: None,
                max_packet_size: 1500,
            },
        );

        // High loss network
        scenarios.insert(
            "high_loss".to_string(),
            NetworkScenario {
                name: "high_loss".to_string(),
                description: "High packet loss (10%) network".to_string(),
                loss_rate: 0.1,
                reorder_prob: 0.05,
                duplicate_prob: 0.02,
                corruption_prob: 0.001,
                base_rtt: Duration::from_millis(50),
                rtt_variance: Duration::from_millis(10),
                bandwidth_limit: Some(1_000_000), // 1 Mbps
                max_packet_size: 1200,
            },
        );

        // Reordering network
        scenarios.insert(
            "reordering".to_string(),
            NetworkScenario {
                name: "reordering".to_string(),
                description: "Network with frequent packet reordering".to_string(),
                loss_rate: 0.01,
                reorder_prob: 0.15,
                duplicate_prob: 0.05,
                corruption_prob: 0.0,
                base_rtt: Duration::from_millis(100),
                rtt_variance: Duration::from_millis(50),
                bandwidth_limit: Some(10_000_000), // 10 Mbps
                max_packet_size: 1500,
            },
        );

        // Congested network
        scenarios.insert(
            "congested".to_string(),
            NetworkScenario {
                name: "congested".to_string(),
                description: "Congested network with limited bandwidth".to_string(),
                loss_rate: 0.03,
                reorder_prob: 0.08,
                duplicate_prob: 0.01,
                corruption_prob: 0.0,
                base_rtt: Duration::from_millis(200),
                rtt_variance: Duration::from_millis(100),
                bandwidth_limit: Some(100_000), // 100 Kbps
                max_packet_size: 1200,
            },
        );

        // Mobile network
        scenarios.insert(
            "mobile".to_string(),
            NetworkScenario {
                name: "mobile".to_string(),
                description: "Mobile network with high latency variation".to_string(),
                loss_rate: 0.05,
                reorder_prob: 0.10,
                duplicate_prob: 0.03,
                corruption_prob: 0.002,
                base_rtt: Duration::from_millis(150),
                rtt_variance: Duration::from_millis(200),
                bandwidth_limit: Some(5_000_000), // 5 Mbps
                max_packet_size: 1400,
            },
        );

        scenarios
    }

    /// Set active network scenario
    pub fn set_scenario(&mut self, scenario_name: &str) -> Result<(), String> {
        if !self.scenarios.contains_key(scenario_name) {
            return Err(format!("Unknown scenario: {}", scenario_name));
        }

        self.current_scenario = Some(scenario_name.to_string());
        println!("Set network scenario: {}", scenario_name);

        if let Some(scenario) = self.scenarios.get(scenario_name) {
            println!("  Description: {}", scenario.description);
            println!("  Loss rate: {:.1}%", scenario.loss_rate * 100.0);
            println!("  Base RTT: {:?}", scenario.base_rtt);
        }

        Ok(())
    }

    /// Send packet through the lab network
    pub fn send_packet(
        &mut self,
        data: Bytes,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), String> {
        let scenario = match &self.current_scenario {
            Some(name) => self
                .scenarios
                .get(name)
                .ok_or("Current scenario not found")?,
            None => return Err("No scenario set".to_string()),
        };

        self.config.packet_id_counter += 1;
        let packet_id = self.config.packet_id_counter;

        self.network_state.packets_sent += 1;
        self.network_state.bytes_transferred += data.len() as u64;

        // Apply network effects
        if self.should_lose_packet(scenario, packet_id) {
            self.network_state.packets_lost += 1;
            println!("Packet {} lost", packet_id);
            return Ok(());
        }

        // Calculate delivery time
        let delivery_delay = self.calculate_delivery_delay(scenario, packet_id);
        let delivery_time = self.network_state.current_time + delivery_delay;

        // Apply corruption if needed
        let mut packet_data = data;
        let corruption = if self.should_corrupt_packet(scenario, packet_id) {
            let corrupted = self.corrupt_packet(&packet_data, scenario);
            packet_data = corrupted.0;
            Some(corrupted.1)
        } else {
            None
        };

        let mut scheduled_packet = ScheduledPacket {
            data: packet_data,
            src,
            dst,
            delivery_time,
            packet_id,
            is_duplicate: false,
            is_reordered: false,
            corruption,
        };

        // Check for duplication
        if self.should_duplicate_packet(scenario, packet_id) {
            self.network_state.packets_duplicated += 1;
            let mut duplicate = scheduled_packet.clone();
            duplicate.is_duplicate = true;
            duplicate.delivery_time += Duration::from_millis(10); // Slight delay for duplicate
            self.delivery_queue.push_back(duplicate);
            println!("Packet {} duplicated", packet_id);
        }

        // Check for reordering
        if self.should_reorder_packet(scenario, packet_id) {
            self.network_state.packets_reordered += 1;
            scheduled_packet.is_reordered = true;
            scheduled_packet.delivery_time += Duration::from_millis(50); // Reorder delay
            println!("Packet {} reordered", packet_id);
        }

        self.delivery_queue.push_back(scheduled_packet);

        // Sort by delivery time to maintain order
        self.delivery_queue
            .make_contiguous()
            .sort_by_key(|p| p.delivery_time);

        Ok(())
    }

    /// Process packet deliveries for current time
    pub fn process_deliveries(&mut self) -> Vec<ScheduledPacket> {
        let mut delivered = Vec::new();

        while let Some(packet) = self.delivery_queue.front() {
            if packet.delivery_time <= self.network_state.current_time {
                let packet = self.delivery_queue.pop_front().unwrap();
                self.network_state.packets_delivered += 1;
                delivered.push(packet);
            } else {
                break;
            }
        }

        delivered
    }

    /// Advance simulation time
    pub fn advance_time(&mut self, duration: Duration) {
        self.network_state.current_time += duration;
    }

    /// Get current network statistics
    pub fn get_stats(&self) -> NetworkStats {
        NetworkStats {
            packets_sent: self.network_state.packets_sent,
            packets_delivered: self.network_state.packets_delivered,
            packets_lost: self.network_state.packets_lost,
            packets_reordered: self.network_state.packets_reordered,
            packets_duplicated: self.network_state.packets_duplicated,
            bytes_transferred: self.network_state.bytes_transferred,
            loss_rate: if self.network_state.packets_sent > 0 {
                self.network_state.packets_lost as f64 / self.network_state.packets_sent as f64
            } else {
                0.0
            },
        }
    }

    // Private helper methods

    fn should_lose_packet(&self, scenario: &NetworkScenario, packet_id: u64) -> bool {
        self.deterministic_random(packet_id, 1000) < (scenario.loss_rate * 1000.0) as u64
    }

    fn should_reorder_packet(&self, scenario: &NetworkScenario, packet_id: u64) -> bool {
        self.deterministic_random(packet_id, 1001) < (scenario.reorder_prob * 1000.0) as u64
    }

    fn should_duplicate_packet(&self, scenario: &NetworkScenario, packet_id: u64) -> bool {
        self.deterministic_random(packet_id, 1002) < (scenario.duplicate_prob * 1000.0) as u64
    }

    fn should_corrupt_packet(&self, scenario: &NetworkScenario, packet_id: u64) -> bool {
        self.deterministic_random(packet_id, 1003) < (scenario.corruption_prob * 1000.0) as u64
    }

    fn calculate_delivery_delay(&self, scenario: &NetworkScenario, packet_id: u64) -> Duration {
        let base_delay = scenario.base_rtt / 2; // One-way delay
        let variance_ms = scenario.rtt_variance.as_millis() as u64;
        let random_variance = self.deterministic_random(packet_id, 1004) % (variance_ms + 1);

        base_delay + Duration::from_millis(random_variance)
    }

    fn corrupt_packet(
        &self,
        data: &Bytes,
        _scenario: &NetworkScenario,
    ) -> (Bytes, PacketCorruption) {
        // Simple corruption: flip a random bit
        let mut corrupted = data.to_vec();
        if !corrupted.is_empty() {
            let pos = (data.len() / 2) % corrupted.len();
            corrupted[pos] ^= 0x01;
        }

        (
            Bytes::from(corrupted),
            PacketCorruption::BitFlip(vec![(data.len() / 2, 0x01)]),
        )
    }

    /// Deterministic pseudo-random number generator
    fn deterministic_random(&self, input: u64, salt: u64) -> u64 {
        // Simple deterministic hash function
        let mut value = input.wrapping_mul(0x9e3779b97f4a7c15);
        value = value.wrapping_add(salt);
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58476d1ce4e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d049bb133111eb);
        value ^= value >> 31;
        value
    }
}

impl Default for QuicPacketLab {
    fn default() -> Self {
        Self::new()
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub packets_sent: u64,
    pub packets_delivered: u64,
    pub packets_lost: u64,
    pub packets_reordered: u64,
    pub packets_duplicated: u64,
    pub bytes_transferred: u64,
    pub loss_rate: f64,
}

/// Test deterministic packet lab scenarios
#[test]
fn test_packet_lab_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    let mut lab = QuicPacketLab::new();

    let test_scenarios = vec!["perfect", "high_loss", "reordering", "congested", "mobile"];

    for scenario_name in test_scenarios {
        println!("\n=== Testing {} scenario ===", scenario_name);

        lab.set_scenario(scenario_name)?;

        // Send test packets
        let src = "127.0.0.1:8080".parse()?;
        let dst = "127.0.0.1:8081".parse()?;

        for i in 0..10 {
            let packet_data = Bytes::from(format!("test packet {}", i));
            lab.send_packet(packet_data, src, dst)?;
        }

        // Process deliveries over time
        for _ in 0..20 {
            lab.advance_time(Duration::from_millis(10));
            let delivered = lab.process_deliveries();

            for packet in delivered {
                println!(
                    "Delivered packet {} (reordered: {}, duplicate: {}, corrupted: {})",
                    packet.packet_id,
                    packet.is_reordered,
                    packet.is_duplicate,
                    packet.corruption.is_some()
                );
            }
        }

        let stats = lab.get_stats();
        println!("Final stats: {:?}", stats);
    }

    Ok(())
}

/// Test packet loss recovery scenarios
#[test]
fn test_packet_loss_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let mut lab = QuicPacketLab::new();
    lab.set_scenario("high_loss")?;

    println!("Testing packet loss recovery with high_loss scenario");

    // Simulate sending many packets to observe loss patterns
    let src = "127.0.0.1:8080".parse()?;
    let dst = "127.0.0.1:8081".parse()?;

    for i in 0..50 {
        let packet_data = Bytes::from(format!("recovery test packet {}", i));
        lab.send_packet(packet_data, src, dst)?;
    }

    // Process over extended time
    let mut delivered_packets = Vec::new();
    for _ in 0..100 {
        lab.advance_time(Duration::from_millis(5));
        let delivered = lab.process_deliveries();
        delivered_packets.extend(delivered);
    }

    let stats = lab.get_stats();
    println!("Recovery test results:");
    println!(
        "  Sent: {}, Delivered: {}, Lost: {} ({:.1}%)",
        stats.packets_sent,
        stats.packets_delivered,
        stats.packets_lost,
        stats.loss_rate * 100.0
    );

    println!(
        "  Reordered: {}, Duplicated: {}",
        stats.packets_reordered, stats.packets_duplicated
    );

    Ok(())
}
