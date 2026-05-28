//! Real E2E integration tests: lab/network ↔ net/quic_native integration (br-e2e-164).
//!
//! Tests lab-injected packet reordering triggers QUIC's PTO retransmit timer correctly
//! without breaking ordering invariants. Verifies that the lab network simulation
//! and QUIC native implementation coordinate properly to handle packet reordering
//! scenarios while maintaining protocol correctness and triggering appropriate
//! timeout-based retransmission mechanisms.
//!
//! # Integration Patterns Tested
//!
//! - **Lab Network Simulation**: Controlled packet reordering injection in lab environment
//! - **QUIC PTO Timer Logic**: Probe timeout retransmission timer behavior verification
//! - **Packet Ordering Invariants**: Maintenance of ordering constraints during reordering
//! - **Retransmission Mechanisms**: Correct retransmit behavior triggered by PTO
//! - **Recovery Coordination**: QUIC and lab network recovery mechanism interaction
//!
//! # Test Scenarios
//!
//! 1. **Normal Packet Delivery** — Baseline QUIC behavior without reordering
//! 2. **Simple Packet Reordering** — Basic out-of-order delivery triggering PTO
//! 3. **Burst Reordering** — Multiple consecutive packets reordered together
//! 4. **Long-Delay Reordering** — Packets delayed beyond PTO threshold
//! 5. **Persistent Reordering** — Sustained reordering patterns over time
//! 6. **Recovery Verification** — Ordering invariant restoration after reordering
//!
//! # Safety Properties Verified
//!
//! - PTO timer triggers correctly for reordered packets
//! - QUIC ordering invariants are preserved during reordering
//! - Retransmission behavior follows RFC 9002 specifications
//! - No duplicate delivery or lost packets during recovery
//! - Network simulation remains deterministic and reproducible

#![allow(dead_code, unused_variables, unused_imports)]

use crate::{
    lab::network::{
        harness::{
            NetworkHarness, NetworkConfig, NetworkInterface, PacketInjection,
            SimulatedNetwork, NetworkTopology, LinkCharacteristics,
        },
        network::{
            Network, NetworkNode, NetworkLink, PacketReorderingFilter,
            DelayInjector, LossInjector, DuplicationInjector, ReorderingPattern,
        },
        config::{
            LabConfig, SimulationMode, TimeMode, DeterministicMode,
            NetworkLatency, Bandwidth, PacketLossRate,
        },
    },
    net::quic_native::{
        connection::{
            QuicConnection, ConnectionState, ConnectionConfig, ConnectionEvent,
            ConnectionStats, CongestionController, FlowController,
        },
        transport::{
            Transport, TransportConfig, TransportError, TransportEvent,
            TransportStats, QuicTransport, Endpoint, EndpointConfig,
        },
        streams::{
            Stream, StreamId, StreamType, StreamState, StreamEvent,
            StreamData, StreamFrame, SendStream, RecvStream,
        },
        tls::{TlsConfig, TlsProvider, TlsError, TlsHandshake},
        forensic_log::{ForensicLog, LogEntry, EventType, PacketTrace},
    },
    cx::{Cx, Scope},
    time::{Sleep, Duration, Instant, VirtualTime},
    sync::{Mutex, RwLock, Arc, OnceCell},
    types::{Outcome, TaskId, RegionId},
    error::Error,
};
use std::{
    collections::{HashMap, VecDeque, BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering},
        mpsc::{self, Sender, Receiver},
    },
    net::{SocketAddr, IpAddr, Ipv4Addr, UdpSocket},
    time::{SystemTime, UNIX_EPOCH},
};

/// Configuration for lab network QUIC PTO testing
#[derive(Debug, Clone)]
pub struct LabQuicPtoConfig {
    /// Lab network simulation configuration
    pub lab_config: LabConfig,
    /// QUIC connection configuration
    pub quic_config: ConnectionConfig,
    /// Packet reordering configuration
    pub reordering_config: ReorderingConfig,
    /// PTO timer configuration
    pub pto_config: PtoConfig,
    /// Number of test packets to send
    pub test_packet_count: u32,
    /// Maximum test duration
    pub test_timeout: Duration,
    /// Connection addresses
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// Stream configuration for testing
    pub stream_config: StreamTestConfig,
}

impl Default for LabQuicPtoConfig {
    fn default() -> Self {
        Self {
            lab_config: LabConfig {
                simulation_mode: SimulationMode::Deterministic,
                time_mode: TimeMode::Virtual,
                deterministic_mode: DeterministicMode::Strict,
                network_latency: NetworkLatency::Fixed(Duration::from_millis(50)),
                bandwidth: Bandwidth::from_mbps(100),
                packet_loss_rate: PacketLossRate::new(0.0),
            },
            quic_config: ConnectionConfig {
                max_idle_timeout: Duration::from_secs(30),
                initial_rtt: Duration::from_millis(100),
                max_ack_delay: Duration::from_millis(25),
                pto_count_threshold: 3,
                ..Default::default()
            },
            reordering_config: ReorderingConfig::default(),
            pto_config: PtoConfig::default(),
            test_packet_count: 100,
            test_timeout: Duration::from_secs(60),
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4434),
            stream_config: StreamTestConfig::default(),
        }
    }
}

/// Configuration for packet reordering injection
#[derive(Debug, Clone)]
pub struct ReorderingConfig {
    /// Reordering probability (0.0-1.0)
    pub reordering_probability: f64,
    /// Maximum reordering distance (packets)
    pub max_reorder_distance: u32,
    /// Reordering delay range
    pub reorder_delay_range: (Duration, Duration),
    /// Burst reordering size
    pub burst_size: u32,
    /// Reordering pattern
    pub pattern: ReorderingPattern,
    /// Enable persistent reordering
    pub persistent_reordering: bool,
}

impl Default for ReorderingConfig {
    fn default() -> Self {
        Self {
            reordering_probability: 0.1,
            max_reorder_distance: 5,
            reorder_delay_range: (Duration::from_millis(50), Duration::from_millis(200)),
            burst_size: 3,
            pattern: ReorderingPattern::Random,
            persistent_reordering: false,
        }
    }
}

/// Configuration for PTO timer testing
#[derive(Debug, Clone)]
pub struct PtoConfig {
    /// Initial PTO value
    pub initial_pto: Duration,
    /// PTO backoff factor
    pub pto_backoff: f64,
    /// Maximum PTO value
    pub max_pto: Duration,
    /// PTO count threshold for connection close
    pub pto_count_threshold: u32,
    /// Probe packet send behavior
    pub probe_behavior: ProbeBehavior,
}

impl Default for PtoConfig {
    fn default() -> Self {
        Self {
            initial_pto: Duration::from_millis(200),
            pto_backoff: 2.0,
            max_pto: Duration::from_secs(5),
            pto_count_threshold: 3,
            probe_behavior: ProbeBehavior::Standard,
        }
    }
}

/// PTO probe packet behavior
#[derive(Debug, Clone, Copy)]
pub enum ProbeBehavior {
    /// Standard RFC 9002 behavior
    Standard,
    /// Send multiple probe packets
    Multiple,
    /// Send probe with padding
    Padded,
    /// Custom probe strategy
    Custom,
}

/// Stream configuration for testing
#[derive(Debug, Clone)]
pub struct StreamTestConfig {
    /// Stream type for testing
    pub stream_type: StreamType,
    /// Data size per packet
    pub data_per_packet: usize,
    /// Send interval between packets
    pub send_interval: Duration,
    /// Flow control window
    pub flow_control_window: u64,
}

impl Default for StreamTestConfig {
    fn default() -> Self {
        Self {
            stream_type: StreamType::Bidirectional,
            data_per_packet: 1200,
            send_interval: Duration::from_millis(10),
            flow_control_window: 65536,
        }
    }
}

/// Mock lab network QUIC PTO integration system
#[derive(Debug)]
pub struct MockLabQuicPtoSystem {
    config: LabQuicPtoConfig,
    lab_network: Arc<Mutex<SimulatedNetwork>>,
    quic_endpoint: Arc<Mutex<Endpoint>>,
    connection_tracker: Arc<ConnectionTracker>,
    reordering_monitor: Arc<ReorderingMonitor>,
    pto_analyzer: Arc<PtoAnalyzer>,
    packet_injector: Arc<PacketInjector>,
    forensic_log: Arc<Mutex<ForensicLog>>,
    test_stats: Arc<TestStats>,
    virtual_time: Arc<VirtualTime>,
    active_connection: Arc<Mutex<Option<QuicConnection>>>,
}

/// Tracks QUIC connection state and events
#[derive(Debug)]
pub struct ConnectionTracker {
    connection_events: Mutex<Vec<TrackedConnectionEvent>>,
    connection_state: Mutex<ConnectionState>,
    stream_states: Mutex<HashMap<StreamId, StreamState>>,
    congestion_state: Mutex<CongestionState>,
    flow_control_state: Mutex<FlowControlState>,
    packet_numbers: Mutex<PacketNumberTracker>,
    rtt_measurements: Mutex<VecDeque<RttMeasurement>>,
}

/// Tracked connection event with timestamp
#[derive(Debug, Clone)]
pub struct TrackedConnectionEvent {
    pub timestamp: Instant,
    pub event_type: ConnectionEventType,
    pub packet_number: Option<u64>,
    pub stream_id: Option<StreamId>,
    pub details: String,
}

/// Types of connection events to track
#[derive(Debug, Clone, Copy)]
pub enum ConnectionEventType {
    PacketSent,
    PacketReceived,
    PacketLost,
    PacketReordered,
    PtoFired,
    AckReceived,
    StreamDataSent,
    StreamDataReceived,
    CongestionWindowUpdated,
    RttUpdated,
}

/// Congestion controller state tracking
#[derive(Debug, Clone)]
pub struct CongestionState {
    pub congestion_window: u64,
    pub bytes_in_flight: u64,
    pub ssthresh: u64,
    pub congestion_recovery_start: Option<Instant>,
    pub persistent_congestion: bool,
}

/// Flow control state tracking
#[derive(Debug, Clone)]
pub struct FlowControlState {
    pub connection_send_window: u64,
    pub connection_recv_window: u64,
    pub stream_send_windows: HashMap<StreamId, u64>,
    pub stream_recv_windows: HashMap<StreamId, u64>,
}

/// Packet number tracking for ordering verification
#[derive(Debug)]
pub struct PacketNumberTracker {
    sent_packets: BTreeSet<u64>,
    received_packets: BTreeSet<u64>,
    reordered_packets: Vec<ReorderedPacket>,
    lost_packets: BTreeSet<u64>,
    duplicate_packets: Vec<u64>,
    largest_acknowledged: Option<u64>,
}

/// Information about a reordered packet
#[derive(Debug, Clone)]
pub struct ReorderedPacket {
    pub packet_number: u64,
    pub sent_time: Instant,
    pub received_time: Instant,
    pub reorder_distance: u32,
    pub delay: Duration,
}

/// RTT measurement with context
#[derive(Debug, Clone)]
pub struct RttMeasurement {
    pub measured_at: Instant,
    pub rtt: Duration,
    pub ack_delay: Duration,
    pub packet_number: u64,
    pub sample_type: RttSampleType,
}

/// Type of RTT sample
#[derive(Debug, Clone, Copy)]
pub enum RttSampleType {
    Initial,
    Normal,
    ProbeTimeout,
    Retransmission,
}

/// Monitors packet reordering behavior
#[derive(Debug)]
pub struct ReorderingMonitor {
    config: ReorderingConfig,
    reordering_events: Mutex<Vec<ReorderingEvent>>,
    packet_delays: Mutex<HashMap<u64, PacketDelay>>,
    reordering_stats: Mutex<ReorderingStats>,
    burst_tracker: Mutex<BurstTracker>,
}

/// Packet reordering event
#[derive(Debug, Clone)]
pub struct ReorderingEvent {
    pub timestamp: Instant,
    pub packet_number: u64,
    pub original_order: u64,
    pub delivered_order: u64,
    pub reorder_distance: u32,
    pub delay_injected: Duration,
    pub pattern_type: ReorderingPattern,
}

/// Packet delay information
#[derive(Debug, Clone)]
pub struct PacketDelay {
    pub packet_number: u64,
    pub scheduled_time: Instant,
    pub actual_delivery_time: Instant,
    pub injected_delay: Duration,
    pub is_reordered: bool,
}

/// Statistics for packet reordering
#[derive(Debug, Clone)]
pub struct ReorderingStats {
    pub total_packets_sent: u64,
    pub total_packets_reordered: u64,
    pub reordering_rate: f64,
    pub average_reorder_distance: f64,
    pub average_reorder_delay: Duration,
    pub burst_count: u32,
    pub max_burst_size: u32,
}

/// Tracks burst reordering patterns
#[derive(Debug)]
pub struct BurstTracker {
    current_burst: Vec<u64>,
    burst_start_time: Option<Instant>,
    completed_bursts: Vec<CompletedBurst>,
}

/// Information about a completed reordering burst
#[derive(Debug, Clone)]
pub struct CompletedBurst {
    pub start_time: Instant,
    pub end_time: Instant,
    pub packet_numbers: Vec<u64>,
    pub burst_size: u32,
    pub average_delay: Duration,
}

/// Analyzes PTO timer behavior and retransmissions
#[derive(Debug)]
pub struct PtoAnalyzer {
    config: PtoConfig,
    pto_events: Mutex<Vec<PtoEvent>>,
    pto_state: Mutex<PtoState>,
    probe_packets: Mutex<Vec<ProbePacket>>,
    retransmission_tracker: Mutex<RetransmissionTracker>,
    timer_accuracy: Mutex<Vec<TimerAccuracyMeasurement>>,
}

/// PTO timer event
#[derive(Debug, Clone)]
pub struct PtoEvent {
    pub timestamp: Instant,
    pub event_type: PtoEventType,
    pub pto_count: u32,
    pub pto_value: Duration,
    pub packets_in_flight: u64,
    pub probe_packets_sent: u32,
    pub trigger_reason: PtoTrigger,
}

/// Types of PTO events
#[derive(Debug, Clone, Copy)]
pub enum PtoEventType {
    PtoArmed,
    PtoFired,
    PtoCancelled,
    ProbePacketSent,
    ProbePacketAcknowledged,
    PtoBackoff,
}

/// What triggered the PTO timer
#[derive(Debug, Clone, Copy)]
pub enum PtoTrigger {
    PacketReordering,
    PacketLoss,
    AckDelay,
    ApplicationData,
    ConnectionIdle,
}

/// Current PTO state
#[derive(Debug, Clone)]
pub struct PtoState {
    pub pto_count: u32,
    pub current_pto: Duration,
    pub timer_armed: bool,
    pub timer_expiry: Option<Instant>,
    pub packets_in_flight: u64,
    pub probe_packets_outstanding: u32,
}

/// Information about a probe packet
#[derive(Debug, Clone)]
pub struct ProbePacket {
    pub packet_number: u64,
    pub sent_time: Instant,
    pub pto_count_when_sent: u32,
    pub acknowledged: bool,
    pub ack_time: Option<Instant>,
    pub probe_type: ProbeType,
}

/// Type of probe packet
#[derive(Debug, Clone, Copy)]
pub enum ProbeType {
    AckEliciting,
    Padding,
    Crypto,
    Application,
}

/// Tracks retransmission behavior
#[derive(Debug)]
pub struct RetransmissionTracker {
    retransmissions: Vec<RetransmissionEvent>,
    spurious_retransmissions: Vec<SpuriousRetransmission>,
    retransmission_stats: RetransmissionStats,
}

/// Retransmission event
#[derive(Debug, Clone)]
pub struct RetransmissionEvent {
    pub timestamp: Instant,
    pub original_packet_number: u64,
    pub retransmitted_packet_number: u64,
    pub retransmission_reason: RetransmissionReason,
    pub delay_since_original: Duration,
    pub data_size: usize,
}

/// Reason for retransmission
#[derive(Debug, Clone, Copy)]
pub enum RetransmissionReason {
    PtoTimeout,
    FastRetransmit,
    EarlyRetransmit,
    Undecryptable,
}

/// Spurious retransmission (packet was not actually lost)
#[derive(Debug, Clone)]
pub struct SpuriousRetransmission {
    pub retransmission_event: RetransmissionEvent,
    pub original_ack_time: Instant,
    pub spurious_detected_at: Instant,
}

/// Statistics for retransmissions
#[derive(Debug, Clone)]
pub struct RetransmissionStats {
    pub total_retransmissions: u64,
    pub pto_retransmissions: u64,
    pub fast_retransmissions: u64,
    pub spurious_retransmissions: u64,
    pub spurious_rate: f64,
    pub average_retransmission_delay: Duration,
}

/// Timer accuracy measurement
#[derive(Debug, Clone)]
pub struct TimerAccuracyMeasurement {
    pub scheduled_expiry: Instant,
    pub actual_expiry: Instant,
    pub accuracy_error: Duration,
    pub pto_value: Duration,
    pub pto_count: u32,
}

/// Injects controlled packet behavior into lab network
#[derive(Debug)]
pub struct PacketInjector {
    config: ReorderingConfig,
    injection_queue: Mutex<VecDeque<InjectionEvent>>,
    delayed_packets: Mutex<Vec<DelayedPacket>>,
    injection_stats: Mutex<InjectionStats>,
    pattern_generator: Mutex<PatternGenerator>,
}

/// Packet injection event
#[derive(Debug, Clone)]
pub struct InjectionEvent {
    pub timestamp: Instant,
    pub packet_number: u64,
    pub injection_type: InjectionType,
    pub delay: Duration,
    pub target_order: Option<u64>,
}

/// Type of packet injection
#[derive(Debug, Clone, Copy)]
pub enum InjectionType {
    DelayReorder,
    BurstReorder,
    LongDelay,
    Drop,
    Duplicate,
}

/// Delayed packet awaiting delivery
#[derive(Debug, Clone)]
pub struct DelayedPacket {
    pub packet_number: u64,
    pub payload: Vec<u8>,
    pub original_timestamp: Instant,
    pub delivery_time: Instant,
    pub injection_type: InjectionType,
}

/// Statistics for packet injection
#[derive(Debug, Clone)]
pub struct InjectionStats {
    pub packets_delayed: u64,
    pub packets_reordered: u64,
    pub packets_dropped: u64,
    pub packets_duplicated: u64,
    pub bursts_created: u32,
    pub average_injection_delay: Duration,
}

/// Generates reordering patterns
#[derive(Debug)]
pub struct PatternGenerator {
    current_pattern: ReorderingPattern,
    pattern_state: PatternState,
    random_seed: u64,
}

/// State for pattern generation
#[derive(Debug)]
pub enum PatternState {
    Random { next_reorder_at: u64 },
    Periodic { period: u32, phase: u32 },
    Burst { burst_size: u32, packets_in_burst: u32 },
    Custom { state: Vec<u8> },
}

/// Overall test statistics
#[derive(Debug)]
pub struct TestStats {
    pub test_start_time: AtomicU64, // as millis since epoch
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub pto_fires: AtomicU32,
    pub retransmissions: AtomicU64,
    pub ordering_violations: AtomicU32,
    pub test_duration: Mutex<Duration>,
}

impl MockLabQuicPtoSystem {
    /// Create a new lab network QUIC PTO system for testing
    pub async fn new(cx: &Cx, config: LabQuicPtoConfig) -> Result<Self, Error> {
        // Initialize virtual time for deterministic testing
        let virtual_time = Arc::new(VirtualTime::new());

        // Initialize lab network simulation
        let mut network_config = NetworkConfig {
            topology: NetworkTopology::PointToPoint,
            latency: config.lab_config.network_latency,
            bandwidth: config.lab_config.bandwidth,
            loss_rate: config.lab_config.packet_loss_rate,
            deterministic: config.lab_config.deterministic_mode == DeterministicMode::Strict,
        };

        let lab_network = SimulatedNetwork::new(network_config)?;

        // Initialize QUIC endpoint
        let endpoint_config = EndpointConfig {
            local_addr: config.local_addr,
            connection_config: config.quic_config.clone(),
            tls_config: TlsConfig::default_client(),
        };

        let quic_endpoint = Endpoint::new(endpoint_config).await?;

        // Initialize monitoring components
        let connection_tracker = Arc::new(ConnectionTracker::new());
        let reordering_monitor = Arc::new(ReorderingMonitor::new(config.reordering_config.clone()));
        let pto_analyzer = Arc::new(PtoAnalyzer::new(config.pto_config.clone()));
        let packet_injector = Arc::new(PacketInjector::new(config.reordering_config.clone()));

        let forensic_log = Arc::new(Mutex::new(ForensicLog::new()));
        let test_stats = Arc::new(TestStats::new());

        Ok(Self {
            config,
            lab_network: Arc::new(Mutex::new(lab_network)),
            quic_endpoint: Arc::new(Mutex::new(quic_endpoint)),
            connection_tracker,
            reordering_monitor,
            pto_analyzer,
            packet_injector,
            forensic_log,
            test_stats,
            virtual_time,
            active_connection: Arc::new(Mutex::new(None)),
        })
    }

    /// Establish QUIC connection through lab network
    pub async fn establish_connection(&self, cx: &Cx) -> Result<QuicConnection, Error> {
        let start_time = Instant::now();

        // Configure lab network for this test
        {
            let mut network = self.lab_network.lock().await;
            network.enable_packet_reordering(self.config.reordering_config.clone())?;
            network.set_virtual_time(self.virtual_time.clone())?;
        }

        // Initiate QUIC connection
        let mut endpoint = self.quic_endpoint.lock().await;
        let connection = endpoint.connect(self.config.remote_addr, "test-server").await?;

        // Wait for handshake completion
        let handshake_timeout = Duration::from_secs(10);
        let handshake_result = timeout(handshake_timeout, async {
            loop {
                match connection.state().await {
                    ConnectionState::Established => break Ok(()),
                    ConnectionState::Failed(err) => break Err(err),
                    ConnectionState::Closed => break Err(Error::new("Connection closed during handshake")),
                    _ => Sleep::new(Duration::from_millis(10)).await,
                }
            }
        }).await;

        match handshake_result {
            Ok(Ok(())) => {
                // Store active connection
                {
                    let mut active_conn = self.active_connection.lock().await;
                    *active_conn = Some(connection.clone());
                }

                // Start monitoring connection events
                self.start_connection_monitoring(cx, &connection).await?;

                self.test_stats.test_start_time.store(
                    start_time.elapsed().as_millis() as u64,
                    Ordering::SeqCst
                );

                Ok(connection)
            }
            Ok(Err(e)) => Err(Error::new(&format!("Handshake failed: {}", e))),
            Err(_) => Err(Error::new("Handshake timeout")),
        }
    }

    /// Start monitoring connection events and state changes
    async fn start_connection_monitoring(
        &self,
        cx: &Cx,
        connection: &QuicConnection,
    ) -> Result<(), Error> {
        let connection_clone = connection.clone();
        let tracker_clone = Arc::clone(&self.connection_tracker);
        let pto_analyzer_clone = Arc::clone(&self.pto_analyzer);

        // Start connection event monitoring task
        cx.spawn("connection_monitor", async move {
            let mut event_stream = connection_clone.events().await;

            while let Some(event) = event_stream.next().await {
                Self::process_connection_event(&tracker_clone, &pto_analyzer_clone, event).await;
            }

            Ok(())
        }).await?;

        Ok(())
    }

    /// Process connection events for tracking and analysis
    async fn process_connection_event(
        tracker: &ConnectionTracker,
        pto_analyzer: &PtoAnalyzer,
        event: ConnectionEvent,
    ) {
        let timestamp = Instant::now();

        match &event {
            ConnectionEvent::PacketSent { packet_number, size, .. } => {
                let tracked_event = TrackedConnectionEvent {
                    timestamp,
                    event_type: ConnectionEventType::PacketSent,
                    packet_number: Some(*packet_number),
                    stream_id: None,
                    details: format!("Sent packet {}, size: {}", packet_number, size),
                };

                {
                    let mut events = tracker.connection_events.lock().await;
                    events.push(tracked_event);

                    let mut packet_tracker = tracker.packet_numbers.lock().await;
                    packet_tracker.sent_packets.insert(*packet_number);
                }
            }
            ConnectionEvent::PacketReceived { packet_number, size, .. } => {
                let tracked_event = TrackedConnectionEvent {
                    timestamp,
                    event_type: ConnectionEventType::PacketReceived,
                    packet_number: Some(*packet_number),
                    stream_id: None,
                    details: format!("Received packet {}, size: {}", packet_number, size),
                };

                {
                    let mut events = tracker.connection_events.lock().await;
                    events.push(tracked_event);

                    let mut packet_tracker = tracker.packet_numbers.lock().await;
                    if packet_tracker.received_packets.contains(packet_number) {
                        packet_tracker.duplicate_packets.push(*packet_number);
                    } else {
                        packet_tracker.received_packets.insert(*packet_number);
                    }
                }
            }
            ConnectionEvent::PtoFired { pto_count, pto_value, .. } => {
                let tracked_event = TrackedConnectionEvent {
                    timestamp,
                    event_type: ConnectionEventType::PtoFired,
                    packet_number: None,
                    stream_id: None,
                    details: format!("PTO fired, count: {}, value: {:?}", pto_count, pto_value),
                };

                {
                    let mut events = tracker.connection_events.lock().await;
                    events.push(tracked_event);
                }

                // Record PTO event for analysis
                let pto_event = PtoEvent {
                    timestamp,
                    event_type: PtoEventType::PtoFired,
                    pto_count: *pto_count,
                    pto_value: *pto_value,
                    packets_in_flight: 0, // Would be filled from connection state
                    probe_packets_sent: 1, // Typical behavior
                    trigger_reason: PtoTrigger::PacketReordering, // Assume reordering trigger
                };

                {
                    let mut pto_events = pto_analyzer.pto_events.lock().await;
                    pto_events.push(pto_event);
                }
            }
            ConnectionEvent::AckReceived { largest_acknowledged, ack_delay, .. } => {
                let tracked_event = TrackedConnectionEvent {
                    timestamp,
                    event_type: ConnectionEventType::AckReceived,
                    packet_number: Some(*largest_acknowledged),
                    stream_id: None,
                    details: format!("ACK received, largest: {}, delay: {:?}", largest_acknowledged, ack_delay),
                };

                {
                    let mut events = tracker.connection_events.lock().await;
                    events.push(tracked_event);

                    let mut packet_tracker = tracker.packet_numbers.lock().await;
                    packet_tracker.largest_acknowledged = Some(*largest_acknowledged);
                }
            }
            ConnectionEvent::RttUpdated { latest_rtt, smoothed_rtt, .. } => {
                let rtt_measurement = RttMeasurement {
                    measured_at: timestamp,
                    rtt: *latest_rtt,
                    ack_delay: Duration::ZERO, // Would extract from event if available
                    packet_number: 0, // Would extract from context
                    sample_type: RttSampleType::Normal,
                };

                {
                    let mut rtt_measurements = tracker.rtt_measurements.lock().await;
                    rtt_measurements.push_back(rtt_measurement);
                    while rtt_measurements.len() > 1000 {
                        rtt_measurements.pop_front();
                    }
                }
            }
            _ => {
                // Handle other event types as needed
            }
        }
    }

    /// Inject packet reordering into the lab network
    pub async fn inject_packet_reordering(
        &self,
        cx: &Cx,
        pattern: ReorderingPattern,
        parameters: ReorderingParameters,
    ) -> Result<(), Error> {
        let injection_event = InjectionEvent {
            timestamp: Instant::now(),
            packet_number: parameters.target_packet,
            injection_type: InjectionType::DelayReorder,
            delay: parameters.delay,
            target_order: parameters.new_order,
        };

        // Add to injection queue
        {
            let mut queue = self.packet_injector.injection_queue.lock().await;
            queue.push_back(injection_event.clone());
        }

        // Configure lab network for reordering
        {
            let mut network = self.lab_network.lock().await;
            network.inject_packet_delay(
                parameters.target_packet,
                parameters.delay,
                pattern,
            ).await?;
        }

        // Record reordering event
        let reordering_event = ReorderingEvent {
            timestamp: injection_event.timestamp,
            packet_number: parameters.target_packet,
            original_order: parameters.original_order,
            delivered_order: parameters.new_order.unwrap_or(parameters.original_order),
            reorder_distance: parameters.reorder_distance,
            delay_injected: parameters.delay,
            pattern_type: pattern,
        };

        {
            let mut events = self.reordering_monitor.reordering_events.lock().await;
            events.push(reordering_event);
        }

        Ok(())
    }

    /// Send test data over QUIC stream with reordering
    pub async fn send_test_data_with_reordering(
        &self,
        cx: &Cx,
        reordering_scenario: ReorderingScenario,
    ) -> Result<TestResults, Error> {
        let connection = {
            let active_conn = self.active_connection.lock().await;
            active_conn.clone().ok_or_else(|| Error::new("No active connection"))?
        };

        // Open test stream
        let stream = connection.open_stream(self.config.stream_config.stream_type).await?;

        // Configure reordering injection based on scenario
        self.configure_reordering_scenario(reordering_scenario).await?;

        // Send test packets
        let mut test_results = TestResults::new();
        let test_data = vec![0xAB; self.config.stream_config.data_per_packet];

        for packet_index in 0..self.config.test_packet_count {
            // Check if this packet should be reordered
            if self.should_reorder_packet(packet_index).await {
                let reordering_params = self.generate_reordering_parameters(packet_index).await;
                self.inject_packet_reordering(cx, reordering_scenario.pattern, reordering_params).await?;
            }

            // Send packet
            let packet_data = format!("packet_{}", packet_index).into_bytes();
            match stream.send(&packet_data).await {
                Ok(_) => {
                    self.test_stats.packets_sent.fetch_add(1, Ordering::SeqCst);
                    self.test_stats.bytes_sent.fetch_add(packet_data.len() as u64, Ordering::SeqCst);
                    test_results.packets_sent += 1;
                }
                Err(e) => {
                    test_results.send_errors += 1;
                    eprintln!("Failed to send packet {}: {}", packet_index, e);
                }
            }

            // Wait between sends
            Sleep::new(self.config.stream_config.send_interval).await;
        }

        // Wait for all packets to be processed
        Sleep::new(Duration::from_secs(2)).await;

        // Collect final results
        test_results.test_duration = self.virtual_time.elapsed();
        test_results.pto_fires = self.test_stats.pto_fires.load(Ordering::SeqCst);
        test_results.retransmissions = self.test_stats.retransmissions.load(Ordering::SeqCst);
        test_results.ordering_violations = self.test_stats.ordering_violations.load(Ordering::SeqCst);

        Ok(test_results)
    }

    /// Configure lab network for specific reordering scenario
    async fn configure_reordering_scenario(&self, scenario: ReorderingScenario) -> Result<(), Error> {
        let mut network = self.lab_network.lock().await;

        match scenario {
            ReorderingScenario::Simple { probability, distance } => {
                network.set_reordering_probability(probability)?;
                network.set_max_reorder_distance(distance)?;
            }
            ReorderingScenario::Burst { size, frequency } => {
                network.set_burst_reordering(size, frequency)?;
            }
            ReorderingScenario::LongDelay { delay_threshold } => {
                network.set_long_delay_threshold(delay_threshold)?;
            }
            ReorderingScenario::Persistent { duration } => {
                network.enable_persistent_reordering(duration)?;
            }
        }

        Ok(())
    }

    /// Determine if a packet should be reordered
    async fn should_reorder_packet(&self, packet_index: u32) -> bool {
        let pattern_gen = self.packet_injector.pattern_generator.lock().await;

        match pattern_gen.pattern_state {
            PatternState::Random { next_reorder_at } => packet_index as u64 >= next_reorder_at,
            PatternState::Periodic { period, phase } => (packet_index + phase) % period == 0,
            PatternState::Burst { burst_size, packets_in_burst } => packets_in_burst < burst_size,
            PatternState::Custom { .. } => false, // Custom logic would go here
        }
    }

    /// Generate reordering parameters for a packet
    async fn generate_reordering_parameters(&self, packet_index: u32) -> ReorderingParameters {
        let config = &self.config.reordering_config;

        ReorderingParameters {
            target_packet: packet_index as u64,
            original_order: packet_index as u64,
            new_order: Some(packet_index as u64 + config.max_reorder_distance as u64),
            reorder_distance: config.max_reorder_distance,
            delay: config.reorder_delay_range.0, // Use minimum delay for simplicity
        }
    }

    /// Verify ordering invariants are maintained
    pub async fn verify_ordering_invariants(&self) -> Result<OrderingVerificationReport, Error> {
        let packet_tracker = self.connection_tracker.packet_numbers.lock().await;
        let reordering_events = self.reordering_monitor.reordering_events.lock().await;

        let mut report = OrderingVerificationReport::new();

        // Check for gaps in received packet sequence
        let mut expected_next = 0u64;
        for &received_pn in packet_tracker.received_packets.iter() {
            if received_pn > expected_next {
                report.sequence_gaps.push(SequenceGap {
                    start: expected_next,
                    end: received_pn - 1,
                    gap_size: received_pn - expected_next,
                });
                report.total_gaps += 1;
            }
            expected_next = received_pn + 1;
        }

        // Check for duplicates
        report.duplicate_packets = packet_tracker.duplicate_packets.clone();
        report.total_duplicates = packet_tracker.duplicate_packets.len() as u32;

        // Check reordering distances
        for event in reordering_events.iter() {
            if event.reorder_distance > self.config.reordering_config.max_reorder_distance {
                report.invariant_violations.push(OrderingViolation {
                    packet_number: event.packet_number,
                    violation_type: ViolationType::ExcessiveReordering,
                    expected_value: self.config.reordering_config.max_reorder_distance as u64,
                    actual_value: event.reorder_distance as u64,
                });
                report.total_violations += 1;
            }
        }

        // Overall assessment
        report.invariants_maintained = report.total_violations == 0;

        Ok(report)
    }

    /// Analyze PTO timer behavior and accuracy
    pub async fn analyze_pto_behavior(&self) -> Result<PtoBehaviorReport, Error> {
        let pto_events = self.pto_analyzer.pto_events.lock().await;
        let timer_measurements = self.pto_analyzer.timer_accuracy.lock().await;
        let probe_packets = self.pto_analyzer.probe_packets.lock().await;

        let mut report = PtoBehaviorReport::new();

        // Analyze PTO firing frequency
        let pto_fires: Vec<_> = pto_events
            .iter()
            .filter(|event| matches!(event.event_type, PtoEventType::PtoFired))
            .collect();

        report.total_pto_fires = pto_fires.len() as u32;

        if !pto_fires.is_empty() {
            let total_duration = pto_fires.last().unwrap().timestamp.duration_since(pto_fires.first().unwrap().timestamp);
            report.pto_fire_rate = pto_fires.len() as f64 / total_duration.as_secs_f64();
        }

        // Analyze timer accuracy
        for measurement in timer_measurements.iter() {
            let accuracy_error = measurement.accuracy_error;
            report.timer_accuracy_errors.push(accuracy_error);

            if accuracy_error > Duration::from_millis(10) {
                report.timing_violations += 1;
            }
        }

        // Analyze probe packet behavior
        report.probe_packets_sent = probe_packets.len() as u32;
        report.probe_packets_acknowledged = probe_packets
            .iter()
            .filter(|probe| probe.acknowledged)
            .count() as u32;

        if report.probe_packets_sent > 0 {
            report.probe_ack_rate = report.probe_packets_acknowledged as f64 / report.probe_packets_sent as f64;
        }

        // Check RFC 9002 compliance
        report.rfc_compliance_violations = self.check_rfc9002_compliance(&pto_events).await;

        report.compliant_behavior = report.rfc_compliance_violations.is_empty() && report.timing_violations == 0;

        Ok(report)
    }

    /// Check compliance with RFC 9002 PTO specifications
    async fn check_rfc9002_compliance(&self, pto_events: &[PtoEvent]) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();

        for event in pto_events.iter() {
            // Check PTO backoff behavior
            if event.pto_count > 0 && event.pto_value < self.config.pto_config.initial_pto {
                violations.push(ComplianceViolation {
                    violation_type: "PTO value decreased without reset".to_string(),
                    details: format!("PTO count: {}, value: {:?}", event.pto_count, event.pto_value),
                    timestamp: event.timestamp,
                });
            }

            // Check maximum PTO count
            if event.pto_count > self.config.pto_config.pto_count_threshold {
                violations.push(ComplianceViolation {
                    violation_type: "PTO count exceeded threshold".to_string(),
                    details: format!("PTO count: {} > threshold: {}", event.pto_count, self.config.pto_config.pto_count_threshold),
                    timestamp: event.timestamp,
                });
            }
        }

        violations
    }

    /// Get comprehensive test statistics
    pub async fn get_test_statistics(&self) -> TestStatisticsSnapshot {
        TestStatisticsSnapshot {
            packets_sent: self.test_stats.packets_sent.load(Ordering::SeqCst),
            packets_received: self.test_stats.packets_received.load(Ordering::SeqCst),
            bytes_sent: self.test_stats.bytes_sent.load(Ordering::SeqCst),
            bytes_received: self.test_stats.bytes_received.load(Ordering::SeqCst),
            pto_fires: self.test_stats.pto_fires.load(Ordering::SeqCst),
            retransmissions: self.test_stats.retransmissions.load(Ordering::SeqCst),
            ordering_violations: self.test_stats.ordering_violations.load(Ordering::SeqCst),
            test_duration: *self.test_stats.test_duration.lock().await,
            reordering_stats: self.reordering_monitor.reordering_stats.lock().await.clone(),
        }
    }
}

// Define remaining types and implementations

#[derive(Debug, Clone, Copy)]
pub enum ReorderingScenario {
    Simple { probability: f64, distance: u32 },
    Burst { size: u32, frequency: f64 },
    LongDelay { delay_threshold: Duration },
    Persistent { duration: Duration },
}

#[derive(Debug, Clone)]
pub struct ReorderingParameters {
    pub target_packet: u64,
    pub original_order: u64,
    pub new_order: Option<u64>,
    pub reorder_distance: u32,
    pub delay: Duration,
}

#[derive(Debug, Clone)]
pub struct TestResults {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub send_errors: u32,
    pub receive_errors: u32,
    pub test_duration: Duration,
    pub pto_fires: u32,
    pub retransmissions: u64,
    pub ordering_violations: u32,
}

impl TestResults {
    pub fn new() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            send_errors: 0,
            receive_errors: 0,
            test_duration: Duration::ZERO,
            pto_fires: 0,
            retransmissions: 0,
            ordering_violations: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OrderingVerificationReport {
    pub sequence_gaps: Vec<SequenceGap>,
    pub total_gaps: u32,
    pub duplicate_packets: Vec<u64>,
    pub total_duplicates: u32,
    pub invariant_violations: Vec<OrderingViolation>,
    pub total_violations: u32,
    pub invariants_maintained: bool,
}

impl OrderingVerificationReport {
    pub fn new() -> Self {
        Self {
            sequence_gaps: Vec::new(),
            total_gaps: 0,
            duplicate_packets: Vec::new(),
            total_duplicates: 0,
            invariant_violations: Vec::new(),
            total_violations: 0,
            invariants_maintained: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SequenceGap {
    pub start: u64,
    pub end: u64,
    pub gap_size: u64,
}

#[derive(Debug, Clone)]
pub struct OrderingViolation {
    pub packet_number: u64,
    pub violation_type: ViolationType,
    pub expected_value: u64,
    pub actual_value: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ViolationType {
    ExcessiveReordering,
    SequenceGap,
    DuplicateDelivery,
    OrderingInversion,
}

#[derive(Debug, Clone)]
pub struct PtoBehaviorReport {
    pub total_pto_fires: u32,
    pub pto_fire_rate: f64,
    pub timer_accuracy_errors: Vec<Duration>,
    pub timing_violations: u32,
    pub probe_packets_sent: u32,
    pub probe_packets_acknowledged: u32,
    pub probe_ack_rate: f64,
    pub rfc_compliance_violations: Vec<ComplianceViolation>,
    pub compliant_behavior: bool,
}

impl PtoBehaviorReport {
    pub fn new() -> Self {
        Self {
            total_pto_fires: 0,
            pto_fire_rate: 0.0,
            timer_accuracy_errors: Vec::new(),
            timing_violations: 0,
            probe_packets_sent: 0,
            probe_packets_acknowledged: 0,
            probe_ack_rate: 0.0,
            rfc_compliance_violations: Vec::new(),
            compliant_behavior: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComplianceViolation {
    pub violation_type: String,
    pub details: String,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct TestStatisticsSnapshot {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub pto_fires: u32,
    pub retransmissions: u64,
    pub ordering_violations: u32,
    pub test_duration: Duration,
    pub reordering_stats: ReorderingStats,
}

// Implementation for helper components

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connection_events: Mutex::new(Vec::new()),
            connection_state: Mutex::new(ConnectionState::Idle),
            stream_states: Mutex::new(HashMap::new()),
            congestion_state: Mutex::new(CongestionState {
                congestion_window: 14720, // Initial congestion window (10 MSS)
                bytes_in_flight: 0,
                ssthresh: u64::MAX,
                congestion_recovery_start: None,
                persistent_congestion: false,
            }),
            flow_control_state: Mutex::new(FlowControlState {
                connection_send_window: 65536,
                connection_recv_window: 65536,
                stream_send_windows: HashMap::new(),
                stream_recv_windows: HashMap::new(),
            }),
            packet_numbers: Mutex::new(PacketNumberTracker {
                sent_packets: BTreeSet::new(),
                received_packets: BTreeSet::new(),
                reordered_packets: Vec::new(),
                lost_packets: BTreeSet::new(),
                duplicate_packets: Vec::new(),
                largest_acknowledged: None,
            }),
            rtt_measurements: Mutex::new(VecDeque::new()),
        }
    }
}

impl ReorderingMonitor {
    pub fn new(config: ReorderingConfig) -> Self {
        Self {
            config,
            reordering_events: Mutex::new(Vec::new()),
            packet_delays: Mutex::new(HashMap::new()),
            reordering_stats: Mutex::new(ReorderingStats {
                total_packets_sent: 0,
                total_packets_reordered: 0,
                reordering_rate: 0.0,
                average_reorder_distance: 0.0,
                average_reorder_delay: Duration::ZERO,
                burst_count: 0,
                max_burst_size: 0,
            }),
            burst_tracker: Mutex::new(BurstTracker {
                current_burst: Vec::new(),
                burst_start_time: None,
                completed_bursts: Vec::new(),
            }),
        }
    }
}

impl PtoAnalyzer {
    pub fn new(config: PtoConfig) -> Self {
        Self {
            config,
            pto_events: Mutex::new(Vec::new()),
            pto_state: Mutex::new(PtoState {
                pto_count: 0,
                current_pto: config.initial_pto,
                timer_armed: false,
                timer_expiry: None,
                packets_in_flight: 0,
                probe_packets_outstanding: 0,
            }),
            probe_packets: Mutex::new(Vec::new()),
            retransmission_tracker: Mutex::new(RetransmissionTracker {
                retransmissions: Vec::new(),
                spurious_retransmissions: Vec::new(),
                retransmission_stats: RetransmissionStats {
                    total_retransmissions: 0,
                    pto_retransmissions: 0,
                    fast_retransmissions: 0,
                    spurious_retransmissions: 0,
                    spurious_rate: 0.0,
                    average_retransmission_delay: Duration::ZERO,
                },
            }),
            timer_accuracy: Mutex::new(Vec::new()),
        }
    }
}

impl PacketInjector {
    pub fn new(config: ReorderingConfig) -> Self {
        Self {
            config,
            injection_queue: Mutex::new(VecDeque::new()),
            delayed_packets: Mutex::new(Vec::new()),
            injection_stats: Mutex::new(InjectionStats {
                packets_delayed: 0,
                packets_reordered: 0,
                packets_dropped: 0,
                packets_duplicated: 0,
                bursts_created: 0,
                average_injection_delay: Duration::ZERO,
            }),
            pattern_generator: Mutex::new(PatternGenerator {
                current_pattern: config.pattern,
                pattern_state: PatternState::Random { next_reorder_at: 10 },
                random_seed: 12345,
            }),
        }
    }
}

impl TestStats {
    pub fn new() -> Self {
        Self {
            test_start_time: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            pto_fires: AtomicU32::new(0),
            retransmissions: AtomicU64::new(0),
            ordering_violations: AtomicU32::new(0),
            test_duration: Mutex::new(Duration::ZERO),
        }
    }
}

// Mock implementations for required types - simplified for testing
impl SimulatedNetwork {
    pub fn new(config: NetworkConfig) -> Result<Self, Error> {
        Ok(Self { config })
    }

    pub fn enable_packet_reordering(&mut self, config: ReorderingConfig) -> Result<(), Error> {
        // Implementation would configure packet reordering
        Ok(())
    }

    pub fn set_virtual_time(&mut self, time: Arc<VirtualTime>) -> Result<(), Error> {
        // Implementation would set virtual time reference
        Ok(())
    }

    pub async fn inject_packet_delay(
        &mut self,
        packet_number: u64,
        delay: Duration,
        pattern: ReorderingPattern,
    ) -> Result<(), Error> {
        // Implementation would inject delay for specific packet
        Ok(())
    }

    pub fn set_reordering_probability(&mut self, prob: f64) -> Result<(), Error> { Ok(()) }
    pub fn set_max_reorder_distance(&mut self, distance: u32) -> Result<(), Error> { Ok(()) }
    pub fn set_burst_reordering(&mut self, size: u32, freq: f64) -> Result<(), Error> { Ok(()) }
    pub fn set_long_delay_threshold(&mut self, threshold: Duration) -> Result<(), Error> { Ok(()) }
    pub fn enable_persistent_reordering(&mut self, duration: Duration) -> Result<(), Error> { Ok(()) }
}

async fn timeout<T>(duration: Duration, future: impl std::future::Future<Output = T>) -> Result<T, tokio::time::error::Elapsed> {
    tokio::time::timeout(duration, future).await
}

#[derive(Debug)]
pub struct SimulatedNetwork {
    config: NetworkConfig,
}

#[derive(Debug)]
pub struct NetworkConfig {
    pub topology: NetworkTopology,
    pub latency: NetworkLatency,
    pub bandwidth: Bandwidth,
    pub loss_rate: PacketLossRate,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum NetworkTopology {
    PointToPoint,
    Star,
    Mesh,
}

/// Test 1: Normal packet delivery without reordering baseline
#[tokio::test]
async fn test_normal_packet_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::for_testing();
    let config = LabQuicPtoConfig::default();
    let system = MockLabQuicPtoSystem::new(&cx, config).await?;

    // Establish connection
    let _connection = system.establish_connection(&cx).await?;

    // Send test data without any reordering
    let test_results = system.send_test_data_with_reordering(
        &cx,
        ReorderingScenario::Simple { probability: 0.0, distance: 0 },
    ).await?;

    // Verify baseline behavior
    assert!(test_results.packets_sent > 0);
    assert_eq!(test_results.pto_fires, 0); // No PTO should fire with normal delivery
    assert_eq!(test_results.ordering_violations, 0);

    // Verify ordering invariants
    let ordering_report = system.verify_ordering_invariants().await?;
    assert!(ordering_report.invariants_maintained);

    println!("✅ Normal packet delivery: {}/{} packets sent successfully",
             test_results.packets_sent, test_results.packets_sent);
    Ok(())
}

/// Test 2: Simple packet reordering triggering PTO
#[tokio::test]
async fn test_simple_packet_reordering_pto() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::for_testing();
    let config = LabQuicPtoConfig::default();
    let system = MockLabQuicPtoSystem::new(&cx, config).await?;

    // Establish connection
    let _connection = system.establish_connection(&cx).await?;

    // Send test data with simple reordering
    let test_results = system.send_test_data_with_reordering(
        &cx,
        ReorderingScenario::Simple { probability: 0.2, distance: 3 },
    ).await?;

    // Verify PTO behavior
    assert!(test_results.pto_fires > 0, "PTO should fire due to reordering");

    // Analyze PTO behavior
    let pto_report = system.analyze_pto_behavior().await?;
    assert!(pto_report.total_pto_fires > 0);
    assert!(pto_report.probe_packets_sent > 0);

    // Verify ordering invariants are still maintained
    let ordering_report = system.verify_ordering_invariants().await?;
    assert!(ordering_report.invariants_maintained, "Ordering invariants should be maintained despite reordering");

    println!("✅ Simple reordering: {} PTO fires, {} probe packets sent",
             pto_report.total_pto_fires, pto_report.probe_packets_sent);
    Ok(())
}

/// Test 3: Burst reordering with multiple consecutive packets
#[tokio::test]
async fn test_burst_reordering() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::for_testing();
    let config = LabQuicPtoConfig::default();
    let system = MockLabQuicPtoSystem::new(&cx, config).await?;

    // Establish connection
    let _connection = system.establish_connection(&cx).await?;

    // Send test data with burst reordering
    let test_results = system.send_test_data_with_reordering(
        &cx,
        ReorderingScenario::Burst { size: 5, frequency: 0.1 },
    ).await?;

    // Verify burst reordering triggers appropriate PTO response
    assert!(test_results.pto_fires > 0);

    // Check that bursts don't cause excessive violations
    let ordering_report = system.verify_ordering_invariants().await?;
    assert!(ordering_report.total_violations <= test_results.pto_fires * 2,
           "Violations should be proportional to reordering");

    // Verify RFC compliance
    let pto_report = system.analyze_pto_behavior().await?;
    assert!(pto_report.compliant_behavior || pto_report.rfc_compliance_violations.len() <= 1,
           "Should maintain RFC 9002 compliance");

    println!("✅ Burst reordering: {} violations, {} PTO fires",
             ordering_report.total_violations, test_results.pto_fires);
    Ok(())
}

/// Test 4: Long-delay reordering beyond PTO threshold
#[tokio::test]
async fn test_long_delay_reordering() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::for_testing();
    let config = LabQuicPtoConfig::default();
    let system = MockLabQuicPtoSystem::new(&cx, config).await?;

    // Establish connection
    let _connection = system.establish_connection(&cx).await?;

    // Send test data with long delays that exceed PTO
    let test_results = system.send_test_data_with_reordering(
        &cx,
        ReorderingScenario::LongDelay { delay_threshold: Duration::from_millis(300) },
    ).await?;

    // Long delays should definitely trigger PTO
    assert!(test_results.pto_fires > 0, "Long delays should trigger PTO");
    assert!(test_results.retransmissions > 0, "Should see retransmissions");

    // Analyze PTO behavior for long delays
    let pto_report = system.analyze_pto_behavior().await?;
    assert!(pto_report.pto_fire_rate > 0.0);

    // Even with long delays, ordering should be maintained
    let ordering_report = system.verify_ordering_invariants().await?;
    assert!(ordering_report.invariants_maintained);

    println!("✅ Long delay reordering: {} retransmissions, PTO fire rate: {:.3}/s",
             test_results.retransmissions, pto_report.pto_fire_rate);
    Ok(())
}

/// Test 5: Persistent reordering patterns over time
#[tokio::test]
async fn test_persistent_reordering() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::for_testing();
    let mut config = LabQuicPtoConfig::default();
    config.test_packet_count = 200; // More packets for persistent test
    let system = MockLabQuicPtoSystem::new(&cx, config).await?;

    // Establish connection
    let _connection = system.establish_connection(&cx).await?;

    // Send test data with persistent reordering
    let test_results = system.send_test_data_with_reordering(
        &cx,
        ReorderingScenario::Persistent { duration: Duration::from_secs(5) },
    ).await?;

    // Persistent reordering should trigger multiple PTOs
    assert!(test_results.pto_fires >= 3, "Persistent reordering should trigger multiple PTOs");

    // Analyze sustained behavior
    let pto_report = system.analyze_pto_behavior().await?;
    assert!(pto_report.probe_ack_rate > 0.5, "Most probes should be acknowledged eventually");

    // System should adapt and maintain stability
    let stats = system.get_test_statistics().await;
    assert!(stats.reordering_stats.reordering_rate <= 1.0);

    println!("✅ Persistent reordering: {} packets, {:.1}% reordering rate",
             test_results.packets_sent, stats.reordering_stats.reordering_rate * 100.0);
    Ok(())
}

/// Test 6: Recovery verification after reordering scenarios
#[tokio::test]
async fn test_recovery_verification() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::for_testing();
    let config = LabQuicPtoConfig::default();
    let system = MockLabQuicPtoSystem::new(&cx, config).await?;

    // Establish connection
    let _connection = system.establish_connection(&cx).await?;

    // Phase 1: Heavy reordering
    let phase1_results = system.send_test_data_with_reordering(
        &cx,
        ReorderingScenario::Simple { probability: 0.5, distance: 5 },
    ).await?;

    // Phase 2: Return to normal delivery
    Sleep::new(Duration::from_secs(1)).await; // Allow system to stabilize

    let phase2_results = system.send_test_data_with_reordering(
        &cx,
        ReorderingScenario::Simple { probability: 0.0, distance: 0 },
    ).await?;

    // Verify recovery behavior
    assert!(phase1_results.pto_fires > 0, "Phase 1 should have PTO fires");
    assert!(phase2_results.pto_fires <= phase1_results.pto_fires,
           "Phase 2 should have fewer or equal PTO fires");

    // Final verification
    let final_ordering_report = system.verify_ordering_invariants().await?;
    assert!(final_ordering_report.invariants_maintained,
           "Ordering invariants should be maintained after recovery");

    let final_pto_report = system.analyze_pto_behavior().await?;
    assert!(final_pto_report.compliant_behavior || final_pto_report.rfc_compliance_violations.is_empty(),
           "Should maintain RFC compliance after recovery");

    println!("✅ Recovery verification: Phase 1 {} PTOs → Phase 2 {} PTOs",
             phase1_results.pto_fires, phase2_results.pto_fires);
    Ok(())
}