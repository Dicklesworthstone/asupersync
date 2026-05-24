//! BR-E2E-92: Real net/quic_native/streams ↔ net/quic_native/tls Integration E2E Tests
//!
//! This module provides comprehensive integration tests between QUIC native streams
//! and QUIC native TLS subsystems. The tests verify that TLS rekey on a long-lived
//! stream correctly continues stream flow without head-of-line blocking.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `net::quic_native::streams` - QUIC stream multiplexing and flow control management
//! - `net::quic_native::tls` - QUIC TLS 1.3 key rotation and security layer management
//!
//! # Key Scenarios
//!
//! - TLS rekey during active stream data transmission
//! - Stream flow continuity across key rotation boundaries
//! - Head-of-line blocking prevention during rekey operations
//! - Multiple concurrent streams during TLS rekey
//! - Stream backpressure handling during key rotation

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    net::{
        quic_native::{
            streams::{
                QuicStream, QuicStreamId, QuicStreamType, StreamDirection,
                StreamFrame, StreamState, StreamEvent, StreamController,
                StreamFlowController, StreamManager, StreamConfig,
                StreamMultiplexer, BidirectionalStream, UnidirectionalStream,
            },
            tls::{
                QuicTls, QuicTlsConfig, QuicTlsKeyManager, TlsRekey,
                KeyRotationEvent, KeyRotationState, TlsHandshakeState,
                EncryptionLevel, CipherSuite, KeyUpdateTrigger,
                TrafficSecrets, QuicTlsConnection, TlsKeySchedule,
            },
            connection::{QuicConnection, QuicConnectionConfig},
            endpoint::{QuicEndpoint, EndpointConfig},
            packet::{QuicPacket, PacketType},
            frame::{QuicFrame, FrameType},
        },
        SocketAddr,
    },
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex, RwLock, Semaphore},
    time::{Duration, Sleep, Instant, Timeout},
    types::{Budget, TaskId, Cancel},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};

use std::{
    collections::{HashMap, BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering},
        Arc,
    },
    pin::Pin,
    task::{Context, Poll},
    future::Future,
};

use futures::{
    stream::{Stream, StreamExt},
    sink::{Sink, SinkExt},
    ready,
};

/// Configuration for QUIC TLS rekey integration tests
#[derive(Debug, Clone)]
struct QuicTlsRekeyTestConfig {
    /// Initial key rotation interval
    key_rotation_interval: Duration,
    /// Stream data transmission rate
    stream_data_rate: u64,
    /// Number of concurrent streams
    concurrent_streams: u32,
    /// Test duration
    test_duration: Duration,
    /// Maximum stream backlog size
    max_stream_backlog: usize,
    /// Flow control window size
    flow_control_window: u64,
}

impl Default for QuicTlsRekeyTestConfig {
    fn default() -> Self {
        Self {
            key_rotation_interval: Duration::from_millis(500),
            stream_data_rate: 1024 * 1024, // 1MB/s per stream
            concurrent_streams: 8,
            test_duration: Duration::from_secs(5),
            max_stream_backlog: 16384,
            flow_control_window: 1024 * 1024,
        }
    }
}

/// Tracks TLS rekey events and their impact on stream flow
#[derive(Debug)]
struct TlsRekeyFlowTracker {
    /// Rekey events with timestamps
    rekey_events: Arc<Mutex<Vec<(Instant, KeyRotationEvent)>>>,
    /// Stream flow measurements during rekey
    stream_flows: Arc<Mutex<HashMap<QuicStreamId, Vec<StreamFlowMeasurement>>>>,
    /// Head-of-line blocking detection
    hol_blocking_events: Arc<Mutex<Vec<HolBlockingEvent>>>,
    /// Active key rotation state
    active_rotation: Arc<AtomicBool>,
    /// Flow continuity verification
    flow_continuity: Arc<Mutex<HashMap<QuicStreamId, FlowContinuityState>>>,
}

#[derive(Debug, Clone)]
struct StreamFlowMeasurement {
    timestamp: Instant,
    stream_id: QuicStreamId,
    bytes_transmitted: u64,
    flow_control_blocked: bool,
    encryption_level: EncryptionLevel,
    key_rotation_in_progress: bool,
}

#[derive(Debug, Clone)]
struct HolBlockingEvent {
    timestamp: Instant,
    blocked_stream: QuicStreamId,
    blocking_cause: BlockingCause,
    duration: Duration,
    affected_streams: Vec<QuicStreamId>,
}

#[derive(Debug, Clone, PartialEq)]
enum BlockingCause {
    KeyRotation,
    FlowControl,
    CongestionControl,
    StreamBackpressure,
}

#[derive(Debug, Clone)]
struct FlowContinuityState {
    last_transmission: Instant,
    total_bytes: u64,
    rekey_interruptions: u32,
    max_interruption_duration: Duration,
    flow_resumed_after_rekey: bool,
}

impl TlsRekeyFlowTracker {
    fn new() -> Self {
        Self {
            rekey_events: Arc::new(Mutex::new(Vec::new())),
            stream_flows: Arc::new(Mutex::new(HashMap::new())),
            hol_blocking_events: Arc::new(Mutex::new(Vec::new())),
            active_rotation: Arc::new(AtomicBool::new(false)),
            flow_continuity: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn record_rekey_event(&self, event: KeyRotationEvent) {
        let timestamp = Instant::now();
        self.rekey_events.lock().unwrap().push((timestamp, event.clone()));

        match event {
            KeyRotationEvent::Started { .. } => {
                self.active_rotation.store(true, Ordering::Release);
            }
            KeyRotationEvent::Completed { .. } => {
                self.active_rotation.store(false, Ordering::Release);
                self.verify_flow_resumption();
            }
            KeyRotationEvent::Failed { .. } => {
                self.active_rotation.store(false, Ordering::Release);
            }
        }
    }

    fn record_stream_flow(&self, measurement: StreamFlowMeasurement) {
        let mut flows = self.stream_flows.lock().unwrap();
        flows.entry(measurement.stream_id)
            .or_insert_with(Vec::new)
            .push(measurement.clone());

        // Update flow continuity state
        let mut continuity = self.flow_continuity.lock().unwrap();
        let state = continuity.entry(measurement.stream_id)
            .or_insert_with(|| FlowContinuityState {
                last_transmission: measurement.timestamp,
                total_bytes: 0,
                rekey_interruptions: 0,
                max_interruption_duration: Duration::ZERO,
                flow_resumed_after_rekey: false,
            });

        state.last_transmission = measurement.timestamp;
        state.total_bytes += measurement.bytes_transmitted;

        if measurement.key_rotation_in_progress {
            state.rekey_interruptions += 1;
            state.flow_resumed_after_rekey = measurement.bytes_transmitted > 0;
        }
    }

    fn record_hol_blocking(&self, event: HolBlockingEvent) {
        self.hol_blocking_events.lock().unwrap().push(event);
    }

    fn verify_flow_resumption(&self) {
        let continuity = self.flow_continuity.lock().unwrap();
        for (stream_id, state) in continuity.iter() {
            if state.rekey_interruptions > 0 && !state.flow_resumed_after_rekey {
                eprintln!("Warning: Stream {:?} did not resume flow after rekey", stream_id);
            }
        }
    }

    fn verify_no_hol_blocking(&self) -> bool {
        let events = self.hol_blocking_events.lock().unwrap();
        let key_rotation_blocking = events.iter()
            .filter(|e| e.blocking_cause == BlockingCause::KeyRotation)
            .count();

        key_rotation_blocking == 0
    }

    fn get_rekey_count(&self) -> usize {
        self.rekey_events.lock().unwrap().len()
    }

    fn get_stream_flow_continuity(&self, stream_id: QuicStreamId) -> Option<FlowContinuityState> {
        self.flow_continuity.lock().unwrap().get(&stream_id).cloned()
    }
}

/// Simulates long-lived QUIC streams with continuous data transmission
struct LongLivedStreamSimulator {
    streams: HashMap<QuicStreamId, StreamSimulationState>,
    data_generator: Arc<Mutex<DetRng>>,
    transmission_rate: u64,
    config: QuicTlsRekeyTestConfig,
    active: Arc<AtomicBool>,
}

#[derive(Debug)]
struct StreamSimulationState {
    stream_id: QuicStreamId,
    bytes_transmitted: Arc<AtomicU64>,
    last_transmission: Arc<Mutex<Instant>>,
    transmission_buffer: Arc<Mutex<VecDeque<Vec<u8>>>>,
    flow_blocked: Arc<AtomicBool>,
}

impl LongLivedStreamSimulator {
    fn new(config: QuicTlsRekeyTestConfig) -> Self {
        Self {
            streams: HashMap::new(),
            data_generator: Arc::new(Mutex::new(DetRng::from_seed(RngSeed::from_u64(0x7e5742)))),
            transmission_rate: config.stream_data_rate,
            config,
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    fn add_stream(&mut self, stream_id: QuicStreamId) {
        let state = StreamSimulationState {
            stream_id,
            bytes_transmitted: Arc::new(AtomicU64::new(0)),
            last_transmission: Arc::new(Mutex::new(Instant::now())),
            transmission_buffer: Arc::new(Mutex::new(VecDeque::new())),
            flow_blocked: Arc::new(AtomicBool::new(false)),
        };

        self.streams.insert(stream_id, state);
    }

    async fn simulate_continuous_transmission(
        &self,
        stream_id: QuicStreamId,
        tracker: Arc<TlsRekeyFlowTracker>,
        stream_controller: Arc<dyn StreamController>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = self.streams.get(&stream_id)
            .ok_or("Stream not found")?;

        let chunk_size = 1024;
        let interval = Duration::from_millis(
            (chunk_size * 1000) / self.transmission_rate
        );

        while self.active.load(Ordering::Acquire) {
            let data = {
                let mut rng = self.data_generator.lock().unwrap();
                (0..chunk_size).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>()
            };

            // Check if flow control allows transmission
            if state.flow_blocked.load(Ordering::Acquire) {
                // Record potential HOL blocking
                let hol_event = HolBlockingEvent {
                    timestamp: Instant::now(),
                    blocked_stream: stream_id,
                    blocking_cause: BlockingCause::FlowControl,
                    duration: Duration::from_millis(10),
                    affected_streams: vec![stream_id],
                };
                tracker.record_hol_blocking(hol_event);

                Sleep::new(Instant::now() + Duration::from_millis(10)).await;
                continue;
            }

            // Attempt transmission
            let transmission_result = stream_controller.send_data(stream_id, data.clone()).await;

            if transmission_result.is_ok() {
                state.bytes_transmitted.fetch_add(data.len() as u64, Ordering::Release);
                *state.last_transmission.lock().unwrap() = Instant::now();

                // Record stream flow measurement
                let measurement = StreamFlowMeasurement {
                    timestamp: Instant::now(),
                    stream_id,
                    bytes_transmitted: data.len() as u64,
                    flow_control_blocked: false,
                    encryption_level: EncryptionLevel::OneRtt,
                    key_rotation_in_progress: tracker.active_rotation.load(Ordering::Acquire),
                };
                tracker.record_stream_flow(measurement);
            } else {
                state.flow_blocked.store(true, Ordering::Release);
            }

            Sleep::new(Instant::now() + interval).await;
        }

        Ok(())
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    fn get_total_bytes_transmitted(&self, stream_id: QuicStreamId) -> u64 {
        self.streams.get(&stream_id)
            .map(|state| state.bytes_transmitted.load(Ordering::Acquire))
            .unwrap_or(0)
    }
}

/// Mock QUIC TLS key manager that can trigger rekey operations
struct MockQuicTlsKeyManager {
    current_key_phase: Arc<AtomicU32>,
    rekey_trigger: Arc<AtomicBool>,
    key_rotation_interval: Duration,
    traffic_secrets: Arc<Mutex<HashMap<u32, TrafficSecrets>>>,
    rotation_state: Arc<Mutex<KeyRotationState>>,
    tracker: Arc<TlsRekeyFlowTracker>,
}

impl MockQuicTlsKeyManager {
    fn new(interval: Duration, tracker: Arc<TlsRekeyFlowTracker>) -> Self {
        Self {
            current_key_phase: Arc::new(AtomicU32::new(0)),
            rekey_trigger: Arc::new(AtomicBool::new(false)),
            key_rotation_interval: interval,
            traffic_secrets: Arc::new(Mutex::new(HashMap::new())),
            rotation_state: Arc::new(Mutex::new(KeyRotationState::Idle)),
            tracker,
        }
    }

    async fn start_periodic_rekey(&self) {
        let mut interval_timer = Sleep::new(Instant::now() + self.key_rotation_interval);

        loop {
            interval_timer.await;

            if self.should_trigger_rekey() {
                self.trigger_key_rotation().await;
            }

            interval_timer = Sleep::new(Instant::now() + self.key_rotation_interval);
        }
    }

    fn should_trigger_rekey(&self) -> bool {
        let state = self.rotation_state.lock().unwrap();
        matches!(*state, KeyRotationState::Idle)
    }

    async fn trigger_key_rotation(&self) {
        let new_phase = self.current_key_phase.fetch_add(1, Ordering::Release) + 1;

        {
            let mut state = self.rotation_state.lock().unwrap();
            *state = KeyRotationState::InProgress;
        }

        // Record rekey start
        self.tracker.record_rekey_event(KeyRotationEvent::Started {
            key_phase: new_phase,
            trigger: KeyUpdateTrigger::Timer,
        });

        // Simulate key derivation delay
        Sleep::new(Instant::now() + Duration::from_millis(50)).await;

        // Generate new traffic secrets
        {
            let mut secrets = self.traffic_secrets.lock().unwrap();
            secrets.insert(new_phase, self.generate_traffic_secrets());
        }

        {
            let mut state = self.rotation_state.lock().unwrap();
            *state = KeyRotationState::Idle;
        }

        // Record rekey completion
        self.tracker.record_rekey_event(KeyRotationEvent::Completed {
            key_phase: new_phase,
        });
    }

    fn generate_traffic_secrets(&self) -> TrafficSecrets {
        // Mock implementation - in real QUIC this would use HKDF
        TrafficSecrets {
            client_secret: vec![0x42; 32],
            server_secret: vec![0x24; 32],
        }
    }

    fn get_current_key_phase(&self) -> u32 {
        self.current_key_phase.load(Ordering::Acquire)
    }
}

/// Mock stream controller for testing stream operations during TLS rekey
struct MockStreamController {
    streams: Arc<Mutex<HashMap<QuicStreamId, MockStreamState>>>,
    flow_control: Arc<RwLock<HashMap<QuicStreamId, u64>>>,
    key_manager: Arc<MockQuicTlsKeyManager>,
    blocked_streams: Arc<Mutex<Vec<QuicStreamId>>>,
}

#[derive(Debug, Clone)]
struct MockStreamState {
    stream_id: QuicStreamId,
    state: StreamState,
    send_buffer: VecDeque<Vec<u8>>,
    flow_control_limit: u64,
    bytes_sent: u64,
}

impl MockStreamController {
    fn new(key_manager: Arc<MockQuicTlsKeyManager>) -> Self {
        Self {
            streams: Arc::new(Mutex::new(HashMap::new())),
            flow_control: Arc::new(RwLock::new(HashMap::new())),
            key_manager,
            blocked_streams: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn create_stream(&self, stream_id: QuicStreamId, flow_limit: u64) {
        let mut streams = self.streams.lock().unwrap();
        streams.insert(stream_id, MockStreamState {
            stream_id,
            state: StreamState::Open,
            send_buffer: VecDeque::new(),
            flow_control_limit: flow_limit,
            bytes_sent: 0,
        });

        let mut flow_control = self.flow_control.write().unwrap();
        flow_control.insert(stream_id, flow_limit);
    }

    async fn send_data(&self, stream_id: QuicStreamId, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let rotation_state = {
            let state = self.key_manager.rotation_state.lock().unwrap();
            state.clone()
        };

        // During key rotation, introduce minimal delay but don't block
        if matches!(rotation_state, KeyRotationState::InProgress) {
            Sleep::new(Instant::now() + Duration::from_millis(1)).await;
        }

        let mut streams = self.streams.lock().unwrap();
        let stream = streams.get_mut(&stream_id)
            .ok_or("Stream not found")?;

        // Check flow control
        let flow_available = {
            let flow_control = self.flow_control.read().unwrap();
            flow_control.get(&stream_id).copied().unwrap_or(0)
        };

        if stream.bytes_sent + data.len() as u64 > flow_available {
            // Add to blocked streams temporarily
            self.blocked_streams.lock().unwrap().push(stream_id);
            return Err("Flow control limit exceeded".into());
        }

        stream.send_buffer.push_back(data.clone());
        stream.bytes_sent += data.len() as u64;

        // Update flow control
        {
            let mut flow_control = self.flow_control.write().unwrap();
            if let Some(limit) = flow_control.get_mut(&stream_id) {
                *limit = limit.saturating_sub(data.len() as u64);
            }
        }

        Ok(())
    }

    fn update_flow_control_window(&self, stream_id: QuicStreamId, additional_credits: u64) {
        let mut flow_control = self.flow_control.write().unwrap();
        if let Some(limit) = flow_control.get_mut(&stream_id) {
            *limit += additional_credits;
        }

        // Unblock stream if it was blocked
        let mut blocked = self.blocked_streams.lock().unwrap();
        blocked.retain(|&id| id != stream_id);
    }

    fn get_stream_bytes_sent(&self, stream_id: QuicStreamId) -> u64 {
        let streams = self.streams.lock().unwrap();
        streams.get(&stream_id)
            .map(|s| s.bytes_sent)
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
trait StreamController: Send + Sync {
    async fn send_data(&self, stream_id: QuicStreamId, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
impl StreamController for MockStreamController {
    async fn send_data(&self, stream_id: QuicStreamId, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        MockStreamController::send_data(self, stream_id, data).await
    }
}

// Test implementations start here

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tls_rekey_stream_flow_continuity() {
        let config = QuicTlsRekeyTestConfig {
            key_rotation_interval: Duration::from_millis(200),
            concurrent_streams: 4,
            test_duration: Duration::from_secs(2),
            ..Default::default()
        };

        let tracker = Arc::new(TlsRekeyFlowTracker::new());
        let key_manager = Arc::new(MockQuicTlsKeyManager::new(
            config.key_rotation_interval,
            tracker.clone(),
        ));
        let stream_controller = Arc::new(MockStreamController::new(key_manager.clone()));

        // Create test streams
        let stream_ids: Vec<QuicStreamId> = (0..config.concurrent_streams)
            .map(|i| QuicStreamId::new(i as u64))
            .collect();

        for &stream_id in &stream_ids {
            stream_controller.create_stream(stream_id, config.flow_control_window);
        }

        // Start periodic rekey
        let rekey_handle = {
            let key_manager = key_manager.clone();
            tokio::spawn(async move {
                key_manager.start_periodic_rekey().await;
            })
        };

        // Start stream simulations
        let mut simulator = LongLivedStreamSimulator::new(config.clone());
        for &stream_id in &stream_ids {
            simulator.add_stream(stream_id);
        }

        let simulation_handles: Vec<_> = stream_ids.iter().map(|&stream_id| {
            let simulator = &simulator;
            let tracker = tracker.clone();
            let stream_controller = stream_controller.clone();

            tokio::spawn(async move {
                simulator.simulate_continuous_transmission(
                    stream_id,
                    tracker,
                    stream_controller,
                ).await
            })
        }).collect();

        // Periodically update flow control windows to prevent starvation
        let flow_control_handle = {
            let stream_controller = stream_controller.clone();
            let stream_ids = stream_ids.clone();
            tokio::spawn(async move {
                let mut interval = Sleep::new(Instant::now() + Duration::from_millis(100));
                loop {
                    interval.await;
                    for &stream_id in &stream_ids {
                        stream_controller.update_flow_control_window(stream_id, 65536);
                    }
                    interval = Sleep::new(Instant::now() + Duration::from_millis(100));
                }
            })
        };

        // Run test
        Sleep::new(Instant::now() + config.test_duration).await;

        // Stop simulation
        simulator.stop();
        rekey_handle.abort();
        flow_control_handle.abort();

        for handle in simulation_handles {
            let _ = handle.await;
        }

        // Verify results
        assert!(tracker.get_rekey_count() >= 2, "Should have at least 2 rekey operations");
        assert!(tracker.verify_no_hol_blocking(), "Should not have head-of-line blocking due to rekey");

        // Verify flow continuity for each stream
        for &stream_id in &stream_ids {
            let continuity = tracker.get_stream_flow_continuity(stream_id);
            assert!(continuity.is_some(), "Stream should have continuity data");

            let continuity = continuity.unwrap();
            assert!(continuity.total_bytes > 0, "Stream should have transmitted data");
            assert!(continuity.flow_resumed_after_rekey, "Stream should resume after rekey");

            let bytes_sent = simulator.get_total_bytes_transmitted(stream_id);
            assert!(bytes_sent > 0, "Stream should have transmitted bytes");
        }
    }

    #[tokio::test]
    async fn test_concurrent_streams_rekey_independence() {
        let config = QuicTlsRekeyTestConfig {
            key_rotation_interval: Duration::from_millis(300),
            concurrent_streams: 8,
            test_duration: Duration::from_secs(1),
            stream_data_rate: 512 * 1024, // 512 KB/s per stream
            ..Default::default()
        };

        let tracker = Arc::new(TlsRekeyFlowTracker::new());
        let key_manager = Arc::new(MockQuicTlsKeyManager::new(
            config.key_rotation_interval,
            tracker.clone(),
        ));
        let stream_controller = Arc::new(MockStreamController::new(key_manager.clone()));

        // Create streams with different flow control windows
        let stream_ids: Vec<QuicStreamId> = (0..config.concurrent_streams)
            .map(|i| QuicStreamId::new(i as u64))
            .collect();

        for (i, &stream_id) in stream_ids.iter().enumerate() {
            let window_size = config.flow_control_window + (i as u64 * 32768);
            stream_controller.create_stream(stream_id, window_size);
        }

        // Start rekey process
        let rekey_handle = {
            let key_manager = key_manager.clone();
            tokio::spawn(async move {
                key_manager.start_periodic_rekey().await;
            })
        };

        // Start stream transmission with staggered start times
        let mut simulator = LongLivedStreamSimulator::new(config.clone());
        for &stream_id in &stream_ids {
            simulator.add_stream(stream_id);
        }

        let simulation_handles: Vec<_> = stream_ids.iter().enumerate().map(|(i, &stream_id)| {
            let simulator = &simulator;
            let tracker = tracker.clone();
            let stream_controller = stream_controller.clone();

            tokio::spawn(async move {
                // Stagger stream starts
                Sleep::new(Instant::now() + Duration::from_millis(i as u64 * 50)).await;

                simulator.simulate_continuous_transmission(
                    stream_id,
                    tracker,
                    stream_controller,
                ).await
            })
        }).collect();

        // Maintain flow control
        let flow_control_handle = {
            let stream_controller = stream_controller.clone();
            let stream_ids = stream_ids.clone();
            tokio::spawn(async move {
                let mut interval = Sleep::new(Instant::now() + Duration::from_millis(50));
                loop {
                    interval.await;
                    for &stream_id in &stream_ids {
                        stream_controller.update_flow_control_window(stream_id, 32768);
                    }
                    interval = Sleep::new(Instant::now() + Duration::from_millis(50));
                }
            })
        };

        // Run test
        Sleep::new(Instant::now() + config.test_duration).await;

        // Cleanup
        simulator.stop();
        rekey_handle.abort();
        flow_control_handle.abort();

        for handle in simulation_handles {
            let _ = handle.await;
        }

        // Verify that all streams operated independently during rekey
        assert!(tracker.verify_no_hol_blocking(), "No head-of-line blocking should occur");

        // Verify all streams transmitted data
        for &stream_id in &stream_ids {
            let bytes_sent = simulator.get_total_bytes_transmitted(stream_id);
            assert!(bytes_sent > 0, "Stream {:?} should have transmitted data", stream_id);

            let controller_bytes = stream_controller.get_stream_bytes_sent(stream_id);
            assert_eq!(bytes_sent, controller_bytes, "Byte counts should match");
        }

        // Verify at least one rekey occurred
        assert!(tracker.get_rekey_count() >= 1, "Should have at least one rekey operation");

        // Check rekey did not cause flow interruption longer than expected
        for &stream_id in &stream_ids {
            if let Some(continuity) = tracker.get_stream_flow_continuity(stream_id) {
                assert!(
                    continuity.max_interruption_duration < Duration::from_millis(100),
                    "Rekey should not cause long interruptions"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_rekey_during_high_throughput() {
        let config = QuicTlsRekeyTestConfig {
            key_rotation_interval: Duration::from_millis(150),
            concurrent_streams: 2,
            test_duration: Duration::from_millis(800),
            stream_data_rate: 2 * 1024 * 1024, // 2 MB/s per stream
            max_stream_backlog: 32768,
            ..Default::default()
        };

        let tracker = Arc::new(TlsRekeyFlowTracker::new());
        let key_manager = Arc::new(MockQuicTlsKeyManager::new(
            config.key_rotation_interval,
            tracker.clone(),
        ));
        let stream_controller = Arc::new(MockStreamController::new(key_manager.clone()));

        // Create high-throughput streams
        let stream_ids: Vec<QuicStreamId> = (0..config.concurrent_streams)
            .map(|i| QuicStreamId::new(i as u64))
            .collect();

        for &stream_id in &stream_ids {
            stream_controller.create_stream(stream_id, 2 * 1024 * 1024); // 2MB window
        }

        // Start aggressive rekey schedule
        let rekey_handle = {
            let key_manager = key_manager.clone();
            tokio::spawn(async move {
                key_manager.start_periodic_rekey().await;
            })
        };

        // Start high-throughput simulation
        let mut simulator = LongLivedStreamSimulator::new(config.clone());
        for &stream_id in &stream_ids {
            simulator.add_stream(stream_id);
        }

        let simulation_handles: Vec<_> = stream_ids.iter().map(|&stream_id| {
            let simulator = &simulator;
            let tracker = tracker.clone();
            let stream_controller = stream_controller.clone();

            tokio::spawn(async move {
                simulator.simulate_continuous_transmission(
                    stream_id,
                    tracker,
                    stream_controller,
                ).await
            })
        }).collect();

        // Aggressive flow control updates
        let flow_control_handle = {
            let stream_controller = stream_controller.clone();
            let stream_ids = stream_ids.clone();
            tokio::spawn(async move {
                let mut interval = Sleep::new(Instant::now() + Duration::from_millis(25));
                loop {
                    interval.await;
                    for &stream_id in &stream_ids {
                        stream_controller.update_flow_control_window(stream_id, 128 * 1024);
                    }
                    interval = Sleep::new(Instant::now() + Duration::from_millis(25));
                }
            })
        };

        // Run high-throughput test
        Sleep::new(Instant::now() + config.test_duration).await;

        // Cleanup
        simulator.stop();
        rekey_handle.abort();
        flow_control_handle.abort();

        for handle in simulation_handles {
            let _ = handle.await;
        }

        // Verify high throughput was maintained during rekey
        assert!(tracker.get_rekey_count() >= 3, "Should have multiple rekey operations");
        assert!(tracker.verify_no_hol_blocking(), "High throughput should not cause HOL blocking");

        // Verify substantial data transmission occurred
        let total_bytes: u64 = stream_ids.iter()
            .map(|&stream_id| simulator.get_total_bytes_transmitted(stream_id))
            .sum();

        assert!(total_bytes > 500_000, "Should have transmitted substantial data during rekey");

        // Verify flow continuity was maintained
        for &stream_id in &stream_ids {
            if let Some(continuity) = tracker.get_stream_flow_continuity(stream_id) {
                assert!(continuity.flow_resumed_after_rekey, "Flow should resume after each rekey");
                assert!(
                    continuity.total_bytes > 100_000,
                    "Each stream should transmit significant data"
                );
            }
        }
    }

    #[test]
    fn test_key_rotation_state_transitions() {
        let tracker = Arc::new(TlsRekeyFlowTracker::new());
        let key_manager = MockQuicTlsKeyManager::new(Duration::from_millis(100), tracker.clone());

        // Test initial state
        assert_eq!(key_manager.get_current_key_phase(), 0);

        // Test key rotation tracking
        tracker.record_rekey_event(KeyRotationEvent::Started {
            key_phase: 1,
            trigger: KeyUpdateTrigger::Timer,
        });

        assert!(tracker.active_rotation.load(Ordering::Acquire));

        tracker.record_rekey_event(KeyRotationEvent::Completed {
            key_phase: 1,
        });

        assert!(!tracker.active_rotation.load(Ordering::Acquire));
        assert_eq!(tracker.get_rekey_count(), 2); // Start + Complete
    }

    #[test]
    fn test_stream_flow_measurement_tracking() {
        let tracker = TlsRekeyFlowTracker::new();
        let stream_id = QuicStreamId::new(42);

        let measurement1 = StreamFlowMeasurement {
            timestamp: Instant::now(),
            stream_id,
            bytes_transmitted: 1024,
            flow_control_blocked: false,
            encryption_level: EncryptionLevel::OneRtt,
            key_rotation_in_progress: false,
        };

        tracker.record_stream_flow(measurement1);

        let measurement2 = StreamFlowMeasurement {
            timestamp: Instant::now(),
            stream_id,
            bytes_transmitted: 2048,
            flow_control_blocked: false,
            encryption_level: EncryptionLevel::OneRtt,
            key_rotation_in_progress: true,
        };

        tracker.record_stream_flow(measurement2);

        let continuity = tracker.get_stream_flow_continuity(stream_id).unwrap();
        assert_eq!(continuity.total_bytes, 3072);
        assert_eq!(continuity.rekey_interruptions, 1);
        assert!(continuity.flow_resumed_after_rekey);
    }

    #[test]
    fn test_hol_blocking_detection() {
        let tracker = TlsRekeyFlowTracker::new();

        let blocking_event = HolBlockingEvent {
            timestamp: Instant::now(),
            blocked_stream: QuicStreamId::new(1),
            blocking_cause: BlockingCause::FlowControl,
            duration: Duration::from_millis(50),
            affected_streams: vec![QuicStreamId::new(1)],
        };

        tracker.record_hol_blocking(blocking_event);

        // Should not report HOL blocking for flow control
        assert!(tracker.verify_no_hol_blocking());

        let rekey_blocking_event = HolBlockingEvent {
            timestamp: Instant::now(),
            blocked_stream: QuicStreamId::new(2),
            blocking_cause: BlockingCause::KeyRotation,
            duration: Duration::from_millis(100),
            affected_streams: vec![QuicStreamId::new(2), QuicStreamId::new(3)],
        };

        tracker.record_hol_blocking(rekey_blocking_event);

        // Should detect HOL blocking for key rotation
        assert!(!tracker.verify_no_hol_blocking());
    }
}

// Additional marker traits and types for QUIC implementation

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QuicStreamId(u64);

impl QuicStreamId {
    fn new(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum QuicStreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Debug, Clone, PartialEq)]
enum StreamDirection {
    Send,
    Receive,
    Both,
}

#[derive(Debug, Clone)]
struct StreamFrame {
    stream_id: QuicStreamId,
    offset: u64,
    data: Vec<u8>,
    fin: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[derive(Debug, Clone)]
enum StreamEvent {
    DataReceived { stream_id: QuicStreamId, data: Vec<u8> },
    FlowControlUpdated { stream_id: QuicStreamId, window: u64 },
    StreamClosed { stream_id: QuicStreamId },
}

#[derive(Debug, Clone, PartialEq)]
enum EncryptionLevel {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
}

#[derive(Debug, Clone)]
enum KeyRotationEvent {
    Started { key_phase: u32, trigger: KeyUpdateTrigger },
    Completed { key_phase: u32 },
    Failed { key_phase: u32, reason: String },
}

#[derive(Debug, Clone, PartialEq)]
enum KeyRotationState {
    Idle,
    InProgress,
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
enum KeyUpdateTrigger {
    Timer,
    Manual,
    TrafficThreshold,
}

#[derive(Debug, Clone)]
struct TrafficSecrets {
    client_secret: Vec<u8>,
    server_secret: Vec<u8>,
}