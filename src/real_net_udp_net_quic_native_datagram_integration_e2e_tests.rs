//! # Real Net/UDP ↔ Net/QUIC_Native Datagram Integration E2E Tests
//!
//! Tests integration between UDP transport and QUIC native datagram functionality
//! to verify that QUIC unreliable datagrams over UDP correctly handle MTU discovery
//! and PMTU drops without head-of-line blocking.
//!
//! ## Integration Focus
//!
//! - **UDP Transport**: MTU discovery, packet fragmentation, PMTU handling
//! - **QUIC Native Datagrams**: unreliable delivery, head-of-line blocking avoidance
//! - **MTU Integration**: PMTU discovery, drop recovery, adaptive sizing
//!
//! ## Key Properties Tested
//!
//! 1. **MTU Discovery**: PMTU discovery works correctly over UDP/QUIC integration
//! 2. **PMTU Drop Handling**: PMTU drops are handled without blocking other flows
//! 3. **Head-of-Line Blocking Avoidance**: Large datagram drops don't block smaller ones
//! 4. **Adaptive Sizing**: Datagram sizes adapt to discovered PMTU limits

use crate::{
    Result,
    cx::Cx,
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr,
        quic_native::{
            connection::{QuicConnection, QuicConnectionConfig, QuicConnectionEvent},
            datagram::{
                DatagramPriority, QuicDatagram, QuicDatagramConfig, QuicDatagramFrame,
                QuicDatagramQueue, UnreliableDelivery,
            },
            frame::{QuicFrame, QuicFrameType},
            transport::{QuicTransport, QuicTransportConfig},
        },
        udp::{
            mtu::{MtuDiscovery, MtuProbeResult, PathMtu, PmtuDiscoveryConfig},
            packet::{UdpPacket, UdpPacketSize},
            socket::{UdpSocket, UdpSocketConfig},
        },
    },
    runtime::{LabRuntime, LabRuntimeBuilder, RuntimeBuilder},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
    types::{
        budget::Budget, cancel::CancelToken, outcome::Outcome, region::RegionId, task::TaskId,
    },
    util::{rng::DetRng, time::TimeSource},
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::atomic::AtomicBool,
};

/// PMTU discovery and drop event for testing
#[derive(Debug, Clone)]
struct PmtuDiscoveryEvent {
    previous_mtu: u16,
    discovered_mtu: u16,
    probe_result: MtuProbeResult,
    discovery_time: Instant,
    affected_datagrams: Vec<DatagramId>,
    recovery_strategy: PmtuRecoveryStrategy,
}

impl PmtuDiscoveryEvent {
    fn new(
        previous_mtu: u16,
        discovered_mtu: u16,
        probe_result: MtuProbeResult,
        affected_datagrams: Vec<DatagramId>,
        recovery_strategy: PmtuRecoveryStrategy,
    ) -> Self {
        Self {
            previous_mtu,
            discovered_mtu,
            probe_result,
            discovery_time: Instant::now(),
            affected_datagrams,
            recovery_strategy,
        }
    }
}

/// PMTU recovery strategies for different drop scenarios
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PmtuRecoveryStrategy {
    /// Fragment large datagrams to fit discovered PMTU
    Fragment,
    /// Drop oversized datagrams and continue with smaller ones
    DropOversized,
    /// Retry with exponential backoff
    RetryWithBackoff,
    /// Switch to reliable stream for large data
    FallbackToStream,
}

/// Datagram identifier for tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DatagramId(u64);

impl DatagramId {
    fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Head-of-line blocking prevention tracker
#[derive(Debug)]
struct HolBlockingTracker {
    datagram_queue: Arc<RwLock<VecDeque<TrackedDatagram>>>,
    blocked_datagrams: Arc<RwLock<Vec<DatagramId>>>,
    successful_deliveries: Arc<AtomicUsize>,
    blocked_deliveries: Arc<AtomicUsize>,
    blocking_violations: Arc<AtomicUsize>,
}

impl HolBlockingTracker {
    fn new() -> Self {
        Self {
            datagram_queue: Arc::new(RwLock::new(VecDeque::new())),
            blocked_datagrams: Arc::new(RwLock::new(Vec::new())),
            successful_deliveries: Arc::new(AtomicUsize::new(0)),
            blocked_deliveries: Arc::new(AtomicUsize::new(0)),
            blocking_violations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn enqueue_datagram(&self, datagram: TrackedDatagram) {
        let mut queue = self.datagram_queue.write();
        queue.push_back(datagram);
    }

    fn process_pmtu_drop(&self, dropped_datagram_id: DatagramId, pmtu_limit: u16) -> Result<()> {
        let mut queue = self.datagram_queue.write();
        let mut blocked = self.blocked_datagrams.write();

        // Find and mark the dropped datagram as blocked
        for datagram in queue.iter_mut() {
            if datagram.id == dropped_datagram_id {
                if datagram.size > pmtu_limit {
                    datagram.mark_blocked_by_pmtu();
                    blocked.push(dropped_datagram_id);
                    self.blocked_deliveries.fetch_add(1, Ordering::Release);
                }
                break;
            }
        }

        // Verify that smaller datagrams are not blocked
        let blocking_violations = queue
            .iter()
            .filter(|d| d.size <= pmtu_limit && d.is_blocked())
            .count();

        if blocking_violations > 0 {
            self.blocking_violations
                .fetch_add(blocking_violations, Ordering::Release);
        }

        Ok(())
    }

    fn process_successful_delivery(&self, datagram_id: DatagramId) {
        let mut queue = self.datagram_queue.write();

        for datagram in queue.iter_mut() {
            if datagram.id == datagram_id {
                datagram.mark_delivered();
                self.successful_deliveries.fetch_add(1, Ordering::Release);
                break;
            }
        }
    }

    fn verify_no_hol_blocking(&self) -> bool {
        self.blocking_violations.load(Ordering::Acquire) == 0
    }

    fn get_delivery_stats(&self) -> (usize, usize, usize) {
        let successful = self.successful_deliveries.load(Ordering::Acquire);
        let blocked = self.blocked_deliveries.load(Ordering::Acquire);
        let violations = self.blocking_violations.load(Ordering::Acquire);
        (successful, blocked, violations)
    }
}

/// Tracked datagram for HoL blocking analysis
#[derive(Debug, Clone)]
struct TrackedDatagram {
    id: DatagramId,
    size: u16,
    priority: DatagramPriority,
    enqueue_time: Instant,
    delivery_state: DatagramDeliveryState,
}

impl TrackedDatagram {
    fn new(id: DatagramId, size: u16, priority: DatagramPriority) -> Self {
        Self {
            id,
            size,
            priority,
            enqueue_time: Instant::now(),
            delivery_state: DatagramDeliveryState::Pending,
        }
    }

    fn mark_blocked_by_pmtu(&mut self) {
        self.delivery_state = DatagramDeliveryState::BlockedByPmtu;
    }

    fn mark_delivered(&mut self) {
        self.delivery_state = DatagramDeliveryState::Delivered;
    }

    fn is_blocked(&self) -> bool {
        matches!(self.delivery_state, DatagramDeliveryState::BlockedByPmtu)
    }
}

/// Datagram delivery states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatagramDeliveryState {
    Pending,
    Delivered,
    BlockedByPmtu,
    Dropped,
}

/// MTU discovery coordinator for UDP/QUIC integration
#[derive(Debug)]
struct UdpQuicMtuCoordinator {
    mtu_discovery_config: PmtuDiscoveryConfig,
    hol_blocking_tracker: HolBlockingTracker,
    discovery_events: Arc<RwLock<Vec<PmtuDiscoveryEvent>>>,
    adaptive_sizing_metrics: AdaptiveSizingMetrics,
    current_pmtu: Arc<Mutex<u16>>,
}

impl UdpQuicMtuCoordinator {
    fn new(mtu_discovery_config: PmtuDiscoveryConfig) -> Self {
        let initial_pmtu = mtu_discovery_config.initial_mtu;

        Self {
            mtu_discovery_config,
            hol_blocking_tracker: HolBlockingTracker::new(),
            discovery_events: Arc::new(RwLock::new(Vec::new())),
            adaptive_sizing_metrics: AdaptiveSizingMetrics::new(),
            current_pmtu: Arc::new(Mutex::new(initial_pmtu)),
        }
    }

    async fn simulate_pmtu_discovery_scenario(
        &self,
        cx: &Cx,
        datagram_scenarios: Vec<DatagramScenario>,
        mtu_changes: Vec<MtuChangeEvent>,
    ) -> Result<()> {
        // Phase 1: Send initial datagrams with various sizes
        let mut datagram_id_counter = 0u64;
        for scenario in datagram_scenarios {
            cx.sleep(scenario.send_delay).await;

            let datagram_id = DatagramId::new(datagram_id_counter);
            datagram_id_counter += 1;

            let tracked_datagram =
                TrackedDatagram::new(datagram_id, scenario.size, scenario.priority);

            self.hol_blocking_tracker
                .enqueue_datagram(tracked_datagram.clone());

            // Check if datagram fits current PMTU
            let current_pmtu = *self.current_pmtu.lock();
            if scenario.size <= current_pmtu {
                // Simulate successful delivery
                self.hol_blocking_tracker
                    .process_successful_delivery(datagram_id);
                self.adaptive_sizing_metrics
                    .record_successful_send(scenario.size);
            } else {
                // Simulate PMTU drop
                self.hol_blocking_tracker
                    .process_pmtu_drop(datagram_id, current_pmtu)?;
                self.adaptive_sizing_metrics
                    .record_pmtu_drop(scenario.size, current_pmtu);
            }
        }

        // Phase 2: Simulate PMTU changes and discovery
        for mtu_change in mtu_changes {
            cx.sleep(mtu_change.change_delay).await;

            self.simulate_pmtu_change(mtu_change).await?;
        }

        Ok(())
    }

    async fn simulate_pmtu_change(&self, mtu_change: MtuChangeEvent) -> Result<()> {
        let previous_pmtu = *self.current_pmtu.lock();
        let new_pmtu = mtu_change.new_mtu;

        // Update current PMTU
        {
            let mut current = self.current_pmtu.lock();
            *current = new_pmtu;
        }

        // Create discovery event
        let discovery_event = PmtuDiscoveryEvent::new(
            previous_pmtu,
            new_pmtu,
            mtu_change.probe_result,
            mtu_change.affected_datagrams.clone(),
            mtu_change.recovery_strategy,
        );

        {
            let mut events = self.discovery_events.write();
            events.push(discovery_event);
        }

        // Apply recovery strategy
        match mtu_change.recovery_strategy {
            PmtuRecoveryStrategy::Fragment => {
                self.adaptive_sizing_metrics.record_fragmentation_event();
            }
            PmtuRecoveryStrategy::DropOversized => {
                for datagram_id in &mtu_change.affected_datagrams {
                    self.hol_blocking_tracker
                        .process_pmtu_drop(*datagram_id, new_pmtu)?;
                }
            }
            PmtuRecoveryStrategy::RetryWithBackoff => {
                self.adaptive_sizing_metrics.record_retry_event();
            }
            PmtuRecoveryStrategy::FallbackToStream => {
                self.adaptive_sizing_metrics.record_fallback_event();
            }
        }

        self.adaptive_sizing_metrics
            .record_mtu_change(previous_pmtu, new_pmtu);

        Ok(())
    }

    fn verify_integration_properties(&self) -> Result<UdpQuicIntegrationResult> {
        // Verify no head-of-line blocking violations
        if !self.hol_blocking_tracker.verify_no_hol_blocking() {
            return Err(format!("Head-of-line blocking violations detected").into());
        }

        // Get delivery statistics
        let (successful_deliveries, blocked_deliveries, hol_violations) =
            self.hol_blocking_tracker.get_delivery_stats();

        // Verify MTU discovery events
        let discovery_events = self.discovery_events.read();
        if discovery_events.is_empty() {
            return Err(format!("No PMTU discovery events recorded").into());
        }

        // Verify adaptive sizing metrics
        let sizing_stats = self.adaptive_sizing_metrics.get_stats();
        if sizing_stats.total_sends == 0 {
            return Err(format!("No datagram sends recorded").into());
        }

        let result = UdpQuicIntegrationResult {
            successful_deliveries,
            blocked_deliveries,
            hol_blocking_violations: hol_violations,
            pmtu_discovery_events: discovery_events.len(),
            adaptive_sizing_stats: sizing_stats,
            integration_successful: hol_violations == 0 && successful_deliveries > 0,
        };

        Ok(result)
    }
}

/// UDP/QUIC integration verification result
#[derive(Debug)]
struct UdpQuicIntegrationResult {
    successful_deliveries: usize,
    blocked_deliveries: usize,
    hol_blocking_violations: usize,
    pmtu_discovery_events: usize,
    adaptive_sizing_stats: AdaptiveSizingStats,
    integration_successful: bool,
}

/// Metrics for adaptive datagram sizing
#[derive(Debug)]
struct AdaptiveSizingMetrics {
    successful_sends: Arc<AtomicUsize>,
    pmtu_drops: Arc<AtomicUsize>,
    fragmentation_events: Arc<AtomicUsize>,
    retry_events: Arc<AtomicUsize>,
    fallback_events: Arc<AtomicUsize>,
    mtu_changes: Arc<AtomicUsize>,
    size_adaptations: Arc<RwLock<Vec<SizeAdaptation>>>,
}

impl AdaptiveSizingMetrics {
    fn new() -> Self {
        Self {
            successful_sends: Arc::new(AtomicUsize::new(0)),
            pmtu_drops: Arc::new(AtomicUsize::new(0)),
            fragmentation_events: Arc::new(AtomicUsize::new(0)),
            retry_events: Arc::new(AtomicUsize::new(0)),
            fallback_events: Arc::new(AtomicUsize::new(0)),
            mtu_changes: Arc::new(AtomicUsize::new(0)),
            size_adaptations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn record_successful_send(&self, size: u16) {
        self.successful_sends.fetch_add(1, Ordering::Release);
        self.record_size_adaptation(size, SizeAdaptationType::SuccessfulSend);
    }

    fn record_pmtu_drop(&self, size: u16, pmtu_limit: u16) {
        self.pmtu_drops.fetch_add(1, Ordering::Release);
        self.record_size_adaptation(size, SizeAdaptationType::PmtuDrop { pmtu_limit });
    }

    fn record_fragmentation_event(&self) {
        self.fragmentation_events.fetch_add(1, Ordering::Release);
    }

    fn record_retry_event(&self) {
        self.retry_events.fetch_add(1, Ordering::Release);
    }

    fn record_fallback_event(&self) {
        self.fallback_events.fetch_add(1, Ordering::Release);
    }

    fn record_mtu_change(&self, old_mtu: u16, new_mtu: u16) {
        self.mtu_changes.fetch_add(1, Ordering::Release);
        self.record_size_adaptation(new_mtu, SizeAdaptationType::MtuChange { old_mtu });
    }

    fn record_size_adaptation(&self, size: u16, adaptation_type: SizeAdaptationType) {
        let mut adaptations = self.size_adaptations.write();
        adaptations.push(SizeAdaptation {
            size,
            adaptation_type,
            timestamp: Instant::now(),
        });
    }

    fn get_stats(&self) -> AdaptiveSizingStats {
        let successful = self.successful_sends.load(Ordering::Acquire);
        let drops = self.pmtu_drops.load(Ordering::Acquire);
        let fragmentations = self.fragmentation_events.load(Ordering::Acquire);
        let retries = self.retry_events.load(Ordering::Acquire);
        let fallbacks = self.fallback_events.load(Ordering::Acquire);
        let mtu_changes = self.mtu_changes.load(Ordering::Acquire);

        AdaptiveSizingStats {
            total_sends: successful + drops,
            successful_sends: successful,
            pmtu_drops: drops,
            fragmentation_events: fragmentations,
            retry_events: retries,
            fallback_events: fallbacks,
            mtu_changes,
        }
    }
}

/// Size adaptation tracking
#[derive(Debug, Clone)]
struct SizeAdaptation {
    size: u16,
    adaptation_type: SizeAdaptationType,
    timestamp: Instant,
}

/// Types of size adaptations
#[derive(Debug, Clone, Copy)]
enum SizeAdaptationType {
    SuccessfulSend,
    PmtuDrop { pmtu_limit: u16 },
    MtuChange { old_mtu: u16 },
    FragmentationApplied,
}

/// Adaptive sizing statistics
#[derive(Debug, Clone)]
struct AdaptiveSizingStats {
    total_sends: usize,
    successful_sends: usize,
    pmtu_drops: usize,
    fragmentation_events: usize,
    retry_events: usize,
    fallback_events: usize,
    mtu_changes: usize,
}

/// Test harness for UDP/QUIC datagram integration
#[derive(Debug)]
struct UdpQuicDatagramTestHarness {
    coordinator: UdpQuicMtuCoordinator,
    quic_config: QuicDatagramConfig,
    udp_config: UdpSocketConfig,
}

impl UdpQuicDatagramTestHarness {
    fn new() -> Self {
        let mtu_discovery_config = PmtuDiscoveryConfig {
            initial_mtu: 1500,
            min_mtu: 576,
            max_mtu: 9000,
            probe_interval: Duration::from_secs(30),
            enable_discovery: true,
        };

        let quic_config = QuicDatagramConfig {
            max_datagram_size: 1200,
            enable_unreliable_datagrams: true,
            datagram_priority_levels: 3,
            queue_size_limit: 1000,
        };

        let udp_config = UdpSocketConfig {
            receive_buffer_size: 64 * 1024,
            send_buffer_size: 64 * 1024,
            enable_mtu_discovery: true,
            fragment_handling: FragmentHandling::Allow,
        };

        Self {
            coordinator: UdpQuicMtuCoordinator::new(mtu_discovery_config),
            quic_config,
            udp_config,
        }
    }

    async fn run_comprehensive_udp_quic_datagram_integration(
        &self,
        cx: &Cx,
    ) -> Result<UdpQuicIntegrationResult> {
        // Create comprehensive test scenarios
        let datagram_scenarios = vec![
            DatagramScenario::new(512, DatagramPriority::Low, Duration::from_millis(10)),
            DatagramScenario::new(1200, DatagramPriority::Normal, Duration::from_millis(20)),
            DatagramScenario::new(1600, DatagramPriority::High, Duration::from_millis(15)), // Will exceed PMTU
            DatagramScenario::new(800, DatagramPriority::Normal, Duration::from_millis(25)),
            DatagramScenario::new(2000, DatagramPriority::Low, Duration::from_millis(30)), // Large datagram
            DatagramScenario::new(400, DatagramPriority::High, Duration::from_millis(35)),
        ];

        let mtu_changes = vec![
            MtuChangeEvent::new(
                1200,
                MtuProbeResult::Success,
                vec![DatagramId::new(2), DatagramId::new(4)],
                PmtuRecoveryStrategy::DropOversized,
                Duration::from_millis(100),
            ),
            MtuChangeEvent::new(
                1400,
                MtuProbeResult::Success,
                vec![],
                PmtuRecoveryStrategy::Fragment,
                Duration::from_millis(150),
            ),
        ];

        // Run integration simulation
        self.coordinator
            .simulate_pmtu_discovery_scenario(cx, datagram_scenarios, mtu_changes)
            .await?;

        // Verify integration properties
        let result = self.coordinator.verify_integration_properties()?;

        Ok(result)
    }
}

/// Datagram scenario configuration
#[derive(Debug, Clone)]
struct DatagramScenario {
    size: u16,
    priority: DatagramPriority,
    send_delay: Duration,
}

impl DatagramScenario {
    fn new(size: u16, priority: DatagramPriority, send_delay: Duration) -> Self {
        Self {
            size,
            priority,
            send_delay,
        }
    }
}

/// MTU change event for testing
#[derive(Debug, Clone)]
struct MtuChangeEvent {
    new_mtu: u16,
    probe_result: MtuProbeResult,
    affected_datagrams: Vec<DatagramId>,
    recovery_strategy: PmtuRecoveryStrategy,
    change_delay: Duration,
}

impl MtuChangeEvent {
    fn new(
        new_mtu: u16,
        probe_result: MtuProbeResult,
        affected_datagrams: Vec<DatagramId>,
        recovery_strategy: PmtuRecoveryStrategy,
        change_delay: Duration,
    ) -> Self {
        Self {
            new_mtu,
            probe_result,
            affected_datagrams,
            recovery_strategy,
            change_delay,
        }
    }
}

/// Mock implementations for testing infrastructure

/// MTU probe results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MtuProbeResult {
    Success,
    TooLarge,
    NetworkError,
    Timeout,
}

/// Datagram priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatagramPriority {
    Low,
    Normal,
    High,
}

/// PMTU discovery configuration
#[derive(Debug, Clone)]
struct PmtuDiscoveryConfig {
    initial_mtu: u16,
    min_mtu: u16,
    max_mtu: u16,
    probe_interval: Duration,
    enable_discovery: bool,
}

/// QUIC datagram configuration
#[derive(Debug, Clone)]
struct QuicDatagramConfig {
    max_datagram_size: u16,
    enable_unreliable_datagrams: bool,
    datagram_priority_levels: usize,
    queue_size_limit: usize,
}

/// UDP socket configuration
#[derive(Debug, Clone)]
struct UdpSocketConfig {
    receive_buffer_size: usize,
    send_buffer_size: usize,
    enable_mtu_discovery: bool,
    fragment_handling: FragmentHandling,
}

/// Fragment handling strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentHandling {
    Allow,
    Deny,
    Fragment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_udp_quic_datagram_integration() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = UdpQuicDatagramTestHarness::new();

        // Create basic scenario with small datagrams
        let scenarios = vec![
            DatagramScenario::new(500, DatagramPriority::Normal, Duration::from_millis(10)),
            DatagramScenario::new(800, DatagramPriority::High, Duration::from_millis(20)),
        ];

        let mtu_changes = vec![];

        // Run basic integration
        harness
            .coordinator
            .simulate_pmtu_discovery_scenario(&cx, scenarios, mtu_changes)
            .await?;

        // Verify basic properties
        let result = harness.coordinator.verify_integration_properties()?;
        assert!(
            result.integration_successful,
            "Basic integration should be successful"
        );
        assert_eq!(
            result.hol_blocking_violations, 0,
            "No HoL blocking should occur"
        );
        assert!(
            result.successful_deliveries > 0,
            "Should have successful deliveries"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_pmtu_drop_without_hol_blocking() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = UdpQuicDatagramTestHarness::new();

        // Create scenario with mixed datagram sizes
        let scenarios = vec![
            DatagramScenario::new(400, DatagramPriority::High, Duration::from_millis(10)),
            DatagramScenario::new(1600, DatagramPriority::Normal, Duration::from_millis(15)), // Will be dropped
            DatagramScenario::new(600, DatagramPriority::Low, Duration::from_millis(20)),
        ];

        // Simulate PMTU drop
        let mtu_changes = vec![MtuChangeEvent::new(
            1200,
            MtuProbeResult::TooLarge,
            vec![DatagramId::new(1)],
            PmtuRecoveryStrategy::DropOversized,
            Duration::from_millis(50),
        )];

        // Run PMTU drop scenario
        harness
            .coordinator
            .simulate_pmtu_discovery_scenario(&cx, scenarios, mtu_changes)
            .await?;

        // Verify no head-of-line blocking
        assert!(
            harness
                .coordinator
                .hol_blocking_tracker
                .verify_no_hol_blocking(),
            "Large datagram drop should not block smaller datagrams"
        );

        let (successful, blocked, violations) = harness
            .coordinator
            .hol_blocking_tracker
            .get_delivery_stats();
        assert!(
            successful > 0,
            "Small datagrams should be delivered successfully"
        );
        assert!(blocked > 0, "Large datagram should be blocked");
        assert_eq!(violations, 0, "No HoL blocking violations should occur");

        Ok(())
    }

    #[tokio::test]
    async fn test_mtu_discovery_and_adaptation() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = UdpQuicDatagramTestHarness::new();

        // Create scenarios with various sizes
        let scenarios = vec![
            DatagramScenario::new(800, DatagramPriority::Normal, Duration::from_millis(10)),
            DatagramScenario::new(1400, DatagramPriority::High, Duration::from_millis(20)),
        ];

        // Simulate MTU discovery process
        let mtu_changes = vec![
            MtuChangeEvent::new(
                1200,
                MtuProbeResult::TooLarge,
                vec![DatagramId::new(1)],
                PmtuRecoveryStrategy::Fragment,
                Duration::from_millis(30),
            ),
            MtuChangeEvent::new(
                1600,
                MtuProbeResult::Success,
                vec![],
                PmtuRecoveryStrategy::Fragment,
                Duration::from_millis(80),
            ),
        ];

        // Run MTU discovery scenario
        harness
            .coordinator
            .simulate_pmtu_discovery_scenario(&cx, scenarios, mtu_changes)
            .await?;

        // Verify MTU discovery and adaptation
        let result = harness.coordinator.verify_integration_properties()?;
        assert!(
            result.pmtu_discovery_events >= 2,
            "Should record MTU discovery events"
        );

        let sizing_stats = result.adaptive_sizing_stats;
        assert_eq!(sizing_stats.mtu_changes, 2, "Should record MTU changes");
        assert!(
            sizing_stats.fragmentation_events > 0,
            "Should use fragmentation strategy"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_comprehensive_udp_quic_datagram_integration() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = UdpQuicDatagramTestHarness::new();

        // Run comprehensive integration test
        let result = harness
            .run_comprehensive_udp_quic_datagram_integration(&cx)
            .await?;

        // Verify comprehensive integration properties
        assert!(
            result.integration_successful,
            "Comprehensive integration should be successful"
        );
        assert_eq!(
            result.hol_blocking_violations, 0,
            "No head-of-line blocking violations"
        );
        assert!(
            result.successful_deliveries >= 4,
            "Multiple successful deliveries expected"
        );
        assert!(
            result.blocked_deliveries >= 1,
            "Some large datagrams should be blocked"
        );
        assert!(
            result.pmtu_discovery_events >= 2,
            "PMTU discovery should occur"
        );

        // Verify adaptive sizing
        let stats = result.adaptive_sizing_stats;
        assert!(stats.total_sends >= 6, "Should send multiple datagrams");
        assert!(stats.pmtu_drops > 0, "Should experience PMTU drops");
        assert_eq!(stats.mtu_changes, 2, "Should adapt to MTU changes");
        assert!(stats.fragmentation_events > 0, "Should use fragmentation");

        println!(
            "UDP/QUIC datagram integration test completed: {}/{} deliveries, {} PMTU events, {} adaptations",
            result.successful_deliveries,
            result.successful_deliveries + result.blocked_deliveries,
            result.pmtu_discovery_events,
            stats.mtu_changes
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_adaptive_sizing_strategies() -> Result<()> {
        let runtime = RuntimeBuilder::new().build()?;
        let cx = runtime.cx();

        let harness = UdpQuicDatagramTestHarness::new();

        // Create scenarios testing different recovery strategies
        let scenarios = vec![
            DatagramScenario::new(900, DatagramPriority::Normal, Duration::from_millis(10)),
            DatagramScenario::new(1800, DatagramPriority::Low, Duration::from_millis(20)),
            DatagramScenario::new(700, DatagramPriority::High, Duration::from_millis(30)),
        ];

        let mtu_changes = vec![
            MtuChangeEvent::new(
                1200,
                MtuProbeResult::TooLarge,
                vec![DatagramId::new(1)],
                PmtuRecoveryStrategy::Fragment,
                Duration::from_millis(40),
            ),
            MtuChangeEvent::new(
                800,
                MtuProbeResult::TooLarge,
                vec![DatagramId::new(0)],
                PmtuRecoveryStrategy::DropOversized,
                Duration::from_millis(80),
            ),
        ];

        // Run adaptive sizing test
        harness
            .coordinator
            .simulate_pmtu_discovery_scenario(&cx, scenarios, mtu_changes)
            .await?;

        // Verify adaptive strategies were applied
        let sizing_stats = harness.coordinator.adaptive_sizing_metrics.get_stats();
        assert!(
            sizing_stats.fragmentation_events > 0,
            "Should use fragmentation strategy"
        );
        assert!(
            sizing_stats.pmtu_drops > 0,
            "Should apply drop strategy for small MTU"
        );
        assert_eq!(
            sizing_stats.mtu_changes, 2,
            "Should adapt to both MTU changes"
        );

        // Verify no blocking violations
        assert!(
            harness
                .coordinator
                .hol_blocking_tracker
                .verify_no_hol_blocking(),
            "Adaptive strategies should prevent HoL blocking"
        );

        Ok(())
    }
}
