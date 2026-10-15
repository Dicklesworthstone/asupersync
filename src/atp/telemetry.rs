//! ATP relay telemetry collection and real-time metrics dashboard.
//!
//! Provides structured observability for ATP relay services including connection
//! metrics, throughput monitoring, quota usage, and error rates. The telemetry
//! system is designed for operational monitoring and debugging without exposing
//! sensitive transfer content.

use crate::net::atp::relay::{
    RelayEventKind, RelayLatencySummary, RelayService, RelayUsage, RelayReservationId,
    RelayTransport,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// Real-time ATP relay telemetry collector.
#[derive(Debug)]
pub struct RelayTelemetryCollector {
    /// Global connection counters
    connections: RelayConnectionCounters,
    /// Per-transport metrics
    transport_metrics: BTreeMap<RelayTransport, TransportMetrics>,
    /// Error rate tracking
    error_metrics: ErrorMetrics,
    /// Historical snapshots for trending
    historical_snapshots: Vec<TelemetrySnapshot>,
    /// Maximum historical snapshots to retain
    max_snapshots: usize,
}

impl RelayTelemetryCollector {
    /// Create new telemetry collector.
    pub fn new() -> Self {
        let mut transport_metrics = BTreeMap::new();
        transport_metrics.insert(RelayTransport::Udp, TransportMetrics::new());
        transport_metrics.insert(RelayTransport::TcpTls443, TransportMetrics::new());

        Self {
            connections: RelayConnectionCounters::new(),
            transport_metrics,
            error_metrics: ErrorMetrics::new(),
            historical_snapshots: Vec::new(),
            max_snapshots: 100, // Keep 100 snapshots ~= 10 minutes at 6s intervals
        }
    }

    /// Record a relay service event.
    pub fn record_event(&mut self, event_kind: RelayEventKind, transport: Option<RelayTransport>) {
        self.connections.record_event(&event_kind);
        self.error_metrics.record_event(&event_kind);

        if let Some(transport) = transport {
            if let Some(metrics) = self.transport_metrics.get_mut(&transport) {
                metrics.record_event(&event_kind);
            }
        }
    }

    /// Record packet forwarding metrics.
    pub fn record_packet_forward(
        &mut self,
        transport: RelayTransport,
        bytes: u64,
        latency_micros: u64,
    ) {
        self.connections.total_bytes_forwarded.fetch_add(bytes, Ordering::Relaxed);
        self.connections.total_packets_forwarded.fetch_add(1, Ordering::Relaxed);

        if let Some(metrics) = self.transport_metrics.get_mut(&transport) {
            metrics.record_packet(bytes, latency_micros);
        }
    }

    /// Record quota rejection.
    pub fn record_quota_rejection(&mut self, bytes_rejected: u64) {
        self.error_metrics.quota_rejections.fetch_add(1, Ordering::Relaxed);
        self.error_metrics.bytes_rejected.fetch_add(bytes_rejected, Ordering::Relaxed);
    }

    /// Take a telemetry snapshot for trending.
    pub fn take_snapshot(&mut self) -> TelemetrySnapshot {
        let snapshot = TelemetrySnapshot {
            timestamp_micros: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_micros() as u64,
            connections: self.connections.snapshot(),
            transport_udp: self.transport_metrics[&RelayTransport::Udp].snapshot(),
            transport_tcp_tls: self.transport_metrics[&RelayTransport::TcpTls443].snapshot(),
            errors: self.error_metrics.snapshot(),
        };

        // Store historical snapshot
        self.historical_snapshots.push(snapshot.clone());
        if self.historical_snapshots.len() > self.max_snapshots {
            self.historical_snapshots.remove(0);
        }

        snapshot
    }

    /// Get real-time telemetry dashboard data.
    pub fn get_dashboard_data(&self) -> RelayDashboardData {
        RelayDashboardData {
            current: TelemetrySnapshot {
                timestamp_micros: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_micros() as u64,
                connections: self.connections.snapshot(),
                transport_udp: self.transport_metrics[&RelayTransport::Udp].snapshot(),
                transport_tcp_tls: self.transport_metrics[&RelayTransport::TcpTls443].snapshot(),
                errors: self.error_metrics.snapshot(),
            },
            historical: self.historical_snapshots.clone(),
        }
    }

    /// Collect metrics from relay service state.
    pub fn collect_from_service(&mut self, service: &RelayService) {
        let events = service.events();

        // Aggregate recent events for trending
        let mut recent_forwards = 0;
        let mut recent_errors = 0;

        for event in events.iter().rev().take(100) { // Last 100 events
            match event.kind {
                RelayEventKind::PacketForwarded => recent_forwards += 1,
                RelayEventKind::QuotaRejected | RelayEventKind::AuthorizationRejected => {
                    recent_errors += 1;
                }
                _ => {}
            }
        }

        self.connections.recent_forward_rate.store(recent_forwards, Ordering::Relaxed);
        self.error_metrics.recent_error_rate.store(recent_errors, Ordering::Relaxed);
    }
}

impl Default for RelayTelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Global relay connection counters.
#[derive(Debug)]
struct RelayConnectionCounters {
    active_reservations: AtomicU64,
    total_reservations: AtomicU64,
    total_packets_forwarded: AtomicU64,
    total_bytes_forwarded: AtomicU64,
    recent_forward_rate: AtomicU64,
}

impl RelayConnectionCounters {
    fn new() -> Self {
        Self {
            active_reservations: AtomicU64::new(0),
            total_reservations: AtomicU64::new(0),
            total_packets_forwarded: AtomicU64::new(0),
            total_bytes_forwarded: AtomicU64::new(0),
            recent_forward_rate: AtomicU64::new(0),
        }
    }

    fn record_event(&self, event: &RelayEventKind) {
        match event {
            RelayEventKind::ReservationAccepted => {
                self.total_reservations.fetch_add(1, Ordering::Relaxed);
                self.active_reservations.fetch_add(1, Ordering::Relaxed);
            }
            RelayEventKind::ReservationExpired | RelayEventKind::ReservationCancelled => {
                self.active_reservations.fetch_sub(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            active_reservations: self.active_reservations.load(Ordering::Relaxed),
            total_reservations: self.total_reservations.load(Ordering::Relaxed),
            total_packets_forwarded: self.total_packets_forwarded.load(Ordering::Relaxed),
            total_bytes_forwarded: self.total_bytes_forwarded.load(Ordering::Relaxed),
            recent_forward_rate: self.recent_forward_rate.load(Ordering::Relaxed),
        }
    }
}

/// Per-transport metrics tracking.
#[derive(Debug)]
struct TransportMetrics {
    packets_forwarded: AtomicU64,
    bytes_forwarded: AtomicU64,
    latest_latency_micros: AtomicU64,
    min_latency_micros: AtomicU64,
    max_latency_micros: AtomicU64,
    total_latency_micros: AtomicU64,
    latency_samples: AtomicU64,
}

impl TransportMetrics {
    fn new() -> Self {
        Self {
            packets_forwarded: AtomicU64::new(0),
            bytes_forwarded: AtomicU64::new(0),
            latest_latency_micros: AtomicU64::new(0),
            min_latency_micros: AtomicU64::new(u64::MAX),
            max_latency_micros: AtomicU64::new(0),
            total_latency_micros: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
        }
    }

    fn record_event(&self, event: &RelayEventKind) {
        if matches!(event, RelayEventKind::PacketForwarded) {
            self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_packet(&self, bytes: u64, latency_micros: u64) {
        self.bytes_forwarded.fetch_add(bytes, Ordering::Relaxed);
        self.latest_latency_micros.store(latency_micros, Ordering::Relaxed);

        // Update min/max latency (approximate due to atomics)
        self.min_latency_micros.fetch_min(latency_micros, Ordering::Relaxed);
        self.max_latency_micros.fetch_max(latency_micros, Ordering::Relaxed);

        self.total_latency_micros.fetch_add(latency_micros, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> TransportSnapshot {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        let total_latency = self.total_latency_micros.load(Ordering::Relaxed);
        let avg_latency = if samples > 0 { total_latency / samples } else { 0 };

        TransportSnapshot {
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            bytes_forwarded: self.bytes_forwarded.load(Ordering::Relaxed),
            latest_latency_micros: self.latest_latency_micros.load(Ordering::Relaxed),
            min_latency_micros: {
                let min = self.min_latency_micros.load(Ordering::Relaxed);
                if min == u64::MAX { 0 } else { min }
            },
            max_latency_micros: self.max_latency_micros.load(Ordering::Relaxed),
            average_latency_micros: avg_latency,
            latency_samples: samples,
        }
    }
}

/// Error metrics tracking.
#[derive(Debug)]
struct ErrorMetrics {
    quota_rejections: AtomicU64,
    auth_rejections: AtomicU64,
    bytes_rejected: AtomicU64,
    recent_error_rate: AtomicU64,
}

impl ErrorMetrics {
    fn new() -> Self {
        Self {
            quota_rejections: AtomicU64::new(0),
            auth_rejections: AtomicU64::new(0),
            bytes_rejected: AtomicU64::new(0),
            recent_error_rate: AtomicU64::new(0),
        }
    }

    fn record_event(&self, event: &RelayEventKind) {
        match event {
            RelayEventKind::QuotaRejected => {
                self.quota_rejections.fetch_add(1, Ordering::Relaxed);
            }
            RelayEventKind::AuthorizationRejected => {
                self.auth_rejections.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn snapshot(&self) -> ErrorSnapshot {
        ErrorSnapshot {
            quota_rejections: self.quota_rejections.load(Ordering::Relaxed),
            auth_rejections: self.auth_rejections.load(Ordering::Relaxed),
            bytes_rejected: self.bytes_rejected.load(Ordering::Relaxed),
            recent_error_rate: self.recent_error_rate.load(Ordering::Relaxed),
        }
    }
}

/// Complete dashboard data for relay telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDashboardData {
    /// Current real-time metrics
    pub current: TelemetrySnapshot,
    /// Historical snapshots for trending
    pub historical: Vec<TelemetrySnapshot>,
}

/// Point-in-time telemetry snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Timestamp in microseconds since epoch
    pub timestamp_micros: u64,
    /// Connection metrics
    pub connections: ConnectionSnapshot,
    /// UDP transport metrics
    pub transport_udp: TransportSnapshot,
    /// TCP/TLS 443 transport metrics
    pub transport_tcp_tls: TransportSnapshot,
    /// Error metrics
    pub errors: ErrorSnapshot,
}

/// Connection metrics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub active_reservations: u64,
    pub total_reservations: u64,
    pub total_packets_forwarded: u64,
    pub total_bytes_forwarded: u64,
    pub recent_forward_rate: u64,
}

/// Transport-specific metrics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportSnapshot {
    pub packets_forwarded: u64,
    pub bytes_forwarded: u64,
    pub latest_latency_micros: u64,
    pub min_latency_micros: u64,
    pub max_latency_micros: u64,
    pub average_latency_micros: u64,
    pub latency_samples: u64,
}

/// Error metrics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSnapshot {
    pub quota_rejections: u64,
    pub auth_rejections: u64,
    pub bytes_rejected: u64,
    pub recent_error_rate: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_collector_records_events() {
        let mut collector = RelayTelemetryCollector::new();

        // Record some events
        collector.record_event(RelayEventKind::ReservationAccepted, Some(RelayTransport::Udp));
        collector.record_packet_forward(RelayTransport::Udp, 1024, 5000);
        collector.record_quota_rejection(512);

        let snapshot = collector.take_snapshot();

        // Verify metrics
        assert_eq!(snapshot.connections.active_reservations, 1);
        assert_eq!(snapshot.connections.total_packets_forwarded, 1);
        assert_eq!(snapshot.transport_udp.packets_forwarded, 1);
        assert_eq!(snapshot.transport_udp.bytes_forwarded, 1024);
        assert_eq!(snapshot.errors.quota_rejections, 1);
        assert_eq!(snapshot.errors.bytes_rejected, 512);
    }

    #[test]
    fn transport_metrics_track_latency() {
        let mut collector = RelayTelemetryCollector::new();

        // Record packets with different latencies
        collector.record_packet_forward(RelayTransport::Udp, 100, 1000);
        collector.record_packet_forward(RelayTransport::Udp, 200, 3000);
        collector.record_packet_forward(RelayTransport::Udp, 300, 2000);

        let snapshot = collector.take_snapshot();

        assert_eq!(snapshot.transport_udp.latency_samples, 3);
        assert_eq!(snapshot.transport_udp.latest_latency_micros, 2000);
        assert_eq!(snapshot.transport_udp.min_latency_micros, 1000);
        assert_eq!(snapshot.transport_udp.max_latency_micros, 3000);
        assert_eq!(snapshot.transport_udp.average_latency_micros, 2000); // (1000+3000+2000)/3
    }

    #[test]
    fn dashboard_data_includes_historical_trending() {
        let mut collector = RelayTelemetryCollector::new();

        // Take multiple snapshots
        collector.record_packet_forward(RelayTransport::Udp, 100, 1000);
        let _snapshot1 = collector.take_snapshot();

        collector.record_packet_forward(RelayTransport::TcpTls443, 200, 2000);
        let _snapshot2 = collector.take_snapshot();

        let dashboard = collector.get_dashboard_data();

        assert_eq!(dashboard.historical.len(), 2);
        assert!(dashboard.current.timestamp_micros > 0);
    }

    #[test]
    fn error_metrics_track_rejections() {
        let mut collector = RelayTelemetryCollector::new();

        collector.record_event(RelayEventKind::QuotaRejected, None);
        collector.record_event(RelayEventKind::AuthorizationRejected, None);
        collector.record_quota_rejection(1024);

        let snapshot = collector.take_snapshot();

        assert_eq!(snapshot.errors.quota_rejections, 1);
        assert_eq!(snapshot.errors.auth_rejections, 1);
        assert_eq!(snapshot.errors.bytes_rejected, 1024);
    }

    // Golden Artifact Tests for ATP Telemetry Serialization Stability

    #[test]
    fn golden_telemetry_snapshot_serialization() {
        use insta::assert_json_snapshot;

        let snapshot = TelemetrySnapshot {
            timestamp_micros: 1640995200000000, // Fixed timestamp: 2022-01-01 00:00:00 UTC
            connections: ConnectionSnapshot {
                active_reservations: 42,
                total_reservations: 150,
                total_packets_forwarded: 98765,
                reservation_success_rate: 0.85,
                average_reservation_latency_micros: 1500,
            },
            transport_udp: TransportSnapshot {
                packets_forwarded: 75000,
                bytes_forwarded: 512000000, // 512 MB
                min_latency_micros: 500,
                max_latency_micros: 5000,
                average_latency_micros: 1200,
                packet_loss_rate: 0.001,
            },
            transport_tcp_tls: TransportSnapshot {
                packets_forwarded: 23765,
                bytes_forwarded: 128000000, // 128 MB
                min_latency_micros: 1000,
                max_latency_micros: 8000,
                average_latency_micros: 2500,
                packet_loss_rate: 0.0005,
            },
            errors: ErrorSnapshot {
                quota_rejections: 12,
                auth_rejections: 3,
                protocol_errors: 1,
                bytes_rejected: 2048000, // 2 MB
            },
        };

        assert_json_snapshot!("telemetry_snapshot_sample", snapshot);
    }

    #[test]
    fn golden_relay_dashboard_data_serialization() {
        use insta::assert_json_snapshot;

        let current = TelemetrySnapshot {
            timestamp_micros: 1640995200000000,
            connections: ConnectionSnapshot {
                active_reservations: 25,
                total_reservations: 100,
                total_packets_forwarded: 50000,
                reservation_success_rate: 0.90,
                average_reservation_latency_micros: 1200,
            },
            transport_udp: TransportSnapshot {
                packets_forwarded: 45000,
                bytes_forwarded: 256000000,
                min_latency_micros: 400,
                max_latency_micros: 4500,
                average_latency_micros: 1000,
                packet_loss_rate: 0.0008,
            },
            transport_tcp_tls: TransportSnapshot {
                packets_forwarded: 5000,
                bytes_forwarded: 32000000,
                min_latency_micros: 800,
                max_latency_micros: 6000,
                average_latency_micros: 2000,
                packet_loss_rate: 0.0003,
            },
            errors: ErrorSnapshot {
                quota_rejections: 5,
                auth_rejections: 1,
                protocol_errors: 0,
                bytes_rejected: 512000,
            },
        };

        let dashboard = RelayDashboardData {
            current: current.clone(),
            historical: vec![
                // Previous snapshot 1 hour ago
                TelemetrySnapshot {
                    timestamp_micros: 1640991600000000, // 1 hour earlier
                    connections: ConnectionSnapshot {
                        active_reservations: 20,
                        total_reservations: 85,
                        total_packets_forwarded: 42000,
                        reservation_success_rate: 0.88,
                        average_reservation_latency_micros: 1300,
                    },
                    transport_udp: TransportSnapshot {
                        packets_forwarded: 38000,
                        bytes_forwarded: 200000000,
                        min_latency_micros: 450,
                        max_latency_micros: 4800,
                        average_latency_micros: 1100,
                        packet_loss_rate: 0.001,
                    },
                    transport_tcp_tls: TransportSnapshot {
                        packets_forwarded: 4000,
                        bytes_forwarded: 25000000,
                        min_latency_micros: 900,
                        max_latency_micros: 6500,
                        average_latency_micros: 2200,
                        packet_loss_rate: 0.0004,
                    },
                    errors: ErrorSnapshot {
                        quota_rejections: 3,
                        auth_rejections: 0,
                        protocol_errors: 1,
                        bytes_rejected: 256000,
                    },
                },
                current,
            ],
        };

        assert_json_snapshot!("relay_dashboard_data_sample", dashboard);
    }

    #[test]
    fn golden_relay_event_kind_serialization() {
        use insta::assert_json_snapshot;

        let events = vec![
            RelayEventKind::ReservationAccepted,
            RelayEventKind::ReservationRejected,
            RelayEventKind::QuotaRejected,
            RelayEventKind::AuthorizationRejected,
            RelayEventKind::PacketForwarded,
            RelayEventKind::ConnectionClosed,
        ];

        assert_json_snapshot!("relay_event_kinds", events);
    }

    #[test]
    fn golden_relay_transport_serialization() {
        use insta::assert_json_snapshot;

        let transports = vec![
            RelayTransport::Udp,
            RelayTransport::TcpTls443,
        ];

        assert_json_snapshot!("relay_transports", transports);
    }
}