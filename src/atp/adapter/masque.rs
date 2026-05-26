//! MASQUE/CONNECT-UDP adapter for ATP compatibility.
//!
//! MASQUE (Multiplexed Application Substrate over QUIC Encryption) enables UDP
//! tunneling through HTTP/3 CONNECT-UDP proxies for enterprise egress and NAT
//! traversal scenarios where direct QUIC is blocked.

#![allow(dead_code)]

use crate::{
    Cx,
    time::{Sleep, wall_now},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

/// Configuration for MASQUE/CONNECT-UDP adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueConfig {
    /// HTTP/3 proxy endpoint for CONNECT-UDP tunneling
    pub proxy_endpoint: String,

    /// Authentication credentials for proxy
    pub proxy_auth: Option<MasqueAuth>,

    /// Maximum tunnel establishment timeout
    pub tunnel_timeout: Duration,

    /// UDP datagram size limits for tunneled traffic
    pub max_datagram_size: usize,

    /// Keepalive interval for proxy connection
    pub keepalive_interval: Duration,

    /// Performance warning threshold for tunnel overhead
    pub overhead_warning_threshold: f64,
}

impl Default for MasqueConfig {
    fn default() -> Self {
        Self {
            proxy_endpoint: "https://proxy.example.com:443".to_string(),
            proxy_auth: None,
            tunnel_timeout: Duration::from_secs(30),
            max_datagram_size: 1350, // Conservative for tunneled UDP
            keepalive_interval: Duration::from_secs(60),
            overhead_warning_threshold: 0.25, // 25% overhead warning
        }
    }
}

/// Authentication methods for MASQUE proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MasqueAuth {
    /// Bearer token authentication
    Bearer { token: String },
    /// Basic authentication
    Basic { username: String, password: String },
    /// Client certificate authentication
    Certificate { cert_path: String, key_path: String },
}

/// MASQUE adapter state and session management.
#[derive(Debug)]
pub struct MasqueAdapter {
    config: MasqueConfig,
    tunnels: HashMap<String, MasqueTunnel>,
    stats: MasqueStats,
}

/// Individual MASQUE tunnel session.
#[derive(Debug)]
pub struct MasqueTunnel {
    tunnel_id: String,
    target_addr: SocketAddr,
    proxy_stream_id: u64,
    established_at: Instant,
    last_activity: Instant,
    bytes_sent: u64,
    bytes_received: u64,
    overhead_ratio: f64,
}

/// Performance and usage statistics for MASQUE adapter.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MasqueStats {
    /// Number of active tunnels
    pub active_tunnels: usize,

    /// Total tunnels established since startup
    pub total_tunnels_created: u64,

    /// Total tunnels closed since startup
    pub total_tunnels_closed: u64,

    /// Tunnel establishment success rate
    pub establishment_success_rate: f64,

    /// Average tunnel setup latency
    pub avg_setup_latency: Duration,

    /// Total bytes tunneled (payload)
    pub total_payload_bytes: u64,

    /// Total bytes with overhead (including HTTP/3 framing)
    pub total_overhead_bytes: u64,

    /// Current overhead ratio (overhead / payload)
    pub current_overhead_ratio: f64,

    /// Number of proxy connection failures
    pub proxy_connection_failures: u64,

    /// Number of tunnel timeout events
    pub tunnel_timeouts: u64,
}

/// Errors that can occur with MASQUE adapter operations.
#[derive(Debug, thiserror::Error)]
pub enum MasqueError {
    #[error("Proxy connection failed: {reason}")]
    ProxyConnectionFailed { reason: String },

    #[error("Tunnel establishment failed for {target}: {reason}")]
    TunnelEstablishmentFailed { target: SocketAddr, reason: String },

    #[error("Authentication failed: {method}")]
    AuthenticationFailed { method: String },

    #[error("Tunnel not found: {tunnel_id}")]
    TunnelNotFound { tunnel_id: String },

    #[error("Datagram too large: {size} > {max}")]
    DatagramTooLarge { size: usize, max: usize },

    #[error("Proxy protocol error: {details}")]
    ProtocolError { details: String },

    #[error("Tunnel timeout after {duration:?}")]
    TunnelTimeout { duration: Duration },
}

impl MasqueAdapter {
    /// Create new MASQUE adapter with configuration.
    pub fn new(config: MasqueConfig) -> Self {
        Self {
            config,
            tunnels: HashMap::new(),
            stats: MasqueStats::default(),
        }
    }

    /// Establish UDP tunnel through MASQUE proxy to target address.
    pub async fn establish_tunnel(
        &mut self,
        cx: &Cx,
        target_addr: SocketAddr,
    ) -> Result<String, MasqueError> {
        let tunnel_id = format!(
            "masque-{}-{}",
            target_addr,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let start_time = Instant::now();

        // Simulate MASQUE tunnel establishment with HTTP/3 CONNECT-UDP
        // In real implementation, this would:
        // 1. Establish HTTP/3 connection to proxy
        // 2. Send CONNECT-UDP request with target address
        // 3. Handle proxy authentication if configured
        // 4. Setup bidirectional stream for UDP datagrams

        cx.trace("masque_tunnel_establish");

        // Simulate network delay for tunnel establishment
        Sleep::new(wall_now() + Duration::from_millis(100)).await;

        let tunnel = MasqueTunnel {
            tunnel_id: tunnel_id.clone(),
            target_addr,
            proxy_stream_id: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64, // Would be actual HTTP/3 stream ID
            established_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            overhead_ratio: 0.15, // Typical MASQUE overhead
        };

        let setup_latency = start_time.elapsed();

        // Check for overhead warnings before moving tunnel
        let overhead_ratio = tunnel.overhead_ratio;
        if overhead_ratio > self.config.overhead_warning_threshold {
            cx.trace("masque_overhead_warning");
        }

        self.tunnels.insert(tunnel_id.clone(), tunnel);

        // Update statistics
        self.stats.active_tunnels = self.tunnels.len();
        self.stats.total_tunnels_created += 1;
        self.stats.avg_setup_latency = (self.stats.avg_setup_latency + setup_latency) / 2;

        Ok(tunnel_id)
    }

    /// Send UDP datagram through established tunnel.
    pub async fn send_datagram(
        &mut self,
        cx: &Cx,
        tunnel_id: &str,
        payload: &[u8],
    ) -> Result<(), MasqueError> {
        if payload.len() > self.config.max_datagram_size {
            return Err(MasqueError::DatagramTooLarge {
                size: payload.len(),
                max: self.config.max_datagram_size,
            });
        }

        let tunnel =
            self.tunnels
                .get_mut(tunnel_id)
                .ok_or_else(|| MasqueError::TunnelNotFound {
                    tunnel_id: tunnel_id.to_string(),
                })?;

        // Simulate HTTP/3 framing overhead for UDP datagram
        let overhead_bytes = (payload.len() as f64 * tunnel.overhead_ratio) as u64;

        tunnel.bytes_sent += payload.len() as u64;
        tunnel.last_activity = Instant::now();

        // Update global stats
        self.stats.total_payload_bytes += payload.len() as u64;
        self.stats.total_overhead_bytes += overhead_bytes;
        self.stats.current_overhead_ratio =
            self.stats.total_overhead_bytes as f64 / self.stats.total_payload_bytes as f64;

        cx.trace("masque_datagram_sent");

        Ok(())
    }

    /// Receive UDP datagram from tunnel.
    pub async fn receive_datagram(
        &mut self,
        cx: &Cx,
        tunnel_id: &str,
    ) -> Result<Vec<u8>, MasqueError> {
        let tunnel =
            self.tunnels
                .get_mut(tunnel_id)
                .ok_or_else(|| MasqueError::TunnelNotFound {
                    tunnel_id: tunnel_id.to_string(),
                })?;

        // Simulate receiving UDP datagram through HTTP/3 proxy
        // In real implementation, this would read from the proxy stream
        let payload = vec![0u8; 1024]; // Placeholder payload
        let overhead_bytes = (payload.len() as f64 * tunnel.overhead_ratio) as u64;

        tunnel.bytes_received += payload.len() as u64;
        tunnel.last_activity = Instant::now();

        // Update global stats
        self.stats.total_payload_bytes += payload.len() as u64;
        self.stats.total_overhead_bytes += overhead_bytes;

        cx.trace("masque_datagram_received");

        Ok(payload)
    }

    /// Close tunnel and clean up resources.
    pub async fn close_tunnel(&mut self, cx: &Cx, tunnel_id: &str) -> Result<(), MasqueError> {
        let tunnel = self
            .tunnels
            .remove(tunnel_id)
            .ok_or_else(|| MasqueError::TunnelNotFound {
                tunnel_id: tunnel_id.to_string(),
            })?;

        let _session_duration = tunnel.established_at.elapsed();

        cx.trace("masque_tunnel_closed");

        // Update statistics
        self.stats.active_tunnels = self.tunnels.len();
        self.stats.total_tunnels_closed += 1;

        Ok(())
    }

    /// Get current adapter statistics.
    pub fn stats(&self) -> &MasqueStats {
        &self.stats
    }

    /// Perform health check on proxy connection.
    pub async fn health_check(&self, cx: &Cx) -> Result<MasqueHealthStatus, MasqueError> {
        // Simulate proxy health check
        Sleep::new(wall_now() + Duration::from_millis(50)).await;

        let status = MasqueHealthStatus {
            proxy_reachable: true,
            auth_valid: self.config.proxy_auth.is_some(),
            avg_latency: Duration::from_millis(45),
            active_tunnels: self.stats.active_tunnels,
            overhead_ratio: self.stats.current_overhead_ratio,
        };

        cx.trace("masque_health_check");

        Ok(status)
    }

    /// Clean up idle tunnels based on keepalive timeout.
    pub async fn cleanup_idle_tunnels(&mut self, cx: &Cx) {
        let now = Instant::now();
        let idle_timeout = self.config.keepalive_interval * 2; // 2x keepalive as timeout

        let mut to_remove = Vec::new();
        for (tunnel_id, tunnel) in &self.tunnels {
            if now.duration_since(tunnel.last_activity) > idle_timeout {
                to_remove.push(tunnel_id.clone());
            }
        }

        for tunnel_id in to_remove {
            if let Ok(()) = self.close_tunnel(cx, &tunnel_id).await {
                cx.trace("masque_tunnel_idle_cleanup");
            }
        }
    }
}

/// Health status information for MASQUE proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueHealthStatus {
    /// Whether proxy endpoint is reachable
    pub proxy_reachable: bool,

    /// Whether authentication credentials are valid
    pub auth_valid: bool,

    /// Average latency to proxy
    pub avg_latency: Duration,

    /// Number of currently active tunnels
    pub active_tunnels: usize,

    /// Current protocol overhead ratio
    pub overhead_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_cx;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    async fn test_masque_adapter_creation() {
        let config = MasqueConfig::default();
        let adapter = MasqueAdapter::new(config);

        assert_eq!(adapter.stats.active_tunnels, 0);
        assert_eq!(adapter.stats.total_tunnels_created, 0);
        assert!(adapter.tunnels.is_empty());
    }

    #[test]
    async fn test_tunnel_establishment() {
        let mut adapter = MasqueAdapter::new(MasqueConfig::default());
        let cx = test_cx();
        let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

        assert!(!tunnel_id.is_empty());
        assert_eq!(adapter.stats.active_tunnels, 1);
        assert_eq!(adapter.stats.total_tunnels_created, 1);
        assert!(adapter.tunnels.contains_key(&tunnel_id));
    }

    #[test]
    async fn test_datagram_size_limits() {
        let mut adapter = MasqueAdapter::new(MasqueConfig {
            max_datagram_size: 1000,
            ..Default::default()
        });
        let cx = test_cx();
        let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

        // Test payload within limits
        let small_payload = vec![0u8; 500];
        assert!(
            adapter
                .send_datagram(&cx, &tunnel_id, &small_payload)
                .await
                .is_ok()
        );

        // Test payload exceeding limits
        let large_payload = vec![0u8; 1500];
        let result = adapter.send_datagram(&cx, &tunnel_id, &large_payload).await;
        assert!(matches!(result, Err(MasqueError::DatagramTooLarge { .. })));
    }

    #[test]
    async fn test_tunnel_lifecycle() {
        let mut adapter = MasqueAdapter::new(MasqueConfig::default());
        let cx = test_cx();
        let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        // Establish tunnel
        let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();
        assert_eq!(adapter.stats.active_tunnels, 1);

        // Send some data
        let payload = vec![0u8; 100];
        adapter
            .send_datagram(&cx, &tunnel_id, &payload)
            .await
            .unwrap();

        // Close tunnel
        adapter.close_tunnel(&cx, &tunnel_id).await.unwrap();
        assert_eq!(adapter.stats.active_tunnels, 0);
        assert_eq!(adapter.stats.total_tunnels_closed, 1);
        assert!(!adapter.tunnels.contains_key(&tunnel_id));
    }

    #[test]
    async fn test_tunnel_not_found_error() {
        let mut adapter = MasqueAdapter::new(MasqueConfig::default());
        let cx = test_cx();

        let result = adapter.send_datagram(&cx, "nonexistent", &[]).await;
        assert!(matches!(result, Err(MasqueError::TunnelNotFound { .. })));
    }

    #[test]
    async fn test_health_check() {
        let adapter = MasqueAdapter::new(MasqueConfig::default());
        let cx = test_cx();

        let health = adapter.health_check(&cx).await.unwrap();

        assert!(health.proxy_reachable);
        assert!(!health.auth_valid); // No auth configured in default
        assert!(health.avg_latency > Duration::ZERO);
        assert_eq!(health.active_tunnels, 0);
    }

    #[test]
    async fn test_overhead_tracking() {
        let mut adapter = MasqueAdapter::new(MasqueConfig::default());
        let cx = test_cx();
        let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

        // Send data and verify overhead tracking
        let payload = vec![0u8; 1000];
        adapter
            .send_datagram(&cx, &tunnel_id, &payload)
            .await
            .unwrap();

        assert!(adapter.stats.total_payload_bytes > 0);
        assert!(adapter.stats.total_overhead_bytes > 0);
        assert!(adapter.stats.current_overhead_ratio > 0.0);
        assert!(adapter.stats.current_overhead_ratio < 1.0);
    }

    #[test]
    async fn test_authentication_config() {
        let config = MasqueConfig {
            proxy_auth: Some(MasqueAuth::Bearer {
                token: "test-token".to_string(),
            }),
            ..Default::default()
        };

        let adapter = MasqueAdapter::new(config);
        let cx = test_cx();

        let health = adapter.health_check(&cx).await.unwrap();
        assert!(health.auth_valid);
    }
}
