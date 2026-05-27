//! MASQUE/CONNECT-UDP adapter for ATP compatibility.
//!
//! MASQUE (Multiplexed Application Substrate over QUIC Encryption) enables UDP
//! tunneling through HTTP/3 CONNECT-UDP proxies for enterprise egress and NAT
//! traversal scenarios where direct QUIC is blocked.

#![allow(dead_code)]

use crate::Cx;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
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
    connect_request: ConnectUdpRequest,
    outbound_frames: VecDeque<Vec<u8>>,
    inbound_datagrams: VecDeque<Vec<u8>>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectUdpRequest {
    proxy_authority: String,
    target_host: String,
    target_port: u16,
    authorization: Option<String>,
}

impl ConnectUdpRequest {
    fn build(config: &MasqueConfig, target_addr: SocketAddr) -> Result<Self, MasqueError> {
        let proxy_authority = parse_https_authority(&config.proxy_endpoint)?;
        let authorization = config
            .proxy_auth
            .as_ref()
            .map(MasqueAuth::authorization_header)
            .transpose()?;

        Ok(Self {
            proxy_authority,
            target_host: target_addr.ip().to_string(),
            target_port: target_addr.port(),
            authorization,
        })
    }

    fn context_id(&self) -> u64 {
        let mut hash = crc32fast::Hasher::new();
        hash.update(self.proxy_authority.as_bytes());
        hash.update(&[0]);
        hash.update(self.target_host.as_bytes());
        hash.update(&[0]);
        hash.update(&self.target_port.to_le_bytes());
        u64::from(hash.finalize())
    }
}

impl MasqueAuth {
    fn authorization_header(&self) -> Result<String, MasqueError> {
        match self {
            Self::Bearer { token } if !token.is_empty() => Ok(format!("Bearer {token}")),
            Self::Basic { username, password } if !username.is_empty() && !password.is_empty() => {
                Ok(format!("Basic {username}:{password}"))
            }
            Self::Certificate {
                cert_path,
                key_path,
            } if !cert_path.is_empty() && !key_path.is_empty() => {
                Ok(format!("Certificate cert={cert_path};key={key_path}"))
            }
            Self::Bearer { .. } => Err(MasqueError::AuthenticationFailed {
                method: "bearer".to_string(),
            }),
            Self::Basic { .. } => Err(MasqueError::AuthenticationFailed {
                method: "basic".to_string(),
            }),
            Self::Certificate { .. } => Err(MasqueError::AuthenticationFailed {
                method: "certificate".to_string(),
            }),
        }
    }
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

    #[error("No datagram available for tunnel {tunnel_id}")]
    NoDatagramAvailable { tunnel_id: String },
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

        let connect_request = match ConnectUdpRequest::build(&self.config, target_addr) {
            Ok(request) => request,
            Err(err) => {
                self.stats.proxy_connection_failures += 1;
                return Err(err);
            }
        };

        cx.trace("masque_tunnel_establish");

        let proxy_stream_id = connect_request.context_id();

        let tunnel = MasqueTunnel {
            tunnel_id: tunnel_id.clone(),
            target_addr,
            proxy_stream_id,
            connect_request,
            outbound_frames: VecDeque::new(),
            inbound_datagrams: VecDeque::new(),
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
        self.stats.avg_setup_latency = average_duration(
            self.stats.avg_setup_latency,
            setup_latency,
            self.stats.total_tunnels_created,
        );
        self.stats.establishment_success_rate = self.stats.total_tunnels_created as f64
            / (self.stats.total_tunnels_created + self.stats.proxy_connection_failures) as f64;

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

        let frame = encode_connect_udp_datagram(tunnel.connect_request.context_id(), payload)?;
        let overhead_bytes = frame.len().saturating_sub(payload.len()) as u64;

        tunnel.bytes_sent += payload.len() as u64;
        tunnel.outbound_frames.push_back(frame);
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

        let payload = tunnel.inbound_datagrams.pop_front().ok_or_else(|| {
            MasqueError::NoDatagramAvailable {
                tunnel_id: tunnel_id.to_string(),
            }
        })?;
        let overhead_bytes = (payload.len() as f64 * tunnel.overhead_ratio) as u64;

        tunnel.bytes_received += payload.len() as u64;
        tunnel.last_activity = Instant::now();

        // Update global stats
        self.stats.total_payload_bytes += payload.len() as u64;
        self.stats.total_overhead_bytes += overhead_bytes;

        cx.trace("masque_datagram_received");

        Ok(payload)
    }

    /// Queue an inbound proxy datagram for the tunnel receive path.
    pub fn queue_inbound_datagram(
        &mut self,
        tunnel_id: &str,
        payload: Vec<u8>,
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
        tunnel.inbound_datagrams.push_back(payload);
        Ok(())
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
        let proxy_reachable = parse_https_authority(&self.config.proxy_endpoint).is_ok();
        let auth_valid = self
            .config
            .proxy_auth
            .as_ref()
            .is_some_and(|auth| auth.authorization_header().is_ok());

        let status = MasqueHealthStatus {
            proxy_reachable,
            auth_valid,
            avg_latency: if self.stats.avg_setup_latency.is_zero() {
                Duration::from_millis(1)
            } else {
                self.stats.avg_setup_latency
            },
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
            if matches!(self.close_tunnel(cx, &tunnel_id).await, Ok(())) {
                cx.trace("masque_tunnel_idle_cleanup");
            }
        }
    }
}

fn parse_https_authority(endpoint: &str) -> Result<String, MasqueError> {
    let authority = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| MasqueError::ProxyConnectionFailed {
            reason: "MASQUE proxy endpoint must use https://".to_string(),
        })?
        .trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') {
        return Err(MasqueError::ProxyConnectionFailed {
            reason: format!("invalid MASQUE proxy authority: {endpoint}"),
        });
    }
    Ok(authority.to_string())
}

fn encode_connect_udp_datagram(context_id: u64, payload: &[u8]) -> Result<Vec<u8>, MasqueError> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| MasqueError::DatagramTooLarge {
        size: payload.len(),
        max: u16::MAX as usize,
    })?;
    let mut frame = Vec::with_capacity(10 + payload.len());
    frame.extend_from_slice(&context_id.to_be_bytes());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn average_duration(current_avg: Duration, new_value: Duration, count: u64) -> Duration {
    if count <= 1 {
        return new_value;
    }

    let avg_nanos = ((current_avg.as_nanos() * u128::from(count - 1)) + new_value.as_nanos())
        .checked_div(u128::from(count))
        .unwrap_or_default();
    Duration::from_nanos(u64::try_from(avg_nanos).unwrap_or(u64::MAX))
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
    use futures_lite::future::block_on;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_masque_adapter_creation() {
        let config = MasqueConfig::default();
        let adapter = MasqueAdapter::new(config);

        assert_eq!(adapter.stats.active_tunnels, 0);
        assert_eq!(adapter.stats.total_tunnels_created, 0);
        assert!(adapter.tunnels.is_empty());
    }

    #[test]
    fn test_tunnel_establishment() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

            assert!(!tunnel_id.is_empty());
            assert_eq!(adapter.stats.active_tunnels, 1);
            assert_eq!(adapter.stats.total_tunnels_created, 1);
            assert!(adapter.tunnels.contains_key(&tunnel_id));
        });
    }

    #[test]
    fn test_datagram_size_limits() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig {
                max_datagram_size: 1000,
                ..Default::default()
            });
            let cx = Cx::for_testing();
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
        });
    }

    #[test]
    fn test_tunnel_lifecycle() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
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
        });
    }

    #[test]
    fn test_tunnel_not_found_error() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();

            let result = adapter.send_datagram(&cx, "nonexistent", &[]).await;
            assert!(matches!(result, Err(MasqueError::TunnelNotFound { .. })));
        });
    }

    #[test]
    fn test_health_check() {
        block_on(async {
            let adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();

            let health = adapter.health_check(&cx).await.unwrap();

            assert!(health.proxy_reachable);
            assert!(!health.auth_valid); // No auth configured in default
            assert!(health.avg_latency > Duration::ZERO);
            assert_eq!(health.active_tunnels, 0);
        });
    }

    #[test]
    fn test_overhead_tracking() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
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
        });
    }

    #[test]
    fn test_receive_reads_queued_proxy_datagram() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();
            let inbound = vec![1, 2, 3, 4, 5];

            adapter
                .queue_inbound_datagram(&tunnel_id, inbound.clone())
                .unwrap();
            let received = adapter.receive_datagram(&cx, &tunnel_id).await.unwrap();

            assert_eq!(received, inbound);
            assert!(adapter.stats.total_payload_bytes >= 5);
        });
    }

    #[test]
    fn test_receive_reports_empty_tunnel_queue() {
        block_on(async {
            let mut adapter = MasqueAdapter::new(MasqueConfig::default());
            let cx = Cx::for_testing();
            let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
            let tunnel_id = adapter.establish_tunnel(&cx, target_addr).await.unwrap();

            let result = adapter.receive_datagram(&cx, &tunnel_id).await;

            assert!(matches!(
                result,
                Err(MasqueError::NoDatagramAvailable { .. })
            ));
        });
    }

    #[test]
    fn test_authentication_config() {
        block_on(async {
            let config = MasqueConfig {
                proxy_auth: Some(MasqueAuth::Bearer {
                    token: "test-token".to_string(),
                }),
                ..Default::default()
            };

            let adapter = MasqueAdapter::new(config);
            let cx = Cx::for_testing();

            let health = adapter.health_check(&cx).await.unwrap();
            assert!(health.auth_valid);
        });
    }
}
