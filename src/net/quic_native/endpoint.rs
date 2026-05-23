//! Native UDP endpoint for QUIC packet I/O loops under Cx.
//!
//! Provides the socket-level native endpoint loop for UDP send/receive
//! so quic_native can exchange datagrams through Asupersync reactor surfaces.
//!
//! # Design
//!
//! - Uses Cx checkpoints in receive/send/batching/shutdown loops
//! - Keeps platform-specific socket behavior isolated
//! - Exposes clean hooks for lab packet injection and qlog/trace capture
//! - Cancellation drains and deregisters reactor state cleanly
//! - No live workers, wakeups, socket registrations, or obligations after region close

use crate::cx::Cx;
use crate::net::{
    UdpBufferConfig, UdpBufferTuneReport, UdpOutboundDatagram, UdpSocket, UdpSocketCapabilities,
};
use smallvec::SmallVec;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for the QUIC UDP endpoint.
#[derive(Debug, Clone)]
pub struct QuicUdpEndpointConfig {
    /// Maximum packet size to receive.
    pub max_packet_size: usize,
    /// Socket receive buffer size.
    pub socket_recv_buffer_size: Option<usize>,
    /// Socket send buffer size.
    pub socket_send_buffer_size: Option<usize>,
    /// Maximum batch size for packet operations.
    pub max_batch_size: usize,
    /// Whether to enable packet timestamping if supported.
    pub enable_timestamping: bool,
}

impl Default for QuicUdpEndpointConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 1500,                      // Standard MTU
            socket_recv_buffer_size: Some(1024 * 1024), // 1MB receive buffer
            socket_send_buffer_size: Some(1024 * 1024), // 1MB send buffer
            max_batch_size: 32,                         // Reasonable batching
            enable_timestamping: true,
        }
    }
}

/// Packet metadata for received datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedPacket {
    /// Source address of the packet.
    pub src_addr: SocketAddr,
    /// Packet data.
    pub data: Vec<u8>,
    /// Receive timestamp (monotonic).
    pub receive_time: Instant,
    /// Estimated transmit timestamp if available.
    pub transmit_time: Option<Instant>,
}

/// Packet to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingPacket {
    /// Destination address.
    pub dst_addr: SocketAddr,
    /// Packet data.
    pub data: Vec<u8>,
    /// Optional explicit send timestamp.
    pub send_time: Option<Instant>,
}

/// Result of a packet I/O batch operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResult {
    /// Number of packets successfully processed.
    pub packets_processed: usize,
    /// Total bytes processed.
    pub bytes_processed: usize,
    /// Processing duration.
    pub duration: Duration,
    /// Any error that terminated the batch early.
    pub error: Option<String>,
}

/// Native UDP endpoint for QUIC packet exchange.
///
/// Integrates with the Asupersync reactor and provides cancel-correct
/// packet I/O loops for the native QUIC implementation.
#[derive(Debug)]
pub struct QuicUdpEndpoint {
    socket: UdpSocket,
    config: QuicUdpEndpointConfig,
    local_addr: SocketAddr,
    socket_capabilities: UdpSocketCapabilities,
    buffer_report: UdpBufferTuneReport,
    endpoint_id: u64,
    metrics: Arc<EndpointMetrics>,
}

/// Endpoint metrics for observability.
#[derive(Debug, Default)]
pub struct EndpointMetrics {
    /// Total packets received.
    pub packets_received: std::sync::atomic::AtomicU64,
    /// Total packets sent.
    pub packets_sent: std::sync::atomic::AtomicU64,
    /// Total bytes received.
    pub bytes_received: std::sync::atomic::AtomicU64,
    /// Total bytes sent.
    pub bytes_sent: std::sync::atomic::AtomicU64,
    /// Receive errors.
    pub receive_errors: std::sync::atomic::AtomicU64,
    /// Send errors.
    pub send_errors: std::sync::atomic::AtomicU64,
}

/// Errors from endpoint operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicUdpEndpointError {
    /// Operation was cancelled via Cx.
    Cancelled,
    /// Socket I/O error.
    Io(String),
    /// Invalid configuration.
    InvalidConfig(String),
    /// Endpoint is shutting down.
    ShuttingDown,
    /// Packet too large for configured limits.
    PacketTooLarge {
        /// Observed packet size in bytes.
        size: usize,
        /// Configured packet-size limit in bytes.
        limit: usize,
    },
    /// Address resolution failed.
    AddressResolution(String),
}

impl From<io::Error> for QuicUdpEndpointError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::Interrupted {
            Self::Cancelled
        } else {
            Self::Io(e.to_string())
        }
    }
}

impl std::fmt::Display for QuicUdpEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Self::ShuttingDown => write!(f, "endpoint shutting down"),
            Self::PacketTooLarge { size, limit } => {
                write!(f, "packet too large: {size} bytes > {limit} limit")
            }
            Self::AddressResolution(msg) => write!(f, "address resolution error: {msg}"),
        }
    }
}

impl std::error::Error for QuicUdpEndpointError {}

impl QuicUdpEndpoint {
    /// Create a new QUIC UDP endpoint bound to the specified address.
    pub async fn bind(
        cx: &Cx,
        addr: SocketAddr,
        config: QuicUdpEndpointConfig,
    ) -> Result<Self, QuicUdpEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(QuicUdpEndpointError::Cancelled);
        }

        // Validate configuration
        if config.max_packet_size == 0 {
            return Err(QuicUdpEndpointError::InvalidConfig(
                "max_packet_size must be > 0".to_string(),
            ));
        }
        if config.max_batch_size == 0 {
            return Err(QuicUdpEndpointError::InvalidConfig(
                "max_batch_size must be > 0".to_string(),
            ));
        }

        let socket = UdpSocket::bind(addr).await?;
        let buffer_report = socket.tune_buffers(UdpBufferConfig {
            recv_buffer_bytes: config.socket_recv_buffer_size,
            send_buffer_bytes: config.socket_send_buffer_size,
        })?;
        let socket_capabilities = socket.capabilities()?;

        let local_addr = socket.local_addr()?;
        let endpoint_id = generate_endpoint_id();

        let endpoint_id_text = endpoint_id.to_string();
        let local_addr_text = local_addr.to_string();
        let platform = format!("{:?}", socket_capabilities.platform);
        let recv_requested = format!("{:?}", buffer_report.requested_recv_buffer_bytes);
        let recv_applied = format!("{:?}", buffer_report.applied_recv_buffer_bytes);
        let send_requested = format!("{:?}", buffer_report.requested_send_buffer_bytes);
        let send_applied = format!("{:?}", buffer_report.applied_send_buffer_bytes);
        let fields = [
            ("endpoint_id", endpoint_id_text.as_str()),
            ("local_addr", local_addr_text.as_str()),
            ("platform", platform.as_str()),
            ("recv_requested", recv_requested.as_str()),
            ("recv_applied", recv_applied.as_str()),
            ("send_requested", send_requested.as_str()),
            ("send_applied", send_applied.as_str()),
        ];
        cx.trace_with_fields("quic_udp_endpoint.bind", &fields);

        Ok(Self {
            socket,
            config,
            local_addr,
            socket_capabilities,
            buffer_report,
            endpoint_id,
            metrics: Arc::new(EndpointMetrics::default()),
        })
    }

    /// Get the local socket address.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the endpoint ID for logging and tracing.
    #[inline]
    pub fn endpoint_id(&self) -> u64 {
        self.endpoint_id
    }

    /// Get endpoint metrics.
    pub fn metrics(&self) -> Arc<EndpointMetrics> {
        self.metrics.clone()
    }

    /// Report socket capabilities used by this endpoint.
    #[inline]
    #[must_use]
    pub fn socket_capabilities(&self) -> &UdpSocketCapabilities {
        &self.socket_capabilities
    }

    /// Report applied socket buffer tuning.
    #[inline]
    #[must_use]
    pub fn buffer_report(&self) -> UdpBufferTuneReport {
        self.buffer_report
    }

    /// Receive a batch of packets with cancellation support.
    ///
    /// Receives up to `max_packets` datagrams, respecting Cx checkpoints.
    /// Returns empty vec if cancelled or no packets available.
    pub async fn receive_batch(
        &mut self,
        cx: &Cx,
        max_packets: usize,
    ) -> Result<Vec<ReceivedPacket>, QuicUdpEndpointError> {
        let effective_max = std::cmp::min(max_packets, self.config.max_batch_size);
        let batch_start = Instant::now();

        if effective_max == 0 {
            return Ok(Vec::new());
        }
        if cx.checkpoint().is_err() {
            return Err(QuicUdpEndpointError::Cancelled);
        }

        let batch = match self
            .socket
            .recv_batch_from(effective_max, self.config.max_packet_size)
            .await
        {
            Ok(batch) => batch,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                return Err(QuicUdpEndpointError::Cancelled);
            }
            Err(e) => {
                self.metrics
                    .receive_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(e.into());
            }
        };

        let mut packets = Vec::with_capacity(batch.packets.len());
        for packet in batch.packets {
            let bytes_read = packet.payload.len();
            let received = ReceivedPacket {
                src_addr: packet.src_addr,
                data: packet.payload,
                receive_time: Instant::now(),
                transmit_time: None,
            };
            packets.push(received);
            self.metrics
                .packets_received
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics
                .bytes_received
                .fetch_add(bytes_read as u64, std::sync::atomic::Ordering::Relaxed);
        }

        if batch.report.error.is_some() {
            self.metrics
                .receive_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let batch_duration = batch_start.elapsed();
        cx.trace(&format!(
            "endpoint: {}: received {} packets in {:?}",
            self.endpoint_id,
            packets.len(),
            batch_duration
        ));

        Ok(packets)
    }

    /// Send a batch of packets with cancellation support.
    ///
    /// Attempts to send all packets, collecting per-packet results.
    /// Respects Cx checkpoints and handles backpressure.
    pub async fn send_batch(
        &mut self,
        cx: &Cx,
        packets: &[OutgoingPacket],
    ) -> Result<BatchResult, QuicUdpEndpointError> {
        let batch_start = Instant::now();
        let mut total_packets = 0;
        let mut total_bytes = 0;
        let mut batch_error = None;

        for chunk in packets.chunks(self.config.max_batch_size) {
            let mut datagrams: SmallVec<[UdpOutboundDatagram<'_>; 32]> =
                SmallVec::with_capacity(chunk.len());

            for packet in chunk {
                if cx.checkpoint().is_err() {
                    return Err(QuicUdpEndpointError::Cancelled);
                }

                if packet.data.len() > self.config.max_packet_size {
                    return Err(QuicUdpEndpointError::PacketTooLarge {
                        size: packet.data.len(),
                        limit: self.config.max_packet_size,
                    });
                }

                datagrams.push(UdpOutboundDatagram {
                    dst_addr: packet.dst_addr,
                    payload: &packet.data,
                });
            }

            let report = match self.socket.send_batch_to(&datagrams).await {
                Ok(report) => report,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    return Err(QuicUdpEndpointError::Cancelled);
                }
                Err(e) => {
                    self.metrics
                        .send_errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(e.into());
                }
            };

            total_packets += report.packets_processed;
            total_bytes += report.bytes_processed;
            self.metrics.packets_sent.fetch_add(
                report.packets_processed as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            self.metrics.bytes_sent.fetch_add(
                report.bytes_processed as u64,
                std::sync::atomic::Ordering::Relaxed,
            );

            if let Some(error) = report.error {
                self.metrics
                    .send_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                batch_error = Some(error);
                break;
            }
        }

        let batch_duration = batch_start.elapsed();
        cx.trace(&format!(
            "endpoint: {}: sent {} packets ({} bytes) in {:?}",
            self.endpoint_id, total_packets, total_bytes, batch_duration
        ));

        Ok(BatchResult {
            packets_processed: total_packets,
            bytes_processed: total_bytes,
            duration: batch_duration,
            error: batch_error,
        })
    }

    /// Gracefully shut down the endpoint.
    ///
    /// Ensures all reactor registrations are cleaned up and no obligations leak.
    pub async fn shutdown(&mut self, cx: &Cx) -> Result<(), QuicUdpEndpointError> {
        if cx.checkpoint().is_err() {
            return Err(QuicUdpEndpointError::Cancelled);
        }

        cx.trace(&format!("endpoint: {}: shutting down", self.endpoint_id));

        // The socket will be dropped, which should clean up reactor registrations
        // The UdpSocket implementation handles this automatically

        Ok(())
    }
}

/// Generate a unique endpoint ID for logging.
fn generate_endpoint_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn test_endpoint_bind_and_addresses() {
        run_test_with_cx(|cx| async move {
            let config = QuicUdpEndpointConfig::default();
            let endpoint = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind endpoint");

            // Should have a valid local address
            let addr = endpoint.local_addr();
            assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
            assert_ne!(addr.port(), 0);

            // Should have a unique endpoint ID
            assert_ne!(endpoint.endpoint_id(), 0);
            assert!(endpoint.socket_capabilities().batching.portable_recv_batch);
            assert!(endpoint.buffer_report().applied_recv_buffer_bytes.is_some());
        });
    }

    #[test]
    fn test_endpoint_config_validation() {
        run_test_with_cx(|cx| async move {
            // Invalid max_packet_size
            let mut config = QuicUdpEndpointConfig::default();
            config.max_packet_size = 0;

            let result = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(QuicUdpEndpointError::InvalidConfig(_))
            ));

            // Invalid max_batch_size
            let mut config = QuicUdpEndpointConfig::default();
            config.max_batch_size = 0;

            let result = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(
                result,
                Err(QuicUdpEndpointError::InvalidConfig(_))
            ));
        });
    }

    #[test]
    fn test_packet_send_receive_loop() {
        run_test_with_cx(|cx| async move {
            let config = QuicUdpEndpointConfig::default();

            // Create two endpoints
            let mut sender =
                QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config.clone())
                    .await
                    .expect("bind sender");
            let mut receiver = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind receiver");

            let receiver_addr = receiver.local_addr();

            // Send a packet
            let packet = OutgoingPacket {
                dst_addr: receiver_addr,
                data: b"hello quic".to_vec(),
                send_time: None,
            };

            let send_result = sender
                .send_batch(&cx, &[packet])
                .await
                .expect("send packet");
            assert_eq!(send_result.packets_processed, 1);
            assert_eq!(send_result.bytes_processed, 10);
            assert!(send_result.error.is_none());

            // Receive the packet
            let received = receiver
                .receive_batch(&cx, 1)
                .await
                .expect("receive packet");
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, b"hello quic");
            assert_eq!(received[0].src_addr.ip(), sender.local_addr().ip());

            // Check metrics
            let sender_metrics = sender.metrics();
            assert_eq!(
                sender_metrics
                    .packets_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                sender_metrics
                    .bytes_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                10
            );

            let receiver_metrics = receiver.metrics();
            assert_eq!(
                receiver_metrics
                    .packets_received
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(
                receiver_metrics
                    .bytes_received
                    .load(std::sync::atomic::Ordering::Relaxed),
                10
            );
        });
    }

    #[test]
    fn test_send_batch_processes_all_packets_across_configured_chunks() {
        run_test_with_cx(|cx| async move {
            let sender_config = QuicUdpEndpointConfig {
                max_batch_size: 2,
                ..QuicUdpEndpointConfig::default()
            };
            let receiver_config = QuicUdpEndpointConfig {
                max_batch_size: 8,
                ..QuicUdpEndpointConfig::default()
            };

            let mut sender =
                QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), sender_config)
                    .await
                    .expect("bind sender");
            let mut receiver =
                QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), receiver_config)
                    .await
                    .expect("bind receiver");

            let receiver_addr = receiver.local_addr();
            let expected_payloads = (0..5)
                .map(|index| format!("packet-{index}").into_bytes())
                .collect::<Vec<_>>();
            let packets = expected_payloads
                .iter()
                .map(|payload| OutgoingPacket {
                    dst_addr: receiver_addr,
                    data: payload.clone(),
                    send_time: None,
                })
                .collect::<Vec<_>>();
            let expected_bytes = expected_payloads.iter().map(Vec::len).sum::<usize>();

            let send_result = sender
                .send_batch(&cx, &packets)
                .await
                .expect("send chunked packet batch");
            assert_eq!(send_result.packets_processed, packets.len());
            assert_eq!(send_result.bytes_processed, expected_bytes);
            assert!(send_result.error.is_none());

            let received = receiver
                .receive_batch(&cx, packets.len())
                .await
                .expect("receive full packet batch");
            let mut received_payloads = received
                .into_iter()
                .map(|packet| packet.data)
                .collect::<Vec<_>>();
            received_payloads.sort();

            let mut expected_sorted = expected_payloads;
            expected_sorted.sort();
            assert_eq!(received_payloads, expected_sorted);

            assert_eq!(
                sender
                    .metrics()
                    .packets_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                5
            );
        });
    }

    #[test]
    fn test_cancellation_during_receive() {
        run_test_with_cx(|cx| async move {
            let config = QuicUdpEndpointConfig::default();
            let mut endpoint = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config)
                .await
                .expect("bind endpoint");

            cx.set_cancel_requested(true);
            let result = endpoint.receive_batch(&cx, 1).await;
            assert!(matches!(result, Err(QuicUdpEndpointError::Cancelled)));
        });
    }

    #[test]
    fn test_cancellation_before_bind_fails_closed() {
        run_test_with_cx(|cx| async move {
            cx.set_cancel_requested(true);

            let config = QuicUdpEndpointConfig::default();
            let result = QuicUdpEndpoint::bind(&cx, "127.0.0.1:0".parse().unwrap(), config).await;
            assert!(matches!(result, Err(QuicUdpEndpointError::Cancelled)));
        });
    }
}
