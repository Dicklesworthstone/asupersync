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
//! - Readiness is selected from the current `Cx` (installed for each
//!   synchronous poll): a `Cx` that carries an I/O driver registers the socket
//!   with that runtime's reactor; a `Cx` without one (the caller-driven
//!   composition, e.g. `futures_lite::block_on` plus an explicit `Cx`)
//!   registers it with the process-global fallback I/O driver in `net::udp`,
//!   so a bounded receive wait parks until a datagram arrives or the timeout
//!   fires instead of re-polling in a hot loop (GH#67)

use crate::cx::Cx;
use crate::net::{
    UDP_MAX_GSO_SEGMENTS, UdpBufferConfig, UdpBufferTuneReport, UdpOutboundDatagram,
    UdpSendBatchStrategy, UdpSocket, UdpSocketCapabilities,
};
use smallvec::SmallVec;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const QUIC_UDP_DEFAULT_SEND_BUFFER_BYTES: usize = 1024 * 1024;

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
    /// Whether to enable packet timestamping if supported. Not applied yet:
    /// the endpoint requests no timestamps whatever the value.
    pub enable_timestamping: bool,
}

impl Default for QuicUdpEndpointConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 1500,
            socket_recv_buffer_size: Some(QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES),
            socket_send_buffer_size: Some(QUIC_UDP_DEFAULT_SEND_BUFFER_BYTES),
            max_batch_size: UDP_MAX_GSO_SEGMENTS,
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
    /// True when at least one chunk used the portable fallback send loop.
    pub fallback_used: bool,
    /// True when at least one chunk used an OS-native send batching syscall.
    pub native_send_batch_used: bool,
    /// True when at least one chunk used UDP Generic Segmentation Offload.
    pub gso_send_used: bool,
    /// Any error that terminated the batch early.
    pub error: Option<String>,
}

/// Best-effort Linux UDP socket receive counters sampled from `/proc/net/udp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpKernelReceiveSnapshot {
    /// Kernel receive queue bytes reported for the socket.
    pub rx_queue_bytes: u64,
    /// Kernel packet drops reported for the socket.
    pub drops: u64,
}

fn homogeneous_packet_run_len(packets: &[OutgoingPacket]) -> usize {
    let Some(first) = packets.first() else {
        return 0;
    };
    let first_len = first.data.len();
    let first_dst = first.dst_addr;
    packets
        .iter()
        .take_while(|packet| packet.data.len() == first_len && packet.dst_addr == first_dst)
        .count()
}

fn send_strategy_for_packet_run(
    packets: &[OutgoingPacket],
    base: UdpSendBatchStrategy,
) -> UdpSendBatchStrategy {
    let mut strategy = base;
    if packets.len() > 1 {
        if let Some(packet) = packets.first() {
            strategy.gso_segment_bytes = packet.data.len();
        }
    }
    strategy
}

fn record_atomic_max(slot: &AtomicU64, value: u64) {
    let mut current = slot.load(Ordering::Relaxed);
    while value > current {
        match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}

fn linux_proc_udp_key(addr: SocketAddr) -> Option<String> {
    match addr {
        SocketAddr::V4(addr) => Some(format!(
            "{:08X}:{:04X}",
            u32::from_le_bytes(addr.ip().octets()),
            addr.port()
        )),
        SocketAddr::V6(_) => None,
    }
}

fn parse_linux_proc_udp_snapshot_line(
    line: &str,
    local_key: &str,
) -> Option<UdpKernelReceiveSnapshot> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let local_address = fields.get(1)?;
    if *local_address != local_key {
        return None;
    }
    let queue_pair = fields.get(4)?;
    let (_, rx_queue_hex) = queue_pair.split_once(':')?;
    let rx_queue_bytes = u64::from_str_radix(rx_queue_hex, 16).ok()?;
    let drops = fields.last()?.parse::<u64>().ok()?;
    Some(UdpKernelReceiveSnapshot {
        rx_queue_bytes,
        drops,
    })
}

fn linux_udp_kernel_receive_snapshot(local_addr: SocketAddr) -> Option<UdpKernelReceiveSnapshot> {
    let local_key = linux_proc_udp_key(local_addr)?;
    let proc_udp = std::fs::read_to_string("/proc/net/udp").ok()?;
    proc_udp
        .lines()
        .find_map(|line| parse_linux_proc_udp_snapshot_line(line, &local_key))
}

/// Native UDP endpoint for QUIC packet exchange.
///
/// Integrates with the Asupersync reactor and provides cancel-correct
/// packet I/O loops for the native QUIC implementation.
#[derive(Debug)]
pub struct QuicUdpEndpoint {
    socket: UdpSocket,
    /// Separate registration prevents pending reads and writes replacing each other's interest.
    managed_send_socket: Option<UdpSocket>,
    config: QuicUdpEndpointConfig,
    local_addr: SocketAddr,
    socket_capabilities: UdpSocketCapabilities,
    buffer_report: UdpBufferTuneReport,
    endpoint_id: u64,
    metrics: Arc<EndpointMetrics>,
    /// Reusable receive scratch buffers, so batch receives do not pay a
    /// `max_packet_size` allocation + zero fill per batch.
    recv_payload_pool: Vec<Vec<u8>>,
    /// Errors the next managed sends report as if the socket returned them.
    #[cfg(test)]
    injected_send_errors: std::collections::VecDeque<io::Error>,
}

/// Endpoint metrics for observability.
#[derive(Debug, Default)]
pub struct EndpointMetrics {
    /// Total packets received.
    pub packets_received: AtomicU64,
    /// Total packets sent.
    pub packets_sent: AtomicU64,
    /// Total bytes received.
    pub bytes_received: AtomicU64,
    /// Total bytes sent.
    pub bytes_sent: AtomicU64,
    /// Total receive batch calls that completed with at least one datagram.
    pub receive_batches: AtomicU64,
    /// Receive batch calls that filled the requested batch budget.
    pub receive_full_batches: AtomicU64,
    /// Largest datagram count returned by a receive batch.
    pub max_receive_batch_packets: AtomicU64,
    /// Datagrams that exactly filled the configured packet buffer and may have truncated.
    pub receive_truncated_packets: AtomicU64,
    /// Latest Linux `/proc/net/udp` receive queue byte sample, or 0 when unavailable.
    pub kernel_rx_queue_bytes_latest: AtomicU64,
    /// Latest Linux `/proc/net/udp` drop counter sample, or 0 when unavailable.
    pub kernel_drops_latest: AtomicU64,
    /// Receive errors.
    pub receive_errors: AtomicU64,
    /// Send errors.
    pub send_errors: AtomicU64,
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
            managed_send_socket: None,
            config,
            local_addr,
            socket_capabilities,
            buffer_report,
            endpoint_id,
            metrics: Arc::new(EndpointMetrics::default()),
            recv_payload_pool: Vec::new(),
            #[cfg(test)]
            injected_send_errors: std::collections::VecDeque::new(),
        })
    }

    /// Get the local socket address.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The bound socket's configuration: adopting owners preserve it, and the
    /// managed loop reads its send size limit.
    pub(crate) fn config(&self) -> &QuicUdpEndpointConfig {
        &self.config
    }

    /// Make the next managed sends fail with these errors before the socket.
    #[cfg(test)]
    pub(crate) fn inject_send_errors(&mut self, errors: impl IntoIterator<Item = io::Error>) {
        self.injected_send_errors.extend(errors);
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
    /// A receive parked on an empty socket also wakes when `cx` is cancelled
    /// and returns [`QuicUdpEndpointError::Cancelled`] (unless cancellation
    /// is masked), instead of waiting for the next datagram.
    pub async fn receive_batch(
        &mut self,
        cx: &Cx,
        max_packets: usize,
    ) -> Result<Vec<ReceivedPacket>, QuicUdpEndpointError> {
        let mut cancelled = std::pin::pin!(cx.cancelled());
        std::future::poll_fn(|task_cx| {
            let polled = self.poll_receive_batch(cx, task_cx, max_packets);
            // Socket readiness alone never observes cancellation: also
            // register this parked receive's waker for `cx` cancellation.
            if polled.is_pending()
                && std::future::Future::poll(cancelled.as_mut(), task_cx).is_ready()
                && cx.checkpoint().is_err()
            {
                return Poll::Ready(Err(QuicUdpEndpointError::Cancelled));
            }
            polled
        })
        .await
    }

    pub(crate) fn poll_receive_batch(
        &mut self,
        cx: &Cx,
        task_cx: &Context<'_>,
        max_packets: usize,
    ) -> Poll<Result<Vec<ReceivedPacket>, QuicUdpEndpointError>> {
        // UDP's low-level polling API selects its driver from the current Cx.
        // Install the supplied owner only for this synchronous poll.
        let _current = Cx::set_current(Some(cx.clone()));
        let effective_max = std::cmp::min(max_packets, self.config.max_batch_size);
        let batch_start = Instant::now();

        if effective_max == 0 {
            return Poll::Ready(Ok(Vec::new()));
        }
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(QuicUdpEndpointError::Cancelled));
        }

        let batch = match self.socket.poll_recv_batch_from_reusing(
            task_cx,
            effective_max,
            self.config.max_packet_size,
            &mut self.recv_payload_pool,
        ) {
            Poll::Ready(Ok(batch)) => batch,
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                return Poll::Ready(Err(QuicUdpEndpointError::Cancelled));
            }
            Poll::Ready(Err(e)) => {
                self.metrics
                    .receive_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Poll::Ready(Err(e.into()));
            }
        };

        let mut packets = Vec::with_capacity(batch.packets.len());
        let mut truncated_packets = 0usize;
        for packet in batch.packets {
            let bytes_read = packet.payload.len();
            if packet.possibly_truncated {
                truncated_packets = truncated_packets.saturating_add(1);
            }
            let received = ReceivedPacket {
                src_addr: packet.src_addr,
                data: packet.payload,
                receive_time: Instant::now(),
                transmit_time: None,
            };
            packets.push(received);
            self.metrics
                .packets_received
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_received
                .fetch_add(bytes_read as u64, Ordering::Relaxed);
        }

        let packet_count = packets.len();
        let received_full_batch = packet_count == effective_max;
        if packet_count > 0 {
            self.metrics.receive_batches.fetch_add(1, Ordering::Relaxed);
            if received_full_batch {
                self.metrics
                    .receive_full_batches
                    .fetch_add(1, Ordering::Relaxed);
            }
            record_atomic_max(
                &self.metrics.max_receive_batch_packets,
                u64::try_from(packet_count).unwrap_or(u64::MAX),
            );
        }
        if truncated_packets > 0 {
            self.metrics.receive_truncated_packets.fetch_add(
                u64::try_from(truncated_packets).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }

        if batch.report.error.is_some() {
            self.metrics.receive_errors.fetch_add(1, Ordering::Relaxed);
        }

        let kernel_snapshot = if std::env::var_os("ATP_QUIC_TRACE").is_some()
            || std::env::var_os("ATP_RQ_TRACE").is_some()
        {
            linux_udp_kernel_receive_snapshot(self.local_addr)
        } else {
            None
        };
        if let Some(snapshot) = kernel_snapshot {
            self.metrics
                .kernel_rx_queue_bytes_latest
                .store(snapshot.rx_queue_bytes, Ordering::Relaxed);
            self.metrics
                .kernel_drops_latest
                .store(snapshot.drops, Ordering::Relaxed);
        }

        // Gate the field formatting: receive_batch runs once per socket batch
        // on the hot receive path, so the ~15 string allocations below must
        // not happen when tracing is off.
        if cx.trace_buffer().is_some() {
            let batch_duration = batch_start.elapsed();
            let endpoint_id = self.endpoint_id.to_string();
            let effective_max = effective_max.to_string();
            let packet_count = packet_count.to_string();
            let byte_count = batch.report.bytes_processed.to_string();
            let duration_micros = batch_duration.as_micros().to_string();
            let full_batch = received_full_batch.to_string();
            let truncated_packets = truncated_packets.to_string();
            let recv_requested = format!("{:?}", self.buffer_report.requested_recv_buffer_bytes);
            let recv_applied = format!("{:?}", self.buffer_report.applied_recv_buffer_bytes);
            let kernel_rx_queue = kernel_snapshot
                .map(|snapshot| snapshot.rx_queue_bytes.to_string())
                .unwrap_or_else(|| "unavailable".to_string());
            let kernel_drops = kernel_snapshot
                .map(|snapshot| snapshot.drops.to_string())
                .unwrap_or_else(|| "unavailable".to_string());
            let error = batch.report.error.as_deref().unwrap_or("none");
            // Correlation-safe field budget: <=12 explicit fields
            // (br-asupersync-an0t8o). local_addr is static per endpoint (on
            // the quic_udp_endpoint.bind entry) and requested_max is the
            // config input already reflected in effective_max.
            cx.trace_with_fields(
                "quic_udp_endpoint.receive_batch",
                &[
                    ("endpoint_id", endpoint_id.as_str()),
                    ("effective_max", effective_max.as_str()),
                    ("packets", packet_count.as_str()),
                    ("bytes", byte_count.as_str()),
                    ("duration_micros", duration_micros.as_str()),
                    ("full_batch", full_batch.as_str()),
                    ("truncated_packets", truncated_packets.as_str()),
                    ("recv_requested", recv_requested.as_str()),
                    ("recv_applied", recv_applied.as_str()),
                    ("kernel_rx_queue_bytes", kernel_rx_queue.as_str()),
                    ("kernel_drops", kernel_drops.as_str()),
                    ("error", error),
                ],
            );
        }

        Poll::Ready(Ok(packets))
    }

    /// Return an acknowledged prefix before any wait, so a racing timer cannot
    /// discard send progress. The managed endpoint retains the entire unsent tail.
    pub(crate) fn poll_send_batch<'a>(
        &mut self,
        cx: &Cx,
        task_cx: &Context<'_>,
        packets: impl IntoIterator<Item = &'a OutgoingPacket>,
    ) -> Poll<io::Result<BatchResult>> {
        let _current = Cx::set_current(Some(cx.clone()));
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let batch_start = Instant::now();
        let mut packets = packets.into_iter();
        let Some(first) = packets.next() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty managed send batch",
            )));
        };
        let run = std::iter::once(first)
            .chain(packets)
            .take(self.config.max_batch_size)
            .take_while(|packet| {
                packet.dst_addr == first.dst_addr && packet.data.len() == first.data.len()
            });
        let mut datagrams: SmallVec<[UdpOutboundDatagram<'_>; 32]> = SmallVec::new();
        for packet in run {
            if packet.data.len() > self.config.max_packet_size {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "packet size {} exceeds endpoint limit {}",
                        packet.data.len(),
                        self.config.max_packet_size
                    ),
                )));
            }
            datagrams.push(UdpOutboundDatagram {
                dst_addr: packet.dst_addr,
                payload: &packet.data,
            });
        }
        #[cfg(test)]
        if let Some(error) = self.injected_send_errors.pop_front() {
            self.metrics.send_errors.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Err(error));
        }
        if self.managed_send_socket.is_none() {
            self.managed_send_socket = Some(self.socket.try_clone()?);
        }
        let socket = self
            .managed_send_socket
            .as_mut()
            .expect("send socket initialized");
        let mut strategy = UdpSendBatchStrategy::default();
        if datagrams.len() > 1 {
            strategy.gso_segment_bytes = first.data.len();
        }
        let report = match socket.poll_send_batch_to_with_strategy(task_cx, &datagrams, strategy) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(report)) => report,
            Poll::Ready(Err(err)) => {
                self.metrics.send_errors.fetch_add(1, Ordering::Relaxed);
                return Poll::Ready(Err(err));
            }
        };
        self.metrics
            .packets_sent
            .fetch_add(report.packets_processed as u64, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(report.bytes_processed as u64, Ordering::Relaxed);
        if report.error.is_some() {
            self.metrics.send_errors.fetch_add(1, Ordering::Relaxed);
        }
        Poll::Ready(Ok(BatchResult {
            packets_processed: report.packets_processed,
            bytes_processed: report.bytes_processed,
            duration: batch_start.elapsed(),
            fallback_used: report.fallback_used,
            native_send_batch_used: report.native_send_batch_used,
            gso_send_used: report.gso_send_used,
            error: report.error,
        }))
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
        self.send_batch_with_strategy(cx, packets, UdpSendBatchStrategy::default())
            .await
    }

    /// Send a batch of packets with an explicit UDP acceleration strategy.
    pub async fn send_batch_with_strategy(
        &mut self,
        cx: &Cx,
        packets: &[OutgoingPacket],
        strategy: UdpSendBatchStrategy,
    ) -> Result<BatchResult, QuicUdpEndpointError> {
        let batch_start = Instant::now();
        let mut total_packets = 0;
        let mut total_bytes = 0;
        let mut batch_error = None;
        let mut fallback_used = false;
        let mut native_send_batch_used = false;
        let mut gso_send_used = false;

        for chunk in packets.chunks(self.config.max_batch_size) {
            let mut offset = 0usize;
            while offset < chunk.len() {
                let run_len = homogeneous_packet_run_len(&chunk[offset..]).max(1);
                let run = &chunk[offset..offset.saturating_add(run_len)];
                let run_strategy = send_strategy_for_packet_run(run, strategy);
                let mut datagrams: SmallVec<[UdpOutboundDatagram<'_>; 32]> =
                    SmallVec::with_capacity(run.len());

                for packet in run {
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

                let report = match self
                    .socket
                    .send_batch_to_with_strategy(&datagrams, run_strategy)
                    .await
                {
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
                fallback_used |= report.fallback_used;
                native_send_batch_used |= report.native_send_batch_used;
                gso_send_used |= report.gso_send_used;
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
                offset = offset.saturating_add(run_len);
            }
            if batch_error.is_some() {
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
            fallback_used,
            native_send_batch_used,
            gso_send_used,
            error: batch_error,
        })
    }

    /// Gracefully shut down the endpoint.
    ///
    /// Ensures all reactor registrations are cleaned up and no obligations leak.
    pub async fn shutdown(&mut self, cx: &Cx) -> Result<(), QuicUdpEndpointError> {
        self.retire_io();
        if cx.checkpoint().is_err() {
            return Err(QuicUdpEndpointError::Cancelled);
        }

        cx.trace(&format!("endpoint: {}: shutting down", self.endpoint_id));

        // Local registrations are already retired even if the owner is cancelled.

        Ok(())
    }

    /// Release local I/O ownership even when an owner's future is dropped.
    pub(crate) fn retire_io(&mut self) {
        self.socket.clear_registration();
        self.managed_send_socket = None;
    }
}

/// Generate a unique endpoint ID for logging.
fn generate_endpoint_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
#[path = "endpoint_inline_tests.rs"]
mod tests;
