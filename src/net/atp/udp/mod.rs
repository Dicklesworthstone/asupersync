//! ATP UDP socket capability boundary.
//!
//! This module wraps the portable `net::UdpSocket` surface with ATP-specific
//! packet limits, buffer tuning, pressure accounting, structured profile logs,
//! and a deterministic lab packet path for replay.

use crate::cx::Cx;
use crate::net::udp::UDP_MAX_PACKET_SIZE;
use crate::net::{
    UDP_MAX_GSO_SEGMENTS, UdpBatchIoReport, UdpBufferConfig, UdpBufferTuneReport, UdpCapability,
    UdpInboundDatagram, UdpOutboundDatagram, UdpRecvBatch, UdpSocket, UdpSocketCapabilities,
};
use parking_lot::Mutex;
use serde_json::{Value, json};
use smallvec::SmallVec;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use std::time::Instant;

/// Default ATP UDP packet payload bound.
pub const ATP_UDP_DEFAULT_MAX_PACKET_SIZE: usize = 1500;
/// Default ATP UDP batch bound.
///
/// One default batch fills a Linux UDP GSO super-packet when packet payloads are
/// fixed-size, while variable-sized packets still fall back to one sendmmsg
/// batch through the portable UDP planner.
pub const ATP_UDP_DEFAULT_BATCH_SIZE: usize = UDP_MAX_GSO_SEGMENTS;

/// ATP UDP socket configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpUdpSocketConfig {
    /// Maximum accepted packet payload.
    pub max_packet_size: usize,
    /// Maximum packets sent in one portable batch.
    pub max_send_batch: usize,
    /// Maximum packets received in one portable batch.
    pub max_recv_batch: usize,
    /// Requested OS socket buffer sizes.
    pub buffers: UdpBufferConfig,
    /// Fail bind if an IPv6 dual-stack socket cannot be proven.
    pub require_dual_stack: bool,
}

impl Default for AtpUdpSocketConfig {
    #[inline]
    fn default() -> Self {
        Self {
            max_packet_size: ATP_UDP_DEFAULT_MAX_PACKET_SIZE,
            max_send_batch: ATP_UDP_DEFAULT_BATCH_SIZE,
            max_recv_batch: ATP_UDP_DEFAULT_BATCH_SIZE,
            buffers: UdpBufferConfig {
                recv_buffer_bytes: Some(1024 * 1024),
                send_buffer_bytes: Some(1024 * 1024),
            },
            require_dual_stack: false,
        }
    }
}

impl AtpUdpSocketConfig {
    #[inline]
    fn validate(self) -> io::Result<()> {
        if self.max_packet_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_packet_size must be > 0",
            ));
        }
        if self.max_send_batch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_send_batch must be > 0",
            ));
        }
        if self.max_recv_batch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_recv_batch must be > 0",
            ));
        }
        Ok(())
    }
}

/// ATP UDP socket profile captured at bind time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpUdpSocketProfile {
    /// Local socket address.
    pub local_addr: SocketAddr,
    /// Portable socket capabilities.
    pub capabilities: UdpSocketCapabilities,
    /// Applied buffer tuning report.
    pub buffers: UdpBufferTuneReport,
    /// Source of this socket profile.
    pub source: &'static str,
}

/// ATP UDP pressure counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AtpUdpPressure {
    /// Send batches issued through the abstraction.
    pub send_batches: u64,
    /// Receive batches issued through the abstraction.
    pub recv_batches: u64,
    /// Send batches that stopped early.
    pub send_pressure_events: u64,
    /// Receive batches that returned truncation or socket errors.
    pub recv_pressure_events: u64,
    /// Received packets that may have been truncated by the caller buffer.
    pub truncation_events: u64,
}

/// Borrowed ATP UDP packet to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpUdpPacket<'a> {
    /// Destination address.
    pub dst_addr: SocketAddr,
    /// Payload bytes. Structured logs never include these bytes.
    pub payload: &'a [u8],
}

/// ATP UDP packet received from the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpUdpReceivedPacket {
    /// Source address.
    pub src_addr: SocketAddr,
    /// Payload bytes copied from the socket.
    pub payload: Vec<u8>,
    /// Monotonic receive timestamp.
    pub receive_time: Instant,
    /// True when the configured packet buffer may have truncated payload.
    pub possibly_truncated: bool,
}

/// ATP UDP receive batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AtpUdpRecvBatch {
    /// Received packets.
    pub packets: Vec<AtpUdpReceivedPacket>,
    /// Portable batch report.
    pub report: UdpBatchIoReport,
}

/// ATP UDP socket wrapper used by native packet I/O paths.
#[derive(Debug)]
pub struct AtpUdpSocket {
    socket: UdpSocket,
    config: AtpUdpSocketConfig,
    profile: AtpUdpSocketProfile,
    pressure: AtpUdpPressure,
}

impl AtpUdpSocket {
    /// Bind and tune an ATP UDP socket.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(
        cx: &Cx,
        addr: A,
        config: AtpUdpSocketConfig,
    ) -> io::Result<Self> {
        config.validate()?;
        checkpoint_io(cx)?;

        let socket = UdpSocket::bind(addr).await?;
        let buffers = socket.tune_buffers(config.buffers)?;
        let capabilities = socket.capabilities()?;

        if config.require_dual_stack && capabilities.dual_stack != UdpCapability::Supported {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "dual-stack UDP socket support could not be proven",
            ));
        }

        let profile = AtpUdpSocketProfile {
            local_addr: socket.local_addr()?,
            capabilities,
            buffers,
            source: "native-udp",
        };

        let this = Self {
            socket,
            config,
            profile,
            pressure: AtpUdpPressure::default(),
        };
        this.trace_profile(cx, "atp_udp.bind");
        Ok(this)
    }

    /// Return the local socket address.
    #[inline]
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.profile.local_addr
    }

    /// Return the profile captured at bind time.
    #[inline]
    #[must_use]
    pub fn profile(&self) -> &AtpUdpSocketProfile {
        &self.profile
    }

    /// Return current pressure counters.
    #[inline]
    #[must_use]
    pub fn pressure(&self) -> AtpUdpPressure {
        self.pressure
    }

    /// Emit a structured JSON doctor record.
    #[must_use]
    pub fn doctor_json(&self) -> Value {
        json!({
            "source": self.profile.source,
            "local_addr": self.profile.local_addr.to_string(),
            "platform": format!("{:?}", self.profile.capabilities.platform),
            "address_family": format!("{:?}", self.profile.capabilities.address_family),
            "dual_stack": format!("{:?}", self.profile.capabilities.dual_stack),
            "ecn": format!("{:?}", self.profile.capabilities.ecn),
            "native_send_batch": self.profile.capabilities.batching.native_send_batch,
            "native_recv_batch": self.profile.capabilities.batching.native_recv_batch,
            "portable_send_batch": self.profile.capabilities.batching.portable_send_batch,
            "portable_recv_batch": self.profile.capabilities.batching.portable_recv_batch,
            "requested_recv_buffer_bytes": self.profile.buffers.requested_recv_buffer_bytes,
            "requested_send_buffer_bytes": self.profile.buffers.requested_send_buffer_bytes,
            "applied_recv_buffer_bytes": self.profile.buffers.applied_recv_buffer_bytes,
            "applied_send_buffer_bytes": self.profile.buffers.applied_send_buffer_bytes,
            "pressure": {
                "send_batches": self.pressure.send_batches,
                "recv_batches": self.pressure.recv_batches,
                "send_pressure_events": self.pressure.send_pressure_events,
                "recv_pressure_events": self.pressure.recv_pressure_events,
                "truncation_events": self.pressure.truncation_events,
            },
        })
    }

    /// Emit a compact human doctor line.
    #[must_use]
    pub fn doctor_human(&self) -> String {
        format!(
            "udp local={} platform={:?} family={:?} dual_stack={:?} ecn={:?} batch=portable send_buf={:?}/{:?} recv_buf={:?}/{:?} pressure_send={} pressure_recv={}",
            self.profile.local_addr,
            self.profile.capabilities.platform,
            self.profile.capabilities.address_family,
            self.profile.capabilities.dual_stack,
            self.profile.capabilities.ecn,
            self.profile.buffers.requested_send_buffer_bytes,
            self.profile.buffers.applied_send_buffer_bytes,
            self.profile.buffers.requested_recv_buffer_bytes,
            self.profile.buffers.applied_recv_buffer_bytes,
            self.pressure.send_pressure_events,
            self.pressure.recv_pressure_events,
        )
    }

    /// Send ATP packets in bounded portable batches.
    pub async fn send_packets(
        &mut self,
        cx: &Cx,
        packets: &[AtpUdpPacket<'_>],
    ) -> io::Result<UdpBatchIoReport> {
        let mut total = UdpBatchIoReport {
            fallback_used: packets.len() > 1,
            ..UdpBatchIoReport::default()
        };

        for chunk in packets.chunks(self.config.max_send_batch) {
            checkpoint_io(cx)?;
            let mut batch: SmallVec<[UdpOutboundDatagram<'_>; ATP_UDP_DEFAULT_BATCH_SIZE]> =
                SmallVec::with_capacity(chunk.len());
            for packet in chunk {
                if packet.payload.len() > self.config.max_packet_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP packet exceeds configured maximum",
                    ));
                }
                batch.push(UdpOutboundDatagram {
                    dst_addr: packet.dst_addr,
                    payload: packet.payload,
                });
            }

            let report = self.socket.send_batch_to(&batch).await?;
            total.packets_processed += report.packets_processed;
            total.bytes_processed += report.bytes_processed;
            total.fallback_used |= report.fallback_used;
            total.native_send_batch_used |= report.native_send_batch_used;
            total.gso_send_used |= report.gso_send_used;
            self.pressure.send_batches += 1;

            if let Some(error) = report.error {
                self.pressure.send_pressure_events += 1;
                total.error = Some(error);
                break;
            }
        }

        self.trace_batch(
            cx,
            "atp_udp.send",
            total.packets_processed,
            total.bytes_processed,
        );
        Ok(total)
    }

    /// Receive ATP packets through a bounded portable batch.
    pub async fn recv_packets(&mut self, cx: &Cx) -> io::Result<AtpUdpRecvBatch> {
        checkpoint_io(cx)?;
        let UdpRecvBatch { packets, report } = self
            .socket
            .recv_batch_from(self.config.max_recv_batch, self.config.max_packet_size)
            .await?;
        let receive_time = Instant::now();
        let mut truncations = 0_u64;
        let packets = packets
            .into_iter()
            .map(|packet| {
                if packet.possibly_truncated {
                    truncations += 1;
                }
                AtpUdpReceivedPacket {
                    src_addr: packet.src_addr,
                    payload: packet.payload,
                    receive_time,
                    possibly_truncated: packet.possibly_truncated,
                }
            })
            .collect::<Vec<_>>();

        self.pressure.recv_batches += 1;
        self.pressure.truncation_events += truncations;
        if truncations > 0 || report.error.is_some() {
            self.pressure.recv_pressure_events += 1;
        }
        self.trace_batch(
            cx,
            "atp_udp.recv",
            report.packets_processed,
            report.bytes_processed,
        );

        Ok(AtpUdpRecvBatch { packets, report })
    }

    #[inline]
    fn trace_profile(&self, cx: &Cx, event: &'static str) {
        let local_addr = self.profile.local_addr.to_string();
        let platform = format!("{:?}", self.profile.capabilities.platform);
        let region_id = format!("{:?}", cx.region_id());
        let task_id = format!("{:?}", cx.task_id());
        let fields = [
            ("source", self.profile.source),
            ("local_addr", local_addr.as_str()),
            ("platform", platform.as_str()),
            ("region_id", region_id.as_str()),
            ("task_id", task_id.as_str()),
        ];
        cx.trace_with_fields(event, &fields);
    }

    #[inline]
    fn trace_batch(&self, cx: &Cx, event: &'static str, packets: usize, bytes: usize) {
        let local_addr = self.profile.local_addr.to_string();
        let packets = packets.to_string();
        let bytes = bytes.to_string();
        let send_pressure = self.pressure.send_pressure_events.to_string();
        let recv_pressure = self.pressure.recv_pressure_events.to_string();
        let region_id = format!("{:?}", cx.region_id());
        let task_id = format!("{:?}", cx.task_id());
        let fields = [
            ("source", self.profile.source),
            ("local_addr", local_addr.as_str()),
            ("packets", packets.as_str()),
            ("bytes", bytes.as_str()),
            ("send_pressure", send_pressure.as_str()),
            ("recv_pressure", recv_pressure.as_str()),
            ("region_id", region_id.as_str()),
            ("task_id", task_id.as_str()),
        ];
        cx.trace_with_fields(event, &fields);
    }
}

/// Deterministic UDP event for lab replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabUdpEvent {
    /// Deliver a packet.
    Deliver {
        /// Packet source.
        src_addr: SocketAddr,
        /// Packet payload.
        payload: Vec<u8>,
        /// Whether this replay event represents truncation.
        possibly_truncated: bool,
    },
    /// Drop a packet/loss event.
    Drop,
    /// Stale readiness notification with no packet available.
    StaleReady,
    /// Surface a socket error.
    SocketError(String),
    /// Close the socket while replay is in progress.
    Close,
}

/// Deterministic UDP socket for lab replay.
#[derive(Debug, Default)]
pub struct LabAtpUdpSocket {
    events: VecDeque<LabUdpEvent>,
    closed: bool,
}

impl LabAtpUdpSocket {
    /// Add a replay event.
    pub fn push_event(&mut self, event: LabUdpEvent) {
        self.events.push_back(event);
    }

    /// Reorder queued events deterministically.
    pub fn reorder(&mut self, from: usize, to: usize) -> bool {
        if from >= self.events.len() || to >= self.events.len() {
            return false;
        }
        let Some(event) = self.events.remove(from) else {
            return false;
        };
        self.events.insert(to, event);
        true
    }

    /// Replay available events until max packets, stale readiness, error, or close.
    pub fn recv_available(&mut self, cx: &Cx, max_packets: usize) -> io::Result<AtpUdpRecvBatch> {
        checkpoint_io(cx)?;
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "lab UDP closed",
            ));
        }

        let mut batch = AtpUdpRecvBatch::default();
        while batch.packets.len() < max_packets {
            checkpoint_io(cx)?;
            match self.events.pop_front() {
                Some(LabUdpEvent::Deliver {
                    src_addr,
                    payload,
                    possibly_truncated,
                }) => {
                    batch.report.packets_processed += 1;
                    batch.report.bytes_processed += payload.len();
                    batch.packets.push(AtpUdpReceivedPacket {
                        src_addr,
                        payload,
                        receive_time: Instant::now(),
                        possibly_truncated,
                    });
                }
                Some(LabUdpEvent::Drop) => {}
                Some(LabUdpEvent::StaleReady) | None => break,
                Some(LabUdpEvent::SocketError(error)) => {
                    if batch.packets.is_empty() {
                        return Err(io::Error::other(error));
                    }
                    batch.report.error = Some(error);
                    break;
                }
                Some(LabUdpEvent::Close) => {
                    self.closed = true;
                    if batch.packets.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "lab UDP closed",
                        ));
                    }
                    batch.report.error = Some("lab UDP closed".to_string());
                    break;
                }
            }
        }
        Ok(batch)
    }
}

const LAB_UDP_EPHEMERAL_PORT_START: u16 = 49_152;
const LAB_UDP_DEFAULT_QUEUE_PACKETS: usize = 4_096;

/// Deterministic delivery policy for one source endpoint in a lab UDP network.
///
/// Loss is counted independently for each bound source. `drop_every = Some(n)`
/// drops send ordinals `n`, `2n`, and so on after counting the send, matching
/// UDP's successful-send-but-lost-on-the-network behavior. `latency` delays
/// send acceptance through the caller's [`Cx`] clock, so cancellation before
/// acceptance has no network effect and virtual time can advance under
/// [`crate::lab::LabRuntime`] without consulting the wall clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LabUdpLinkPolicy {
    /// Deterministically drop every Nth datagram from this source.
    pub drop_every: Option<NonZeroU64>,
    /// Delay before the virtual network accepts a send.
    pub latency: Duration,
}

/// Per-source counters from a deterministic lab UDP network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LabUdpLinkStats {
    /// Datagram sends accepted from the source socket.
    pub sent: u64,
    /// Accepted sends intentionally lost by policy or bounded-queue pressure.
    pub dropped: u64,
    /// Datagrams enqueued at a destination endpoint.
    pub delivered: u64,
}

#[derive(Debug, Default)]
struct LabUdpEndpointState {
    packets: VecDeque<UdpInboundDatagram>,
    recv_waker: Option<Waker>,
    closed: bool,
}

#[derive(Debug)]
struct LabAtpUdpNetworkState {
    endpoints: BTreeMap<SocketAddr, LabUdpEndpointState>,
    policies: BTreeMap<SocketAddr, LabUdpLinkPolicy>,
    stats: BTreeMap<SocketAddr, LabUdpLinkStats>,
    next_ephemeral_port: u16,
    max_queue_packets: usize,
}

impl LabAtpUdpNetworkState {
    fn new(max_queue_packets: usize) -> Self {
        Self {
            endpoints: BTreeMap::new(),
            policies: BTreeMap::new(),
            stats: BTreeMap::new(),
            next_ephemeral_port: LAB_UDP_EPHEMERAL_PORT_START,
            max_queue_packets: max_queue_packets.max(1),
        }
    }

    fn allocate_addr(&mut self, requested: SocketAddr) -> io::Result<SocketAddr> {
        if requested.port() != 0 {
            return Ok(requested);
        }

        let first = self.next_ephemeral_port;
        loop {
            let candidate = SocketAddr::new(requested.ip(), self.next_ephemeral_port);
            self.next_ephemeral_port = self.next_ephemeral_port.wrapping_add(1);
            if self.next_ephemeral_port < LAB_UDP_EPHEMERAL_PORT_START {
                self.next_ephemeral_port = LAB_UDP_EPHEMERAL_PORT_START;
            }
            if !self.endpoints.contains_key(&candidate) {
                return Ok(candidate);
            }
            if self.next_ephemeral_port == first {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "lab UDP ephemeral port range exhausted",
                ));
            }
        }
    }
}

/// Explicit, per-test virtual UDP network for deterministic lab execution.
///
/// The network is deliberately not ambient: callers create it, bind endpoints,
/// and pass sockets to the tasks that own them. Delivery order is FIFO, address
/// allocation and accounting use ordered maps, receive readiness is waker-backed,
/// and every queue is bounded. Clones share only this network instance.
#[derive(Debug, Clone)]
pub struct LabAtpUdpNetwork {
    inner: Arc<Mutex<LabAtpUdpNetworkState>>,
}

impl Default for LabAtpUdpNetwork {
    fn default() -> Self {
        Self::with_queue_capacity(LAB_UDP_DEFAULT_QUEUE_PACKETS)
    }
}

impl LabAtpUdpNetwork {
    /// Create a virtual UDP network with a bounded queue per endpoint.
    #[must_use]
    pub fn with_queue_capacity(max_queue_packets: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LabAtpUdpNetworkState::new(max_queue_packets))),
        }
    }

    /// Bind one endpoint. Port zero receives a deterministic ephemeral port.
    pub fn bind(&self, requested: SocketAddr) -> io::Result<LabAtpUdpNetworkSocket> {
        let local_addr = {
            let mut state = self.inner.lock();
            let local_addr = state.allocate_addr(requested)?;
            if state
                .endpoints
                .get(&local_addr)
                .is_some_and(|endpoint| !endpoint.closed)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("lab UDP address already bound: {local_addr}"),
                ));
            }
            state
                .endpoints
                .insert(local_addr, LabUdpEndpointState::default());
            state.policies.remove(&local_addr);
            state.stats.insert(local_addr, LabUdpLinkStats::default());
            local_addr
        };
        Ok(LabAtpUdpNetworkSocket {
            network: self.clone(),
            local_addr,
            connected_peer: None,
        })
    }

    /// Set the deterministic outbound policy for a bound source endpoint.
    pub fn set_source_policy(
        &self,
        source: SocketAddr,
        policy: LabUdpLinkPolicy,
    ) -> io::Result<()> {
        let mut state = self.inner.lock();
        if state
            .endpoints
            .get(&source)
            .is_none_or(|endpoint| endpoint.closed)
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("lab UDP source is not available: {source}"),
            ));
        }
        state.policies.insert(source, policy);
        Ok(())
    }

    /// Return current counters for a bound source endpoint.
    #[must_use]
    pub fn source_stats(&self, source: SocketAddr) -> Option<LabUdpLinkStats> {
        self.inner.lock().stats.get(&source).copied()
    }

    /// Number of datagrams currently queued at an endpoint.
    #[must_use]
    pub fn queued_datagrams(&self, endpoint: SocketAddr) -> Option<usize> {
        self.inner
            .lock()
            .endpoints
            .get(&endpoint)
            .map(|state| state.packets.len())
    }

    /// Whether an endpoint currently has a receive waiter registered.
    #[must_use]
    pub fn has_receive_waiter(&self, endpoint: SocketAddr) -> Option<bool> {
        self.inner
            .lock()
            .endpoints
            .get(&endpoint)
            .map(|state| state.recv_waker.is_some())
    }
}

/// A bound socket on a [`LabAtpUdpNetwork`].
///
/// This type mirrors only the UDP operations required by ATP's datagram paths;
/// it never opens an operating-system socket.
#[derive(Debug)]
pub struct LabAtpUdpNetworkSocket {
    network: LabAtpUdpNetwork,
    local_addr: SocketAddr,
    connected_peer: Option<SocketAddr>,
}

impl LabAtpUdpNetworkSocket {
    /// Return this socket's deterministic local address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Set the default destination used by [`Self::send`].
    pub fn connect(&mut self, peer: SocketAddr) -> io::Result<()> {
        let state = self.network.inner.lock();
        if state
            .endpoints
            .get(&peer)
            .is_none_or(|endpoint| endpoint.closed)
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("lab UDP peer is not bound: {peer}"),
            ));
        }
        drop(state);
        self.connected_peer = Some(peer);
        Ok(())
    }

    /// Send one datagram to this socket's connected peer.
    pub async fn send(&mut self, cx: &Cx, payload: &[u8]) -> io::Result<usize> {
        let peer = self.connected_peer.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "lab UDP socket is not connected",
            )
        })?;
        self.send_to(cx, payload, peer).await
    }

    /// Send one datagram through the explicit virtual network.
    pub async fn send_to(
        &mut self,
        cx: &Cx,
        payload: &[u8],
        destination: SocketAddr,
    ) -> io::Result<usize> {
        checkpoint_io(cx)?;
        if payload.len() > UDP_MAX_PACKET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "lab UDP payload size {} exceeds UDP_MAX_PACKET_SIZE ({UDP_MAX_PACKET_SIZE})",
                    payload.len()
                ),
            ));
        }
        let policy = {
            let state = self.network.inner.lock();
            let source_closed = state
                .endpoints
                .get(&self.local_addr)
                .is_none_or(|endpoint| endpoint.closed);
            if source_closed {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "lab UDP source is closed",
                ));
            }
            let destination_closed = state
                .endpoints
                .get(&destination)
                .is_none_or(|endpoint| endpoint.closed);
            if destination_closed {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("lab UDP destination is unavailable: {destination}"),
                ));
            }
            state
                .policies
                .get(&self.local_addr)
                .copied()
                .unwrap_or_default()
        };

        if !policy.latency.is_zero() {
            crate::time::sleep(cx.now_for_observability(), policy.latency).await;
            checkpoint_io(cx)?;
        }

        let wake = {
            let mut state = self.network.inner.lock();
            let source_closed = state
                .endpoints
                .get(&self.local_addr)
                .is_none_or(|endpoint| endpoint.closed);
            if source_closed {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "lab UDP source is closed",
                ));
            }
            let destination_closed = state
                .endpoints
                .get(&destination)
                .is_none_or(|endpoint| endpoint.closed);
            if destination_closed {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("lab UDP destination is unavailable: {destination}"),
                ));
            }
            let stats = state.stats.entry(self.local_addr).or_default();
            stats.sent = stats.sent.saturating_add(1);
            let drop_by_policy = policy
                .drop_every
                .is_some_and(|every| stats.sent % every.get() == 0);
            if drop_by_policy {
                stats.dropped = stats.dropped.saturating_add(1);
                return Ok(payload.len());
            }
            let queue_full = state
                .endpoints
                .get(&destination)
                .is_some_and(|endpoint| endpoint.packets.len() >= state.max_queue_packets);
            if queue_full {
                let stats = state.stats.entry(self.local_addr).or_default();
                stats.dropped = stats.dropped.saturating_add(1);
                return Ok(payload.len());
            }
            let wake = {
                let endpoint = state
                    .endpoints
                    .get_mut(&destination)
                    .expect("destination checked after virtual send delay");
                endpoint.packets.push_back(UdpInboundDatagram {
                    src_addr: self.local_addr,
                    payload: payload.to_vec(),
                    possibly_truncated: false,
                });
                endpoint.recv_waker.take()
            };
            let stats = state.stats.entry(self.local_addr).or_default();
            stats.delivered = stats.delivered.saturating_add(1);
            wake
        };
        if let Some(waker) = wake {
            waker.wake();
        }
        Ok(payload.len())
    }

    /// Send a batch to the connected peer using deterministic per-packet routing.
    pub async fn send_connected_batch(
        &mut self,
        cx: &Cx,
        payloads: &[&[u8]],
    ) -> io::Result<UdpBatchIoReport> {
        let mut report = UdpBatchIoReport {
            fallback_used: true,
            ..UdpBatchIoReport::default()
        };
        for payload in payloads {
            match self.send(cx, payload).await {
                Ok(sent) => {
                    report.packets_processed += 1;
                    report.bytes_processed += sent;
                }
                Err(error) if report.packets_processed == 0 => return Err(error),
                Err(error) => {
                    report.error = Some(error.to_string());
                    break;
                }
            }
        }
        Ok(report)
    }

    /// Poll for one datagram and copy it into `buffer`.
    pub fn poll_recv_from(
        &mut self,
        task_cx: &Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        if buffer.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "lab UDP receive buffer must not be empty",
            )));
        }
        let mut state = self.network.inner.lock();
        let Some(endpoint) = state.endpoints.get_mut(&self.local_addr) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "lab UDP endpoint is not bound",
            )));
        };
        if endpoint.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "lab UDP endpoint is closed",
            )));
        }
        if let Some(packet) = endpoint.packets.pop_front() {
            let copied = buffer.len().min(packet.payload.len());
            buffer[..copied].copy_from_slice(&packet.payload[..copied]);
            return Poll::Ready(Ok((copied, packet.src_addr)));
        }
        if endpoint
            .recv_waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(task_cx.waker()))
        {
            endpoint.recv_waker = Some(task_cx.waker().clone());
        }
        Poll::Pending
    }

    /// Poll for one datagram, then drain all immediately available datagrams.
    pub fn poll_recv_batch(
        &mut self,
        task_cx: &Context<'_>,
        max_packets: usize,
        packet_size: usize,
    ) -> Poll<io::Result<UdpRecvBatch>> {
        if max_packets == 0 {
            return Poll::Ready(Ok(UdpRecvBatch::default()));
        }
        if packet_size == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "lab UDP packet size must not be zero",
            )));
        }
        if packet_size > UDP_MAX_PACKET_SIZE {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "lab UDP packet size {packet_size} exceeds UDP_MAX_PACKET_SIZE ({UDP_MAX_PACKET_SIZE})"
                ),
            )));
        }

        let mut state = self.network.inner.lock();
        let Some(endpoint) = state.endpoints.get_mut(&self.local_addr) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "lab UDP endpoint is not bound",
            )));
        };
        if endpoint.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "lab UDP endpoint is closed",
            )));
        }
        if endpoint.packets.is_empty() {
            if endpoint
                .recv_waker
                .as_ref()
                .is_none_or(|waker| !waker.will_wake(task_cx.waker()))
            {
                endpoint.recv_waker = Some(task_cx.waker().clone());
            }
            return Poll::Pending;
        }

        let mut batch = UdpRecvBatch::default();
        while batch.packets.len() < max_packets {
            let Some(mut packet) = endpoint.packets.pop_front() else {
                break;
            };
            if packet.payload.len() > packet_size {
                packet.payload.truncate(packet_size);
                packet.possibly_truncated = true;
            }
            batch.report.packets_processed += 1;
            batch.report.bytes_processed += packet.payload.len();
            batch.packets.push(packet);
        }
        Poll::Ready(Ok(batch))
    }

    /// Close this endpoint and wake a parked receiver.
    pub fn close(&mut self) {
        let wake = {
            let mut state = self.network.inner.lock();
            state
                .endpoints
                .get_mut(&self.local_addr)
                .and_then(|endpoint| {
                    endpoint.closed = true;
                    endpoint.packets.clear();
                    endpoint.recv_waker.take()
                })
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

impl Drop for LabAtpUdpNetworkSocket {
    fn drop(&mut self) {
        self.close();
    }
}

#[inline]
fn checkpoint_io(cx: &Cx) -> io::Result<()> {
    if cx.checkpoint().is_err() {
        Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn config_rejects_zero_limits() {
        assert!(
            AtpUdpSocketConfig {
                max_packet_size: 0,
                ..AtpUdpSocketConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            AtpUdpSocketConfig {
                max_send_batch: 0,
                ..AtpUdpSocketConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            AtpUdpSocketConfig {
                max_recv_batch: 0,
                ..AtpUdpSocketConfig::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn default_config_batches_one_udp_gso_window() {
        let config = AtpUdpSocketConfig::default();

        assert_eq!(ATP_UDP_DEFAULT_BATCH_SIZE, UDP_MAX_GSO_SEGMENTS);
        assert_eq!(config.max_send_batch, UDP_MAX_GSO_SEGMENTS);
        assert_eq!(config.max_recv_batch, UDP_MAX_GSO_SEGMENTS);
    }

    #[test]
    fn lab_network_close_discards_packets_and_allows_rebind() {
        run_test_with_cx(|cx| async move {
            let network = LabAtpUdpNetwork::with_queue_capacity(2);
            let sender_addr: SocketAddr = "127.0.0.1:42001".parse().expect("sender address");
            let receiver_addr: SocketAddr = "127.0.0.1:42002".parse().expect("receiver address");
            let mut sender = network.bind(sender_addr).expect("bind sender");
            let receiver = network.bind(receiver_addr).expect("bind receiver");

            sender
                .send_to(&cx, b"queued-before-close", receiver_addr)
                .await
                .expect("enqueue lab datagram");
            assert_eq!(network.queued_datagrams(receiver_addr), Some(1));
            drop(receiver);
            assert_eq!(network.queued_datagrams(receiver_addr), Some(0));
            assert!(
                network
                    .set_source_policy(receiver_addr, LabUdpLinkPolicy::default())
                    .is_err(),
                "a closed source must refuse policy changes"
            );

            let rebound = network.bind(receiver_addr).expect("rebind closed address");
            assert_eq!(rebound.local_addr(), receiver_addr);
            assert_eq!(
                network.source_stats(receiver_addr),
                Some(LabUdpLinkStats::default())
            );
        });
    }

    #[test]
    fn bind_reports_profile_and_doctor_outputs() {
        run_test_with_cx(|cx| async move {
            let socket = AtpUdpSocket::bind(
                &cx,
                "127.0.0.1:0",
                AtpUdpSocketConfig {
                    buffers: UdpBufferConfig {
                        recv_buffer_bytes: Some(16 * 1024),
                        send_buffer_bytes: Some(16 * 1024),
                    },
                    ..AtpUdpSocketConfig::default()
                },
            )
            .await
            .expect("bind ATP UDP socket");

            assert_eq!(socket.profile().source, "native-udp");
            assert!(socket.doctor_json().get("local_addr").is_some());
            assert!(socket.doctor_human().contains("udp local="));
        });
    }

    #[test]
    fn lab_replay_handles_loss_reorder_truncation_stale_error_and_close() {
        run_test_with_cx(|cx| async move {
            let src_a = "127.0.0.1:10001".parse().unwrap();
            let src_b = "127.0.0.1:10002".parse().unwrap();
            let mut lab = LabAtpUdpSocket::default();
            lab.push_event(LabUdpEvent::Deliver {
                src_addr: src_a,
                payload: b"first".to_vec(),
                possibly_truncated: false,
            });
            lab.push_event(LabUdpEvent::Drop);
            lab.push_event(LabUdpEvent::Deliver {
                src_addr: src_b,
                payload: b"second".to_vec(),
                possibly_truncated: true,
            });
            lab.push_event(LabUdpEvent::StaleReady);
            assert!(lab.reorder(0, 2));

            let batch = lab.recv_available(&cx, 4).expect("replay lab UDP");
            assert_eq!(batch.packets.len(), 2);
            assert_eq!(batch.packets[0].src_addr, src_b);
            assert!(batch.packets[0].possibly_truncated);
            assert_eq!(batch.packets[1].src_addr, src_a);

            lab.push_event(LabUdpEvent::SocketError("boom".to_string()));
            let err = lab.recv_available(&cx, 1).expect_err("socket error");
            assert_eq!(err.kind(), io::ErrorKind::Other);

            lab.push_event(LabUdpEvent::Close);
            let err = lab.recv_available(&cx, 1).expect_err("close race");
            assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        });
    }
}
