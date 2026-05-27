//! ATP UDP socket capability boundary.
//!
//! This module wraps the portable `net::UdpSocket` surface with ATP-specific
//! packet limits, buffer tuning, pressure accounting, structured profile logs,
//! and a deterministic lab packet path for replay.

use crate::cx::Cx;
use crate::net::{
    UdpBatchIoReport, UdpBufferConfig, UdpBufferTuneReport, UdpCapability, UdpOutboundDatagram,
    UdpRecvBatch, UdpSocket, UdpSocketCapabilities,
};
use serde_json::{Value, json};
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Instant;

/// Default ATP UDP packet payload bound.
pub const ATP_UDP_DEFAULT_MAX_PACKET_SIZE: usize = 1500;
/// Default ATP UDP batch bound.
pub const ATP_UDP_DEFAULT_BATCH_SIZE: usize = 32;

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
