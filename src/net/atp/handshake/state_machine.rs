//! QUIC Handshake State Machine
//!
//! Implements the core QUIC handshake state machine with deterministic
//! transitions and comprehensive trace generation for replay.

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::net::atp::quic::packet_protection::AtpPacketProtectionConfig;
use crate::types::outcome::Outcome;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// QUIC protocol version constants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum QuicVersion {
    /// QUIC version 1 (RFC 9000)
    V1 = 0x00000001,
    /// Version negotiation packet marker
    Negotiation = 0x00000000,
}

impl QuicVersion {
    /// Check if this version is supported
    pub fn is_supported(version: u32) -> bool {
        matches!(version, 0x00000001)
    }

    /// Get list of supported versions for negotiation
    pub fn supported_versions() -> Vec<u32> {
        vec![Self::V1 as u32]
    }
}

/// Handshake endpoint role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Client,
    Server,
}

/// QUIC packet number space
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketSpace {
    Initial,
    Handshake,
    Application,
}

/// Handshake state machine states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state - waiting to start handshake
    Idle,
    /// Version negotiation in progress (client only)
    VersionNegotiating { attempted_version: u32 },
    /// Waiting for retry packet validation (client only)
    WaitingRetry { retry_token: Bytes },
    /// Initial packet exchange in progress
    Initial { crypto_offset: u64 },
    /// Handshake packet exchange in progress
    Handshake { crypto_offset: u64 },
    /// Handshake complete, confirming with HANDSHAKE_DONE
    Confirming,
    /// Handshake completed successfully
    Completed {
        negotiated_version: u32,
        transport_params: HashMap<u64, Bytes>,
    },
    /// Handshake failed
    Failed {
        error: HandshakeError,
        retry_allowed: bool,
    },
}

/// Handshake error types
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// Version negotiation failed
    #[error("unsupported QUIC version: {version:08x}")]
    UnsupportedVersion { version: u32 },

    /// Invalid retry token
    #[error("invalid retry token")]
    InvalidRetryToken,

    /// Transport parameter validation failed
    #[error("invalid transport parameter: {param_id} - {reason}")]
    InvalidTransportParam { param_id: u64, reason: String },

    /// Duplicate transport parameter
    #[error("duplicate transport parameter: {param_id}")]
    DuplicateTransportParam { param_id: u64 },

    /// TLS handshake error
    #[error("TLS handshake failed: {reason}")]
    TlsError { reason: String },

    /// Packet protection error
    #[error("packet protection failed: {reason}")]
    ProtectionError { reason: String },

    /// Connection ID error
    #[error("connection ID error: {reason}")]
    ConnectionIdError { reason: String },

    /// Anti-amplification limit exceeded
    #[error("anti-amplification limit exceeded")]
    AmplificationLimitExceeded,

    /// Handshake timeout
    #[error("handshake timeout after {elapsed:?}")]
    Timeout { elapsed: Duration },

    /// Peer sent invalid packet
    #[error("invalid packet from peer: {reason}")]
    InvalidPacket { reason: String },
}

/// Handshake event for trace generation
#[derive(Debug, Clone)]
pub enum HandshakeEvent {
    /// Handshake started
    Started {
        role: EndpointRole,
        initial_version: u32,
        region_id: String,
    },

    /// Version negotiation packet sent/received
    VersionNegotiation {
        supported_versions: Vec<u32>,
        selected_version: Option<u32>,
    },

    /// Retry packet sent/received
    Retry {
        original_dest_cid: Bytes,
        retry_token: Bytes,
        retry_source_cid: Bytes,
    },

    /// Initial packet exchange
    InitialPacket {
        packet_number: u64,
        crypto_offset: u64,
        crypto_length: u64,
        source_cid: Bytes,
        dest_cid: Bytes,
    },

    /// Handshake packet exchange
    HandshakePacket {
        packet_number: u64,
        crypto_offset: u64,
        crypto_length: u64,
    },

    /// Transport parameters exchanged
    TransportParams { params: HashMap<u64, Bytes> },

    /// Key phase transition
    KeyPhaseTransition { space: PacketSpace, phase: u8 },

    /// Handshake completion
    Completed {
        elapsed: Duration,
        final_version: u32,
    },

    /// Handshake failure
    Failed {
        error: HandshakeError,
        elapsed: Duration,
    },
}

/// QUIC handshake state machine
pub struct QuicHandshakeMachine {
    /// Current handshake state
    state: HandshakeState,

    /// Endpoint role
    role: EndpointRole,

    /// Handshake start time
    start_time: Instant,

    /// Handshake timeout
    timeout: Duration,

    /// Packet protection config
    #[allow(dead_code)]
    protection_config: AtpPacketProtectionConfig,

    /// Generated trace events
    trace_events: Vec<HandshakeEvent>,

    /// Current packet numbers by space
    packet_numbers: HashMap<PacketSpace, u64>,

    /// Received packet tracking for replay protection
    #[allow(dead_code)]
    received_packets: HashMap<PacketSpace, Vec<u64>>,
}

impl QuicHandshakeMachine {
    /// Create a new handshake state machine
    pub fn new(
        role: EndpointRole,
        protection_config: AtpPacketProtectionConfig,
        timeout: Duration,
    ) -> Self {
        let mut packet_numbers = HashMap::new();
        packet_numbers.insert(PacketSpace::Initial, 0);
        packet_numbers.insert(PacketSpace::Handshake, 0);
        packet_numbers.insert(PacketSpace::Application, 0);

        Self {
            state: HandshakeState::Idle,
            role,
            start_time: Instant::now(),
            timeout,
            protection_config,
            trace_events: Vec::new(),
            packet_numbers,
            received_packets: HashMap::new(),
        }
    }

    /// Start the handshake process
    pub fn start(&mut self, cx: &Cx, initial_version: u32) -> Outcome<(), HandshakeError> {
        if !QuicVersion::is_supported(initial_version) {
            let error = HandshakeError::UnsupportedVersion {
                version: initial_version,
            };
            self.state = HandshakeState::Failed {
                error: error.clone(),
                retry_allowed: false,
            };
            self.emit_event(HandshakeEvent::Failed {
                error: error.clone(),
                elapsed: self.start_time.elapsed(),
            });
            return Outcome::err(error);
        }

        self.state = HandshakeState::Initial { crypto_offset: 0 };

        let region_id = format!("{}", cx.region_id());
        self.emit_event(HandshakeEvent::Started {
            role: self.role,
            initial_version,
            region_id,
        });

        Outcome::ok(())
    }

    /// Process received packet
    pub fn process_packet(
        &mut self,
        _cx: &Cx,
        packet_data: &[u8],
        _space: PacketSpace,
    ) -> Outcome<Vec<u8>, HandshakeError> {
        // Check for timeout
        if self.start_time.elapsed() > self.timeout {
            let error = HandshakeError::Timeout {
                elapsed: self.start_time.elapsed(),
            };
            self.state = HandshakeState::Failed {
                error: error.clone(),
                retry_allowed: false,
            };
            self.emit_event(HandshakeEvent::Failed {
                error: error.clone(),
                elapsed: self.start_time.elapsed(),
            });
            return Outcome::err(error);
        }

        if packet_data.is_empty() {
            let error = HandshakeError::InvalidPacket {
                reason: "empty packet".to_string(),
            };
            return Outcome::err(error);
        }

        let packet_number = Self::decode_packet_number(packet_data);
        let received = self.received_packets.entry(_space).or_default();
        if received.contains(&packet_number) {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: format!("duplicate packet number {packet_number} in {_space:?} space"),
            });
        }
        received.push(packet_number);

        let crypto_length = packet_data.len() as u64;
        let current_state = self.state.clone();
        let response = match (current_state, _space) {
            (HandshakeState::Idle, _) => {
                return Outcome::err(HandshakeError::InvalidPacket {
                    reason: "packet received before handshake start".to_string(),
                });
            }
            (HandshakeState::Initial { crypto_offset }, PacketSpace::Initial) => {
                let offset = crypto_offset;
                self.emit_event(HandshakeEvent::InitialPacket {
                    packet_number,
                    crypto_offset: offset,
                    crypto_length,
                    source_cid: Bytes::new(),
                    dest_cid: Bytes::new(),
                });

                self.state = HandshakeState::Handshake { crypto_offset: 0 };
                self.build_handshake_response(PacketSpace::Initial, packet_number, offset)
            }
            (HandshakeState::Handshake { crypto_offset }, PacketSpace::Handshake) => {
                let offset = crypto_offset;
                self.emit_event(HandshakeEvent::HandshakePacket {
                    packet_number,
                    crypto_offset: offset,
                    crypto_length,
                });

                match self.role {
                    EndpointRole::Client => {
                        self.state = HandshakeState::Confirming;
                    }
                    EndpointRole::Server => {
                        self.complete_from_peer_params(HashMap::new());
                    }
                }
                self.build_handshake_response(PacketSpace::Handshake, packet_number, offset)
            }
            (HandshakeState::Confirming, PacketSpace::Application) => {
                self.complete_from_peer_params(HashMap::new());
                self.build_handshake_response(PacketSpace::Application, packet_number, 0)
            }
            (HandshakeState::Completed { .. }, PacketSpace::Application) => Vec::new(),
            (state, space) => {
                return Outcome::err(HandshakeError::InvalidPacket {
                    reason: format!("unexpected {space:?} packet while in {state:?}"),
                });
            }
        };

        Outcome::ok(response)
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Completed { .. })
    }

    /// Check if handshake failed
    pub fn is_failed(&self) -> bool {
        matches!(self.state, HandshakeState::Failed { .. })
    }

    /// Get current handshake state
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Get trace events for replay/diagnostics
    pub fn trace_events(&self) -> &[HandshakeEvent] {
        &self.trace_events
    }

    /// Get next packet number for a space
    pub fn next_packet_number(&mut self, space: PacketSpace) -> u64 {
        let pn = self.packet_numbers.get_mut(&space).unwrap();
        let current = *pn;
        *pn += 1;
        current
    }

    /// Emit trace event
    fn emit_event(&mut self, event: HandshakeEvent) {
        self.trace_events.push(event);
    }

    fn decode_packet_number(packet_data: &[u8]) -> u64 {
        let mut bytes = [0_u8; 8];
        let copy_len = packet_data.len().min(bytes.len());
        let start = bytes.len() - copy_len;
        bytes[start..].copy_from_slice(&packet_data[..copy_len]);
        u64::from_be_bytes(bytes)
    }

    fn build_handshake_response(
        &mut self,
        space: PacketSpace,
        packet_number: u64,
        crypto_offset: u64,
    ) -> Vec<u8> {
        let response_packet_number = self.next_packet_number(space);
        let mut response = Vec::with_capacity(1 + 8 + 8 + 8);
        response.push(match space {
            PacketSpace::Initial => 0,
            PacketSpace::Handshake => 1,
            PacketSpace::Application => 2,
        });
        response.extend_from_slice(&response_packet_number.to_be_bytes());
        response.extend_from_slice(&packet_number.to_be_bytes());
        response.extend_from_slice(&crypto_offset.to_be_bytes());
        response
    }

    fn complete_from_peer_params(&mut self, transport_params: HashMap<u64, Bytes>) {
        self.emit_event(HandshakeEvent::TransportParams {
            params: transport_params.clone(),
        });
        self.state = HandshakeState::Completed {
            negotiated_version: QuicVersion::V1 as u32,
            transport_params,
        };
        self.emit_event(HandshakeEvent::Completed {
            elapsed: self.start_time.elapsed(),
            final_version: QuicVersion::V1 as u32,
        });
    }

    /// Generate qlog-style trace for diagnostics
    pub fn generate_qlog_trace(&self) -> serde_json::Value {
        serde_json::json!({
            "version": "0.1",
            "title": "ATP QUIC Handshake Trace",
            "description": "Handshake state machine trace for replay and diagnostics",
            "configuration": {
                "time_offset": 0,
                "time_units": "ms"
            },
            "events": self.trace_events.iter().map(|event| {
                match event {
                    HandshakeEvent::Started { role, initial_version, region_id } => {
                        serde_json::json!({
                            "name": "handshake_started",
                            "data": {
                                "role": format!("{:?}", role),
                                "initial_version": format!("0x{:08x}", initial_version),
                                "region_id": region_id
                            }
                        })
                    },
                    HandshakeEvent::Completed { elapsed, final_version } => {
                        serde_json::json!({
                            "name": "handshake_completed",
                            "data": {
                                "elapsed_ms": elapsed.as_millis(),
                                "final_version": format!("0x{:08x}", final_version)
                            }
                        })
                    },
                    HandshakeEvent::Failed { error, elapsed } => {
                        serde_json::json!({
                            "name": "handshake_failed",
                            "data": {
                                "error": format!("{}", error),
                                "elapsed_ms": elapsed.as_millis()
                            }
                        })
                    },
                    _ => serde_json::json!({ "name": "other_event" })
                }
            }).collect::<Vec<_>>()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_machine_creation() {
        let config = AtpPacketProtectionConfig::default();
        let timeout = Duration::from_secs(30);
        let machine = QuicHandshakeMachine::new(EndpointRole::Client, config, timeout);

        assert_eq!(machine.role, EndpointRole::Client);
        assert_eq!(machine.state, HandshakeState::Idle);
        assert!(!machine.is_complete());
        assert!(!machine.is_failed());
    }

    #[test]
    fn test_handshake_start_valid_version() {
        let mut machine = QuicHandshakeMachine::new(
            EndpointRole::Client,
            AtpPacketProtectionConfig::default(),
            Duration::from_secs(30),
        );

        let cx = Cx::for_testing();
        let result = machine.start(&cx, QuicVersion::V1 as u32);

        assert!(result.is_ok());
        assert!(matches!(machine.state, HandshakeState::Initial { .. }));
        assert_eq!(machine.trace_events.len(), 1);
    }

    #[test]
    fn test_handshake_start_invalid_version() {
        let mut machine = QuicHandshakeMachine::new(
            EndpointRole::Client,
            AtpPacketProtectionConfig::default(),
            Duration::from_secs(30),
        );

        let cx = Cx::for_testing();
        let result = machine.start(&cx, 0x12345678);

        assert!(result.is_err());
        assert!(machine.is_failed());
        assert_eq!(machine.trace_events.len(), 1);
    }

    #[test]
    fn test_packet_number_generation() {
        let mut machine = QuicHandshakeMachine::new(
            EndpointRole::Client,
            AtpPacketProtectionConfig::default(),
            Duration::from_secs(30),
        );

        assert_eq!(machine.next_packet_number(PacketSpace::Initial), 0);
        assert_eq!(machine.next_packet_number(PacketSpace::Initial), 1);
        assert_eq!(machine.next_packet_number(PacketSpace::Handshake), 0);
        assert_eq!(machine.next_packet_number(PacketSpace::Application), 0);
    }
}
