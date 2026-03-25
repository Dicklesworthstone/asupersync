//! Protocol adapters for external messaging ecosystems.
//!
//! This module provides a small, capability-aware contract for protocol
//! adapters that need to negotiate capabilities, serialize outbound frames,
//! decode inbound frames, and report lifecycle/health state without pulling
//! ambient runtime assumptions into the adapter layer.

use crate::cx::Cx;
use crate::messaging::redis::{RedisProtocolLimits, RespValue};

/// Error returned by protocol adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolAdapterError {
    /// The caller's capability context has already been cancelled.
    Cancelled,
    /// A lifecycle transition was requested from an invalid state.
    Lifecycle {
        /// Human-readable adapter name.
        adapter: &'static str,
        /// Description of the rejected lifecycle transition.
        detail: String,
    },
    /// Outbound serialization failed.
    Encode {
        /// Human-readable adapter name.
        adapter: &'static str,
        /// Error detail from the underlying encoder.
        detail: String,
    },
    /// Inbound frame decoding failed.
    Decode {
        /// Human-readable adapter name.
        adapter: &'static str,
        /// Error detail from the underlying decoder.
        detail: String,
    },
}

impl std::fmt::Display for ProtocolAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "protocol adapter operation cancelled"),
            Self::Lifecycle { adapter, detail } => {
                write!(f, "{adapter} lifecycle error: {detail}")
            }
            Self::Encode { adapter, detail } => {
                write!(f, "{adapter} encode error: {detail}")
            }
            Self::Decode { adapter, detail } => {
                write!(f, "{adapter} decode error: {detail}")
            }
        }
    }
}

impl std::error::Error for ProtocolAdapterError {}

/// Connection lifecycle state for a protocol adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolConnectionState {
    /// No transport has been attached yet.
    Idle,
    /// The adapter can exchange application frames.
    Ready,
    /// The adapter is draining in-flight work before close.
    Draining,
    /// The transport is closed and the adapter cannot be reused.
    Closed,
}

/// Transport lifecycle events that an adapter must react to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolTransportEvent {
    /// The underlying transport is now connected and writable.
    Connected,
    /// The caller requested a graceful drain before close.
    DrainRequested,
    /// The transport closed cleanly.
    Closed,
    /// The transport reset abruptly.
    Reset,
}

/// Stable capability summary published during protocol negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtocolCapabilities {
    /// Whether the protocol can safely carry multiple outstanding requests.
    pub pipelined_requests: bool,
    /// Whether the protocol has a natural request/reply model.
    pub request_reply: bool,
    /// Whether the protocol naturally supports streaming deliveries.
    pub streaming_publish: bool,
    /// Additional named features supported by the adapter.
    pub features: Vec<&'static str>,
}

/// Result of a protocol capability exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolNegotiation {
    /// Human-readable adapter name.
    pub adapter_name: &'static str,
    /// Protocol family this adapter speaks.
    pub protocol_family: &'static str,
    /// Optional version or dialect hint.
    pub version_hint: Option<&'static str>,
    /// Capabilities advertised by the adapter.
    pub capabilities: ProtocolCapabilities,
}

/// Adapter health snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolHealth {
    /// Current lifecycle state.
    pub state: ProtocolConnectionState,
    /// Whether the adapter is ready to exchange application frames.
    pub ready: bool,
    /// Short lifecycle explanation.
    pub detail: &'static str,
}

/// Successfully decoded protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedProtocolMessage<M> {
    /// Decoded application/protocol message.
    pub message: M,
    /// Number of input bytes consumed to decode the frame.
    pub consumed: usize,
}

/// Common contract for protocol adapters.
pub trait ProtocolAdapter: Send + Sync + 'static {
    /// Application or wire-frame type produced by the adapter.
    type Message: Clone + Send + Sync + 'static;

    /// Human-readable adapter name.
    fn adapter_name(&self) -> &'static str;

    /// Protocol family identifier.
    fn protocol_family(&self) -> &'static str;

    /// Current connection lifecycle state.
    fn connection_state(&self) -> ProtocolConnectionState;

    /// Run protocol negotiation / capability exchange.
    fn begin_handshake(&self, cx: &Cx) -> Result<ProtocolNegotiation, ProtocolAdapterError>;

    /// Report stable adapter capabilities.
    fn capabilities(&self) -> ProtocolCapabilities;

    /// Encode a message into the supplied output buffer.
    fn encode_message(
        &self,
        message: &Self::Message,
        out: &mut Vec<u8>,
    ) -> Result<(), ProtocolAdapterError>;

    /// Attempt to decode one message from the provided bytes.
    ///
    /// Returns `Ok(None)` when more bytes are required.
    fn try_decode_message(
        &self,
        input: &[u8],
    ) -> Result<Option<DecodedProtocolMessage<Self::Message>>, ProtocolAdapterError>;

    /// Apply a transport lifecycle event.
    fn on_transport_event(
        &mut self,
        cx: &Cx,
        event: ProtocolTransportEvent,
    ) -> Result<ProtocolConnectionState, ProtocolAdapterError>;

    /// Return a health summary for the adapter.
    fn health_check(&self, cx: &Cx) -> Result<ProtocolHealth, ProtocolAdapterError>;
}

/// RESP protocol adapter backed by the existing Redis wire types.
#[derive(Debug, Clone)]
pub struct RespProtocolAdapter {
    limits: RedisProtocolLimits,
    state: ProtocolConnectionState,
}

impl RespProtocolAdapter {
    /// Create a RESP adapter using the provided decoder limits.
    #[must_use]
    pub fn new(limits: RedisProtocolLimits) -> Self {
        Self {
            limits,
            state: ProtocolConnectionState::Idle,
        }
    }

    /// Return the protocol limits used by this adapter.
    #[must_use]
    pub const fn limits(&self) -> RedisProtocolLimits {
        self.limits
    }
}

impl Default for RespProtocolAdapter {
    fn default() -> Self {
        Self::new(RedisProtocolLimits::default())
    }
}

impl ProtocolAdapter for RespProtocolAdapter {
    type Message = RespValue;

    fn adapter_name(&self) -> &'static str {
        "redis-resp-adapter"
    }

    fn protocol_family(&self) -> &'static str {
        "redis-resp"
    }

    fn connection_state(&self) -> ProtocolConnectionState {
        self.state
    }

    fn begin_handshake(&self, cx: &Cx) -> Result<ProtocolNegotiation, ProtocolAdapterError> {
        cx.checkpoint()
            .map_err(|_| ProtocolAdapterError::Cancelled)?;
        if self.state == ProtocolConnectionState::Closed {
            return Err(ProtocolAdapterError::Lifecycle {
                adapter: self.adapter_name(),
                detail: "cannot negotiate after transport close".to_string(),
            });
        }

        Ok(ProtocolNegotiation {
            adapter_name: self.adapter_name(),
            protocol_family: self.protocol_family(),
            version_hint: Some("RESP2"),
            capabilities: self.capabilities(),
        })
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            pipelined_requests: true,
            request_reply: true,
            streaming_publish: false,
            features: vec![
                "bulk_strings",
                "arrays",
                "integers",
                "simple_strings",
                "error_frames",
            ],
        }
    }

    fn encode_message(
        &self,
        message: &Self::Message,
        out: &mut Vec<u8>,
    ) -> Result<(), ProtocolAdapterError> {
        if self.state == ProtocolConnectionState::Closed {
            return Err(ProtocolAdapterError::Lifecycle {
                adapter: self.adapter_name(),
                detail: "cannot encode after transport close".to_string(),
            });
        }
        message.encode_into(out);
        Ok(())
    }

    fn try_decode_message(
        &self,
        input: &[u8],
    ) -> Result<Option<DecodedProtocolMessage<Self::Message>>, ProtocolAdapterError> {
        if self.state == ProtocolConnectionState::Closed {
            return Err(ProtocolAdapterError::Lifecycle {
                adapter: self.adapter_name(),
                detail: "cannot decode after transport close".to_string(),
            });
        }

        RespValue::try_decode_with_limits(input, &self.limits)
            .map(|decoded| {
                decoded.map(|(message, consumed)| DecodedProtocolMessage { message, consumed })
            })
            .map_err(|err| ProtocolAdapterError::Decode {
                adapter: self.adapter_name(),
                detail: err.to_string(),
            })
    }

    fn on_transport_event(
        &mut self,
        cx: &Cx,
        event: ProtocolTransportEvent,
    ) -> Result<ProtocolConnectionState, ProtocolAdapterError> {
        cx.checkpoint()
            .map_err(|_| ProtocolAdapterError::Cancelled)?;

        let next = match (self.state, event) {
            (ProtocolConnectionState::Idle, ProtocolTransportEvent::Connected) => {
                ProtocolConnectionState::Ready
            }
            (
                ProtocolConnectionState::Idle
                | ProtocolConnectionState::Ready
                | ProtocolConnectionState::Draining,
                ProtocolTransportEvent::Closed | ProtocolTransportEvent::Reset,
            ) => ProtocolConnectionState::Closed,
            (ProtocolConnectionState::Ready, ProtocolTransportEvent::DrainRequested) => {
                ProtocolConnectionState::Draining
            }
            (ProtocolConnectionState::Closed, _) => {
                return Err(ProtocolAdapterError::Lifecycle {
                    adapter: self.adapter_name(),
                    detail: "adapter is already closed".to_string(),
                });
            }
            _ => {
                return Err(ProtocolAdapterError::Lifecycle {
                    adapter: self.adapter_name(),
                    detail: format!("event {event:?} is invalid from state {:?}", self.state),
                });
            }
        };

        self.state = next;
        Ok(self.state)
    }

    fn health_check(&self, cx: &Cx) -> Result<ProtocolHealth, ProtocolAdapterError> {
        cx.checkpoint()
            .map_err(|_| ProtocolAdapterError::Cancelled)?;

        let detail = match self.state {
            ProtocolConnectionState::Idle => "waiting for transport connect",
            ProtocolConnectionState::Ready => "adapter ready",
            ProtocolConnectionState::Draining => "draining in-flight work",
            ProtocolConnectionState::Closed => "transport closed",
        };

        Ok(ProtocolHealth {
            state: self.state,
            ready: self.state == ProtocolConnectionState::Ready,
            detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolAdapter, ProtocolAdapterError, ProtocolConnectionState, ProtocolTransportEvent,
        RespProtocolAdapter,
    };
    use crate::cx::Cx;
    use crate::messaging::redis::RespValue;
    use crate::types::{Budget, RegionId, TaskId};

    fn test_cx(slot: u32) -> Cx {
        Cx::new(
            RegionId::new_for_test(slot, 0),
            TaskId::new_for_test(slot, 0),
            Budget::INFINITE,
        )
    }

    #[test]
    fn resp_adapter_reports_handshake_capabilities() {
        let cx = test_cx(1);
        let adapter = RespProtocolAdapter::default();

        let negotiation = adapter.begin_handshake(&cx).expect("handshake succeeds");

        assert_eq!(negotiation.adapter_name, "redis-resp-adapter");
        assert_eq!(negotiation.protocol_family, "redis-resp");
        assert_eq!(negotiation.version_hint, Some("RESP2"));
        assert!(negotiation.capabilities.pipelined_requests);
        assert!(negotiation.capabilities.request_reply);
        assert!(negotiation.capabilities.features.contains(&"bulk_strings"));
    }

    #[test]
    fn resp_adapter_round_trips_resp_frames() {
        let adapter = RespProtocolAdapter::default();
        let frame = RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"PING".to_vec())),
            RespValue::BulkString(Some(b"payload".to_vec())),
        ]));

        let mut encoded = Vec::new();
        adapter
            .encode_message(&frame, &mut encoded)
            .expect("encode succeeds");

        let decoded = adapter
            .try_decode_message(&encoded)
            .expect("decode succeeds")
            .expect("full frame available");

        assert_eq!(decoded.message, frame);
        assert_eq!(decoded.consumed, encoded.len());
    }

    #[test]
    fn resp_adapter_tracks_lifecycle_and_health() {
        let cx = test_cx(2);
        let mut adapter = RespProtocolAdapter::default();

        assert_eq!(adapter.connection_state(), ProtocolConnectionState::Idle);
        assert_eq!(
            adapter.on_transport_event(&cx, ProtocolTransportEvent::Connected),
            Ok(ProtocolConnectionState::Ready)
        );
        assert!(adapter.health_check(&cx).expect("health").ready);
        assert_eq!(
            adapter.on_transport_event(&cx, ProtocolTransportEvent::DrainRequested),
            Ok(ProtocolConnectionState::Draining)
        );
        assert_eq!(
            adapter.on_transport_event(&cx, ProtocolTransportEvent::Closed),
            Ok(ProtocolConnectionState::Closed)
        );
        assert!(!adapter.health_check(&cx).expect("health").ready);
    }

    #[test]
    fn resp_adapter_rejects_reopen_after_close() {
        let cx = test_cx(3);
        let mut adapter = RespProtocolAdapter::default();
        adapter
            .on_transport_event(&cx, ProtocolTransportEvent::Closed)
            .expect("initial close succeeds");

        let err = adapter
            .on_transport_event(&cx, ProtocolTransportEvent::Connected)
            .expect_err("closed adapter should reject reconnect");

        assert!(matches!(err, ProtocolAdapterError::Lifecycle { .. }));
    }

    #[test]
    fn resp_adapter_observes_cancellation() {
        let cx = test_cx(4);
        cx.set_cancel_requested(true);

        let adapter = RespProtocolAdapter::default();
        let err = adapter
            .begin_handshake(&cx)
            .expect_err("cancelled cx should fail handshake");

        assert_eq!(err, ProtocolAdapterError::Cancelled);
    }
}
