//! Native QUIC transport state machines (Tokio-free).
//!
//! This module layers protocol behavior on top of `net::quic_core` codecs:
//! - TLS/key-phase progression model
//! - transport/loss recovery model
//! - stream + flow-control model

pub mod connection;
pub mod connection_manager;
pub mod endpoint;
pub mod forensic_log;
pub mod managed_endpoint;
pub mod streams;
pub mod tls;
pub mod transport;

#[cfg(test)]
pub mod integration_tests;

#[cfg(test)]
pub mod transport_conformance_tests;

#[cfg(test)]
pub mod tls_conformance_harness;

pub use connection::{NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError};
pub use connection_manager::{
    ConnectionRouter, ConnectionRouterError, ConnectionRouterStats, ConnectionTimerEvent,
    QuicTimerScheduler, RoutingResult, TimerType,
};
pub use endpoint::{
    BatchResult, EndpointMetrics, OutgoingPacket, QuicUdpEndpoint, QuicUdpEndpointConfig,
    QuicUdpEndpointError, ReceivedPacket,
};
pub use managed_endpoint::{ManagedEndpointConfig, ManagedEndpointError, ManagedQuicEndpoint};
pub use streams::{
    FlowControlError, FlowCredit, QuicStream, QuicStreamError, StreamDirection, StreamId,
    StreamRole, StreamTable, StreamTableError,
};
#[cfg(any(test, feature = "test-internals"))]
pub use tls::DeterministicQuicCryptoProvider;
pub use tls::{
    CryptoLevel, HeaderProtectionMask, KeyUpdateEvent, PacketProtectionRequest,
    PacketProtectionSpace, ProtectedPacket, ProtectionKeySnapshot, ProtectionProof,
    QuicHandshakeTranscript, QuicPacketProtectionProvider, QuicTlsError, QuicTlsMachine,
    TranscriptHash, UnprotectedPacket,
};
#[cfg(feature = "tls")]
pub use tls::{RustlsQuicCryptoProvider, RustlsQuicProviderSide};
pub use transport::{
    AckEvent, AckRange, PacketNumberSpace, QuicConnectionState, QuicTransportMachine, RttEstimator,
    SentPacketMeta, TransportError,
};
