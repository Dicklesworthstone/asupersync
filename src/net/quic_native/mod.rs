//! Native QUIC transport state machines (Tokio-free).
//!
//! This module layers protocol behavior on top of `net::quic_core` codecs:
//! - TLS/key-phase progression model
//! - transport/loss recovery model
//! - stream + flow-control model

pub mod connection;
pub mod forensic_log;
pub mod streams;
pub mod tls;
pub mod transport;

pub use connection::{NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError};
pub use streams::{
    FlowControlError, FlowCredit, QuicStream, QuicStreamError, StreamDirection, StreamId,
    StreamRole, StreamTable, StreamTableError,
};
pub use tls::{CryptoLevel, KeyUpdateEvent, QuicTlsError, QuicTlsMachine};
pub use transport::{
    AckEvent, AckRange, PacketNumberSpace, QuicConnectionState, QuicTransportMachine, RttEstimator,
    SentPacketMeta, TransportError,
};
