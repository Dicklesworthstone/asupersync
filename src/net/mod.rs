//! Async networking primitives.
//!
//! Phase 0 exposes synchronous std::net wrappers through async-looking APIs.
//! This keeps the public surface stable while the runtime lacks a reactor.

#![allow(clippy::unused_async)]

/// DNS resolution with caching and Happy Eyeballs support.
pub mod dns;
/// Happy Eyeballs v2 (RFC 8305) concurrent dual-stack connection racing.
pub mod happy_eyeballs;
/// Compatibility QUIC API backed by external quinn stack (not part of native T4 path).
#[cfg(all(feature = "quic-compat", not(feature = "quic")))]
pub mod quic;
/// Native QUIC protocol core codecs and types (Tokio-free, runtime-agnostic).
pub mod quic_core;
/// Native QUIC transport state machines (TLS, recovery, streams).
pub mod quic_native;
/// Native QUIC API surface (T4.1).
///
/// This module intentionally aliases the Tokio-free native QUIC stack so users
/// can enable `feature = "quic"` and import `asupersync::net::quic::*` through
/// a stable feature boundary while T4.2/T4.3 continue transport hardening.
#[cfg(feature = "quic")]
pub mod quic {
    /// Native QUIC connection type.
    pub type QuicConnection = super::quic_native::NativeQuicConnection;
    /// Native QUIC configuration type.
    pub type QuicConfig = super::quic_native::NativeQuicConnectionConfig;
    /// Native QUIC error type.
    pub type QuicError = super::quic_native::NativeQuicConnectionError;
    /// Native QUIC stream alias used for send-side operations.
    pub type SendStream = super::quic_native::QuicStream;
    /// Native QUIC stream alias used for recv-side operations.
    pub type RecvStream = super::quic_native::QuicStream;
}
/// Compatibility QUIC API when both native and compat feature lanes are enabled.
#[cfg(all(feature = "quic-compat", feature = "quic"))]
#[path = "quic/mod.rs"]
pub mod quic_compat;
mod resolve;
pub mod sys;
/// TCP networking primitives.
///
/// Browser/wasm builds keep the type surface available for API compatibility,
/// but native socket entry points fail fast with `io::ErrorKind::Unsupported`.
pub mod tcp;
mod udp;
/// Unix domain socket networking primitives (includes `UnixListener`, `UnixStream`).
#[cfg(unix)]
pub mod unix;
/// WebSocket protocol implementation (RFC 6455).
pub mod websocket;
/// MessagePort-based coordination utilities for browser worker runtimes.
pub mod worker_channel;

pub use happy_eyeballs::{HappyEyeballsConfig, connect as happy_eyeballs_connect};
#[cfg(all(feature = "quic-compat", not(feature = "quic")))]
pub use quic::{
    ClientAuth as QuicClientAuth, QuicConfig, QuicConnection, QuicEndpoint, QuicError,
    QuicIncoming, RecvStream as QuicRecvStream, SendStream as QuicSendStream,
};
#[cfg(feature = "quic")]
pub use quic::{
    QuicConfig, QuicConnection, QuicError, QuicIncoming, RecvStream as QuicRecvStream,
    SendStream as QuicSendStream,
};
#[cfg(all(feature = "quic-compat", feature = "quic"))]
pub use quic_compat::{
    ClientAuth as QuicCompatClientAuth, QuicConfig as QuicCompatConfig,
    QuicConnection as QuicCompatConnection, QuicEndpoint as QuicCompatEndpoint,
    QuicError as QuicCompatError, QuicIncoming as QuicCompatIncoming,
    RecvStream as QuicCompatRecvStream, SendStream as QuicCompatSendStream,
};
pub use quic_native::{
    AckEvent, AckRange, CryptoLevel, FlowControlError, FlowCredit, KeyUpdateEvent,
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError, PacketNumberSpace,
    QuicConnectionState, QuicStream, QuicStreamError, QuicTlsError, QuicTlsMachine,
    QuicTransportMachine, RttEstimator, SentPacketMeta, StreamDirection, StreamId, StreamRole,
    StreamTable, StreamTableError, TransportError,
};
pub use resolve::{lookup_all, lookup_one};
#[cfg(target_os = "windows")]
pub use sys::windows::{NamedPipeClient, NamedPipeClientOptions};
pub use tcp::listener::{Incoming, TcpListener};
pub use tcp::socket::TcpSocket;
pub use tcp::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, ReuniteError, WriteHalf};
pub use tcp::stream::TcpStream;
pub use tcp::stream::TcpStreamBuilder;
pub use udp::{RecvStream, SendSink, UdpSocket};
#[cfg(unix)]
pub use unix::{
    Incoming as UnixIncoming, OwnedReadHalf as UnixOwnedReadHalf,
    OwnedWriteHalf as UnixOwnedWriteHalf, ReadHalf as UnixReadHalf,
    ReuniteError as UnixReuniteError, UnixListener, UnixStream, WriteHalf as UnixWriteHalf,
};
pub use websocket::{
    ClientHandshake, CloseCode, Frame, FrameCodec, HandshakeError, Message, Opcode, Role as WsRole,
    ServerHandshake, ServerWebSocket, WebSocket, WebSocketAcceptor, WebSocketConfig, WebSocketRead,
    WebSocketWrite, WsAcceptError, WsConnectError, WsError, WsReuniteError, WsUrl, apply_mask,
};
