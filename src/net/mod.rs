//! Async networking primitives.
//!
//! Phase 0 exposes synchronous std::net wrappers through async-looking APIs.
//! This keeps the public surface stable while the runtime lacks a reactor.

#![allow(clippy::unused_async)]

/// DNS resolution with caching and Happy Eyeballs support.
pub mod dns;
mod resolve;
pub mod sys;
/// TCP networking primitives.
pub mod tcp;
mod udp;
/// Unix domain socket networking primitives (includes `UnixListener`, `UnixStream`).
#[cfg(unix)]
pub mod unix;
/// WebSocket protocol implementation (RFC 6455).
pub mod websocket;

pub use resolve::{lookup_all, lookup_one};
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
pub use websocket::{apply_mask, CloseCode, Frame, FrameCodec, Opcode, Role as WsRole, WsError};
