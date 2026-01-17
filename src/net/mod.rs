//! Async networking primitives.
//!
//! Phase 0 exposes synchronous std::net wrappers through async-looking APIs.
//! This keeps the public surface stable while the runtime lacks a reactor.

#![allow(clippy::unused_async)]

pub mod sys;
pub mod tcp;
mod udp;

pub use tcp::listener::{Incoming, TcpListener};
pub use tcp::socket::TcpSocket;
pub use tcp::split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf};
pub use tcp::stream::TcpStream;
pub use udp::{RecvStream, SendSink, UdpSocket};