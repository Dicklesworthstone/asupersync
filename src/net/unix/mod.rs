//! Unix domain socket networking primitives.
//!
//! This module provides async wrappers for Unix domain sockets, supporting both
//! filesystem path sockets and Linux abstract namespace sockets.
//!
//! # Socket Types
//!
//! - [`UnixListener`]: Accepts incoming Unix socket connections
//! - [`UnixStream`]: Bidirectional byte stream for client connections
//! - [`UnixDatagram`]: Connectionless datagram socket for local IPC
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::unix::{UnixListener, UnixStream, UnixDatagram};
//!
//! async fn server() -> std::io::Result<()> {
//!     let listener = UnixListener::bind("/tmp/my_socket.sock").await?;
//!
//!     loop {
//!         let (stream, _addr) = listener.accept().await?;
//!         // Handle connection...
//!     }
//! }
//!
//! async fn client() -> std::io::Result<()> {
//!     let stream = UnixStream::connect("/tmp/my_socket.sock").await?;
//!     // Use stream...
//!     Ok(())
//! }
//!
//! async fn datagram_example() -> std::io::Result<()> {
//!     let (a, b) = UnixDatagram::pair()?;
//!     a.send(b"hello").await?;
//!     let mut buf = [0u8; 5];
//!     let n = b.recv(&mut buf).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Platform Support
//!
//! Unix domain sockets are available on all Unix-like platforms. Abstract
//! namespace sockets (via [`UnixListener::bind_abstract`]) are Linux-only.

pub mod ancillary;
pub mod datagram;
pub mod listener;
pub mod split;
pub mod stream;

pub use ancillary::{
    ancillary_space_for_fds, AncillaryMessage, AncillaryMessages, ScmRights, SocketAncillary,
};
pub use datagram::UnixDatagram;
pub use listener::{Incoming, UnixListener};
pub use split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, ReuniteError, WriteHalf};
pub use stream::{UCred, UnixStream};
