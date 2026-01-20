//! Unix domain socket networking primitives.
//!
//! This module provides async wrappers for Unix domain sockets, supporting both
//! filesystem path sockets and Linux abstract namespace sockets.
//!
//! # Socket Types
//!
//! - [`UnixListener`]: Accepts incoming Unix socket connections
//! - [`UnixStream`]: Bidirectional byte stream for client connections
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::unix::{UnixListener, UnixStream};
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
//! ```
//!
//! # Platform Support
//!
//! Unix domain sockets are available on all Unix-like platforms. Abstract
//! namespace sockets (via [`UnixListener::bind_abstract`]) are Linux-only.

pub mod listener;
pub mod split;
pub mod stream;

pub use listener::{Incoming, UnixListener};
pub use split::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, ReuniteError, WriteHalf};
pub use stream::UnixStream;
