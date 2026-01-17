//! Extension traits and future adapters for async I/O.
//!
//! These helpers are intentionally small and mirror common `std::io` patterns.
//!
//! # Cancel safety
//!
//! - [`ReadExact`] is **not** cancel-safe: it mutates the provided output buffer.
//! - [`ReadToEnd`] is cancel-safe: bytes already pushed into the `Vec<u8>` remain.
//! - [`WriteAll`] is **not** cancel-safe: partial writes may occur.
//! - [`WritePermit`](super::WritePermit) is cancel-safe: uncommitted data is discarded on drop.

mod read_ext;
mod write_ext;

pub use read_ext::{AsyncReadExt, ReadExact, ReadToEnd, ReadToString, ReadU8};
pub use write_ext::{
    AsyncWriteExt, Buf, Flush, Shutdown, WriteAll, WriteAllBuf, WriteU8, WriteVectored,
};
