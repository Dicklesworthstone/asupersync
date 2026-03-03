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
mod seek_ext;
mod write_ext;

pub use read_ext::{
    AsyncReadExt, AsyncReadVectoredExt, Read, ReadExact, ReadF32, ReadF32Le, ReadF64, ReadF64Le,
    ReadI8, ReadI16, ReadI16Le, ReadI32, ReadI32Le, ReadI64, ReadI64Le, ReadI128, ReadI128Le,
    ReadToEnd, ReadToString, ReadU8, ReadU16, ReadU16Le, ReadU32, ReadU32Le, ReadU64, ReadU64Le,
    ReadU128, ReadU128Le, ReadVectored,
};
pub use seek_ext::{AsyncSeekExt, Seek};
pub use write_ext::{
    AsyncWriteExt, Buf, Flush, Shutdown, Write, WriteAll, WriteAllBuf, WriteF32, WriteF32Le,
    WriteF64, WriteF64Le, WriteI8, WriteI16, WriteI16Le, WriteI32, WriteI32Le, WriteI64,
    WriteI64Le, WriteI128, WriteI128Le, WriteU8, WriteU16, WriteU16Le, WriteU32, WriteU32Le,
    WriteU64, WriteU64Le, WriteU128, WriteU128Le, WriteVectored,
};
