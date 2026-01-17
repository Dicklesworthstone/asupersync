//! Async I/O traits and adapters.
//!
//! This module provides minimal `AsyncRead` and `AsyncWrite` traits, a safe
//! `ReadBuf` type, and common adapters and extension futures. The design
//! mirrors `std::io` and `futures::io` but is intentionally small and cancel-aware.
//!
//! # Cancel Safety
//!
//! ## Read operations
//! - `poll_read` is cancel-safe (partial data is discarded by the caller).
//! - `read_exact` is **not** cancel-safe (partial state is retained).
//! - `read_to_end` is cancel-safe (collected bytes remain in the buffer).
//!
//! ## Write operations
//! - `poll_write` is cancel-safe (partial writes are OK).
//! - `write_all` is **not** cancel-safe (partial writes may occur).
//! - `WritePermit` is cancel-safe (uncommitted data is discarded on drop).
//! - `flush` and `shutdown` are cancel-safe (can retry).
//!
//! ## Copy operations
//! - `copy` is cancel-safe (bytes already written remain committed).
//! - `copy_buf` is cancel-safe (bytes already written remain committed).
//! - `copy_with_progress` is cancel-safe (progress callback is accurate).
//! - `copy_bidirectional` is cancel-safe (both directions can be partially complete).

mod copy;
pub mod ext;
mod read;
mod read_buf;
mod split;
mod write;
mod write_permit;

pub use copy::{
    copy, copy_bidirectional, copy_buf, copy_with_progress, AsyncBufRead, Copy, CopyBidirectional,
    CopyBuf, CopyWithProgress,
};
pub use ext::{AsyncReadExt, ReadExact, ReadToEnd, ReadToString, ReadU8};
pub use ext::{AsyncWriteExt, Buf, Flush, Shutdown, WriteAll, WriteAllBuf, WriteU8, WriteVectored};
pub use read::{AsyncRead, Chain, Take};
pub use read_buf::ReadBuf;
pub use split::{split, ReadHalf, SplitStream, WriteHalf};
pub use write::AsyncWrite;
pub use write_permit::WritePermit;
