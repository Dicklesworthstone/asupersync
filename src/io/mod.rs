//! Async I/O traits, adapters, and capability infrastructure.
//!
//! This module provides minimal `AsyncRead` and `AsyncWrite` traits, a safe
//! `ReadBuf` type, and common adapters and extension futures. The design
//! mirrors `std::io` and `futures::io` but is intentionally small and cancel-aware.
//!
//! # I/O Capability Model
//!
//! Asupersync uses explicit capability-based I/O access. The [`IoCap`] trait
//! defines the I/O capability boundary - tasks can only perform I/O when they
//! have access to an implementation:
//!
//! - Production: Real I/O via reactor (epoll/kqueue/IOCP)
//! - Lab: Virtual I/O for deterministic testing (see [`LabIoCap`])
//!
//! # Cancel Safety
//!
//! ## Read operations
//! - `poll_read` is cancel-safe (partial data is discarded by the caller).
//! - `read_exact` is **not** cancel-safe (partial state is retained).
//! - `read_to_end` is cancel-safe (collected bytes remain in the buffer).
//! - `read_to_string` is **not** fully cancel-safe (bytes are preserved, but a partial UTF-8 sequence at the end may be lost if cancelled).
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

mod buf_reader;
mod buf_writer;
pub mod cap;
mod copy;
pub mod ext;
mod lines;
mod read;
mod read_buf;
mod seek;
mod split;
mod write;
mod write_permit;

pub use copy::{
    AsyncBufRead, Copy, CopyBidirectional, CopyBuf, CopyWithProgress, copy, copy_bidirectional,
    copy_buf, copy_with_progress,
};
pub use ext::{
    AsyncReadExt, AsyncReadVectoredExt, ReadExact, ReadToEnd, ReadToString, ReadU8, ReadVectored,
};
pub use ext::{AsyncWriteExt, Buf, Flush, Shutdown, WriteAll, WriteAllBuf, WriteU8, WriteVectored};
pub use read::{AsyncRead, AsyncReadVectored, Chain, Take};
pub use read_buf::ReadBuf;
pub use seek::AsyncSeek;
pub use split::{ReadHalf, SplitStream, WriteHalf, split};
pub use write::{AsyncWrite, AsyncWriteVectored};
pub use write_permit::WritePermit;

pub use buf_reader::BufReader;
pub use buf_writer::BufWriter;
pub use cap::{IoCap, IoNotAvailable, LabIoCap};
pub use lines::Lines;
pub use std::io::SeekFrom;
