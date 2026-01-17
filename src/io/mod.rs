//! Async I/O traits and adapters.
//!
//! This module provides a minimal `AsyncRead` trait, a safe `ReadBuf` type,
//! and common adapters and extension futures. The design mirrors `std::io`
//! and `futures::io` but is intentionally small and cancel-aware.
//!
//! # Cancel Safety
//!
//! - `poll_read` is cancel-safe (partial data is discarded by the caller).
//! - `read_exact` is **not** cancel-safe (partial state is retained).
//! - `read_to_end` is cancel-safe (collected bytes remain in the buffer).

pub mod ext;
mod read;
mod read_buf;

pub use ext::{AsyncReadExt, ReadExact, ReadToEnd, ReadToString, ReadU8};
pub use read::{AsyncRead, Chain, Take};
pub use read_buf::ReadBuf;
