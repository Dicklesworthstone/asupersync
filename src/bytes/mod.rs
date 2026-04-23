//! Bytes and Buffer Management
//!
//! Zero-copy buffer types providing the foundation for efficient network I/O,
//! codec implementations, and protocol parsing.
//!
//! # Overview
//!
//! This module provides:
//! - [`Bytes`]: Immutable, reference-counted byte slice with cheap cloning
//! - [`BytesMut`]: Mutable buffer with efficient growth and splitting
//! - [`Buf`]: Trait for reading bytes from a buffer
//! - [`BufMut`]: Trait for writing bytes to a buffer
//!
//! # Design Notes
//!
//! Unlike the `bytes` crate, this implementation uses safe Rust throughout,
//! avoiding raw pointers in favor of `Arc<Vec<u8>>` and `Vec<u8>`. This
//! trades some performance for safety, alignment with asupersync's
//! `#![forbid(unsafe_code)]` policy, and simplicity.
//!
//! # Cancel-Safety
//!
//! Buffer operations are synchronous and thus inherently cancel-safe.
//! No async operations are involved in buffer manipulation.

pub mod buf;
mod bytes;
mod bytes_mut;

#[cfg(feature = "test-internals")]
pub mod profiling;

#[cfg(test)]
mod allocation_hotpaths_test;

pub use buf::{Buf, BufMut, Chain, Limit, Take};
pub use bytes::{Bytes, BytesCursor};
pub use bytes_mut::BytesMut;
