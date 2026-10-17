//! Streaming compression over the runtime's async I/O traits.
//!
//! [`zstd`] wraps any [`AsyncWrite`](crate::io::AsyncWrite) or
//! [`AsyncRead`](crate::io::AsyncRead) with the in-house Zstandard codec,
//! `asupersync-zstd`, which has no `unsafe` code. This module exists only with
//! the `zstd` cargo feature.

pub mod zstd;
