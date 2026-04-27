//! HTTP/3 client support over QUIC.
//!
//! This module wraps the `h3` and `h3-quinn` crates with Asupersync `Cx`
//! cancellation semantics. It is gated behind the `http3-compat` feature.
//!
//! # Driver Model
//!
//! `H3Client::new` returns an `(H3Client, H3Driver)` pair. The driver must be
//! polled concurrently to make progress on control streams and connection
//! state. Spawn it within a region (or poll manually) for correct operation.
//!
//! # Cancellation
//!
//! Cancellation requests reset active request streams with
//! `H3_REQUEST_CANCELLED`, ensuring partial responses are discarded and the
//! connection remains usable.

mod body;
mod client;
mod error;

pub use body::H3Body;
pub use client::{H3Client, H3Driver};
pub use error::H3Error;
