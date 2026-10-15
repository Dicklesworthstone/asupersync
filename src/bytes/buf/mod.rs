//! Buffer traits for reading and writing bytes.
//!
//! This module provides the [`Buf`] and [`BufMut`] traits which define
//! abstract interfaces for reading from and writing to byte buffers.
//!
//! # Overview
//!
//! - [`Buf`]: Trait for reading bytes from a buffer (cursor-like interface)
//! - [`BufMut`]: Trait for writing bytes to a buffer
//!
//! These traits enable generic codec implementations, zero-copy buffer
//! chaining, and efficient protocol parsing.

mod buf_mut_trait;
mod buf_trait;
mod chain;
mod limit;
mod take;

pub use buf_mut_trait::BufMut;
pub use buf_trait::Buf;
pub use chain::Chain;
pub use limit::Limit;
pub use take::Take;
