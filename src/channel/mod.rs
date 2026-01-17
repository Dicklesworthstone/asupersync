//! Two-phase channel primitives for cancel-safe communication.
//!
//! This module provides channels that use the two-phase reserve/commit pattern
//! to prevent message loss during cancellation. Unlike traditional channels,
//! these channels split the send operation into two steps:
//!
//! 1. **Reserve**: Allocate a slot and create an obligation
//! 2. **Commit**: Send the actual message (cannot fail)
//!
//! # Cancel Safety
//!
//! The two-phase pattern ensures that cancellation at any point is clean:
//!
//! - If cancelled during reserve: nothing is committed
//! - If cancelled after reserve: the permit's `Drop` impl aborts cleanly
//! - The commit operation (`send`) is infallible once the permit is obtained
//!
//! # Example
//!
//! ```ignore
//! use asupersync::channel::mpsc;
//!
//! // Create a bounded channel
//! let (tx, rx) = mpsc::channel::<i32>(10);
//!
//! // Two-phase send pattern
//! let permit = tx.reserve(&cx).await?;  // Phase 1: reserve slot
//! permit.send(42);                       // Phase 2: commit (cannot fail)
//!
//! // Receive
//! let value = rx.recv(&cx).await?;
//! ```
//!
//! # Module Contents
//!
//! - [`mpsc`]: Multi-producer, single-consumer bounded channel
//! - [`oneshot`]: Single-use channel for exactly one value
//! - [`broadcast`]: Multi-producer, multi-consumer broadcast channel
//! - [`watch`]: Single-producer, multi-consumer state observation

pub mod broadcast;
pub mod mpsc;
pub mod oneshot;
pub mod watch;

// Re-export commonly used types from mpsc (the default channel)
pub use mpsc::{channel, Receiver, SendPermit, Sender};