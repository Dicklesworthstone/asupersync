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
pub mod clock_skew;
pub mod crash;
pub mod fault;
pub mod flow_control_monitor;
pub mod mpsc;
pub mod oneshot;
pub mod partition;
pub mod session;
pub mod watch;

#[cfg(test)]
#[path = "deadlock_test.rs"]
mod deadlock_test;

#[cfg(test)]
#[path = "mpsc_lost_wakeup_test.rs"]
mod mpsc_lost_wakeup_test;

#[cfg(test)]
#[path = "atomicity_test.rs"]
mod atomicity_test;

#[cfg(test)]
#[path = "stress_test.rs"]
mod stress_test;

#[cfg(test)]
#[path = "verification_suite.rs"]
mod verification_suite;

#[cfg(test)]
#[path = "broadcast_metamorphic.rs"]
mod broadcast_metamorphic;

#[cfg(test)]
#[path = "oneshot_metamorphic.rs"]
mod oneshot_metamorphic;

// Re-export commonly used types from mpsc (the default channel)
pub use mpsc::{Receiver, SendPermit, Sender, channel};
pub use session::{TrackedOneshotSender, TrackedSender, tracked_channel, tracked_oneshot};
