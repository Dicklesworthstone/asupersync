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
//! Use bounded [`mpsc::channel`] by default. [`mpsc::unbounded_channel`] (also
//! available as [`mpsc::unbounded`]) is available when the caller has a separate
//! memory-pressure policy and needs a synchronous send path that never waits
//! for capacity.
//!
//! # Choosing Send Discipline
//!
//! | Channel | Reserve/commit path | One-call send | Nonblocking receive |
//! |---------|---------------------|---------------|---------------------|
//! | [`mpsc`] bounded | `Sender::reserve(&cx).await` then `SendPermit::send(value)` | `Sender::send(&cx, value).await` | `Receiver::try_recv()` / `Receiver::recv_many(&cx, &mut buf, limit).await` |
//! | [`mpsc`] unbounded | `UnboundedSender::reserve(&cx).await` then `SendPermit::send(value)` | `UnboundedSender::send(value)` | `UnboundedReceiver::try_recv()` / `UnboundedReceiver::recv_many(&cx, &mut buf, limit).await` |
//! | [`broadcast`] | `Sender::reserve(&cx)` then `SendPermit::send(value)` | `Sender::send(&cx, value)` | `Receiver::try_recv()` |
//! | [`oneshot`] | `Sender::reserve(&cx)` then `SendPermit::send(value)` | `Sender::send(&cx, value)` | `Receiver::try_recv()` |
//! | [`watch`] | Latest-value update; no reservation needed | `Sender::send(value)` | `Receiver::borrow()` after `Receiver::changed(&cx).await` |
//! | [`session`] tracked wrappers | Tracked reserve/commit with proofs | Tracked `send(...)` helpers | Underlying tracked receiver |
//!
//! # Convenience Surface Verdicts
//!
//! | Surface | Verdict | Notes |
//! |---------|---------|-------|
//! | Bounded [`mpsc`] `send(&cx, value)` | exists-covered | Async sugar delegates to `reserve(&cx).await` then permit commit. |
//! | Unbounded [`mpsc`] `send(value)` | exists-covered | Capacity cannot wait; caller owns memory-pressure policy. |
//! | [`broadcast`] `send(&cx, value)` | exists-covered | Sync sugar checks `Cx` before granting a permit and returns the receiver count at commit. |
//! | [`oneshot`] `send(&cx, value)` | exists-covered | Consumes the sender, reserves with `Cx`, then commits or returns the value. |
//! | [`watch`] `send(value)` | not-applicable two-phase | Latest-value update is synchronous and has no capacity wait or held send obligation. |
//! | [`session`] tracked send helpers | tracked-wrapper | Session proofs wrap the underlying channel obligations. |
//!
//! Use reserve/commit when a task may hold the send right across awaits and
//! must make the obligation explicit. Use one-call send when the value is ready
//! now and the operation should either commit or report closure. Use `try_send`
//! and `try_recv` for load-shed or polling loops that must not wait. Use
//! `recv_many` when the receiver is a drain loop and batching lowers lock/wake
//! overhead; it still observes `Cx` cancellation before consuming values.
//!
//! # Example
//!
//! <!-- core-api-doctest: channel-families -->
//! ```
//! use asupersync::{Cx, main};
//! use asupersync::channel::{broadcast, mpsc, oneshot, watch};
//!
//! #[main]
//! async fn main(cx: &Cx) {
//!     let (mpsc_tx, mut mpsc_rx) = mpsc::channel(1);
//!     mpsc_tx.send(cx, 10_i32).await.expect("bounded send");
//!     assert_eq!(mpsc_rx.recv(cx).await.expect("bounded receive"), 10);
//!     drop(mpsc_rx);
//!     assert!(mpsc_tx.send(cx, 11).await.is_err());
//!
//!     let (oneshot_tx, mut oneshot_rx) = oneshot::channel();
//!     oneshot_tx.send(cx, 20_i32).expect("oneshot send");
//!     assert_eq!(oneshot_rx.recv(cx).await.expect("oneshot receive"), 20);
//!
//!     let (broadcast_tx, mut broadcast_rx) = broadcast::channel(2);
//!     assert_eq!(broadcast_tx.send(cx, 30_i32).expect("broadcast send"), 1);
//!     assert_eq!(broadcast_rx.recv(cx).await.expect("broadcast receive"), 30);
//!
//!     let (watch_tx, mut watch_rx) = watch::channel(40_i32);
//!     watch_tx.send(41).expect("watch send");
//!     watch_rx.changed(cx).await.expect("watch change");
//!     assert_eq!(*watch_rx.borrow(), 41);
//! }
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
pub mod erasure;
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
#[path = "broadcast_metamorphic.rs"]
mod broadcast_metamorphic;

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
#[path = "oneshot_metamorphic.rs"]
mod oneshot_metamorphic;

#[cfg(test)]
#[path = "mpsc_metamorphic.rs"]
mod mpsc_metamorphic;

#[cfg(test)]
#[path = "watch_borrow_vs_changed_metamorphic.rs"]
mod watch_borrow_vs_changed_metamorphic;

#[cfg(test)]
#[path = "mpsc_message_preservation_metamorphic.rs"]
mod mpsc_message_preservation_metamorphic;
#[cfg(test)]
#[path = "mpsc_reservation_commutation_metamorphic.rs"]
mod mpsc_reservation_commutation_metamorphic;

#[cfg(test)]
#[path = "broadcast_no_message_loss_metamorphic.rs"]
mod broadcast_no_message_loss_metamorphic;

#[cfg(test)]
#[path = "oneshot_exactly_once_metamorphic.rs"]
mod oneshot_exactly_once_metamorphic;

// Re-export commonly used types from mpsc (the default channel)
pub use mpsc::{
    Receiver, SendPermit, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded,
    unbounded_channel,
};
pub use session::{TrackedOneshotSender, TrackedSender, tracked_channel, tracked_oneshot};
