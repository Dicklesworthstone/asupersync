//! One import to productivity: `use asupersync::prelude::*;`.
//!
//! This is the curated working set for writing an asupersync program — the
//! types and functions you reach for in the first ten lines of real code,
//! mirroring the `use tokio::prelude::*` / `use std::prelude` muscle memory.
//! It is deliberately small; every entry below earns its place, and every
//! notable *exclusion* is justified so future-self knows the reasoning rather
//! than re-litigating it.
//!
//! # What you get and when you reach for it
//!
//! Capability + structured concurrency:
//! - [`Cx`] — the capability context threaded through every async operation.
//! - [`Scope`] — create child regions and spawn structured tasks.
//!
//! Results, budgets, time, cancellation:
//! - [`Outcome`] — the four-valued result (`Ok` / `Err` / `Cancelled` / `Panicked`).
//! - [`Error`] — the runtime error type for fallible operations.
//! - [`Budget`] — bounded cleanup time: sufficient conditions, not hopes.
//! - [`Time`] — the deterministic clock type used across the runtime.
//! - [`CancelKind`] / [`CancelReason`] — why work was asked to stop.
//!
//! Runtime entry points + task handles:
//! - [`Runtime`] / [`RuntimeBuilder`] / [`RuntimeHandle`] — build and drive a runtime.
//! - [`TaskHandle`] — await or cancel a spawned task.
//! - [`JoinSet`] — dynamic fan-out collection with explicit drain/cancel.
//!
//! Channels (re-exported as *modules*, so you call `mpsc::channel(..)` — never a
//! glob, to keep `channel`/`Sender`/`Receiver` names unambiguous):
//! - [`mpsc`] / [`oneshot`] / [`broadcast`] / [`watch`].
//!
//! Cancel-aware synchronization primitives:
//! - [`Mutex`] / [`RwLock`] / [`Semaphore`] / [`Notify`] / [`Barrier`] / [`OnceCell`].
//!
//! Time helpers and stream combinators:
//! - [`sleep`] / [`timeout`] / [`interval`].
//! - [`StreamExt`] — the async-iterator combinator surface.
//!
//! Structured-concurrency macros (present on the default `proc-macros` feature):
//! - [`scope!`] / [`spawn!`] / [`join!`] / [`race!`].
//!
//! Deterministic lab essentials (only under `cfg(test)` or the `test-internals`
//! feature — these are testing tools, not production surface):
//! - [`LabRuntime`] / [`LabConfig`].
//!
//! # Deliberate exclusions (and why)
//!
//! - **`Result`** — would shadow `std::prelude::Result` ambiguously. Import the
//!   crate alias explicitly as `asupersync::Result` when you want it.
//! - **`TaskGroup`** — not landed yet; it joins the prelude when its owning
//!   API-v2 slice ships.
//! - **`#[asupersync::main]` / `#[asupersync::test]` attribute macros** — arrive
//!   with `asupersync-dx-core-api-v2-u1z5hn.3`; until then start from
//!   [`RuntimeBuilder`].
//! - **`ContendedMutex`** — a lock-metrics instrument, not an everyday lock; use
//!   [`Mutex`].
//! - **Internal / domain surfaces** (WASM ABI, epoch internals, remote sagas,
//!   RaptorQ, distributed primitives) — import those from their own modules; the
//!   prelude stays a single screenful by design.
//!
//! # Examples
//!
//! Set up the everyday working set with nothing but the prelude:
//!
//! ```
//! use asupersync::prelude::*;
//!
//! let _shared = Mutex::new(0_u32);
//! let _readers = RwLock::new(0_u32);
//! let _gate = Semaphore::new(4);
//! let _slot: OnceCell<u32> = OnceCell::new();
//! let (_tx, _rx) = mpsc::channel::<u32>(16);
//! let (_btx, _brx) = broadcast::channel::<u32>(16);
//! let (_otx, _orx) = oneshot::channel::<u32>();
//! let (_wtx, _wrx) = watch::channel(0_u32);
//! ```
//!
//! Build a runtime and reason about four-valued outcomes:
//!
//! ```
//! use asupersync::prelude::*;
//!
//! // One entry point for building a runtime.
//! let _builder = RuntimeBuilder::new();
//!
//! // Outcome is four-valued: Ok / Err / Cancelled / Panicked.
//! let outcome: Outcome<u32, Error> = Outcome::Ok(7);
//! assert!(matches!(outcome, Outcome::Ok(7)));
//! ```
//!
//! Budgets, the clock, and cancellation kinds are all in scope:
//!
//! ```
//! use asupersync::prelude::*;
//!
//! fn cleanup_within(_budget: Budget) {}
//! let _budget_slot: Option<Budget> = None;
//! let _clock_slot: Option<Time> = None;
//! let _cancel_kind: Option<CancelKind> = None;
//! let _cancel_reason: Option<CancelReason> = None;
//! ```

// ── Capability context + structured concurrency ───────────────────────────
pub use crate::{Cx, Scope};

// ── Outcomes, errors, budgets, time, cancellation ─────────────────────────
pub use crate::{Budget, CancelKind, CancelReason, Error, Outcome, Time};

// ── Runtime entry points + task handles ───────────────────────────────────
pub use crate::combinator::{JoinSet, JoinSummary};
pub use crate::runtime::{Runtime, RuntimeBuilder, RuntimeHandle, TaskHandle};

// ── Channel constructors (module re-exports, never a glob) ─────────────────
pub use crate::channel::{broadcast, mpsc, oneshot, watch};

// ── Cancel-aware synchronization primitives ───────────────────────────────
pub use crate::sync::{Barrier, Mutex, Notify, OnceCell, RwLock, Semaphore};

// ── Time helpers + stream combinators ─────────────────────────────────────
pub use crate::stream::StreamExt;
pub use crate::time::{interval, sleep, timeout};

// ── Structured-concurrency DSL macros (default `proc-macros` feature) ──────
#[cfg(feature = "proc-macros")]
pub use crate::{join, race, scope, spawn};

// ── Deterministic lab essentials (tests / `test-internals` only) ──────────
#[cfg(any(test, feature = "test-internals"))]
pub use crate::{LabConfig, LabRuntime};
