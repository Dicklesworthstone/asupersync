//! Runtime state and scheduling.
//!
//! This module contains the core runtime machinery:
//!
//! - [`state`]: Global runtime state (Σ = {regions, tasks, obligations, now})
//! - [`scheduler`]: Three-lane priority scheduler
//! - [`waker`]: Waker implementation with deduplication
//! - [`timer`]: Timer heap for deadline management

pub mod scheduler;
pub mod state;
pub mod timer;
pub mod waker;

pub use scheduler::Scheduler;
pub use state::RuntimeState;
