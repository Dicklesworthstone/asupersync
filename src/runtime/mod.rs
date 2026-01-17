//! Runtime state and scheduling.
//!
//! This module contains the core runtime machinery:
//!
//! - [`state`]: Global runtime state (Σ = {regions, tasks, obligations, now})
//! - [`scheduler`]: Three-lane priority scheduler
//! - [`stored_task`]: Type-erased future storage
//! - [`task_handle`]: TaskHandle for awaiting spawned task results
//! - [`waker`]: Waker implementation with deduplication
//! - [`timer`]: Timer heap for deadline management

pub mod scheduler;
pub mod state;
pub mod stored_task;
pub mod task_handle;
pub mod timer;
pub mod waker;

pub use scheduler::Scheduler;
pub use state::RuntimeState;
pub use stored_task::StoredTask;
pub use task_handle::{JoinError, TaskHandle};
