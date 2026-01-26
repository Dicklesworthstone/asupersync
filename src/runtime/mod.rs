//! Runtime state and scheduling.
//!
//! This module contains the core runtime machinery:
//!
//! - [`config`]: Runtime configuration types
//! - [`builder`]: Runtime builder and handles
//! - [`state`]: Global runtime state (Σ = {regions, tasks, obligations, now})
//! - [`scheduler`]: Three-lane priority scheduler
//! - [`stored_task`]: Type-erased future storage
//! - [`task_handle`]: TaskHandle for awaiting spawned task results
//! - [`waker`]: Waker implementation with deduplication
//! - [`timer`]: Timer heap for deadline management
//! - [`deadline_monitor`]: Deadline monitoring for approaching timeouts
//! - [`reactor`]: I/O reactor abstraction
//! - [`io_driver`]: Reactor driver that dispatches readiness to wakers
//! - [`region_heap`]: Region-owned heap allocator with quiescent reclamation

pub mod builder;
pub mod config;
pub mod deadline_monitor;
pub mod io_driver;
pub mod reactor;
pub mod region_heap;
pub mod scheduler;
pub mod state;
pub mod stored_task;
pub mod task_handle;
pub mod timer;
pub mod waker;
/// Yield points for cooperative multitasking.
pub mod yield_now;

pub use builder::{DeadlineMonitoringBuilder, JoinHandle, Runtime, RuntimeBuilder, RuntimeHandle};
pub use config::{BlockingPoolConfig, RuntimeConfig};
pub use deadline_monitor::{DeadlineMonitor, DeadlineWarning, MonitorConfig, WarningReason};
pub use io_driver::{IoDriver, IoDriverHandle, IoRegistration};
pub use reactor::{Event, Events, Interest, LabReactor, Reactor, Registration, Source, Token};
pub use region_heap::{global_alloc_count, HeapIndex, HeapRef, HeapStats, RegionHeap};
pub use scheduler::Scheduler;
pub use state::{RuntimeSnapshot, RuntimeState, SpawnError};
pub use stored_task::StoredTask;
pub use task_handle::{JoinError, TaskHandle};
pub use yield_now::yield_now;
