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
//!
//! # Runtime Builder
//!
//! Asupersync configures the runtime with a fluent, move-based builder API.
//! Each builder method consumes `self` and returns an updated builder, enabling
//! ergonomic chaining without borrowing hazards.
//!
//! ## Quick Start
//!
//! ```ignore
//! use asupersync::runtime::RuntimeBuilder;
//!
//! let runtime = RuntimeBuilder::new().build()?;
//! runtime.block_on(async { /* your async work */ });
//! ```
//!
//! ## Single-Threaded (Deterministic)
//!
//! ```ignore
//! use asupersync::runtime::RuntimeBuilder;
//!
//! let runtime = RuntimeBuilder::current_thread().build()?;
//! runtime.block_on(async { /* deterministic tests */ });
//! ```
//!
//! ## High-Throughput Server
//!
//! ```ignore
//! use asupersync::runtime::RuntimeBuilder;
//!
//! let runtime = RuntimeBuilder::high_throughput()
//!     .global_queue_limit(65_536)
//!     .blocking_threads(4, 64)
//!     .build()?;
//! ```
//!
//! ## Low-Latency Workloads
//!
//! ```ignore
//! use asupersync::runtime::RuntimeBuilder;
//! use std::time::Duration;
//!
//! let runtime = RuntimeBuilder::low_latency()
//!     .poll_budget(16)
//!     .deadline_monitoring(|m| {
//!         m.enabled(true)
//!             .check_interval(Duration::from_millis(5))
//!             .warning_threshold_fraction(0.2)
//!     })
//!     .build()?;
//! ```
//!
//! ## Config File + Environment Overrides
//!
//! ```ignore
//! use asupersync::runtime::RuntimeBuilder;
//!
//! // Requires the `config-file` feature.
//! let runtime = RuntimeBuilder::from_toml("config/runtime.toml")?
//!     .with_env_overrides()?
//!     .build()?;
//! ```
//!
//! # Error Handling
//!
//! ```ignore
//! use asupersync::runtime::RuntimeBuilder;
//!
//! // Requires the `config-file` feature.
//! let result = RuntimeBuilder::from_toml_str("not valid {{{");
//! assert!(result.is_err());
//! ```
//!
//! # Migration Guide (RuntimeConfig → RuntimeBuilder)
//!
//! ```ignore
//! use asupersync::runtime::{Runtime, RuntimeBuilder, RuntimeConfig};
//!
//! // Old style: build a config directly.
//! let mut config = RuntimeConfig::default();
//! config.worker_threads = 4;
//! let runtime = Runtime::with_config(config)?;
//!
//! // New style: builder chain.
//! let runtime = RuntimeBuilder::new()
//!     .worker_threads(4)
//!     .build()?;
//! ```
//!
//! # Configuration Reference (Defaults + Notes)
//!
//! - `worker_threads`: default = available parallelism (min 1). Higher throughput, more CPU use.
//! - `thread_stack_size`: default = 2 MiB. Larger stack increases memory per worker.
//! - `thread_name_prefix`: default = `asupersync-worker`. Improves diagnostics.
//! - `global_queue_limit`: default = 0 (unbounded). Lower values add backpressure.
//! - `steal_batch_size`: default = 16. Larger favors throughput; smaller favors latency.
//! - `blocking_threads(min, max)`: default = 0..0. Max is clamped to be >= min.
//! - `enable_parking`: default = true. Disabling reduces wake latency at CPU cost.
//! - `poll_budget`: default = 128. Lower for fairness, higher for throughput.
//! - `root_region_limits`: default = None. Admission limits applied to root region.
//! - `on_thread_start/stop`: lifecycle hooks; keep work minimal to avoid jitter.
//! - `metrics(...)`: default = NoOp. Custom providers add instrumentation overhead.
//! - `deadline_monitoring(...)`: disabled by default; enables warning callbacks.

pub mod blocking_pool;
pub mod builder;
pub mod config;
pub mod deadline_monitor;
pub mod env_config;
pub mod io_driver;
pub mod io_op;
pub mod reactor;
pub mod region_heap;
pub mod scheduler;
/// Async wrapper for blocking pool operations.
pub mod spawn_blocking;
pub mod state;
pub mod stored_task;
pub mod task_handle;
pub mod timer;
pub mod waker;
/// Yield points for cooperative multitasking.
pub mod yield_now;

/// Thread-local storage for non-Send local tasks.
///
/// Local tasks are pinned to the worker thread that created them. They are
/// stored in TLS so only that worker can poll them.
pub mod local {
    use crate::runtime::stored_task::LocalStoredTask;
    use crate::types::TaskId;
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static LOCAL_TASKS: RefCell<HashMap<TaskId, LocalStoredTask>> =
            RefCell::new(HashMap::new());
    }

    /// Store a local task in thread-local storage.
    pub fn store_local_task(task_id: TaskId, task: LocalStoredTask) {
        LOCAL_TASKS.with(|tasks| {
            tasks.borrow_mut().insert(task_id, task);
        });
    }

    /// Remove a local task from thread-local storage.
    #[must_use]
    pub fn remove_local_task(task_id: TaskId) -> Option<LocalStoredTask> {
        LOCAL_TASKS.with(|tasks| tasks.borrow_mut().remove(&task_id))
    }
}

pub use crate::record::RegionLimits;
pub use blocking_pool::{
    BlockingPool, BlockingPoolHandle, BlockingPoolOptions, BlockingTaskHandle,
};
pub use builder::{DeadlineMonitoringBuilder, JoinHandle, Runtime, RuntimeBuilder, RuntimeHandle};
pub use config::{BlockingPoolConfig, RuntimeConfig};
pub use deadline_monitor::{
    AdaptiveDeadlineConfig, DeadlineMonitor, DeadlineWarning, MonitorConfig, WarningReason,
};
pub use io_driver::{IoDriver, IoDriverHandle, IoRegistration};
pub use io_op::IoOp;
pub use reactor::{Event, Events, Interest, LabReactor, Reactor, Registration, Source, Token};
pub use region_heap::{global_alloc_count, HeapIndex, HeapRef, HeapStats, RegionHeap};
pub use scheduler::Scheduler;
pub use spawn_blocking::{spawn_blocking, spawn_blocking_io};
pub use state::{RuntimeSnapshot, RuntimeState, SpawnError};
pub use stored_task::StoredTask;
pub use task_handle::{JoinError, TaskHandle};
pub use yield_now::yield_now;
