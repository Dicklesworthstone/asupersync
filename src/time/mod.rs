//! Time primitives: sleep, timeout, and interval operations.
//!
//! This module provides core time-based operations for async programming:
//! - [`Sleep`]: A future that completes after a deadline
//! - [`TimeoutFuture`]: A wrapper that adds a timeout to any future
//! - [`Interval`]: A repeating timer that yields at a fixed period
//!
//! # Virtual vs Wall Time
//!
//! These primitives work with both production (wall clock) time and
//! virtual time in the lab runtime. The time source is determined by
//! the runtime context.
//!
//! # Cancel Safety
//!
//! All time primitives are cancel-safe:
//! - `Sleep`: Can be dropped and recreated without side effects
//! - `TimeoutFuture`: The inner future may have side effects on cancellation
//! - `Interval`: Next tick proceeds from where it was interrupted
//!
//! # Example
//!
//! ```ignore
//! use asupersync::time::{sleep, timeout, interval};
//! use std::time::Duration;
//!
//! // Sleep for 100 milliseconds
//! sleep(Duration::from_millis(100)).await;
//!
//! // Wrap an operation with a timeout
//! match timeout(Duration::from_secs(5), async { expensive_operation() }).await {
//!     Ok(result) => println!("Completed: {result}"),
//!     Err(_) => println!("Timed out!"),
//! }
//!
//! // Create an interval timer
//! let mut ticker = interval(now, Duration::from_millis(100));
//! for _ in 0..5 {
//!     let tick = ticker.tick(now);
//!     process_tick(tick);
//! }
//! ```

mod budget_ext;
mod deadline;
mod driver;
mod elapsed;
mod interval;
pub mod intrusive_wheel;
mod sleep;
mod timeout_future;
mod wheel;

pub use budget_ext::{BudgetTimeExt, budget_sleep, budget_timeout};
pub use deadline::{with_deadline, with_timeout};
pub use driver::{
    TimeSource, TimerDriver, TimerDriverApi, TimerDriverHandle, TimerHandle, VirtualClock,
    WallClock,
};
pub use elapsed::Elapsed;
pub use interval::{Interval, MissedTickBehavior, interval, interval_at};
pub use sleep::{Sleep, sleep, sleep_until, wall_now};
pub use timeout_future::{TimeoutFuture, timeout, timeout_at};
pub use wheel::{
    CoalescingConfig, TimerDurationExceeded, TimerHandle as WheelTimerHandle, TimerWheel,
    TimerWheelConfig,
};
