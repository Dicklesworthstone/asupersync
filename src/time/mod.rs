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
//! <!-- core-api-doctest: time-primitives -->
//! ```
//! use asupersync::{Cx, main};
//! use asupersync::time::{interval, sleep, timeout};
//! use asupersync::types::Time;
//! use std::future::ready;
//! use std::time::Duration;
//!
//! #[main]
//! async fn main(cx: &Cx) {
//!     cx.checkpoint().expect("example starts active");
//!     let now = Time::from_secs(10);
//!
//!     let sleeper = sleep(now, Duration::from_millis(100));
//!     assert_eq!(sleeper.deadline(), Time::from_nanos(10_100_000_000));
//!
//!     let value = timeout(now, Duration::from_secs(5), ready(42_u8))
//!         .await
//!         .expect("ready future beats its timeout");
//!     assert_eq!(value, 42);
//!     let elapsed = timeout(now, Duration::from_secs(5), ready(()));
//!     assert!(elapsed.is_elapsed(Time::from_secs(15)));
//!
//!     let mut ticker = interval(now, Duration::from_millis(100));
//!     assert_eq!(ticker.tick(now), now);
//!     assert_eq!(ticker.tick(Time::from_nanos(10_100_000_000)), Time::from_nanos(10_100_000_000));
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
pub mod utc;
mod wheel;

pub use budget_ext::{BudgetTimeExt, budget_sleep, budget_timeout};
pub use deadline::{
    DeadlineJitterDecision, DeadlineJitterPolicy, DeadlineJitterScope, with_deadline, with_timeout,
};
pub use driver::{
    BrowserClockConfig, BrowserMonotonicClock, TimeSource, TimerDriver, TimerDriverApi,
    TimerDriverHandle, TimerHandle, VirtualClock, WallClock,
};
pub use elapsed::Elapsed;
pub use interval::{Interval, MissedTickBehavior, interval, interval_at};
pub(crate) use sleep::process_epoch;
pub use sleep::{Sleep, sleep, sleep_until, wall_now};
pub use timeout_future::{TimeoutFuture, timeout, timeout_at};
pub use utc::format_unix_nanos_rfc3339;
pub use wheel::{
    CoalescingConfig, TimerDurationExceeded, TimerHandle as WheelTimerHandle, TimerWheel,
    TimerWheelConfig,
};
