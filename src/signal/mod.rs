//! Async signal handling and graceful shutdown.
//!
//! This module provides primitives for handling Unix signals and implementing
//! graceful shutdown patterns in async applications.
//!
//! # Components
//!
//! - [`SignalKind`]: Enumeration of Unix signal types
//! - [`Signal`]: Async stream for receiving signals (Phase 1)
//! - [`ctrl_c`]: Cross-platform Ctrl+C handling (Phase 1)
//! - [`ShutdownController`]: Coordinated graceful shutdown
//! - [`ShutdownReceiver`]: Handle for receiving shutdown notifications
//! - [`with_graceful_shutdown`]: Run tasks with shutdown support
//!
//! # Phase 0 Implementation
//!
//! In Phase 0, signal handling requires external infrastructure that is not
//! yet available:
//!
//! - Unix signals require either unsafe libc bindings or the `signal-hook` crate
//! - Cross-platform Ctrl+C requires the `ctrlc` crate or similar
//!
//! The [`ShutdownController`] and graceful shutdown helpers are fully
//! functional using our sync primitives.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::signal::{ShutdownController, with_graceful_shutdown, GracefulOutcome};
//!
//! async fn run_server() {
//!     let controller = ShutdownController::new();
//!
//!     // Subscribe to shutdown notifications
//!     let receiver = controller.subscribe();
//!
//!     // Run a task with graceful shutdown support
//!     let result = with_graceful_shutdown(
//!         async { /* server loop */ 42 },
//!         receiver,
//!     ).await;
//!
//!     match result {
//!         GracefulOutcome::Completed(value) => println!("Completed: {value}"),
//!         GracefulOutcome::ShutdownSignaled => println!("Shutdown requested"),
//!     }
//! }
//! ```
//!
//! # Cancel Safety
//!
//! - `Signal::recv`: Cancel-safe
//! - `ShutdownReceiver::wait`: Cancel-safe
//! - `ctrl_c`: Cancel-safe

mod ctrl_c;
mod graceful;
mod kind;
mod shutdown;
mod signal;

pub use ctrl_c::{CtrlCError, ctrl_c, is_available};
pub use graceful::{
    GracePeriodGuard, GracefulBuilder, GracefulConfig, GracefulOutcome, with_graceful_shutdown,
};
pub use kind::SignalKind;
pub use shutdown::{ShutdownController, ShutdownReceiver};
pub use signal::{Signal, SignalError, signal};

// Unix-specific signal helpers
#[cfg(unix)]
pub use signal::{sigchld, sighup, sigint, sigquit, sigterm, sigusr1, sigusr2, sigwinch};
