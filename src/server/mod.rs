//! Server lifecycle and connection management.
//!
//! This module provides the building blocks for HTTP server lifecycle:
//!
//! - [`ShutdownSignal`] — Phase-aware shutdown coordination with drain timeouts
//! - [`ShutdownPhase`] — Shutdown state machine (Running → Draining → ForceClosing → Stopped)
//! - [`ConnectionManager`] — Active connection tracking with capacity limits
//! - [`ConnectionGuard`] — RAII guard for automatic connection deregistration
//!
//! These types build on the lower-level [`ShutdownController`](crate::signal::ShutdownController)
//! to provide server-specific lifecycle management with structured concurrency semantics.
//!
//! # Architecture
//!
//! ```text
//! Server Region (lifetime: until shutdown)
//! │
//! ├── Acceptor (stops on ShutdownSignal::begin_drain)
//! │
//! └── Connections (tracked by ConnectionManager)
//!     ├── Connection[1] (holds ConnectionGuard)
//!     │   ├── Request[1.1]
//!     │   └── Request[1.2]
//!     └── Connection[2]
//! ```
//!
//! # Example
//!
//! ```ignore
//! use asupersync::server::{ConnectionManager, ShutdownSignal};
//! use std::time::Duration;
//! use std::net::SocketAddr;
//!
//! let signal = ShutdownSignal::new();
//! let manager = ConnectionManager::new(Some(10_000), signal.clone());
//!
//! // Accept loop checks shutdown signal:
//! while !signal.is_shutting_down() {
//!     // let (stream, addr) = listener.accept().await?;
//!     # let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
//!     if let Some(guard) = manager.register(addr) {
//!         // spawn connection handler with guard
//!     }
//! }
//!
//! // Initiate graceful shutdown with 30s drain:
//! manager.begin_drain(Duration::from_secs(30));
//! manager.wait_all_closed().await;
//! signal.mark_stopped();
//! ```

pub mod connection;
pub mod shutdown;

pub use connection::{ConnectionGuard, ConnectionId, ConnectionInfo, ConnectionManager};
pub use shutdown::{ShutdownPhase, ShutdownSignal, ShutdownStats};
