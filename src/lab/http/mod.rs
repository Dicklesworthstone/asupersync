//! Virtual HTTP components for deterministic testing.
//!
//! Provides a [`VirtualServer`] and [`VirtualClient`] that operate entirely
//! within a lab runtime, enabling deterministic and reproducible HTTP testing
//! with virtual time, fault injection, and schedule exploration.
//!
//! # Architecture
//!
//! ```text
//! VirtualClient ──request──▶ VirtualServer
//!      ▲                         │
//!      └─────response────────────┘
//! ```
//!
//! In Phase 0, requests are dispatched synchronously through the web
//! [`Router`](crate::web::router::Router). No actual TCP connections are
//! created — the client calls the server's router directly.
//!
//! # Determinism
//!
//! All non-determinism flows through the lab runtime's [`DetRng`]:
//! - Request ordering in concurrent batches
//! - Fault injection decisions
//! - Simulated latency jitter
//!
//! Same seed → identical request ordering and responses.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::lab::http::{VirtualServer, VirtualClient, TestHarness};
//! use asupersync::lab::LabConfig;
//! use asupersync::web::{Router, get};
//! use asupersync::web::handler::FnHandler;
//!
//! let router = Router::new()
//!     .route("/health", get(FnHandler::new(|| "ok")));
//!
//! let mut harness = TestHarness::new(LabConfig::new(42), router);
//!
//! // Single request
//! let resp = harness.client().get("/health");
//! assert_eq!(resp.status.as_u16(), 200);
//!
//! // Deterministic concurrent requests
//! let responses = harness.client().get_batch(&["/a", "/b", "/c"]);
//! // Same seed → same ordering every time
//! ```

mod client;
mod harness;
mod server;

pub use client::{RequestBuilder, VirtualClient};
pub use harness::{RequestTrace, TestHarness, TraceEntry};
pub use server::VirtualServer;
