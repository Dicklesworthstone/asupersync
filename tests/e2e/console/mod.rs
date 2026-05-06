//! Console end-to-end (E2E) test suite.
//!
//! This module provides comprehensive end-to-end tests for the runtime debug
//! console covering:
//! - Terminal capability detection and rendering
//! - Styled text output with color modes
//! - Unicode width calculations
//! - Diagnostic queries (explain_region, explain_task, etc.)
//!
//! Tests are organized to support:
//! - Deterministic lab runtime testing
//! - Snapshot testing for rendering output
//! - Integration with the observability module

pub mod common;
pub mod diagnostics;
pub mod rendering;
pub mod util;
