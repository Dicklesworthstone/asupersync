//! Native adapters for explicitly installed OpenTelemetry SDK components.
//!
//! These adapters retain the external SDK's provider and reader ownership.
//! Delivery runs in a caller-started managed native queue; this module creates
//! no runtime, global provider, periodic reader, or background thread.

mod metrics;

pub use metrics::{OtlpSdkMetricExporter, OtlpSdkMetricsConfig, OtlpSdkMetricsError};
