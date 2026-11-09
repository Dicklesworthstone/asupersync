//! Native adapters for explicitly installed OpenTelemetry SDK components.
//!
//! These adapters retain the external SDK's provider and reader ownership.
//! Delivery runs in a caller-started managed native queue; this module creates
//! no runtime, global provider, periodic reader, or background thread.

mod common;
mod logs;
mod metrics;
mod traces;

pub use logs::{OtlpSdkLogConfig, OtlpSdkLogError, OtlpSdkLogExporter};
pub use metrics::{OtlpSdkMetricExporter, OtlpSdkMetricsConfig, OtlpSdkMetricsError};
pub use traces::{OtlpSdkSpanExporter, OtlpSdkTraceConfig, OtlpSdkTraceError};
