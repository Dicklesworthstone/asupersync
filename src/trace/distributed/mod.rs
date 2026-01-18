//! Symbol-based distributed tracing for the RaptorQ layer.
//!
//! This module provides trace identifiers, trace context propagation,
//! symbol span recording, and in-process collection for diagnostics.

pub mod collector;
pub mod context;
pub mod id;
pub mod span;

pub use collector::{SymbolTraceCollector, TraceRecord, TraceSummary};
pub use context::{RegionTag, SymbolTraceContext, TraceFlags};
pub use id::{SymbolSpanId, TraceId};
pub use span::{SymbolSpan, SymbolSpanKind, SymbolSpanStatus};
