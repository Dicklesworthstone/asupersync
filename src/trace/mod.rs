//! Tracing infrastructure for deterministic replay.
//!
//! This module provides structured tracing for the runtime, enabling:
//!
//! - Deterministic replay of executions
//! - Debugging and analysis of concurrent behavior
//! - Mazurkiewicz trace semantics for DPOR
//!
//! # Submodules
//!
//! - [`event`]: Observability trace events for debugging and analysis
//! - [`replay`]: Compact replay events for deterministic record/replay
//! - [`recorder`]: Trace recorder for Lab runtime instrumentation
//! - [`replayer`]: Trace replayer for deterministic replay with stepping support
//! - [`file`]: Binary file format for trace persistence
//! - [`buffer`]: Ring buffer for recent events
//! - [`format`]: Output formatting utilities
//! - [`streaming`]: Streaming replay for large traces with O(1) memory
//! - [`integrity`]: Trace file integrity verification
//! - [`filter`]: Trace event filtering during recording
//! - [`compat`]: Forward/backward compatibility and migration support

pub mod buffer;
pub mod compat;
pub mod distributed;
pub mod event;
pub mod file;
pub mod filter;
pub mod format;
pub mod integrity;
pub mod recorder;
pub mod replay;
pub mod replayer;
pub mod streaming;

pub use buffer::TraceBuffer;
pub use compat::{
    check_schema_compatibility, CompatEvent, CompatEventIterator, CompatReader, CompatStats,
    CompatibilityResult, TraceMigration, TraceMigrator, MIN_SUPPORTED_SCHEMA_VERSION,
};
pub use event::{TraceData, TraceEvent, TraceEventKind, TRACE_EVENT_SCHEMA_VERSION};
pub use file::{
    read_trace, write_trace, CompressionMode, TraceEventIterator, TraceFileConfig, TraceFileError,
    TraceReader, TraceWriter, TRACE_FILE_VERSION, TRACE_MAGIC,
};
pub use filter::{EventCategory, FilterBuilder, FilterableEvent, TraceFilter};
pub use integrity::{
    find_first_corruption, is_trace_valid_quick, verify_trace, IntegrityIssue, IssueSeverity,
    VerificationOptions, VerificationResult,
};
pub use recorder::{
    LimitAction, LimitKind, LimitReached, RecorderConfig, TraceRecorder, DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_MEMORY,
};
pub use replay::{
    CompactRegionId, CompactTaskId, ReplayEvent, ReplayTrace, ReplayTraceError, TraceMetadata,
    REPLAY_SCHEMA_VERSION,
};
pub use replayer::{Breakpoint, DivergenceError, ReplayError, ReplayMode, TraceReplayer};
pub use streaming::{
    ReplayCheckpoint, ReplayProgress, StreamingReplayError, StreamingReplayResult,
    StreamingReplayer,
};
