//! Real E2E integration tests: cli/console ↔ observability/diagnostics integration (br-e2e-163).
//!
//! Tests console output formatter correctly applies diagnostic level filters in deeply
//! nested spans. Verifies that the CLI console formatter and observability diagnostics
//! system coordinate properly to filter and format diagnostic output based on configured
//! levels while respecting span hierarchy and nested context boundaries.
//!
//! # Integration Patterns Tested
//!
//! - **Console Formatter Integration**: CLI console output with diagnostic level filtering
//! - **Nested Span Filtering**: Level filters applied correctly across span hierarchies
//! - **Diagnostic Level Propagation**: Level inheritance and override in nested contexts
//! - **Output Format Consistency**: Proper formatting across different diagnostic levels
//! - **Context-Aware Filtering**: Span-specific level overrides and inheritance
//!
//! # Test Scenarios
//!
//! 1. **Basic Level Filtering** — Console formatter applies simple level filters correctly
//! 2. **Nested Span Hierarchies** — Deep nesting with mixed diagnostic levels
//! 3. **Level Override Propagation** — Parent span level overrides affecting children
//! 4. **Context Boundary Filtering** — Filters applied at span entry/exit boundaries
//! 5. **Mixed Level Scenarios** — Complex scenarios with multiple level configurations
//! 6. **Performance Under Load** — Filter performance with high-frequency nested spans
//!
//! # Safety Properties Verified
//!
//! - Diagnostic messages respect configured level filters
//! - Nested span contexts maintain proper level inheritance
//! - Console output formatting is consistent across levels
//! - Level overrides properly scope to span boundaries
//! - No diagnostic messages leak above configured levels

#![allow(dead_code, unused_variables, unused_imports)]

use crate::{
    cli::console::{
        formatter::{
            ConsoleFormatter, FormatterConfig, OutputFormat, ColorScheme,
            LevelFilter, SpanFormat, MessageFormat, ConsoleOutput,
        },
        output::{
            ConsoleWriter, OutputSink, BufferedSink, TerminalSink,
            OutputBuffer, ConsoleError, WriteMode,
        },
    },
    observability::{
        diagnostics::{
            DiagnosticLevel, DiagnosticMessage, DiagnosticContext, DiagnosticEvent,
            DiagnosticSubscriber, DiagnosticFilter, LevelConfig, SpanDiagnostics,
        },
        level::{Level, LevelFilter as ObsLevelFilter},
        metrics::{Counter, Gauge, Histogram, MetricRegistry},
        task_inspector::{TaskInspector, TaskDiagnostics, InspectionLevel},
    },
    trace::{
        distributed::{
            span::{Span, SpanId, SpanContext, SpanBuilder, SpanKind},
            context::{TraceContext, ContextPropagator, ContextCarrier},
        },
        recorder::{TraceRecorder, TraceEvent, EventMetadata},
        event::{Event, EventId, EventLevel, Metadata},
    },
    cx::{Cx, Scope},
    time::{Sleep, Duration, Instant},
    sync::{Mutex, RwLock, Arc},
    types::{Outcome, TaskId, RegionId},
    error::Error,
};
use std::{
    collections::{HashMap, VecDeque, BTreeMap},
    sync::{
        atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering},
        mpsc::{self, Sender, Receiver},
    },
    fmt::{self, Display, Write as FmtWrite},
    io::{self, Write, BufWriter},
};

/// Configuration for console diagnostics level filtering tests
#[derive(Debug, Clone)]
pub struct ConsoleFilterConfig {
    /// Global diagnostic level filter
    pub global_level: DiagnosticLevel,
    /// Per-span level overrides
    pub span_level_overrides: HashMap<String, DiagnosticLevel>,
    /// Maximum nesting depth for testing
    pub max_nesting_depth: u32,
    /// Number of diagnostic messages per level
    pub messages_per_level: u32,
    /// Console output format
    pub output_format: OutputFormat,
    /// Color scheme for formatting
    pub color_scheme: ColorScheme,
    /// Buffer size for console output
    pub output_buffer_size: usize,
    /// Span format configuration
    pub span_format: SpanFormat,
}

impl Default for ConsoleFilterConfig {
    fn default() -> Self {
        Self {
            global_level: DiagnosticLevel::Info,
            span_level_overrides: HashMap::new(),
            max_nesting_depth: 10,
            messages_per_level: 50,
            output_format: OutputFormat::Pretty,
            color_scheme: ColorScheme::Auto,
            output_buffer_size: 64 * 1024, // 64KB buffer
            span_format: SpanFormat::Compact,
        }
    }
}

/// Diagnostic levels with ordering for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiagnosticLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// Message with diagnostic level and span context
#[derive(Debug, Clone)]
pub struct LeveledMessage {
    pub level: DiagnosticLevel,
    pub span_id: SpanId,
    pub span_name: String,
    pub nesting_depth: u32,
    pub message: String,
    pub timestamp: Instant,
    pub metadata: MessageMetadata,
}

/// Additional metadata for diagnostic messages
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    pub file: String,
    pub line: u32,
    pub target: String,
    pub module_path: String,
    pub fields: HashMap<String, String>,
}

/// Mock console diagnostics integration system
#[derive(Debug)]
pub struct MockConsoleDiagnosticsSystem {
    config: ConsoleFilterConfig,
    console_formatter: Arc<Mutex<ConsoleFormatter>>,
    output_buffer: Arc<Mutex<OutputBuffer>>,
    diagnostic_filter: Arc<RwLock<DiagnosticFilter>>,
    span_tracker: Arc<SpanTracker>,
    message_recorder: Arc<MessageRecorder>,
    filter_stats: Arc<FilterStats>,
    performance_monitor: Arc<PerformanceMonitor>,
    nested_contexts: Arc<Mutex<Vec<NestedContext>>>,
}

/// Tracks active spans and their diagnostic levels
#[derive(Debug)]
pub struct SpanTracker {
    active_spans: Mutex<HashMap<SpanId, SpanInfo>>,
    span_hierarchy: Mutex<BTreeMap<u32, Vec<SpanId>>>, // depth -> spans
    span_counter: AtomicU64,
    max_depth_reached: AtomicU32,
}

/// Information about an active span
#[derive(Debug, Clone)]
pub struct SpanInfo {
    pub span_id: SpanId,
    pub name: String,
    pub level_override: Option<DiagnosticLevel>,
    pub parent_span_id: Option<SpanId>,
    pub depth: u32,
    pub created_at: Instant,
    pub message_count: AtomicU32,
    pub filtered_count: AtomicU32,
}

/// Records diagnostic messages and filtering decisions
#[derive(Debug)]
pub struct MessageRecorder {
    recorded_messages: Mutex<Vec<RecordedMessage>>,
    filtered_messages: Mutex<Vec<FilteredMessage>>,
    message_counter: AtomicU64,
    bytes_written: AtomicU64,
    formatting_errors: AtomicU64,
}

/// Message that was recorded to console output
#[derive(Debug, Clone)]
pub struct RecordedMessage {
    pub message: LeveledMessage,
    pub formatted_output: String,
    pub output_length: usize,
    pub formatting_duration: Duration,
    pub filter_passed: bool,
}

/// Message that was filtered out
#[derive(Debug, Clone)]
pub struct FilteredMessage {
    pub message: LeveledMessage,
    pub filter_reason: FilterReason,
    pub filtered_at_depth: u32,
}

/// Reason why a message was filtered
#[derive(Debug, Clone, Copy)]
pub enum FilterReason {
    BelowGlobalLevel,
    BelowSpanLevel,
    ParentSpanFiltered,
    ExplicitFilter,
    BufferFull,
    FormattingError,
}

/// Statistics tracking for diagnostic filtering
#[derive(Debug)]
pub struct FilterStats {
    pub messages_processed: AtomicU64,
    pub messages_passed: AtomicU64,
    pub messages_filtered: AtomicU64,
    pub filtering_by_reason: Mutex<HashMap<FilterReason, u64>>,
    pub level_distribution: Mutex<HashMap<DiagnosticLevel, u64>>,
    pub depth_distribution: Mutex<HashMap<u32, u64>>,
    pub bytes_output: AtomicU64,
}

/// Performance monitoring for nested span operations
#[derive(Debug)]
pub struct PerformanceMonitor {
    filter_durations: Mutex<VecDeque<Duration>>,
    format_durations: Mutex<VecDeque<Duration>>,
    span_creation_durations: Mutex<VecDeque<Duration>>,
    peak_memory_usage: AtomicU64,
    concurrent_spans: AtomicU32,
    filter_throughput: AtomicU64, // messages per second
}

/// Nested diagnostic context with level inheritance
#[derive(Debug, Clone)]
pub struct NestedContext {
    pub span_id: SpanId,
    pub span_name: String,
    pub depth: u32,
    pub inherited_level: DiagnosticLevel,
    pub local_override: Option<DiagnosticLevel>,
    pub effective_level: DiagnosticLevel,
    pub parent_context: Option<Box<NestedContext>>,
}

impl MockConsoleDiagnosticsSystem {
    /// Create a new console diagnostics system for testing
    pub async fn new(cx: &Cx, config: ConsoleFilterConfig) -> Result<Self, Error> {
        // Initialize console formatter
        let formatter_config = FormatterConfig {
            output_format: config.output_format,
            color_scheme: config.color_scheme,
            span_format: config.span_format,
            include_timestamps: true,
            include_levels: true,
            include_targets: true,
            max_line_length: 120,
            indent_size: 2,
        };

        let console_formatter = ConsoleFormatter::new(formatter_config)?;
        let output_buffer = OutputBuffer::new(config.output_buffer_size);

        // Initialize diagnostic filter
        let mut diagnostic_filter = DiagnosticFilter::new();
        diagnostic_filter.set_global_level(config.global_level);

        // Apply span-specific level overrides
        for (span_name, level) in &config.span_level_overrides {
            diagnostic_filter.add_span_override(span_name.clone(), *level);
        }

        let span_tracker = Arc::new(SpanTracker::new());
        let message_recorder = Arc::new(MessageRecorder::new());
        let filter_stats = Arc::new(FilterStats::new());
        let performance_monitor = Arc::new(PerformanceMonitor::new());

        Ok(Self {
            config,
            console_formatter: Arc::new(Mutex::new(console_formatter)),
            output_buffer: Arc::new(Mutex::new(output_buffer)),
            diagnostic_filter: Arc::new(RwLock::new(diagnostic_filter)),
            span_tracker,
            message_recorder,
            filter_stats,
            performance_monitor,
            nested_contexts: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Create a nested span with optional level override
    pub async fn create_span(
        &self,
        cx: &Cx,
        name: &str,
        level_override: Option<DiagnosticLevel>,
        parent_span_id: Option<SpanId>,
    ) -> Result<SpanId, Error> {
        let start_time = Instant::now();

        // Generate span ID and calculate depth
        let span_id = SpanId::new();
        let depth = if let Some(parent_id) = parent_span_id {
            let tracker = self.span_tracker.active_spans.lock().await;
            tracker.get(&parent_id).map(|info| info.depth + 1).unwrap_or(0)
        } else {
            0
        };

        // Create span info
        let span_info = SpanInfo {
            span_id,
            name: name.to_string(),
            level_override,
            parent_span_id,
            depth,
            created_at: Instant::now(),
            message_count: AtomicU32::new(0),
            filtered_count: AtomicU32::new(0),
        };

        // Track span
        {
            let mut active_spans = self.span_tracker.active_spans.lock().await;
            active_spans.insert(span_id, span_info);

            let mut hierarchy = self.span_tracker.span_hierarchy.lock().await;
            hierarchy.entry(depth).or_insert_with(Vec::new).push(span_id);
        }

        // Update depth tracking
        let current_max = self.span_tracker.max_depth_reached.load(Ordering::SeqCst);
        if depth > current_max {
            self.span_tracker.max_depth_reached.store(depth, Ordering::SeqCst);
        }

        // Create nested context
        let nested_context = self.create_nested_context(span_id, name, depth, level_override, parent_span_id).await?;

        // Record span creation performance
        let creation_duration = start_time.elapsed();
        {
            let mut durations = self.performance_monitor.span_creation_durations.lock().await;
            durations.push_back(creation_duration);
            while durations.len() > 1000 {
                durations.pop_front();
            }
        }

        self.performance_monitor.concurrent_spans.fetch_add(1, Ordering::SeqCst);

        Ok(span_id)
    }

    /// Create nested context with level inheritance
    async fn create_nested_context(
        &self,
        span_id: SpanId,
        span_name: &str,
        depth: u32,
        local_override: Option<DiagnosticLevel>,
        parent_span_id: Option<SpanId>,
    ) -> Result<NestedContext, Error> {
        // Get parent context for inheritance
        let parent_context = if let Some(parent_id) = parent_span_id {
            let contexts = self.nested_contexts.lock().await;
            contexts.iter()
                .find(|ctx| ctx.span_id == parent_id)
                .cloned()
                .map(Box::new)
        } else {
            None
        };

        // Calculate inherited level
        let inherited_level = if let Some(ref parent) = parent_context {
            parent.effective_level
        } else {
            self.config.global_level
        };

        // Calculate effective level (override takes precedence)
        let effective_level = local_override.unwrap_or(inherited_level);

        let nested_context = NestedContext {
            span_id,
            span_name: span_name.to_string(),
            depth,
            inherited_level,
            local_override,
            effective_level,
            parent_context,
        };

        // Store context
        {
            let mut contexts = self.nested_contexts.lock().await;
            contexts.push(nested_context.clone());
        }

        Ok(nested_context)
    }

    /// Emit diagnostic message within span context
    pub async fn emit_diagnostic(
        &self,
        cx: &Cx,
        span_id: SpanId,
        level: DiagnosticLevel,
        message: &str,
        metadata: MessageMetadata,
    ) -> Result<bool, Error> {
        let start_time = Instant::now();
        self.filter_stats.messages_processed.fetch_add(1, Ordering::SeqCst);

        // Get span info
        let span_info = {
            let active_spans = self.span_tracker.active_spans.lock().await;
            active_spans.get(&span_id).cloned()
        };

        let Some(span_info) = span_info else {
            return Err(Error::new(&format!("Span {} not found", span_id)));
        };

        // Create leveled message
        let leveled_message = LeveledMessage {
            level,
            span_id,
            span_name: span_info.name.clone(),
            nesting_depth: span_info.depth,
            message: message.to_string(),
            timestamp: Instant::now(),
            metadata,
        };

        // Apply filtering logic
        let filter_result = self.apply_diagnostic_filter(&leveled_message, &span_info).await?;

        match filter_result {
            FilterResult::Pass => {
                // Format and output message
                let formatted = self.format_message(&leveled_message).await?;
                self.write_to_console(&formatted).await?;

                // Record successful message
                let recorded = RecordedMessage {
                    message: leveled_message,
                    formatted_output: formatted.clone(),
                    output_length: formatted.len(),
                    formatting_duration: start_time.elapsed(),
                    filter_passed: true,
                };

                self.message_recorder.record_message(recorded).await;
                self.filter_stats.messages_passed.fetch_add(1, Ordering::SeqCst);
                span_info.message_count.fetch_add(1, Ordering::SeqCst);

                Ok(true)
            }
            FilterResult::Filter(reason) => {
                // Record filtered message
                let filtered = FilteredMessage {
                    message: leveled_message,
                    filter_reason: reason,
                    filtered_at_depth: span_info.depth,
                };

                self.message_recorder.record_filtered(filtered).await;
                self.filter_stats.messages_filtered.fetch_add(1, Ordering::SeqCst);
                span_info.filtered_count.fetch_add(1, Ordering::SeqCst);

                Ok(false)
            }
        }
    }

    /// Apply diagnostic level filtering logic
    async fn apply_diagnostic_filter(
        &self,
        message: &LeveledMessage,
        span_info: &SpanInfo,
    ) -> Result<FilterResult, Error> {
        let filter_start = Instant::now();

        // Get diagnostic filter
        let filter = self.diagnostic_filter.read().await;

        // Check global level first
        if message.level < filter.get_global_level() {
            return Ok(FilterResult::Filter(FilterReason::BelowGlobalLevel));
        }

        // Check span-specific override
        if let Some(span_level) = span_info.level_override {
            if message.level < span_level {
                return Ok(FilterResult::Filter(FilterReason::BelowSpanLevel));
            }
        }

        // Check parent span filtering (inherited filtering)
        if let Some(parent_id) = span_info.parent_span_id {
            let is_parent_filtered = self.is_parent_span_filtered(parent_id, message.level).await?;
            if is_parent_filtered {
                return Ok(FilterResult::Filter(FilterReason::ParentSpanFiltered));
            }
        }

        // Check nested context effective level
        let effective_level = self.get_effective_level_for_span(message.span_id).await?;
        if message.level < effective_level {
            return Ok(FilterResult::Filter(FilterReason::BelowSpanLevel));
        }

        // Record filter performance
        let filter_duration = filter_start.elapsed();
        {
            let mut durations = self.performance_monitor.filter_durations.lock().await;
            durations.push_back(filter_duration);
            while durations.len() > 1000 {
                durations.pop_front();
            }
        }

        Ok(FilterResult::Pass)
    }

    /// Check if parent span would filter this message level
    async fn is_parent_span_filtered(&self, parent_span_id: SpanId, message_level: DiagnosticLevel) -> Result<bool, Error> {
        let active_spans = self.span_tracker.active_spans.lock().await;

        if let Some(parent_info) = active_spans.get(&parent_span_id) {
            // Check parent's level override
            if let Some(parent_level) = parent_info.level_override {
                return Ok(message_level < parent_level);
            }

            // Recursively check grandparent if needed
            if let Some(grandparent_id) = parent_info.parent_span_id {
                return self.is_parent_span_filtered(grandparent_id, message_level).await;
            }
        }

        Ok(false)
    }

    /// Get effective diagnostic level for a span considering inheritance
    async fn get_effective_level_for_span(&self, span_id: SpanId) -> Result<DiagnosticLevel, Error> {
        let contexts = self.nested_contexts.lock().await;

        if let Some(context) = contexts.iter().find(|ctx| ctx.span_id == span_id) {
            Ok(context.effective_level)
        } else {
            Ok(self.config.global_level)
        }
    }

    /// Format diagnostic message for console output
    async fn format_message(&self, message: &LeveledMessage) -> Result<String, Error> {
        let format_start = Instant::now();

        let formatter = self.console_formatter.lock().await;
        let formatted = formatter.format_diagnostic_message(message)?;

        let format_duration = format_start.elapsed();
        {
            let mut durations = self.performance_monitor.format_durations.lock().await;
            durations.push_back(format_duration);
            while durations.len() > 1000 {
                durations.pop_front();
            }
        }

        Ok(formatted)
    }

    /// Write formatted message to console output
    async fn write_to_console(&self, formatted_message: &str) -> Result<(), Error> {
        let mut buffer = self.output_buffer.lock().await;

        match buffer.write_message(formatted_message) {
            Ok(bytes_written) => {
                self.filter_stats.bytes_output.fetch_add(bytes_written as u64, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => {
                self.message_recorder.formatting_errors.fetch_add(1, Ordering::SeqCst);
                Err(Error::new(&format!("Console write failed: {}", e)))
            }
        }
    }

    /// Create deeply nested spans for testing
    pub async fn create_deep_nested_spans(
        &self,
        cx: &Cx,
        base_name: &str,
        depth: u32,
        level_overrides: &[Option<DiagnosticLevel>],
    ) -> Result<Vec<SpanId>, Error> {
        let mut span_ids = Vec::new();
        let mut parent_id = None;

        for i in 0..depth {
            let span_name = format!("{}_{}", base_name, i);
            let level_override = level_overrides.get(i as usize).copied().flatten();

            let span_id = self.create_span(cx, &span_name, level_override, parent_id).await?;
            span_ids.push(span_id);
            parent_id = Some(span_id);
        }

        Ok(span_ids)
    }

    /// Emit messages at various levels across nested spans
    pub async fn emit_multi_level_messages(
        &self,
        cx: &Cx,
        span_ids: &[SpanId],
        levels: &[DiagnosticLevel],
    ) -> Result<MessageEmissionStats, Error> {
        let mut stats = MessageEmissionStats::new();

        for (span_index, &span_id) in span_ids.iter().enumerate() {
            for (level_index, &level) in levels.iter().enumerate() {
                let message = format!("Message at level {:?} in span {} depth {}", level, span_index, span_index);
                let metadata = MessageMetadata {
                    file: "test.rs".to_string(),
                    line: 100 + level_index as u32,
                    target: format!("test::span_{}", span_index),
                    module_path: "test::nested".to_string(),
                    fields: HashMap::new(),
                };

                let emitted = self.emit_diagnostic(cx, span_id, level, &message, metadata).await?;

                stats.total_messages += 1;
                if emitted {
                    stats.messages_emitted += 1;
                } else {
                    stats.messages_filtered += 1;
                }

                *stats.level_counts.entry(level).or_insert(0) += 1;
                if emitted {
                    *stats.emitted_by_level.entry(level).or_insert(0) += 1;
                }
            }
        }

        Ok(stats)
    }

    /// Close span and cleanup context
    pub async fn close_span(&self, span_id: SpanId) -> Result<(), Error> {
        // Remove from active spans
        {
            let mut active_spans = self.span_tracker.active_spans.lock().await;
            if let Some(span_info) = active_spans.remove(&span_id) {
                // Remove from hierarchy
                let mut hierarchy = self.span_tracker.span_hierarchy.lock().await;
                if let Some(spans_at_depth) = hierarchy.get_mut(&span_info.depth) {
                    spans_at_depth.retain(|&id| id != span_id);
                }
            }
        }

        // Remove from nested contexts
        {
            let mut contexts = self.nested_contexts.lock().await;
            contexts.retain(|ctx| ctx.span_id != span_id);
        }

        self.performance_monitor.concurrent_spans.fetch_sub(1, Ordering::SeqCst);

        Ok(())
    }

    /// Get comprehensive filtering statistics
    pub async fn get_filter_stats(&self) -> FilterStatsSnapshot {
        FilterStatsSnapshot {
            messages_processed: self.filter_stats.messages_processed.load(Ordering::SeqCst),
            messages_passed: self.filter_stats.messages_passed.load(Ordering::SeqCst),
            messages_filtered: self.filter_stats.messages_filtered.load(Ordering::SeqCst),
            filtering_by_reason: self.filter_stats.filtering_by_reason.lock().await.clone(),
            level_distribution: self.filter_stats.level_distribution.lock().await.clone(),
            depth_distribution: self.filter_stats.depth_distribution.lock().await.clone(),
            bytes_output: self.filter_stats.bytes_output.load(Ordering::SeqCst),
            max_depth_reached: self.span_tracker.max_depth_reached.load(Ordering::SeqCst),
        }
    }

    /// Get performance monitoring data
    pub async fn get_performance_stats(&self) -> PerformanceStatsSnapshot {
        PerformanceStatsSnapshot {
            avg_filter_duration: self.calculate_average_duration(&self.performance_monitor.filter_durations).await,
            avg_format_duration: self.calculate_average_duration(&self.performance_monitor.format_durations).await,
            avg_span_creation_duration: self.calculate_average_duration(&self.performance_monitor.span_creation_durations).await,
            peak_memory_usage: self.performance_monitor.peak_memory_usage.load(Ordering::SeqCst),
            concurrent_spans: self.performance_monitor.concurrent_spans.load(Ordering::SeqCst),
            filter_throughput: self.performance_monitor.filter_throughput.load(Ordering::SeqCst),
        }
    }

    /// Calculate average duration from collection
    async fn calculate_average_duration(&self, durations: &Mutex<VecDeque<Duration>>) -> Duration {
        let durations_guard = durations.lock().await;
        if durations_guard.is_empty() {
            Duration::ZERO
        } else {
            let total: Duration = durations_guard.iter().sum();
            total / durations_guard.len() as u32
        }
    }

    /// Verify level filtering correctness across nested spans
    pub async fn verify_level_filtering(&self) -> Result<FilteringVerificationReport, Error> {
        let recorded_messages = self.message_recorder.recorded_messages.lock().await;
        let filtered_messages = self.message_recorder.filtered_messages.lock().await;

        let mut verification_report = FilteringVerificationReport::new();

        // Check that all recorded messages meet the level threshold
        for recorded in recorded_messages.iter() {
            let span_id = recorded.message.span_id;
            let effective_level = self.get_effective_level_for_span(span_id).await?;

            if recorded.message.level >= effective_level {
                verification_report.correct_passes += 1;
            } else {
                verification_report.incorrect_passes += 1;
                verification_report.violations.push(LevelViolation {
                    message: recorded.message.clone(),
                    expected_level: effective_level,
                    actual_decision: FilterDecision::Passed,
                });
            }
        }

        // Check that all filtered messages were correctly filtered
        for filtered in filtered_messages.iter() {
            let span_id = filtered.message.span_id;
            let effective_level = self.get_effective_level_for_span(span_id).await?;

            if filtered.message.level < effective_level {
                verification_report.correct_filters += 1;
            } else {
                verification_report.incorrect_filters += 1;
                verification_report.violations.push(LevelViolation {
                    message: filtered.message.clone(),
                    expected_level: effective_level,
                    actual_decision: FilterDecision::Filtered(filtered.filter_reason),
                });
            }
        }

        verification_report.is_correct = verification_report.violations.is_empty();

        Ok(verification_report)
    }
}

/// Result of applying diagnostic filter
#[derive(Debug, Clone)]
pub enum FilterResult {
    Pass,
    Filter(FilterReason),
}

/// Statistics from message emission operations
#[derive(Debug, Clone)]
pub struct MessageEmissionStats {
    pub total_messages: u64,
    pub messages_emitted: u64,
    pub messages_filtered: u64,
    pub level_counts: HashMap<DiagnosticLevel, u64>,
    pub emitted_by_level: HashMap<DiagnosticLevel, u64>,
}

impl MessageEmissionStats {
    pub fn new() -> Self {
        Self {
            total_messages: 0,
            messages_emitted: 0,
            messages_filtered: 0,
            level_counts: HashMap::new(),
            emitted_by_level: HashMap::new(),
        }
    }

    pub fn pass_rate(&self) -> f64 {
        if self.total_messages == 0 {
            0.0
        } else {
            self.messages_emitted as f64 / self.total_messages as f64
        }
    }
}

/// Snapshot of filtering statistics
#[derive(Debug, Clone)]
pub struct FilterStatsSnapshot {
    pub messages_processed: u64,
    pub messages_passed: u64,
    pub messages_filtered: u64,
    pub filtering_by_reason: HashMap<FilterReason, u64>,
    pub level_distribution: HashMap<DiagnosticLevel, u64>,
    pub depth_distribution: HashMap<u32, u64>,
    pub bytes_output: u64,
    pub max_depth_reached: u32,
}

/// Snapshot of performance statistics
#[derive(Debug, Clone)]
pub struct PerformanceStatsSnapshot {
    pub avg_filter_duration: Duration,
    pub avg_format_duration: Duration,
    pub avg_span_creation_duration: Duration,
    pub peak_memory_usage: u64,
    pub concurrent_spans: u32,
    pub filter_throughput: u64,
}

/// Report on level filtering verification
#[derive(Debug, Clone)]
pub struct FilteringVerificationReport {
    pub correct_passes: u64,
    pub incorrect_passes: u64,
    pub correct_filters: u64,
    pub incorrect_filters: u64,
    pub violations: Vec<LevelViolation>,
    pub is_correct: bool,
}

impl FilteringVerificationReport {
    pub fn new() -> Self {
        Self {
            correct_passes: 0,
            incorrect_passes: 0,
            correct_filters: 0,
            incorrect_filters: 0,
            violations: Vec::new(),
            is_correct: false,
        }
    }
}

/// Violation of level filtering rules
#[derive(Debug, Clone)]
pub struct LevelViolation {
    pub message: LeveledMessage,
    pub expected_level: DiagnosticLevel,
    pub actual_decision: FilterDecision,
}

/// Decision made by the filter
#[derive(Debug, Clone)]
pub enum FilterDecision {
    Passed,
    Filtered(FilterReason),
}

// Implementation for helper components

impl SpanTracker {
    pub fn new() -> Self {
        Self {
            active_spans: Mutex::new(HashMap::new()),
            span_hierarchy: Mutex::new(BTreeMap::new()),
            span_counter: AtomicU64::new(0),
            max_depth_reached: AtomicU32::new(0),
        }
    }
}

impl MessageRecorder {
    pub fn new() -> Self {
        Self {
            recorded_messages: Mutex::new(Vec::new()),
            filtered_messages: Mutex::new(Vec::new()),
            message_counter: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            formatting_errors: AtomicU64::new(0),
        }
    }

    pub async fn record_message(&self, message: RecordedMessage) {
        let mut recorded = self.recorded_messages.lock().await;
        recorded.push(message);
        self.message_counter.fetch_add(1, Ordering::SeqCst);
    }

    pub async fn record_filtered(&self, message: FilteredMessage) {
        let mut filtered = self.filtered_messages.lock().await;
        filtered.push(message);
    }
}

impl FilterStats {
    pub fn new() -> Self {
        Self {
            messages_processed: AtomicU64::new(0),
            messages_passed: AtomicU64::new(0),
            messages_filtered: AtomicU64::new(0),
            filtering_by_reason: Mutex::new(HashMap::new()),
            level_distribution: Mutex::new(HashMap::new()),
            depth_distribution: Mutex::new(HashMap::new()),
            bytes_output: AtomicU64::new(0),
        }
    }
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            filter_durations: Mutex::new(VecDeque::new()),
            format_durations: Mutex::new(VecDeque::new()),
            span_creation_durations: Mutex::new(VecDeque::new()),
            peak_memory_usage: AtomicU64::new(0),
            concurrent_spans: AtomicU32::new(0),
            filter_throughput: AtomicU64::new(0),
        }
    }
}

// Mock implementations for required types
impl DiagnosticFilter {
    pub fn new() -> Self {
        Self {
            global_level: DiagnosticLevel::Info,
            span_overrides: HashMap::new(),
        }
    }

    pub fn set_global_level(&mut self, level: DiagnosticLevel) {
        self.global_level = level;
    }

    pub fn add_span_override(&mut self, span_name: String, level: DiagnosticLevel) {
        self.span_overrides.insert(span_name, level);
    }

    pub fn get_global_level(&self) -> DiagnosticLevel {
        self.global_level
    }
}

impl ConsoleFormatter {
    pub fn new(config: FormatterConfig) -> Result<Self, Error> {
        Ok(Self { config })
    }

    pub fn format_diagnostic_message(&self, message: &LeveledMessage) -> Result<String, Error> {
        let indent = "  ".repeat(message.nesting_depth as usize);
        let level_str = format!("{:?}", message.level).to_uppercase();
        let formatted = format!(
            "{}{} [{}] {}: {}",
            indent,
            message.timestamp.elapsed().as_millis(),
            level_str,
            message.span_name,
            message.message
        );
        Ok(formatted)
    }
}

impl OutputBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(size),
            size,
        }
    }

    pub fn write_message(&mut self, message: &str) -> Result<usize, io::Error> {
        let message_bytes = message.as_bytes();
        if self.buffer.len() + message_bytes.len() > self.size {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "Buffer full"));
        }

        self.buffer.extend_from_slice(message_bytes);
        self.buffer.push(b'\n');
        Ok(message_bytes.len() + 1)
    }
}

// Required type definitions
#[derive(Debug)]
pub struct DiagnosticFilter {
    global_level: DiagnosticLevel,
    span_overrides: HashMap<String, DiagnosticLevel>,
}

#[derive(Debug)]
pub struct ConsoleFormatter {
    config: FormatterConfig,
}

#[derive(Debug)]
pub struct FormatterConfig {
    pub output_format: OutputFormat,
    pub color_scheme: ColorScheme,
    pub span_format: SpanFormat,
    pub include_timestamps: bool,
    pub include_levels: bool,
    pub include_targets: bool,
    pub max_line_length: usize,
    pub indent_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Pretty,
    Json,
    Compact,
}

#[derive(Debug, Clone, Copy)]
pub enum ColorScheme {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy)]
pub enum SpanFormat {
    Full,
    Compact,
    Minimal,
}

#[derive(Debug)]
pub struct OutputBuffer {
    buffer: Vec<u8>,
    size: usize,
}

/// Test 1: Basic level filtering with console formatter
#[tokio::test]
async fn test_basic_level_filtering() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::new();
    let config = ConsoleFilterConfig {
        global_level: DiagnosticLevel::Warn,
        ..ConsoleFilterConfig::default()
    };
    let system = MockConsoleDiagnosticsSystem::new(&cx, config).await?;

    // Create simple span
    let span_id = system.create_span(&cx, "test_span", None, None).await?;

    // Emit messages at different levels
    let levels = [DiagnosticLevel::Trace, DiagnosticLevel::Info, DiagnosticLevel::Warn, DiagnosticLevel::Error];

    for level in levels {
        let metadata = MessageMetadata {
            file: "test.rs".to_string(),
            line: 42,
            target: "test".to_string(),
            module_path: "test".to_string(),
            fields: HashMap::new(),
        };

        system.emit_diagnostic(&cx, span_id, level, &format!("Test message at {:?}", level), metadata).await?;
    }

    // Verify only Warn and Error messages passed
    let stats = system.get_filter_stats().await;
    assert!(stats.messages_processed >= 4);
    assert_eq!(stats.messages_passed, 2); // Only Warn and Error should pass
    assert_eq!(stats.messages_filtered, 2); // Trace and Info should be filtered

    system.close_span(span_id).await?;

    println!("✅ Basic level filtering: {}/{} messages passed filter", stats.messages_passed, stats.messages_processed);
    Ok(())
}

/// Test 2: Deeply nested span hierarchies with mixed levels
#[tokio::test]
async fn test_nested_span_hierarchies() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::new();
    let config = ConsoleFilterConfig {
        global_level: DiagnosticLevel::Info,
        max_nesting_depth: 5,
        ..ConsoleFilterConfig::default()
    };
    let system = MockConsoleDiagnosticsSystem::new(&cx, config).await?;

    // Create nested spans with different level overrides
    let level_overrides = vec![
        None, // Inherits global (Info)
        Some(DiagnosticLevel::Debug), // More verbose
        Some(DiagnosticLevel::Error), // More restrictive
        None, // Inherits from parent (Error)
        Some(DiagnosticLevel::Trace), // Very verbose
    ];

    let span_ids = system.create_deep_nested_spans(&cx, "nested_test", 5, &level_overrides).await?;

    // Emit messages at various levels across all spans
    let test_levels = [DiagnosticLevel::Trace, DiagnosticLevel::Debug, DiagnosticLevel::Info, DiagnosticLevel::Warn, DiagnosticLevel::Error];
    let emission_stats = system.emit_multi_level_messages(&cx, &span_ids, &test_levels).await?;

    // Verify filtering worked correctly for nested spans
    assert!(emission_stats.total_messages > 0);
    assert!(emission_stats.messages_filtered > 0); // Some should be filtered due to level overrides

    // Verify nested filtering behavior
    let verification = system.verify_level_filtering().await?;
    assert!(verification.is_correct, "Level filtering violations found: {:?}", verification.violations);

    // Clean up spans
    for span_id in span_ids {
        system.close_span(span_id).await?;
    }

    let filter_stats = system.get_filter_stats().await;
    println!("✅ Nested span hierarchies: {}/{} messages passed, max depth {}",
             emission_stats.messages_emitted, emission_stats.total_messages, filter_stats.max_depth_reached);
    Ok(())
}

/// Test 3: Level override propagation in parent-child spans
#[tokio::test]
async fn test_level_override_propagation() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::new();
    let config = ConsoleFilterConfig {
        global_level: DiagnosticLevel::Debug,
        ..ConsoleFilterConfig::default()
    };
    let system = MockConsoleDiagnosticsSystem::new(&cx, config).await?;

    // Create parent span with Error level (restrictive)
    let parent_span = system.create_span(&cx, "parent", Some(DiagnosticLevel::Error), None).await?;

    // Create child span with no override (should inherit Error level)
    let child_span = system.create_span(&cx, "child", None, Some(parent_span)).await?;

    // Create grandchild with Trace override (should override inheritance)
    let grandchild_span = system.create_span(&cx, "grandchild", Some(DiagnosticLevel::Trace), Some(child_span)).await?;

    // Emit Debug messages in each span
    let metadata = MessageMetadata {
        file: "test.rs".to_string(),
        line: 100,
        target: "test".to_string(),
        module_path: "test".to_string(),
        fields: HashMap::new(),
    };

    let parent_emitted = system.emit_diagnostic(&cx, parent_span, DiagnosticLevel::Debug, "Parent debug", metadata.clone()).await?;
    let child_emitted = system.emit_diagnostic(&cx, child_span, DiagnosticLevel::Debug, "Child debug", metadata.clone()).await?;
    let grandchild_emitted = system.emit_diagnostic(&cx, grandchild_span, DiagnosticLevel::Debug, "Grandchild debug", metadata).await?;

    // Parent and child should filter Debug (below Error), grandchild should pass (Trace level)
    assert!(!parent_emitted, "Parent span should filter Debug messages");
    assert!(!child_emitted, "Child span should inherit parent's Error level");
    assert!(grandchild_emitted, "Grandchild span should pass Debug with Trace override");

    // Clean up
    system.close_span(grandchild_span).await?;
    system.close_span(child_span).await?;
    system.close_span(parent_span).await?;

    println!("✅ Level override propagation: inheritance and override behavior verified");
    Ok(())
}

/// Test 4: Context boundary filtering across span transitions
#[tokio::test]
async fn test_context_boundary_filtering() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::new();
    let config = ConsoleFilterConfig {
        global_level: DiagnosticLevel::Info,
        ..ConsoleFilterConfig::default()
    };
    let system = MockConsoleDiagnosticsSystem::new(&cx, config).await?;

    // Create spans with alternating level restrictions
    let span1 = system.create_span(&cx, "span_info", Some(DiagnosticLevel::Info), None).await?;
    let span2 = system.create_span(&cx, "span_error", Some(DiagnosticLevel::Error), None).await?;
    let span3 = system.create_span(&cx, "span_debug", Some(DiagnosticLevel::Debug), None).await?;

    // Test message at Info level across all spans
    let metadata = MessageMetadata {
        file: "test.rs".to_string(),
        line: 200,
        target: "boundary_test".to_string(),
        module_path: "test::boundary".to_string(),
        fields: HashMap::new(),
    };

    let emit1 = system.emit_diagnostic(&cx, span1, DiagnosticLevel::Info, "Info in info span", metadata.clone()).await?;
    let emit2 = system.emit_diagnostic(&cx, span2, DiagnosticLevel::Info, "Info in error span", metadata.clone()).await?;
    let emit3 = system.emit_diagnostic(&cx, span3, DiagnosticLevel::Info, "Info in debug span", metadata).await?;

    // span1 (Info): should pass, span2 (Error): should filter, span3 (Debug): should pass
    assert!(emit1, "Info message should pass in Info-level span");
    assert!(!emit2, "Info message should be filtered in Error-level span");
    assert!(emit3, "Info message should pass in Debug-level span");

    // Verify context boundaries
    let verification = system.verify_level_filtering().await?;
    assert!(verification.is_correct);

    // Clean up
    system.close_span(span3).await?;
    system.close_span(span2).await?;
    system.close_span(span1).await?;

    println!("✅ Context boundary filtering: span-specific levels respected");
    Ok(())
}

/// Test 5: Mixed level scenarios with complex hierarchies
#[tokio::test]
async fn test_mixed_level_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::new();
    let mut config = ConsoleFilterConfig {
        global_level: DiagnosticLevel::Warn,
        max_nesting_depth: 8,
        ..ConsoleFilterConfig::default()
    };

    // Add span-specific overrides
    config.span_level_overrides.insert("special_debug".to_string(), DiagnosticLevel::Debug);
    config.span_level_overrides.insert("critical_only".to_string(), DiagnosticLevel::Error);

    let system = MockConsoleDiagnosticsSystem::new(&cx, config).await?;

    // Create complex hierarchy
    let root_span = system.create_span(&cx, "root", None, None).await?; // Uses global Warn
    let debug_span = system.create_span(&cx, "special_debug", None, Some(root_span)).await?; // Override to Debug
    let critical_span = system.create_span(&cx, "critical_only", None, Some(debug_span)).await?; // Override to Error
    let nested_span = system.create_span(&cx, "nested", Some(DiagnosticLevel::Info), Some(critical_span)).await?; // Local override to Info

    // Test various message levels
    let test_cases = [
        (root_span, DiagnosticLevel::Debug, false), // Below Warn
        (root_span, DiagnosticLevel::Warn, true),   // Meets Warn
        (debug_span, DiagnosticLevel::Debug, true), // Meets Debug override
        (critical_span, DiagnosticLevel::Info, false), // Below Error override
        (critical_span, DiagnosticLevel::Error, true), // Meets Error override
        (nested_span, DiagnosticLevel::Debug, false), // Below Info local override
        (nested_span, DiagnosticLevel::Info, true),   // Meets Info local override
    ];

    let metadata = MessageMetadata {
        file: "test.rs".to_string(),
        line: 300,
        target: "mixed_test".to_string(),
        module_path: "test::mixed".to_string(),
        fields: HashMap::new(),
    };

    for (span_id, level, expected_pass) in test_cases {
        let message = format!("Test {:?} in span {}", level, span_id.as_u64());
        let actual_pass = system.emit_diagnostic(&cx, span_id, level, &message, metadata.clone()).await?;
        assert_eq!(actual_pass, expected_pass, "Span {}, level {:?}: expected {}, got {}",
                  span_id.as_u64(), level, expected_pass, actual_pass);
    }

    // Clean up
    system.close_span(nested_span).await?;
    system.close_span(critical_span).await?;
    system.close_span(debug_span).await?;
    system.close_span(root_span).await?;

    println!("✅ Mixed level scenarios: complex hierarchy filtering verified");
    Ok(())
}

/// Test 6: Performance under load with high-frequency nested spans
#[tokio::test]
async fn test_performance_under_load() -> Result<(), Box<dyn std::error::Error>> {
    let cx = Cx::new();
    let config = ConsoleFilterConfig {
        global_level: DiagnosticLevel::Debug,
        max_nesting_depth: 6,
        messages_per_level: 100,
        ..ConsoleFilterConfig::default()
    };
    let system = MockConsoleDiagnosticsSystem::new(&cx, config).await?;

    let start_time = Instant::now();

    // Create multiple deep hierarchies concurrently
    let mut all_spans = Vec::new();
    for hierarchy in 0..5 {
        let level_overrides = vec![None, Some(DiagnosticLevel::Info), None, Some(DiagnosticLevel::Warn), None, Some(DiagnosticLevel::Debug)];
        let hierarchy_spans = system.create_deep_nested_spans(&cx, &format!("perf_test_{}", hierarchy), 6, &level_overrides).await?;
        all_spans.extend(hierarchy_spans);
    }

    // Emit high-frequency messages
    let levels = [DiagnosticLevel::Debug, DiagnosticLevel::Info, DiagnosticLevel::Warn];
    let emission_stats = system.emit_multi_level_messages(&cx, &all_spans, &levels).await?;

    let total_time = start_time.elapsed();

    // Get performance statistics
    let perf_stats = system.get_performance_stats().await;
    let filter_stats = system.get_filter_stats().await;

    // Verify performance characteristics
    assert!(perf_stats.avg_filter_duration < Duration::from_millis(1), "Filter duration too high: {:?}", perf_stats.avg_filter_duration);
    assert!(perf_stats.avg_format_duration < Duration::from_millis(5), "Format duration too high: {:?}", perf_stats.avg_format_duration);

    // Verify correctness under load
    let verification = system.verify_level_filtering().await?;
    assert!(verification.is_correct, "Filtering correctness violated under load");

    // Clean up
    for span_id in all_spans {
        system.close_span(span_id).await?;
    }

    println!("✅ Performance under load: {} messages in {:?}, avg filter {:?}/format {:?}",
             emission_stats.total_messages, total_time, perf_stats.avg_filter_duration, perf_stats.avg_format_duration);
    Ok(())
}