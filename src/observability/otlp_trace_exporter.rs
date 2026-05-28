//! OTLP trace exporter with load shedding for high-throughput span processing.
//!
//! **AUDIT SCOPE**: This module addresses the critical gap in OTLP trace export
//! under high load (10,000+ spans/sec). Previously, only metrics had load shedding.
//!
//! **OTLP BEST PRACTICES IMPLEMENTED**:
//! - Bounded span export queue with configurable capacity
//! - Drop OLDEST span batches when queue is full (preserve recent data)
//! - Track dropped spans count in `otel.exporter.dropped_spans` metric
//! - Maintain FIFO export order
//! - Background batch processing with configurable timeout

use crate::runtime::resource_monitor::{
    OverloadBrownoutLedger, OverloadBrownoutPhase, OverloadBrownoutReason,
};
use crossbeam_queue::ArrayQueue;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Default maximum length for OTLP span attribute values per OTLP §2.5.3.
/// Values exceeding this length are truncated with ellipsis suffix.
const DEFAULT_MAX_ATTRIBUTE_VALUE_LENGTH: usize = 255;

/// Truncate span attribute value per OTLP §2.5.3 specification.
///
/// **OTLP COMPLIANCE**: Attribute string values SHOULD be capped at ~255 characters
/// by default with ellipsis suffix when truncated. Respects UTF-8 character boundaries.
fn truncate_attribute_value(value: &str) -> String {
    if value.len() <= DEFAULT_MAX_ATTRIBUTE_VALUE_LENGTH {
        value.to_string()
    } else {
        // Find last char boundary at or before limit
        let mut end = DEFAULT_MAX_ATTRIBUTE_VALUE_LENGTH;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        let mut result = String::with_capacity(end + 3); // Reserve space for ellipsis
        result.push_str(&value[..end]);
        result.push('…'); // Unicode ellipsis character (3 bytes UTF-8)
        result
    }
}

/// Export error for OTLP trace exporter.
#[derive(Debug, Clone)]
pub enum ExportError {
    /// Network or transport error.
    Transport(String),
    /// Invalid data or format error.
    InvalidData(String),
    /// Rate limit exceeded.
    RateLimited,
    /// Service unavailable.
    Unavailable,
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "transport error: {}", msg),
            Self::InvalidData(msg) => write!(f, "invalid data: {}", msg),
            Self::RateLimited => write!(f, "rate limited"),
            Self::Unavailable => write!(f, "service unavailable"),
        }
    }
}

impl std::error::Error for ExportError {}

/// Load shedding statistics for monitoring.
#[derive(Debug, Clone)]
pub struct LoadSheddingStats {
    /// Current queue depth.
    pub queue_depth: usize,
    /// Maximum queue capacity.
    pub queue_capacity: usize,
    /// Total number of dropped batches.
    pub dropped_batches: u64,
    /// Total number of spans dropped by brownout priority filtering.
    pub brownout_dropped_spans: u64,
    /// Total number of spans retained as summary-only evidence during brownout.
    pub retained_summary_spans: u64,
}

/// OTLP-specific action selected from the shared brownout ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpBrownoutAction {
    /// Export all sampled spans through the normal queue.
    ExportAll,
    /// Drop spans marked low priority before they reach the queue.
    DropLowPriority,
    /// Skip queueing and retain only summary accounting for sampled spans.
    RetainSummaryOnly,
}

#[derive(Debug, Clone)]
struct OtlpBrownoutPolicyState {
    action: OtlpBrownoutAction,
    shared_phase: OverloadBrownoutPhase,
    fallback_used: bool,
    shared_reason_codes: Vec<OverloadBrownoutReason>,
}

impl Default for OtlpBrownoutPolicyState {
    fn default() -> Self {
        Self {
            action: OtlpBrownoutAction::ExportAll,
            shared_phase: OverloadBrownoutPhase::Normal,
            fallback_used: false,
            shared_reason_codes: Vec::new(),
        }
    }
}

/// Snapshot of the current OTLP brownout-aware exporter policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpBrownoutPolicySnapshot {
    /// Current OTLP-specific action.
    pub action: OtlpBrownoutAction,
    /// Shared runtime brownout phase the exporter is following.
    pub shared_phase: OverloadBrownoutPhase,
    /// Whether the exporter is running in standalone fallback mode.
    pub fallback_used: bool,
    /// Shared brownout reason codes copied into the exporter view.
    pub shared_reason_codes: Vec<OverloadBrownoutReason>,
    /// Total number of spans dropped by brownout priority filtering.
    pub brownout_dropped_spans: u64,
    /// Total number of spans retained as summary-only evidence during brownout.
    pub retained_summary_spans: u64,
    /// Total number of spans dropped by queue overflow replacement.
    pub queue_dropped_spans: u64,
}

/// Contract version for the OTLP tail-based sampling support boundary.
pub const OTLP_TAIL_SAMPLING_SCOPE_CONTRACT_VERSION: &str = "otlp-tail-sampling-scope-contract-v1";

/// Evidence owner bead for the current tail-based sampling support boundary.
pub const OTLP_TAIL_SAMPLING_SCOPE_BEAD_ID: &str = "asupersync-7s6";

/// Downstream proof bead that consumes this support boundary.
pub const OTLP_TAIL_SAMPLING_E2E_BEAD_ID: &str = "asupersync-uw9zg9";

/// Current production support class for OTLP tail-based sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpTailSamplingSupportClass {
    /// The runtime does not currently implement deferred, trace-completion-based
    /// sampling; downstream proof must record this as unsupported, not as a pass.
    ExplicitlyUnsupported,
}

impl OtlpTailSamplingSupportClass {
    /// Machine-readable `support_class` value for this support boundary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitlyUnsupported => "explicitly_unsupported",
        }
    }
}

/// Production support-scope snapshot for OTLP tail-based sampling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpTailSamplingScope {
    /// Version of this support-boundary contract.
    pub contract_version: &'static str,
    /// Bead that owns the truthfulness decision.
    pub bead_id: &'static str,
    /// Downstream E2E/proof bead that must consume this boundary.
    pub feeds_bead_id: &'static str,
    /// Support class consumed by implementation-completeness policy checks.
    pub support_class: OtlpTailSamplingSupportClass,
    /// Evidence quality for this boundary.
    pub evidence_quality: &'static str,
    /// Verdict expected for proof records until support lands.
    pub verdict: &'static str,
    /// Whether a production tail-based sampler is available.
    pub production_supported: bool,
    /// Production surfaces that are currently missing.
    pub missing_surfaces: &'static [&'static str],
    /// Required semantics for a future supported implementation.
    pub desired_semantics: &'static [&'static str],
}

impl OtlpTailSamplingScope {
    /// Machine-readable `support_class` field value.
    #[must_use]
    pub const fn support_class_str(&self) -> &'static str {
        self.support_class.as_str()
    }
}

/// Return the current production support stance for OTLP tail-based sampling.
///
/// This deliberately lives beside the trace exporter so audits and proof
/// scripts can query production truth instead of using an idealized local
/// sampler. The existing exporter supports head-based filtering via W3C
/// `trace_flags`; deferred tail decisions remain unsupported until a real
/// buffering/completion policy is implemented.
#[must_use]
pub const fn otlp_tail_based_sampling_scope() -> OtlpTailSamplingScope {
    OtlpTailSamplingScope {
        contract_version: OTLP_TAIL_SAMPLING_SCOPE_CONTRACT_VERSION,
        bead_id: OTLP_TAIL_SAMPLING_SCOPE_BEAD_ID,
        feeds_bead_id: OTLP_TAIL_SAMPLING_E2E_BEAD_ID,
        support_class: OtlpTailSamplingSupportClass::ExplicitlyUnsupported,
        evidence_quality: "unsupported",
        verdict: "unsupported",
        production_supported: false,
        missing_surfaces: &[
            "trace-completion detector",
            "bounded span buffer for deferred decisions",
            "late sampling policy API",
            "flush/shutdown behavior for undecided traces",
        ],
        desired_semantics: &[
            "policy match after trace completion",
            "consistent decision across every span in a trace",
            "bounded memory and trace-expiry behavior",
            "no trace leaks on cancellation, flush, or shutdown",
        ],
    }
}

/// Bounded export queue with oldest-drop load shedding.
///
/// **PERFORMANCE**: Uses lock-free ArrayQueue to eliminate mutex contention
/// under high-frequency span creation (100K+ spans/sec).
#[derive(Debug)]
pub struct BoundedExportQueue<T> {
    queue: ArrayQueue<T>,
    capacity: usize,
    dropped_count: AtomicU64,
}

impl<T> BoundedExportQueue<T> {
    /// Create a new bounded queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            capacity,
            dropped_count: AtomicU64::new(0),
        }
    }

    /// Enqueue an item, dropping the oldest if capacity is exceeded.
    /// Returns the dropped item when load shedding occurs.
    ///
    /// **LOCK-FREE**: Delegates to `ArrayQueue::force_push`, which atomically
    /// replaces the oldest entry when the buffer is full. An earlier
    /// implementation (br-asupersync-eup06n) used a manual pop+push protected
    /// by a Mutex; that lock only serialized overflow callers against each
    /// other, so concurrent fast-path producers could refill the slot opened
    /// by the overflow path's pop and panic the "overflow replacement must
    /// succeed" assertion under load.
    pub fn enqueue(&self, item: T) -> Option<T> {
        let dropped = self.queue.force_push(item);
        if dropped.is_some() {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
        }
        dropped
    }

    /// Dequeue the oldest item.
    ///
    /// **LOCK-FREE**: Uses atomic operations for zero-contention access.
    pub fn dequeue(&self) -> Option<T> {
        self.queue.pop()
    }

    /// Get current queue length.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Return true when no batches are queued.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get queue capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get total dropped count.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }
}

/// OTLP span batch for export.
#[derive(Debug, Clone)]
pub struct SpanBatch {
    /// Unique batch identifier for tracking.
    pub batch_id: u64,
    /// Spans in this batch.
    pub spans: Vec<OtlpSpan>,
    /// Timestamp when batch was created.
    pub created_at: std::time::Instant,
}

/// Simplified OTLP span representation for testing.
#[derive(Debug, Clone)]
pub struct OtlpSpan {
    /// Unique span identifier.
    pub span_id: String,
    /// Human-readable span name.
    pub name: String,
    /// Span start timestamp.
    pub start_time_unix_nano: u64,
    /// Span end timestamp.
    pub end_time_unix_nano: u64,
    /// Span attributes (key-value pairs).
    pub attributes: Vec<(String, String)>,
    /// Trace flags from W3C trace context (for head-based sampling).
    /// If None, span is assumed to be sampled for backward compatibility.
    pub trace_flags: Option<u8>,
}

impl OtlpSpan {
    /// Returns true if this span should be sampled (exported).
    ///
    /// **HEAD-BASED SAMPLING**: Per OTLP specification, spans with
    /// trace_flags=0 (not sampled) MUST be dropped before serialization.
    pub fn is_sampled(&self) -> bool {
        match self.trace_flags {
            Some(flags) => (flags & 0x01) != 0, // Check sampled bit
            None => true, // Backward compatibility: assume sampled if flags not set
        }
    }

    /// Create a new OTLP span with sampling information.
    ///
    /// **OTLP COMPLIANCE**: Attribute values are automatically truncated per §2.5.3
    /// to prevent payload bloat. Values exceeding 255 characters are truncated with
    /// ellipsis suffix while respecting UTF-8 boundaries.
    pub fn new_with_flags(
        span_id: String,
        name: String,
        start_time_unix_nano: u64,
        end_time_unix_nano: u64,
        attributes: Vec<(String, String)>,
        trace_flags: u8,
    ) -> Self {
        let truncated_attributes = attributes
            .into_iter()
            .map(|(key, value)| (key, truncate_attribute_value(&value)))
            .collect();

        Self {
            span_id,
            name,
            start_time_unix_nano,
            end_time_unix_nano,
            attributes: truncated_attributes,
            trace_flags: Some(trace_flags),
        }
    }

    /// Create a new OTLP span with automatic attribute truncation.
    ///
    /// **OTLP COMPLIANCE**: Convenience constructor that applies OTLP §2.5.3
    /// attribute value truncation automatically.
    pub fn new(
        span_id: String,
        name: String,
        start_time_unix_nano: u64,
        end_time_unix_nano: u64,
        attributes: Vec<(String, String)>,
    ) -> Self {
        let truncated_attributes = attributes
            .into_iter()
            .map(|(key, value)| (key, truncate_attribute_value(&value)))
            .collect();

        Self {
            span_id,
            name,
            start_time_unix_nano,
            end_time_unix_nano,
            attributes: truncated_attributes,
            trace_flags: None, // Backward compatibility: assume sampled if not set
        }
    }
}

/// Trait for OTLP trace exporters.
pub trait TraceExporter: Send + Sync + std::fmt::Debug {
    /// Export a batch of spans.
    fn export(&self, batch: &SpanBatch) -> Result<(), ExportError>;

    /// Flush any buffered spans.
    fn flush(&self) -> Result<(), ExportError>;
}

/// OTLP-compliant trace exporter with bounded export queue and oldest-drop load shedding.
///
/// **CRITICAL**: This implements the missing load shedding for trace exports that
/// was previously only available for metrics exports.
///
/// **Load Shedding Behavior**:
/// - When queue reaches `batch_capacity`, drops OLDEST span batches
/// - Preserves NEWEST span batches for recent observability
/// - Reports dropped span count in metrics per OTLP best practices
#[derive(Debug)]
pub struct LoadSheddingTraceExporter {
    inner: Box<dyn TraceExporter>,
    export_queue: BoundedExportQueue<SpanBatch>,
    batch_timeout: Duration,
    dropped_spans_metric: Arc<AtomicU64>,
    brownout_state: Mutex<OtlpBrownoutPolicyState>,
    brownout_dropped_spans_metric: Arc<AtomicU64>,
    retained_summary_spans_metric: Arc<AtomicU64>,
}

impl LoadSheddingTraceExporter {
    /// Create a new load shedding trace exporter.
    ///
    /// # Arguments
    /// * `inner` - Underlying trace exporter (e.g., OTLP HTTP exporter)
    /// * `batch_capacity` - Maximum number of span batches to queue (recommended: 100-1000)
    /// * `batch_timeout` - Maximum time to wait before flushing batches
    #[must_use]
    pub fn new(
        inner: Box<dyn TraceExporter>,
        batch_capacity: usize,
        batch_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            export_queue: BoundedExportQueue::new(batch_capacity),
            batch_timeout,
            dropped_spans_metric: Arc::new(AtomicU64::new(0)),
            brownout_state: Mutex::new(OtlpBrownoutPolicyState::default()),
            brownout_dropped_spans_metric: Arc::new(AtomicU64::new(0)),
            retained_summary_spans_metric: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get load shedding statistics for monitoring.
    #[must_use]
    pub fn load_shedding_stats(&self) -> LoadSheddingStats {
        LoadSheddingStats {
            queue_depth: self.export_queue.len(),
            queue_capacity: self.export_queue.capacity(),
            dropped_batches: self.export_queue.dropped_count(),
            brownout_dropped_spans: self.brownout_dropped_spans_count(),
            retained_summary_spans: self.retained_summary_spans_count(),
        }
    }

    /// Get the total number of dropped spans (sum across all dropped batches).
    ///
    /// **OTLP COMPLIANCE**: This provides the `otel.exporter.dropped_spans` metric
    /// required by OTLP best practices for observability of load shedding.
    #[must_use]
    pub fn dropped_spans_count(&self) -> u64 {
        self.dropped_spans_metric.load(Ordering::Relaxed)
    }

    /// Get the total number of spans dropped by brownout priority filtering.
    #[must_use]
    pub fn brownout_dropped_spans_count(&self) -> u64 {
        self.brownout_dropped_spans_metric.load(Ordering::Relaxed)
    }

    /// Get the total number of spans retained as summary-only brownout evidence.
    #[must_use]
    pub fn retained_summary_spans_count(&self) -> u64 {
        self.retained_summary_spans_metric.load(Ordering::Relaxed)
    }

    /// Update the exporter's brownout policy from the shared runtime brownout ledger.
    ///
    /// `None` keeps the exporter in its standalone conservative fallback path.
    pub fn update_brownout_policy(
        &self,
        brownout: Option<&OverloadBrownoutLedger>,
    ) -> OtlpBrownoutPolicySnapshot {
        let mut state = self.brownout_state.lock();
        match brownout {
            Some(ledger) => {
                state.action = Self::action_for_phase(ledger.phase);
                state.shared_phase = ledger.phase;
                state.fallback_used = ledger.fallback_used;
                state.shared_reason_codes.clone_from(&ledger.reason_codes);
            }
            None => {
                state.action = OtlpBrownoutAction::ExportAll;
                state.shared_phase = OverloadBrownoutPhase::Normal;
                state.fallback_used = true;
                state.shared_reason_codes.clear();
            }
        }
        drop(state);
        self.brownout_policy_snapshot()
    }

    /// Read the current brownout policy snapshot.
    #[must_use]
    pub fn brownout_policy_snapshot(&self) -> OtlpBrownoutPolicySnapshot {
        let state = self.brownout_state.lock().clone();
        OtlpBrownoutPolicySnapshot {
            action: state.action,
            shared_phase: state.shared_phase,
            fallback_used: state.fallback_used,
            shared_reason_codes: state.shared_reason_codes,
            brownout_dropped_spans: self.brownout_dropped_spans_count(),
            retained_summary_spans: self.retained_summary_spans_count(),
            queue_dropped_spans: self.dropped_spans_count(),
        }
    }

    fn action_for_phase(phase: OverloadBrownoutPhase) -> OtlpBrownoutAction {
        match phase {
            OverloadBrownoutPhase::Normal | OverloadBrownoutPhase::Observe => {
                OtlpBrownoutAction::ExportAll
            }
            OverloadBrownoutPhase::Degrade | OverloadBrownoutPhase::Recovery => {
                OtlpBrownoutAction::DropLowPriority
            }
            OverloadBrownoutPhase::ShedOptional => OtlpBrownoutAction::RetainSummaryOnly,
        }
    }

    fn is_low_priority_span(span: &OtlpSpan) -> bool {
        span.attributes.iter().any(|(key, value)| {
            (key == "otlp.priority" || key == "observability.priority") && value == "low"
        })
    }

    /// Process all queued span batches (called by background export task).
    ///
    /// Returns the number of batches successfully processed.
    pub fn process_queue(&self) -> Result<usize, ExportError> {
        let mut processed = 0;
        let mut _total_spans_processed = 0;

        while let Some(batch) = self.export_queue.dequeue() {
            // Track aging of batches (warn if spans are getting stale)
            let batch_age = batch.created_at.elapsed();
            if batch_age > Duration::from_secs(30) {
                #[cfg(feature = "tracing-integration")]
                crate::tracing_compat::warn!(
                    target: "asupersync::observability::otlp_trace",
                    "Exporting stale span batch: age={}s, spans={}",
                    batch_age.as_secs(),
                    batch.spans.len()
                );
            }

            // Export the batch
            self.inner.export(&batch)?;
            processed += 1;
            _total_spans_processed += batch.spans.len();

            // Apply batch timeout to prevent blocking export thread too long
            if batch.created_at.elapsed() > self.batch_timeout {
                break;
            }
        }

        #[cfg(feature = "tracing-integration")]
        if processed > 0 {
            crate::tracing_compat::trace!(
                target: "asupersync::observability::otlp_trace",
                "Processed {} span batches ({} spans)",
                processed,
                _total_spans_processed
            );
        }

        Ok(processed)
    }
}

impl TraceExporter for LoadSheddingTraceExporter {
    /// Export span batch with head-based sampling and load shedding.
    ///
    /// **HEAD-BASED SAMPLING**: Per OTLP specification, spans with trace_flags=0
    /// (not sampled) are filtered out before export. This prevents unnecessary
    /// network overhead and storage costs for unsampled traces.
    ///
    /// **LOAD SHEDDING**: When queue is full, drops OLDEST batch to preserve
    /// recent observability data. Updates `otel.exporter.dropped_spans` metric.
    fn export(&self, batch: &SpanBatch) -> Result<(), ExportError> {
        // **HEAD-BASED SAMPLING**: Filter out unsampled spans before export
        let sampled_spans: Vec<OtlpSpan> = batch
            .spans
            .iter()
            .filter(|span| span.is_sampled())
            .cloned()
            .collect();

        let unsampled_count = batch.spans.len() - sampled_spans.len();
        if unsampled_count > 0 {
            #[cfg(feature = "tracing-integration")]
            crate::tracing_compat::debug!(
                target: "asupersync::observability::otlp_trace",
                "Head-based sampling: dropped {} unsampled spans (trace_flags=0), \
                 exporting {} sampled spans",
                unsampled_count,
                sampled_spans.len()
            );
        }

        // Skip export if no spans remain after sampling
        if sampled_spans.is_empty() {
            return Ok(());
        }

        let brownout_state = self.brownout_state.lock().clone();
        let mut sampled_spans = sampled_spans;
        match brownout_state.action {
            OtlpBrownoutAction::ExportAll => {}
            OtlpBrownoutAction::DropLowPriority => {
                let before = sampled_spans.len();
                sampled_spans.retain(|span| !Self::is_low_priority_span(span));
                let dropped = (before - sampled_spans.len()) as u64;
                if dropped > 0 {
                    self.brownout_dropped_spans_metric
                        .fetch_add(dropped, Ordering::Relaxed);
                }
                if sampled_spans.is_empty() {
                    return Ok(());
                }
            }
            OtlpBrownoutAction::RetainSummaryOnly => {
                self.retained_summary_spans_metric
                    .fetch_add(sampled_spans.len() as u64, Ordering::Relaxed);
                return Ok(());
            }
        }

        // Create filtered batch with only sampled spans
        let filtered_batch = SpanBatch {
            batch_id: batch.batch_id,
            spans: sampled_spans,
            created_at: batch.created_at,
        };

        if let Some(dropped_batch) = self.export_queue.enqueue(filtered_batch) {
            let dropped_spans = dropped_batch.spans.len() as u64;

            // Update dropped spans metric (required by OTLP best practices)
            self.dropped_spans_metric
                .fetch_add(dropped_spans, Ordering::Relaxed);

            #[cfg(feature = "tracing-integration")]
            crate::tracing_compat::warn!(
                target: "asupersync::observability::otlp_trace",
                "OTLP trace export queue full: dropped oldest span batch ({} spans). \
                 Queue capacity: {}, total dropped spans: {}",
                dropped_spans,
                self.export_queue.capacity(),
                self.dropped_spans_count()
            );
        }

        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        // Process all queued batches then flush underlying exporter
        self.process_queue()?;
        self.inner.flush()
    }
}

impl Drop for LoadSheddingTraceExporter {
    /// Graceful shutdown with bounded timeout per OTLP specification.
    ///
    /// **OTLP COMPLIANCE**: When exporter is dropped (runtime shutdown, service restart),
    /// attempt to flush pending spans within bounded timeout to prevent data loss.
    ///
    /// **Timeout Strategy**:
    /// - Maximum 3 seconds for graceful flush
    /// - Uses existing flush() mechanism with timeout wrapper
    /// - Partial success acceptable if timeout is reached
    /// - Prevents shutdown deadlock while minimizing data loss
    ///
    /// **Critical for**:
    /// - Service deployments and restarts
    /// - Container termination and scaling
    /// - Process crash recovery scenarios
    /// - Observability continuity during incidents
    fn drop(&mut self) {
        const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

        let queue_depth = self.export_queue.len();
        if queue_depth == 0 {
            return; // No pending spans to flush
        }

        #[cfg(feature = "tracing-integration")]
        crate::tracing_compat::info!(
            target: "asupersync::observability::otlp_trace",
            "OTLP exporter graceful shutdown: flushing {} pending batches (timeout: {:?})",
            queue_depth,
            SHUTDOWN_TIMEOUT
        );

        let flush_start = std::time::Instant::now();

        // Attempt graceful flush with timeout
        // We use a simplified approach that doesn't involve threading to avoid borrowing issues
        let flush_result = loop {
            // Check if we've exceeded the timeout
            if flush_start.elapsed() >= SHUTDOWN_TIMEOUT {
                #[cfg(feature = "tracing-integration")]
                crate::tracing_compat::warn!(
                    target: "asupersync::observability::otlp_trace",
                    "OTLP exporter shutdown timeout ({:?}): abandoning {} pending batches to prevent deadlock",
                    SHUTDOWN_TIMEOUT,
                    self.export_queue.len()
                );
                break Err(ExportError::Transport("shutdown timeout".to_string()));
            }

            // Process a single batch with short timeout to avoid blocking
            if let Some(batch) = self.export_queue.dequeue() {
                match self.inner.export(&batch) {
                    Ok(()) => {
                        // Successfully exported, continue with next batch
                    }
                    Err(_e) => {
                        #[cfg(feature = "tracing-integration")]
                        crate::tracing_compat::warn!(
                            target: "asupersync::observability::otlp_trace",
                            "OTLP exporter shutdown: export failed for batch, continuing with remaining: {}",
                            _e
                        );
                        // Continue trying to export remaining batches even if one fails
                    }
                }
            } else {
                // No more batches in queue - flush underlying exporter
                match self.inner.flush() {
                    Ok(()) => {
                        break Ok(());
                    }
                    Err(e) => {
                        break Err(e);
                    }
                }
            }
        };

        let _flush_duration = flush_start.elapsed();
        let final_queue_depth = self.export_queue.len();
        let _batches_flushed = queue_depth.saturating_sub(final_queue_depth);

        match flush_result {
            Ok(()) => {
                #[cfg(feature = "tracing-integration")]
                crate::tracing_compat::info!(
                    target: "asupersync::observability::otlp_trace",
                    "OTLP exporter graceful shutdown completed: {} batches flushed in {:?}",
                    _batches_flushed,
                    _flush_duration
                );
            }
            Err(_e) => {
                #[cfg(feature = "tracing-integration")]
                crate::tracing_compat::warn!(
                    target: "asupersync::observability::otlp_trace",
                    "OTLP exporter shutdown flush failed: {} (flushed {} of {} batches in {:?})",
                    _e,
                    _batches_flushed,
                    queue_depth,
                    _flush_duration
                );
            }
        }
    }
}

/// In-memory OTLP exporter for deterministic load-shedding and shutdown tests.
#[derive(Clone)]
pub struct InMemoryOtlpHttpExporter {
    exported_batches: Arc<Mutex<Vec<SpanBatch>>>,
    export_delay: Duration,
}

impl InMemoryOtlpHttpExporter {
    /// Create a new in-memory exporter with deterministic per-batch latency.
    #[must_use]
    pub fn new(export_delay: Duration) -> Self {
        Self {
            exported_batches: Arc::new(Mutex::new(Vec::new())),
            export_delay,
        }
    }

    /// Get all exported batches for verification.
    #[must_use]
    pub fn exported_batches(&self) -> Vec<SpanBatch> {
        self.exported_batches.lock().clone()
    }

    /// Get the total number of exported spans.
    #[must_use]
    pub fn exported_span_count(&self) -> usize {
        self.exported_batches
            .lock()
            .iter()
            .map(|batch| batch.spans.len())
            .sum()
    }
}

impl TraceExporter for InMemoryOtlpHttpExporter {
    fn export(&self, batch: &SpanBatch) -> Result<(), ExportError> {
        std::thread::sleep(self.export_delay);

        self.exported_batches.lock().push(batch.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

impl std::fmt::Debug for InMemoryOtlpHttpExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryOtlpHttpExporter")
            .field("export_delay", &self.export_delay)
            .field(
                "exported_batches_count",
                &self.exported_batches.lock().len(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn create_test_span(span_id: &str, name: &str) -> OtlpSpan {
        OtlpSpan {
            span_id: span_id.to_string(),
            name: name.to_string(),
            start_time_unix_nano: 1000000000,
            end_time_unix_nano: 1000001000,
            attributes: vec![("service".to_string(), "test".to_string())],
            trace_flags: Some(0x01), // Default to sampled for backward compatibility
        }
    }

    fn create_test_batch(batch_id: u64, span_count: usize) -> SpanBatch {
        let spans = (0..span_count)
            .map(|i| create_test_span(&format!("span-{}-{}", batch_id, i), "test_operation"))
            .collect();

        SpanBatch {
            batch_id,
            spans,
            created_at: Instant::now(),
        }
    }

    /// **AUDIT TEST**: Verifies OTLP trace exporter load shedding under high load.
    ///
    /// **SCENARIO**: 10,000+ spans/sec arrive, batch_size=512, queue capacity=3
    /// **REQUIREMENT**: Spans are dropped when batch fills, oldest-drop behavior
    /// **METRICS**: `otel.exporter.dropped_spans` correctly reports dropped count
    #[test]
    fn audit_otlp_trace_exporter_high_load_shedding() {
        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
        let queue_capacity = 3;
        let batch_timeout = Duration::from_secs(1);

        let exporter = LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            queue_capacity,
            batch_timeout,
        );

        // Create batches with 512 spans each (typical OTLP batch size)
        let batch_size = 512;
        let batches: Vec<SpanBatch> = (0..6).map(|i| create_test_batch(i, batch_size)).collect();

        // Submit batches beyond capacity to trigger load shedding
        for batch in &batches {
            let result = exporter.export(batch);
            assert!(
                result.is_ok(),
                "export should succeed even during load shedding"
            );
        }

        // Verify load shedding statistics
        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.queue_capacity, 3, "queue capacity should be 3");
        assert_eq!(stats.queue_depth, 3, "queue should be at capacity");
        assert_eq!(
            stats.dropped_batches, 3,
            "should have dropped 3 oldest batches"
        );

        // **CRITICAL**: Verify dropped spans metric (OTLP compliance requirement)
        let expected_dropped_spans = 3 * batch_size as u64; // 3 batches × 512 spans each
        assert_eq!(
            exporter.dropped_spans_count(),
            expected_dropped_spans,
            "otel.exporter.dropped_spans must track total dropped spans"
        );

        // Process queue and verify only newest batches were preserved
        let processed = exporter
            .process_queue()
            .expect("queue processing should succeed");
        assert_eq!(processed, 3, "should process 3 remaining batches");

        let exported = memory_exporter.exported_batches();
        assert_eq!(exported.len(), 3, "should have exported 3 batches");

        // Verify NEWEST batches were preserved (batch IDs 3, 4, 5)
        let exported_batch_ids: Vec<u64> = exported.iter().map(|b| b.batch_id).collect();
        assert_eq!(
            exported_batch_ids,
            vec![3, 4, 5],
            "should preserve NEWEST batches and drop oldest (0,1,2)"
        );

        println!("✅ OTLP TRACE EXPORTER LOAD SHEDDING AUDIT PASSED");
        println!("   Queue capacity: {}", stats.queue_capacity);
        println!("   Dropped batches: {}", stats.dropped_batches);
        println!("   Dropped spans: {}", exporter.dropped_spans_count());
        println!("   Preserved batches: {:?}", exported_batch_ids);
    }

    /// **AUDIT TEST**: Normal operation without load shedding.
    #[test]
    fn audit_normal_operation_no_shedding() {
        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
        let exporter = LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            10, // Large capacity
            Duration::from_secs(1),
        );

        // Submit batches within capacity
        for i in 0..5 {
            let batch = create_test_batch(i, 100);
            exporter.export(&batch).expect("export should succeed");
        }

        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.dropped_batches, 0, "no batches should be dropped");
        assert_eq!(
            exporter.dropped_spans_count(),
            0,
            "no spans should be dropped"
        );

        exporter
            .process_queue()
            .expect("queue processing should succeed");
        let exported_spans = memory_exporter.exported_span_count();
        assert_eq!(exported_spans, 500, "all 500 spans should be exported");

        println!("✅ NORMAL OPERATION AUDIT PASSED - No load shedding");
    }

    /// **AUDIT TEST**: FIFO order preservation during load shedding.
    #[test]
    fn audit_fifo_order_preserved_during_shedding() {
        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
        let exporter = LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            2, // Very small capacity
            Duration::from_secs(1),
        );

        // Submit 4 batches, expect FIFO processing of newest 2
        for i in 0..4 {
            let batch = create_test_batch(i, 10);
            exporter.export(&batch).expect("export should succeed");
        }

        exporter
            .process_queue()
            .expect("queue processing should succeed");
        let exported = memory_exporter.exported_batches();

        // Should export batches 2,3 in FIFO order (oldest batches 0,1 dropped)
        assert_eq!(exported.len(), 2, "should export 2 batches");
        assert_eq!(exported[0].batch_id, 2, "first exported should be batch 2");
        assert_eq!(exported[1].batch_id, 3, "second exported should be batch 3");

        println!("✅ FIFO ORDER AUDIT PASSED - Correct processing order maintained");
    }

    /// br-asupersync-eup06n: regression test for the multi-producer overflow
    /// race. Many concurrent producers + a tiny capacity used to trip the
    /// `assert!(...push.is_ok(), "overflow replacement must succeed")` panic
    /// on a saturated queue. With `force_push` the enqueue must always make
    /// progress without panicking, and the dropped count must equal
    /// (total_pushes - capacity).
    #[test]
    fn enqueue_does_not_panic_under_concurrent_overload() {
        use std::sync::Arc;
        use std::thread;

        const CAPACITY: usize = 8;
        const PRODUCERS: usize = 16;
        const PER_PRODUCER: usize = 4096;

        let queue: Arc<BoundedExportQueue<u64>> = Arc::new(BoundedExportQueue::new(CAPACITY));

        let mut handles = Vec::with_capacity(PRODUCERS);
        for producer in 0..PRODUCERS {
            let queue = Arc::clone(&queue);
            handles.push(thread::spawn(move || {
                let base = (producer as u64) * (PER_PRODUCER as u64);
                for offset in 0..PER_PRODUCER {
                    let _ = queue.enqueue(base + offset as u64);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("producer must not panic");
        }

        let dropped = queue.dropped_count();
        let len = queue.len();
        let total = (PRODUCERS * PER_PRODUCER) as u64;
        assert_eq!(
            dropped + len as u64,
            total,
            "every push must either land in the queue or be counted as dropped",
        );
        assert!(len <= CAPACITY, "queue must respect capacity");
        assert_eq!(
            dropped,
            total - len as u64,
            "dropped count must equal total minus retained",
        );
    }
}
