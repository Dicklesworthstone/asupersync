//! Comprehensive observability and logging infrastructure.
//!
//! This module provides structured observability primitives for the Asupersync
//! runtime and RaptorQ distributed layer. Unlike the low-level `trace` module
//! (which is optimized for deterministic replay), this module provides:
//!
//! - **Structured logging** with severity levels and rich context
//! - **Metrics** for runtime statistics (counters, gauges, histograms)
//! - **Diagnostic context** for hierarchical operation tracking
//! - **Event batching** for efficient reporting
//! - **Configuration** for runtime observability settings
//!
//! # Design Principles
//!
//! 1. **No stdout/stderr in core**: All output goes through structured types
//! 2. **Determinism-compatible**: Metrics use explicit time, not wall clock
//! 3. **Zero-allocation hot path**: Critical paths avoid heap allocation
//! 4. **Composable**: Works with both lab runtime and production
//!
//! # Example
//!
//! ```ignore
//! use asupersync::observability::{LogEntry, LogLevel, Metrics, ObservabilityConfig};
//!
//! let config = ObservabilityConfig::default()
//!     .with_log_level(LogLevel::Info)
//!     .with_sample_rate(0.1);
//!
//! let mut metrics = Metrics::new();
//! metrics.counter("symbols_encoded").increment(1);
//! metrics.gauge("pending_symbols").set(42);
//!
//! let entry = LogEntry::info("Symbol encoded successfully")
//!     .with_field("object_id", "Obj-12345678")
//!     .with_field("symbol_count", "10");
//! ```

pub mod analyzer_plugin;
#[cfg(test)]
pub mod batch_span_processor_flush_audit_test;
pub mod cancellation_analyzer;
pub mod cancellation_debt_monitor;
pub mod cancellation_tracer;
pub mod cancellation_visualizer;
#[cfg(all(test, feature = "metrics"))]
pub mod cardinality_limits_audit_test;
pub mod collector;
pub mod context;
pub mod debt_runtime_integration;
pub mod diagnostics;
pub mod entry;
#[cfg(test)]
pub mod head_based_sampling_audit_test;
#[cfg(feature = "metrics")]
pub mod histogram_conformance;
pub mod level;
pub mod metrics;
#[cfg(test)]
pub mod mock_code_finder_clean_sweep_audit_test;
#[cfg(test)]
pub mod multi_runtime_subscriber_audit_test;
pub mod network_diagnostics;
pub mod network_truth;
pub mod obligation_tracker;
#[cfg(feature = "metrics")]
pub mod otel;
#[cfg(test)]
pub mod otel_conformance_tests;
#[cfg(test)]
pub mod otel_sampling_strategy_audit_test;
pub mod otel_structured_concurrency;
#[cfg(test)]
pub mod otlp_attribute_size_cap_audit_test;
// br-asupersync-lf1a77: stale OTLP audit files that depended on removed
// synthetic HTTP/span APIs remain tracked in-place, but their invariants are
// normalized into compiled production-seam tests and the OTLP inventory artifact
// before re-entry.
#[cfg(test)]
pub mod otlp_add_attributes_missing_api_audit_test;
#[cfg(test)]
pub mod otlp_clock_skew_handling_audit_test;
#[cfg(test)]
pub mod otlp_collector_oom_recovery_audit_test;
#[cfg(test)]
pub mod otlp_compression_audit_test;
#[cfg(test)]
pub mod otlp_compression_negotiation_audit_test;
pub mod otlp_dst_clock_jump_audit_test;
#[cfg(test)]
pub mod otlp_empty_key_attribute_audit_test;
#[cfg(test)]
pub mod otlp_graceful_shutdown_audit_test;
#[cfg(test)]
pub mod otlp_high_frequency_span_audit_test;
#[cfg(test)]
pub mod otlp_metrics_collection_interval_audit_test;
#[cfg(test)]
pub mod otlp_network_partition_audit_test;
#[cfg(test)]
pub mod otlp_partial_success_audit_test;
#[cfg(test)]
pub mod otlp_resource_attributes_inheritance_audit_test;
#[cfg(test)]
pub mod otlp_resource_detection_priority_audit_test;
#[cfg(test)]
pub mod otlp_retry_after_audit_test;
#[cfg(test)]
pub mod otlp_runtime_drop_deadlock_audit_test;
#[cfg(test)]
pub mod otlp_session_resumption_audit_test;
#[cfg(test)]
pub mod otlp_span_deduplication_audit_test;
#[cfg(test)]
pub mod otlp_span_event_timestamping_audit_test;
#[cfg(test)]
pub mod otlp_tail_based_sampling_audit_test;
pub mod otlp_trace_exporter;
#[cfg(test)]
pub mod otlp_trace_state_propagation_audit_test;
#[cfg(test)]
pub mod otlp_unexpected_status_audit_test;
#[cfg(test)]
pub mod otlp_upgrade_required_audit_test;
pub mod performance_budget_monitor;
pub mod pressure_governor;
pub mod resource_accounting;
#[cfg(all(test, feature = "metrics"))]
pub mod resource_attribute_merging_audit_test;
pub mod runtime_integration;
#[cfg(test)]
pub mod runtime_metrics_endpoint_audit_test;
#[cfg(test)]
pub mod sampling_decision_propagation_audit_test;
#[cfg(test)]
pub mod span_id_collision_audit_test;
#[cfg(test)]
pub mod span_lifecycle_obligation_leak_audit_test;
#[cfg(test)]
pub mod span_propagation_audit_test;
pub mod spectral_health;
pub mod structured_cancellation_analyzer;
#[cfg(test)]
pub mod subscriber_installation_order_audit_test;
pub mod swarm_pressure_governor;
pub mod task_inspector;
#[cfg(all(test, feature = "metrics"))]
pub mod tls_configuration_audit_test;
#[cfg(test)]
pub mod trace_id_format_audit_test;
#[cfg(test)]
pub mod trace_id_high_load_audit_test;
#[cfg(test)]
pub mod w3c_baggage_propagation_audit_test;
pub mod w3c_trace_context;
#[cfg(test)]
pub mod w3c_trace_id_randomness_audit_test;

pub use analyzer_plugin::{
    ANALYZER_PLUGIN_CONTRACT_VERSION, AggregatedAnalyzerFinding, AnalyzerCapability,
    AnalyzerFinding, AnalyzerOutput, AnalyzerPlugin, AnalyzerPluginDescriptor,
    AnalyzerPluginPackReport, AnalyzerPluginRegistry, AnalyzerPluginRunError, AnalyzerRequest,
    AnalyzerSandboxPolicy, AnalyzerSchemaVersion, AnalyzerSeverity, PluginExecutionRecord,
    PluginExecutionState, PluginLifecycleEvent, PluginLifecyclePhase, PluginRegistrationError,
    SchemaDecision, SchemaNegotiation, negotiate_schema_version, run_analyzer_plugin_pack_smoke,
};
pub use cancellation_analyzer::{
    AnalyzerConfig as CancellationAnalyzerConfig, BottleneckAnalysis, CancellationAnalyzer,
    CleanupEfficiency, CleanupTimingAnalysis, DistributionStats, EntityPerformance,
    ImplementationComplexity, OptimizationRecommendation, PerformanceAnalysis,
    PerformanceRegression, RecommendationPriority, ThroughputMetrics, TrendAnalysis,
    TrendDirection,
};
pub use cancellation_debt_monitor::{
    CancellationDebtConfig, CancellationDebtMonitor, DebtAlert, DebtAlertLevel, DebtSnapshot,
    PendingWork, WorkType,
};
pub use cancellation_tracer::{
    CancellationAnalysis, CancellationTrace, CancellationTraceId, CancellationTraceStep,
    CancellationTracer, CancellationTracerConfig, CancellationTracerStats,
    CancellationTracerStatsSnapshot, EntityType, PropagationAnomaly, analyze_cancellation_patterns,
};
pub use cancellation_visualizer::{
    AnomalyInfo, AnomalySeverity, BottleneckInfo, CancellationDashboard, CancellationTreeNode,
    CancellationVisualizer, ThroughputStats, TimingFormat, VisualizerConfig,
};
pub use collector::LogCollector;
pub use context::{DiagnosticContext, Span, SpanId};
pub use debt_runtime_integration::{DebtHealthReport, DebtRuntimeIntegration};
pub use diagnostics::{
    BlockReason, CancelReasonInfo, CancellationExplanation, CancellationStep, DeadlockCycle,
    DeadlockSeverity, Diagnostics, DirectionalDeadlockReport, ObligationLeak, Reason,
    RegionOpenExplanation, TAIL_LATENCY_BUDGET_CERTIFICATE_SCHEMA_VERSION,
    TAIL_LATENCY_COMPACT_EVENT_SCHEMA_VERSION, TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION,
    TailLatencyBudgetCertificate, TailLatencyBudgetEvidence, TailLatencyBudgetGate,
    TailLatencyBudgetQuantiles, TailLatencyBudgetTermEvidence, TailLatencyBudgetUncertainty,
    TailLatencyBudgetVerdict, TailLatencyCompactEvent, TailLatencyCompactSample,
    TailLatencyEmitError, TailLatencyEmitterConfig, TailLatencyFieldValue, TailLatencyLogFieldSpec,
    TailLatencySignalSpec, TailLatencyTaxonomyContract, TailLatencyTermSpec,
    TaskBlockedExplanation, WAIT_CAUSE_REMEDIATION_REPORT_SCHEMA_VERSION, WaitCauseCategory,
    WaitCauseObligationEvidence, WaitCauseRemediationEvidence, WaitCauseRemediationFinding,
    WaitCauseRemediationReport, WaitCauseRemediationVerdict, WaitCauseSeverity,
    WaitCauseTaskEvidence, WaitCauseTaskWaitKind, build_wait_cause_remediation_report,
    emit_tail_latency_compact_event, tail_latency_taxonomy_contract,
    verify_tail_latency_budget_certificate,
};
pub use entry::LogEntry;
pub use level::LogLevel;
pub use metrics::{
    Counter, Gauge, Histogram, MetricValue, Metrics, MetricsProvider, NoOpMetrics, OutcomeKind,
};
pub use network_diagnostics::{
    LimitingFactor, NetworkDiagnosticCli, NetworkDiagnosticReport, NetworkDiagnosticReporter,
    NetworkSummary, PressureLevel,
};
pub use network_truth::{
    MetricEstimate, NetworkTruthCollector, NetworkTruthMetrics, PathQuality, PressureModel,
};
pub use obligation_tracker::{
    ObligationInfo, ObligationStateInfo, ObligationSummary, ObligationTracker,
    ObligationTrackerConfig, TypeSummary,
};
#[cfg(feature = "metrics")]
pub use otel::{
    CardinalityOverflow, ExportError, InMemoryExporter, InMemoryLogsExporter,
    LoadSheddingLogsExporter, LogAttributes, LogsExporter, LogsSnapshot, MetricsConfig,
    MetricsExporter, MetricsSnapshot, MultiExporter, MultiLogsExporter, NullExporter,
    NullLogsExporter, OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES, OTLP_LOGS_MAX_ATTRIBUTES,
    OTLP_LOGS_SCHEMA_URL, OTLP_LOGS_SCOPE_NAME, OtelMetrics, OtlpLogRecord, OtlpLogsHttpExporter,
    SamplingConfig, StdoutExporter, log_level_to_otlp_severity,
};
pub use otel_structured_concurrency::{
    EntityId, OtelStructuredConcurrencyConfig, SpanStorage, SpanType,
};
pub use otlp_trace_exporter::{
    LoadSheddingTraceExporter, OTLP_TAIL_SAMPLING_E2E_BEAD_ID, OTLP_TAIL_SAMPLING_SCOPE_BEAD_ID,
    OTLP_TAIL_SAMPLING_SCOPE_CONTRACT_VERSION, OtlpSpan, OtlpTailSamplingScope,
    OtlpTailSamplingSupportClass, SpanBatch, TraceExporter, otlp_tail_based_sampling_scope,
};
pub use performance_budget_monitor::{
    BudgetAlert, BudgetDirection, BudgetEvaluation, BudgetSample, BudgetSeverity,
    PerformanceBudget, PerformanceBudgetMonitor, PerformanceBudgetSnapshot,
};
pub use pressure_governor::{
    AdmissionDecision, PressureGovernor, PressureGovernorConfig, PressureSnapshot,
    PressureThresholds,
};
pub use resource_accounting::{
    AdmissionKindStats, ObligationKindStats, ResourceAccounting, ResourceAccountingSnapshot,
};
pub use structured_cancellation_analyzer::{
    AlertSeverity, AlertType, CancellationAlert, LabRuntimeIntegration, RealTimeStats,
    StructuredCancellationAnalyzer, StructuredCancellationConfig,
};
pub use swarm_pressure_governor::{
    ResourceEnvelope, SwarmAdmissionDecision, SwarmAdmissionDecisionReceipt, SwarmAdmissionOwner,
    SwarmAdmissionWorkloadReceipt, SwarmPressureError, SwarmPressureGovernor,
    SwarmPressureGovernorConfig, SwarmPressureMetrics, SwarmProofLaneKind,
    SwarmWorkloadAdmissionRequest, SwarmWorkloadLeaseId, SwarmWorkloadLeaseReceipt,
    SwarmWorkloadLeaseScheduleEntry, SwarmWorkloadLeaseState, SwarmWorkloadPressureFeedback,
    SwarmWorkloadPressureSource,
};
pub use task_inspector::{
    TASK_CONSOLE_WIRE_SCHEMA_V1, TaskConsoleWireSnapshot, TaskDetails, TaskDetailsWire,
    TaskInspector, TaskInspectorConfig, TaskRegionCountWire, TaskStateInfo, TaskSummary,
    TaskSummaryWire,
};
pub use w3c_trace_context::{
    SpanId as W3CSpanId, TraceContextError, TraceFlags, TraceId, W3CBaggage, W3CPropagationContext,
    W3CTraceContext, extract_baggage_from_http, extract_from_http, extract_propagation_from_http,
    inject_baggage_to_http, inject_to_grpc, inject_to_http,
};

/// br-asupersync-z5ge0x: globally-installable observability clock for
/// ambient-context (no-Cx) callers.
///
/// Lab runtimes / replay harnesses install this once at test setup so
/// observability records emitted from Drop impls, panic handlers,
/// background sweeps spawned outside the runtime, and other ambient
/// contexts derive their wall-clock from a deterministic source instead
/// of leaking `SystemTime::now()`. Production code does NOT install
/// anything; the no-Cx path then falls back to ambient `SystemTime::now()`
/// as before, but the fallback emits `tracing::warn!` exactly once per
/// process so the leak is visible to operators.
///
/// `OnceLock` semantics: the clock can be installed at most once per
/// process. Subsequent installation attempts are no-ops (the first
/// installation wins). This matches the singleton lifetime of a
/// process-wide deterministic time source.
static GLOBAL_OBSERVABILITY_CLOCK: std::sync::OnceLock<fn() -> std::time::SystemTime> =
    std::sync::OnceLock::new();

/// Latch (br-asupersync-z5ge0x) ensuring the ambient-fallback warning
/// fires at most once per process. Without this, observability emitted
/// from a hot Drop path or panic handler could flood the log every time
/// it ran outside a Cx scope.
static AMBIENT_FALLBACK_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Error returned when installing the process-global observability clock fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalObservabilityClockInstallError {
    /// A global observability clock has already been installed for this process.
    AlreadyInstalled,
}

impl std::fmt::Display for GlobalObservabilityClockInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInstalled => f.write_str("global observability clock already installed"),
        }
    }
}

impl std::error::Error for GlobalObservabilityClockInstallError {}

/// Installs the process-global observability clock used by
/// [`replayable_system_time`] when no `Cx` is in scope (br-asupersync-z5ge0x).
///
/// Returns `Ok(())` on the first installation and
/// [`GlobalObservabilityClockInstallError::AlreadyInstalled`] on every
/// subsequent attempt — the OnceLock semantics mean the first install wins for
/// the lifetime of the process. Lab runtimes and replay harnesses MUST call this
/// at test setup; production should not call it (and will then receive the
/// explicit warn-once when ambient fallback fires).
///
/// The provided `clock_fn` MUST be deterministic for replay
/// guarantees — typically a closure-free `fn` pointer that consults a
/// virtual clock in static state or a counter.
pub fn install_global_observability_clock(
    clock_fn: fn() -> std::time::SystemTime,
) -> Result<(), GlobalObservabilityClockInstallError> {
    GLOBAL_OBSERVABILITY_CLOCK
        .set(clock_fn)
        .map_err(|_| GlobalObservabilityClockInstallError::AlreadyInstalled)
}

/// Returns a wall-clock `SystemTime` that is replayable when an asupersync
/// `Cx` with an installed timer driver is in scope.
///
/// **Resolution order (br-asupersync-z5ge0x):**
/// 1. If a `Cx` is current, derive `SystemTime` from `cx.now_for_observability()`
///    — fully deterministic and replayable.
/// 2. Else if a global observability clock has been installed via
///    [`install_global_observability_clock`], call it — deterministic for
///    lab/replay runs that install a virtual clock at test setup.
/// 3. Else fall back to `SystemTime::now()` AND emit `tracing::warn!`
///    exactly once per process. The fallback breaks replay determinism
///    for any record that uses it, so the warn line lets operators
///    spot ambient-context observability they may have missed (Drop
///    impls, panic handlers, background sweeps spawned outside the
///    runtime, `std::thread::spawn`'d helpers).
///
/// The `pub` ↔ `pub(crate)` distinction matters: this is `pub(crate)`
/// because production callers should not be designing their
/// observability around the timestamp source — they should just emit
/// records and the resolution policy is centralized here.
///
/// For callers that want the strict "no deterministic source available
/// → skip the record entirely" semantic, see
/// [`try_replayable_system_time`].
///
/// This is the canonical replacement for direct `std::time::SystemTime::now()`
/// calls inside `src/observability/*` per asupersync_plan_v4.md §I7
/// (no ambient authority for time queries).
#[must_use]
pub(crate) fn replayable_system_time() -> std::time::SystemTime {
    if let Some(cx) = crate::cx::Cx::current() {
        let nanos = cx.now_for_observability().as_nanos();
        return std::time::UNIX_EPOCH + std::time::Duration::from_nanos(nanos);
    }
    if let Some(clock_fn) = GLOBAL_OBSERVABILITY_CLOCK.get() {
        return clock_fn();
    }
    // Ambient fallback. Warn once per process so the leak is visible.
    if !AMBIENT_FALLBACK_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        crate::tracing_compat::warn!(
            "observability: replayable_system_time fell back to \
             ambient SystemTime::now() — observability records emitted \
             outside a Cx scope and without a globally-installed \
             observability clock break replay determinism. Install a \
             clock via observability::install_global_observability_clock \
             at lab-runtime setup to fix. (warning fires once per process)"
        );
    }
    std::time::SystemTime::now()
}

/// Strict variant of [`replayable_system_time`] that returns `None`
/// when no deterministic source is available, instead of falling back
/// to ambient `SystemTime::now()` (br-asupersync-z5ge0x).
///
/// Callers that PREFER to skip emitting a record over emitting a
/// non-replay-deterministic timestamp use this variant. Returns:
/// - `Some(..)` derived from `Cx::current().now_for_observability()` if a Cx is in scope.
/// - `Some(..)` from the globally-installed observability clock if [`install_global_observability_clock`] has been called.
/// - `None` otherwise.
///
/// This NEVER calls `SystemTime::now()` and NEVER emits the
/// ambient-fallback warning — the absent-source signal is given to the
/// caller via `None`.
#[must_use]
#[allow(dead_code)] // br-asupersync-z5ge0x: API surface for callers that want
// the strict-no-fallback semantic; in-tree callers haven't migrated yet,
// but the API needs to be in place so they can.
pub(crate) fn try_replayable_system_time() -> Option<std::time::SystemTime> {
    if let Some(cx) = crate::cx::Cx::current() {
        let nanos = cx.now_for_observability().as_nanos();
        return Some(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(nanos));
    }
    GLOBAL_OBSERVABILITY_CLOCK.get().map(|clock_fn| clock_fn())
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
pub(crate) fn parse_http_retry_after(headers: &[(String, String)]) -> Option<std::time::Duration> {
    parse_http_retry_after_at(headers, replayable_system_time())
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
pub(crate) fn parse_http_retry_after_at(
    headers: &[(String, String)],
    now: std::time::SystemTime,
) -> Option<std::time::Duration> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .map(|(_, value)| value.trim())?;

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(std::time::Duration::from_secs(seconds));
    }

    let target_seconds = parse_http_date_unix_seconds(value)?;
    let now_seconds = system_time_unix_seconds(now);
    if target_seconds <= now_seconds {
        return Some(std::time::Duration::ZERO);
    }

    u64::try_from(target_seconds - now_seconds)
        .ok()
        .map(std::time::Duration::from_secs)
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn system_time_unix_seconds(time: std::time::SystemTime) -> i64 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(err) => {
            let duration = err.duration();
            let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
            if duration.subsec_nanos() == 0 {
                -seconds
            } else {
                seconds.saturating_neg().saturating_sub(1)
            }
        }
    }
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn parse_http_date_unix_seconds(value: &str) -> Option<i64> {
    parse_imf_fixdate(value)
        .or_else(|| parse_rfc850_date(value))
        .or_else(|| parse_asctime_date(value))
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn parse_imf_fixdate(value: &str) -> Option<i64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 6 || !parts[0].ends_with(',') || !parts[5].eq_ignore_ascii_case("GMT") {
        return None;
    }

    if parts[3].len() != 4 || !parts[3].bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let day = parts[1].parse::<u32>().ok()?;
    let month = parse_http_month(parts[2])?;
    let year = parts[3].parse::<i32>().ok()?;
    let (hour, minute, second) = parse_http_time(parts[4])?;
    unix_seconds_from_utc(year, month, day, hour, minute, second)
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn parse_rfc850_date(value: &str) -> Option<i64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 4 || !parts[0].ends_with(',') || !parts[3].eq_ignore_ascii_case("GMT") {
        return None;
    }

    let date_parts: Vec<&str> = parts[1].split('-').collect();
    if date_parts.len() != 3 {
        return None;
    }

    if date_parts[2].len() != 2 || !date_parts[2].bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let day = date_parts[0].parse::<u32>().ok()?;
    let month = parse_http_month(date_parts[1])?;
    let short_year = date_parts[2].parse::<i32>().ok()?;
    let year = if short_year >= 70 {
        1900 + short_year
    } else {
        2000 + short_year
    };
    let (hour, minute, second) = parse_http_time(parts[2])?;
    unix_seconds_from_utc(year, month, day, hour, minute, second)
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn parse_asctime_date(value: &str) -> Option<i64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 5 {
        return None;
    }

    let month = parse_http_month(parts[1])?;
    let day = parts[2].parse::<u32>().ok()?;
    let (hour, minute, second) = parse_http_time(parts[3])?;
    let year = parts[4].parse::<i32>().ok()?;
    unix_seconds_from_utc(year, month, day, hour, minute, second)
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn parse_http_month(value: &str) -> Option<u32> {
    match value.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn parse_http_time(value: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 3 {
        return None;
    }

    let hour = parts[0].parse::<u32>().ok()?;
    let minute = parts[1].parse::<u32>().ok()?;
    let second = parts[2].parse::<u32>().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    Some((hour, minute, second.min(59)))
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn unix_seconds_from_utc(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if month == 0 || month > 12 || day == 0 || day > days_in_month(year, month) {
        return None;
    }

    let days = days_from_civil(year, month, day);
    days.checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[must_use]
#[cfg(any(test, feature = "metrics"))]
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
pub(crate) fn _reset_ambient_fallback_warned_for_test() {
    AMBIENT_FALLBACK_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
}

#[allow(clippy::cast_precision_loss)]
fn sample_unit_interval(key: u64) -> f64 {
    const TWO_POW_53_F64: f64 = 9_007_199_254_740_992.0;
    let bits = splitmix64(key) >> 11;
    bits as f64 / TWO_POW_53_F64
}

fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Configuration for observability and logging.
///
/// This struct controls logging levels, tracing behavior, and sampling rates
/// for the runtime. It integrates with both the high-level observability
/// infrastructure and the low-level trace module.
///
/// # Example
///
/// ```
/// use asupersync::observability::{LogLevel, ObservabilityConfig};
///
/// // Development config: verbose logging
/// let dev_config = ObservabilityConfig::default()
///     .with_log_level(LogLevel::Debug)
///     .with_trace_all_symbols(true);
///
/// // Production config: minimal overhead
/// let prod_config = ObservabilityConfig::default()
///     .with_log_level(LogLevel::Warn)
///     .with_sample_rate(0.01)
///     .with_trace_all_symbols(false);
/// ```
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Minimum log level to record.
    log_level: LogLevel,
    /// Whether to trace all symbols (expensive, useful for debugging).
    trace_all_symbols: bool,
    /// Sampling rate for traces (0.0 = none, 1.0 = all).
    sample_rate: f64,
    /// Maximum number of spans to retain in the diagnostic context.
    max_spans: usize,
    /// Maximum number of log entries to retain in the collector.
    max_log_entries: usize,
    /// Whether to include timestamps in log entries.
    include_timestamps: bool,
    /// Whether to enable metrics collection.
    metrics_enabled: bool,
}

impl ObservabilityConfig {
    /// Creates a new observability configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            log_level: LogLevel::Info,
            trace_all_symbols: false,
            sample_rate: 1.0,
            max_spans: 1000,
            max_log_entries: 10000,
            include_timestamps: true,
            metrics_enabled: true,
        }
    }

    /// Sets the minimum log level.
    #[must_use]
    pub fn with_log_level(mut self, level: LogLevel) -> Self {
        self.log_level = level;
        self
    }

    /// Sets whether to trace all symbols.
    #[must_use]
    pub fn with_trace_all_symbols(mut self, trace: bool) -> Self {
        self.trace_all_symbols = trace;
        self
    }

    /// Sets the sampling rate for traces.
    ///
    /// # Panics
    ///
    /// Panics if the rate is not in the range [0.0, 1.0].
    #[must_use]
    pub fn with_sample_rate(mut self, rate: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&rate),
            "sample_rate must be between 0.0 and 1.0"
        );
        self.sample_rate = rate;
        self
    }

    /// Sets the maximum number of spans to retain.
    #[must_use]
    pub fn with_max_spans(mut self, max: usize) -> Self {
        self.max_spans = max;
        self
    }

    /// Sets the maximum number of log entries to retain.
    #[must_use]
    pub fn with_max_log_entries(mut self, max: usize) -> Self {
        self.max_log_entries = max;
        self
    }

    /// Sets whether to include timestamps in log entries.
    #[must_use]
    pub fn with_include_timestamps(mut self, include: bool) -> Self {
        self.include_timestamps = include;
        self
    }

    /// Sets whether to enable metrics collection.
    #[must_use]
    pub fn with_metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Returns the minimum log level.
    #[must_use]
    pub const fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Returns whether to trace all symbols.
    #[must_use]
    pub const fn trace_all_symbols(&self) -> bool {
        self.trace_all_symbols
    }

    /// Returns the sampling rate for traces.
    #[must_use]
    pub const fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    /// Returns the maximum number of spans to retain.
    #[must_use]
    pub const fn max_spans(&self) -> usize {
        self.max_spans
    }

    /// Returns the maximum number of log entries to retain.
    #[must_use]
    pub const fn max_log_entries(&self) -> usize {
        self.max_log_entries
    }

    /// Returns whether timestamps are included in log entries.
    #[must_use]
    pub const fn include_timestamps(&self) -> bool {
        self.include_timestamps
    }

    /// Returns whether metrics collection is enabled.
    #[must_use]
    pub const fn metrics_enabled(&self) -> bool {
        self.metrics_enabled
    }

    /// Creates a log collector configured according to this config.
    #[must_use]
    pub fn create_collector(&self) -> LogCollector {
        LogCollector::new(self.max_log_entries).with_min_level(self.log_level)
    }

    /// Creates a diagnostic context configured according to this config.
    #[must_use]
    pub fn create_diagnostic_context(&self) -> DiagnosticContext {
        DiagnosticContext::new().with_max_completed(self.max_spans)
    }

    /// Creates a metrics registry if metrics are enabled.
    #[must_use]
    pub fn create_metrics(&self) -> Option<Metrics> {
        if self.metrics_enabled {
            Some(Metrics::new())
        } else {
            None
        }
    }

    /// Checks if a trace should be sampled based on the sample rate.
    ///
    /// Uses deterministic sampling based on a hash of the provided key.
    #[must_use]
    pub fn should_sample(&self, key: u64) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }

        sample_unit_interval(key) < self.sample_rate
    }

    /// Returns a development-oriented configuration.
    ///
    /// Verbose logging, full tracing, all metrics enabled.
    #[must_use]
    pub fn development() -> Self {
        Self::new()
            .with_log_level(LogLevel::Debug)
            .with_trace_all_symbols(true)
            .with_sample_rate(1.0)
    }

    /// Returns a production-oriented configuration.
    ///
    /// Minimal logging, sampled tracing, metrics enabled.
    #[must_use]
    pub fn production() -> Self {
        Self::new()
            .with_log_level(LogLevel::Warn)
            .with_trace_all_symbols(false)
            .with_sample_rate(0.01)
    }

    /// Returns a testing-oriented configuration.
    ///
    /// Full logging and tracing for deterministic replay.
    #[must_use]
    pub fn testing() -> Self {
        Self::new()
            .with_log_level(LogLevel::Trace)
            .with_trace_all_symbols(true)
            .with_sample_rate(1.0)
            .with_max_spans(10_000)
            .with_max_log_entries(100_000)
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn config_default() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.log_level(), LogLevel::Info);
        assert!(!config.trace_all_symbols());
        assert!((config.sample_rate() - 1.0).abs() < f64::EPSILON);
        assert!(config.metrics_enabled());
    }

    /// br-asupersync-z5ge0x: try_replayable_system_time returns None
    /// when there is no Cx in scope AND no global observability clock
    /// has been installed. This is the strict-no-fallback variant; it
    /// must NEVER consult ambient SystemTime::now and NEVER emit the
    /// warn line.
    ///
    /// Note: this test runs in a dedicated thread to ensure no prior
    /// test in the same thread installed a Cx via thread-local that we
    /// might inherit; OnceLock state is process-wide so we only assert
    /// the None case if no installer has fired earlier in the process.
    #[test]
    fn try_replayable_system_time_returns_none_without_source_in_isolated_thread() {
        // Spawn a fresh thread so no thread-local Cx leaks in.
        let result = std::thread::spawn(|| {
            // If a prior test in this process installed the global
            // clock, try_replayable_system_time returns Some — that's
            // valid behaviour, just not the case we're asserting. Skip
            // the assertion in that scenario.
            if GLOBAL_OBSERVABILITY_CLOCK.get().is_some() {
                return;
            }
            let observed = try_replayable_system_time();
            assert!(
                observed.is_none(),
                "try_replayable_system_time must return None when neither Cx nor global clock is available; observed {observed:?}"
            );
        })
        .join();
        assert!(result.is_ok());
    }

    /// br-asupersync-z5ge0x: install_global_observability_clock installs
    /// the singleton at most once per process. The first installation
    /// returns Ok; subsequent attempts return Err and do NOT replace
    /// the installed clock.
    ///
    /// Because OnceLock is process-wide and other tests may install
    /// their own clock, this test only asserts the once-only semantic
    /// — it accepts EITHER (a) we won the install race and observe the
    /// time from our deterministic clock, OR (b) we lost the race to
    /// some prior test and observe a Time from THEIR clock. In both
    /// cases install_global_observability_clock must reject our second
    /// call with Err.
    #[test]
    fn install_global_observability_clock_is_once_only() {
        fn fixed_clock() -> std::time::SystemTime {
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(0xC0FFEE)
        }
        // First install: may succeed (we won) or fail (someone else won).
        let first = install_global_observability_clock(fixed_clock);
        // Second install must always fail (OnceLock is set after first).
        let second = install_global_observability_clock(fixed_clock);
        assert!(
            second.is_err(),
            "second install must return Err per OnceLock semantics; first attempt was {first:?}"
        );
        // The clock is now definitely populated (either by us or a
        // prior test); try_replayable_system_time must return Some
        // even with no Cx in scope.
        let observed = std::thread::spawn(try_replayable_system_time)
            .join()
            .expect("isolated-thread query");
        assert!(
            observed.is_some(),
            "with the global clock populated, try_replayable_system_time must return Some"
        );
    }

    #[test]
    fn retry_after_parses_delay_seconds_and_http_date_formats() {
        fn fixed_time(
            year: i32,
            month: u32,
            day: u32,
            hour: u32,
            minute: u32,
            second: u32,
        ) -> std::time::SystemTime {
            let unix_seconds = unix_seconds_from_utc(year, month, day, hour, minute, second)
                .expect("valid fixed test time");
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(
                    u64::try_from(unix_seconds).expect("post-epoch time"),
                )
        }

        let delay_headers = vec![("Retry-After".to_string(), " 42 ".to_string())];
        assert_eq!(
            parse_http_retry_after_at(&delay_headers, std::time::UNIX_EPOCH),
            Some(std::time::Duration::from_secs(42))
        );

        let one_minute_before_imf = fixed_time(2015, 10, 21, 7, 27, 0);
        let one_minute_before_obs = fixed_time(1994, 11, 6, 8, 48, 37);

        for value in [
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            let now = if value.starts_with("Wed") {
                one_minute_before_imf
            } else {
                one_minute_before_obs
            };
            let headers = vec![("Retry-After".to_string(), value.to_string())];
            assert_eq!(
                parse_http_retry_after_at(&headers, now),
                Some(std::time::Duration::from_secs(60)),
                "Retry-After HTTP-date should parse: {value}"
            );
        }

        let past_headers = vec![(
            "Retry-After".to_string(),
            "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
        )];
        assert_eq!(
            parse_http_retry_after_at(&past_headers, fixed_time(2015, 10, 21, 7, 29, 0)),
            Some(std::time::Duration::ZERO),
            "past Retry-After HTTP-date should allow immediate retry"
        );

        let malformed_headers = vec![("Retry-After".to_string(), "next Tuesday".to_string())];
        assert_eq!(
            parse_http_retry_after_at(&malformed_headers, std::time::UNIX_EPOCH),
            None
        );
    }

    #[test]
    fn config_builder() {
        let config = ObservabilityConfig::new()
            .with_log_level(LogLevel::Debug)
            .with_trace_all_symbols(true)
            .with_sample_rate(0.5)
            .with_max_spans(500)
            .with_max_log_entries(5000)
            .with_include_timestamps(false)
            .with_metrics_enabled(false);

        assert_eq!(config.log_level(), LogLevel::Debug);
        assert!(config.trace_all_symbols());
        assert!((config.sample_rate() - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.max_spans(), 500);
        assert_eq!(config.max_log_entries(), 5000);
        assert!(!config.include_timestamps());
        assert!(!config.metrics_enabled());
    }

    #[test]
    fn config_presets() {
        let dev = ObservabilityConfig::development();
        assert_eq!(dev.log_level(), LogLevel::Debug);
        assert!(dev.trace_all_symbols());

        let prod = ObservabilityConfig::production();
        assert_eq!(prod.log_level(), LogLevel::Warn);
        assert!(!prod.trace_all_symbols());
        assert!(prod.sample_rate() < 0.1);

        let test = ObservabilityConfig::testing();
        assert_eq!(test.log_level(), LogLevel::Trace);
        assert!(test.trace_all_symbols());
    }

    #[test]
    fn config_create_collector() {
        let config = ObservabilityConfig::new()
            .with_log_level(LogLevel::Warn)
            .with_max_log_entries(100);

        let collector = config.create_collector();
        assert_eq!(collector.min_level(), LogLevel::Warn);
        assert_eq!(collector.capacity(), 100);
    }

    #[test]
    fn config_create_metrics() {
        let enabled = ObservabilityConfig::new().with_metrics_enabled(true);
        assert!(enabled.create_metrics().is_some());

        let disabled = ObservabilityConfig::new().with_metrics_enabled(false);
        assert!(disabled.create_metrics().is_none());
    }

    #[test]
    fn config_sampling() {
        let full = ObservabilityConfig::new().with_sample_rate(1.0);
        assert!(full.should_sample(0));
        assert!(full.should_sample(u64::MAX));

        let none = ObservabilityConfig::new().with_sample_rate(0.0);
        assert!(!none.should_sample(0));
        assert!(!none.should_sample(u64::MAX));

        let half = ObservabilityConfig::new().with_sample_rate(0.5);
        // Deterministic: same key always gives same result
        let result1 = half.should_sample(12345);
        let result2 = half.should_sample(12345);
        assert_eq!(result1, result2);
    }

    #[test]
    fn config_sampling_hashes_low_sequential_keys() {
        let half = ObservabilityConfig::new().with_sample_rate(0.5);
        let sampled = (0..64).filter(|&key| half.should_sample(key)).count();

        assert!(
            sampled > 0,
            "hashed sampling should accept some low sequential keys"
        );
        assert!(
            sampled < 64,
            "hashed sampling should not deterministically accept every low sequential key"
        );
    }

    #[test]
    #[should_panic(expected = "sample_rate must be between 0.0 and 1.0")]
    fn config_invalid_sample_rate_high() {
        let _ = ObservabilityConfig::new().with_sample_rate(1.5);
    }

    #[test]
    #[should_panic(expected = "sample_rate must be between 0.0 and 1.0")]
    fn config_invalid_sample_rate_negative() {
        let _ = ObservabilityConfig::new().with_sample_rate(-0.1);
    }
}
