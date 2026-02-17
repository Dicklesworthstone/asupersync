//! In-process collector for symbol trace spans.

use super::context::RegionTag;
use super::id::TraceId;
use super::span::{SymbolSpan, SymbolSpanKind, SymbolSpanStatus};
use crate::types::symbol::ObjectId;
use crate::types::Time;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::Duration;

/// Stored trace record for a single trace ID.
#[derive(Clone, Debug)]
pub struct TraceRecord {
    /// Trace identifier.
    pub trace_id: TraceId,
    /// Associated object ID (if known).
    pub object_id: Option<ObjectId>,
    /// First time seen.
    pub first_seen: Time,
    /// Last update time.
    pub last_updated: Time,
    /// Spans associated with the trace.
    pub spans: Vec<SymbolSpan>,
    /// Regions traversed.
    pub regions: Vec<RegionTag>,
    /// Whether trace is complete.
    pub is_complete: bool,
}

/// Summary for a trace record.
#[derive(Clone, Debug)]
pub struct TraceSummary {
    /// Trace ID.
    pub trace_id: TraceId,
    /// Object ID.
    pub object_id: Option<ObjectId>,
    /// Total span count.
    pub span_count: usize,
    /// Symbols encoded.
    pub symbols_encoded: u32,
    /// Symbols transmitted.
    pub symbols_transmitted: u32,
    /// Symbols received.
    pub symbols_received: u32,
    /// Symbols dropped.
    pub symbols_dropped: u32,
    /// End-to-end latency (first encode to decode complete).
    pub end_to_end_latency: Option<Duration>,
    /// Encoding duration.
    pub encode_duration: Option<Duration>,
    /// Transmission duration (median).
    pub transmit_duration_median: Option<Duration>,
    /// Decoding duration.
    pub decode_duration: Option<Duration>,
    /// Regions traversed.
    pub regions: Vec<String>,
    /// Whether successful.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Collector for symbol-based traces.
pub struct SymbolTraceCollector {
    traces: RwLock<HashMap<TraceId, TraceRecord>>,
    max_traces: usize,
    max_age: Duration,
    clock_skew_tolerance: Duration,
    local_region: RegionTag,
}

impl SymbolTraceCollector {
    /// Creates a new collector.
    #[must_use]
    pub fn new(local_region: RegionTag) -> Self {
        Self {
            traces: RwLock::new(HashMap::new()),
            max_traces: 10_000,
            max_age: Duration::from_hours(1),
            clock_skew_tolerance: Duration::from_millis(100),
            local_region,
        }
    }

    /// Returns the local region tag.
    #[must_use]
    pub fn local_region(&self) -> &RegionTag {
        &self.local_region
    }

    /// Sets the maximum number of traces to retain.
    #[must_use]
    pub fn with_max_traces(mut self, max: usize) -> Self {
        self.max_traces = max;
        self
    }

    /// Sets the maximum trace age before eviction.
    #[must_use]
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = age;
        self
    }

    /// Sets the clock skew tolerance.
    #[must_use]
    pub fn with_clock_skew_tolerance(mut self, tolerance: Duration) -> Self {
        self.clock_skew_tolerance = tolerance;
        self
    }

    /// Returns the configured clock skew tolerance.
    #[must_use]
    pub const fn clock_skew_tolerance(&self) -> Duration {
        self.clock_skew_tolerance
    }

    /// Records a span.
    pub fn record_span(&self, span: &SymbolSpan, now: Time) {
        let trace_id = span.context().trace_id();
        let mut traces = self.traces.write();

        let record = traces.entry(trace_id).or_insert_with(|| TraceRecord {
            trace_id,
            object_id: span.object_id(),
            first_seen: now,
            last_updated: now,
            spans: Vec::new(),
            regions: Vec::new(),
            is_complete: false,
        });

        record.last_updated = now;
        if record.object_id.is_none() {
            record.object_id = span.object_id();
        }
        record.spans.push(span.clone());

        let region = span.context().origin_region().clone();
        if !record.regions.contains(&region) {
            record.regions.push(region);
        }

        if span.kind() == SymbolSpanKind::Decode
            && matches!(
                span.status(),
                SymbolSpanStatus::Ok | SymbolSpanStatus::Error
            )
        {
            record.is_complete = true;
        }

        if traces.len() > self.max_traces {
            self.evict_oldest(&mut traces, now);
        }
    }

    /// Gets a trace by ID.
    #[must_use]
    pub fn get_trace(&self, trace_id: TraceId) -> Option<TraceRecord> {
        self.traces.read().get(&trace_id).cloned()
    }

    /// Gets a summary for a trace.
    #[must_use]
    pub fn get_summary(&self, trace_id: TraceId) -> Option<TraceSummary> {
        let record = {
            let traces = self.traces.read();
            traces.get(&trace_id)?.clone()
        };

        let mut symbols_encoded = 0u32;
        let mut symbols_transmitted = 0u32;
        let mut symbols_received = 0u32;
        let mut symbols_dropped = 0u32;
        let mut encode_duration = None;
        let mut decode_duration = None;
        let mut transmit_durations = Vec::new();
        let mut first_encode_time: Option<Time> = None;
        let mut decode_complete_time: Option<Time> = None;
        let mut error = None;

        for span in &record.spans {
            match span.kind() {
                SymbolSpanKind::Encode => {
                    if let Some(count) = span.symbol_count() {
                        symbols_encoded = symbols_encoded.saturating_add(count);
                    }
                    if encode_duration.is_none() {
                        encode_duration =
                            span.duration().map(|t| Duration::from_nanos(t.as_nanos()));
                    }
                    if first_encode_time.is_none() {
                        first_encode_time = Some(span.start_time());
                    }
                }
                SymbolSpanKind::Transmit => {
                    symbols_transmitted = symbols_transmitted.saturating_add(1);
                    if let Some(d) = span.duration() {
                        transmit_durations.push(Duration::from_nanos(d.as_nanos()));
                    }
                    if span.status() == SymbolSpanStatus::Dropped {
                        symbols_dropped = symbols_dropped.saturating_add(1);
                    }
                }
                SymbolSpanKind::Receive => {
                    symbols_received = symbols_received.saturating_add(1);
                }
                SymbolSpanKind::Decode => {
                    decode_duration = span.duration().map(|t| Duration::from_nanos(t.as_nanos()));
                    if let Some(end) = span.end_time() {
                        decode_complete_time = Some(end);
                    }
                    if span.status() == SymbolSpanStatus::Error {
                        error = span.error_message().map(ToString::to_string);
                    }
                }
                _ => {}
            }
        }

        let end_to_end_latency = match (first_encode_time, decode_complete_time) {
            (Some(start), Some(end)) => Some(Duration::from_nanos(end.duration_since(start))),
            _ => None,
        };

        let transmit_duration_median = if transmit_durations.is_empty() {
            None
        } else {
            transmit_durations.sort_by_key(Duration::as_nanos);
            let mid = transmit_durations.len() / 2;
            Some(transmit_durations[mid])
        };

        Some(TraceSummary {
            trace_id,
            object_id: record.object_id,
            span_count: record.spans.len(),
            symbols_encoded,
            symbols_transmitted,
            symbols_received,
            symbols_dropped,
            end_to_end_latency,
            encode_duration,
            transmit_duration_median,
            decode_duration,
            regions: record
                .regions
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            success: record.is_complete && error.is_none(),
            error,
        })
    }

    /// Lists active traces (not yet complete).
    #[must_use]
    pub fn active_traces(&self) -> Vec<TraceId> {
        self.traces
            .read()
            .iter()
            .filter(|(_, r)| !r.is_complete)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Lists complete traces.
    #[must_use]
    pub fn complete_traces(&self) -> Vec<TraceId> {
        self.traces
            .read()
            .iter()
            .filter(|(_, r)| r.is_complete)
            .map(|(id, _)| *id)
            .collect()
    }

    fn evict_oldest(&self, traces: &mut HashMap<TraceId, TraceRecord>, now: Time) {
        let mut to_remove: Vec<_> = traces
            .iter()
            .filter(|(_, r)| r.is_complete)
            .map(|(id, r)| (*id, r.last_updated))
            .collect();

        to_remove.sort_by_key(|(_, updated)| *updated);

        let remove_count = (traces.len() / 10).max(1);
        for (id, _) in to_remove.into_iter().take(remove_count) {
            traces.remove(&id);
        }

        let max_age_nanos = self.max_age.as_nanos().min(u128::from(u64::MAX)) as u64;
        let cutoff = now.saturating_sub_nanos(max_age_nanos);
        traces.retain(|_, r| r.last_updated >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::distributed::context::{RegionTag, SymbolTraceContext};
    use crate::trace::distributed::id::{SymbolSpanId, TraceId};
    use crate::trace::distributed::span::SymbolSpan;
    use crate::types::symbol::SymbolId;
    use crate::util::DetRng;

    #[test]
    fn collector_records_spans() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(42);
        let trace_id = TraceId::new_for_test(1);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("us-east-1"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(0));
        collector.record_span(&span, Time::from_millis(0));

        let record = collector.get_trace(trace_id).expect("trace should exist");
        assert_eq!(record.spans.len(), 1);
        assert_eq!(record.regions.len(), 1);
    }

    #[test]
    fn collector_detects_completion() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(7);
        let trace_id = TraceId::new_for_test(2);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("sender"),
            &mut rng,
        );
        let mut decode_span =
            SymbolSpan::new_decode(ctx, ObjectId::new_for_test(2), 4, Time::from_millis(100));
        decode_span.complete_ok(Time::from_millis(120));
        collector.record_span(&decode_span, Time::from_millis(120));

        let record = collector.get_trace(trace_id).expect("trace should exist");
        assert!(record.is_complete);
        assert_eq!(collector.complete_traces(), vec![trace_id]);
    }

    #[test]
    fn trace_summary_calculations() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(42);
        let trace_id = TraceId::new_for_test(3);
        let object_id = ObjectId::new_for_test(3);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("sender"),
            &mut rng,
        );

        let mut encode_span = SymbolSpan::new_encode(ctx.clone(), object_id, Time::from_millis(0));
        encode_span.set_symbol_count(10);
        encode_span.complete_ok(Time::from_millis(100));
        collector.record_span(&encode_span, Time::from_millis(100));

        for i in 0..10 {
            let mut tx_span = SymbolSpan::new_transmit(
                ctx.child(&mut rng),
                SymbolId::new_for_test(3, 0, i),
                Time::from_millis(100 + u64::from(i) * 10),
            );
            tx_span.complete_ok(Time::from_millis(150 + u64::from(i) * 10));
            collector.record_span(&tx_span, Time::from_millis(150 + u64::from(i) * 10));
        }

        let mut decode_span =
            SymbolSpan::new_decode(ctx.child(&mut rng), object_id, 10, Time::from_millis(300));
        decode_span.complete_ok(Time::from_millis(400));
        collector.record_span(&decode_span, Time::from_millis(400));

        let summary = collector
            .get_summary(trace_id)
            .expect("summary should exist");
        assert_eq!(summary.symbols_encoded, 10);
        assert_eq!(summary.symbols_transmitted, 10);
        assert!(summary.success);
        assert!(summary.end_to_end_latency.is_some());
    }
}
