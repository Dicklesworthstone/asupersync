//! QUIC Handshake Trace Generation
//!
//! Generates comprehensive traces for handshake replay, diagnostics, and debugging.

use crate::net::atp::handshake::state_machine::{HandshakeEvent, PacketSpace};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Trace level for filtering events
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TraceLevel {
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
    Verbose = 4,
}

/// Structured trace event with metadata
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// Timestamp in milliseconds since start
    pub timestamp_ms: u64,
    /// Trace level
    pub level: TraceLevel,
    /// Event category
    pub category: String,
    /// Event name
    pub event: String,
    /// Event data
    pub data: Value,
    /// Region ID context
    pub region_id: Option<String>,
    /// Packet space context
    pub packet_space: Option<PacketSpace>,
}

impl TraceEntry {
    /// Create a new trace entry
    pub fn new(
        timestamp_ms: u64,
        level: TraceLevel,
        category: impl Into<String>,
        event: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            timestamp_ms,
            level,
            category: category.into(),
            event: event.into(),
            data,
            region_id: None,
            packet_space: None,
        }
    }

    /// Set region ID context
    pub fn with_region_id(mut self, region_id: impl Into<String>) -> Self {
        self.region_id = Some(region_id.into());
        self
    }

    /// Set packet space context
    pub fn with_packet_space(mut self, space: PacketSpace) -> Self {
        self.packet_space = Some(space);
        self
    }
}

/// Handshake trace collector
#[derive(Debug)]
pub struct HandshakeTracer {
    /// Start time for relative timestamps
    start_time: SystemTime,
    /// Collected trace entries
    entries: Vec<TraceEntry>,
    /// Minimum trace level to collect
    min_level: TraceLevel,
    /// Maximum number of entries to keep
    max_entries: usize,
}

impl HandshakeTracer {
    /// Create a new handshake tracer
    pub fn new(min_level: TraceLevel, max_entries: usize) -> Self {
        Self {
            start_time: SystemTime::now(),
            entries: Vec::new(),
            min_level,
            max_entries,
        }
    }

    /// Create a tracer with default settings
    pub fn default() -> Self {
        Self::new(TraceLevel::Info, 10000)
    }

    /// Add a trace entry
    pub fn trace(&mut self, entry: TraceEntry) {
        if entry.level <= self.min_level {
            // Remove oldest entries if at capacity
            if self.entries.len() >= self.max_entries {
                self.entries.remove(0);
            }
            self.entries.push(entry);
        }
    }

    /// Convert handshake event to trace entry
    pub fn trace_handshake_event(&mut self, event: &HandshakeEvent, region_id: Option<String>) {
        let timestamp_ms = self
            .start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;

        let entry = match event {
            HandshakeEvent::Started {
                role,
                initial_version,
                region_id: event_region,
            } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Info,
                "handshake",
                "started",
                json!({
                    "role": format!("{:?}", role),
                    "initial_version": format!("0x{:08x}", initial_version),
                    "region_id": event_region
                }),
            )
            .with_region_id(event_region.clone()),

            HandshakeEvent::VersionNegotiation {
                supported_versions,
                selected_version,
            } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Info,
                "handshake",
                "version_negotiation",
                json!({
                    "supported_versions": supported_versions.iter()
                        .map(|v| format!("0x{:08x}", v))
                        .collect::<Vec<_>>(),
                    "selected_version": selected_version
                        .map(|v| format!("0x{:08x}", v))
                }),
            ),

            HandshakeEvent::Retry {
                original_dest_cid,
                retry_token,
                retry_source_cid,
            } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Info,
                "handshake",
                "retry",
                json!({
                    "original_dest_cid": hex::encode(original_dest_cid),
                    "retry_token": hex::encode(retry_token),
                    "retry_source_cid": hex::encode(retry_source_cid),
                    "retry_token_length": retry_token.len()
                }),
            ),

            HandshakeEvent::InitialPacket {
                packet_number,
                crypto_offset,
                crypto_length,
                source_cid,
                dest_cid,
            } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Debug,
                "handshake",
                "initial_packet",
                json!({
                    "packet_number": packet_number,
                    "crypto_offset": crypto_offset,
                    "crypto_length": crypto_length,
                    "source_cid": hex::encode(source_cid),
                    "dest_cid": hex::encode(dest_cid)
                }),
            )
            .with_packet_space(PacketSpace::Initial),

            HandshakeEvent::HandshakePacket {
                packet_number,
                crypto_offset,
                crypto_length,
            } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Debug,
                "handshake",
                "handshake_packet",
                json!({
                    "packet_number": packet_number,
                    "crypto_offset": crypto_offset,
                    "crypto_length": crypto_length
                }),
            )
            .with_packet_space(PacketSpace::Handshake),

            HandshakeEvent::TransportParams { params } => {
                let params_json: Value = params
                    .iter()
                    .map(|(&id, value)| {
                        (format!("0x{:02x}", id), Value::String(hex::encode(value)))
                    })
                    .collect::<serde_json::Map<_, _>>()
                    .into();

                TraceEntry::new(
                    timestamp_ms,
                    TraceLevel::Info,
                    "handshake",
                    "transport_params",
                    json!({
                        "params": params_json,
                        "param_count": params.len()
                    }),
                )
            }

            HandshakeEvent::KeyPhaseTransition { space, phase } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Info,
                "handshake",
                "key_phase_transition",
                json!({
                    "space": format!("{:?}", space),
                    "phase": phase
                }),
            )
            .with_packet_space(*space),

            HandshakeEvent::Completed {
                elapsed,
                final_version,
            } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Info,
                "handshake",
                "completed",
                json!({
                    "elapsed_ms": elapsed.as_millis(),
                    "final_version": format!("0x{:08x}", final_version)
                }),
            ),

            HandshakeEvent::Failed { error, elapsed } => TraceEntry::new(
                timestamp_ms,
                TraceLevel::Error,
                "handshake",
                "failed",
                json!({
                    "error": format!("{}", error),
                    "elapsed_ms": elapsed.as_millis()
                }),
            ),
        };

        if let Some(ref region) = region_id {
            self.trace(entry.with_region_id(region.clone()));
        } else {
            self.trace(entry);
        }
    }

    /// Add packet protection trace
    pub fn trace_packet_protection(
        &mut self,
        direction: &str,
        space: PacketSpace,
        packet_number: u64,
        protected_length: usize,
    ) {
        let timestamp_ms = self
            .start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;

        let entry = TraceEntry::new(
            timestamp_ms,
            TraceLevel::Debug,
            "protection",
            format!("packet_{}", direction),
            json!({
                "packet_number": packet_number,
                "protected_length": protected_length,
                "space": format!("{:?}", space)
            }),
        )
        .with_packet_space(space);

        self.trace(entry);
    }

    /// Add connection ID trace
    pub fn trace_connection_id(&mut self, event: &str, cid: &[u8], sequence: Option<u64>) {
        let timestamp_ms = self
            .start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;

        let mut data = json!({
            "connection_id": hex::encode(cid),
            "length": cid.len()
        });

        if let Some(seq) = sequence {
            data.as_object_mut()
                .unwrap()
                .insert("sequence".to_string(), json!(seq));
        }

        let entry = TraceEntry::new(
            timestamp_ms,
            TraceLevel::Debug,
            "connection_id",
            event,
            data,
        );

        self.trace(entry);
    }

    /// Generate qlog-compatible trace
    pub fn to_qlog(&self) -> Value {
        let events: Vec<Value> = self
            .entries
            .iter()
            .map(|entry| {
                let mut event = json!({
                    "time": entry.timestamp_ms,
                    "name": format!("{}:{}", entry.category, entry.event),
                    "data": entry.data
                });

                if let Some(ref region_id) = entry.region_id {
                    event
                        .as_object_mut()
                        .unwrap()
                        .insert("region_id".to_string(), json!(region_id));
                }

                if let Some(space) = entry.packet_space {
                    event
                        .as_object_mut()
                        .unwrap()
                        .insert("packet_space".to_string(), json!(format!("{:?}", space)));
                }

                event
            })
            .collect();

        json!({
            "qlog_version": "0.3",
            "qlog_format": "JSON",
            "title": "ATP QUIC Handshake Trace",
            "description": "Detailed handshake trace for replay and diagnostics",
            "traces": [{
                "vantage_point": {
                    "name": "atp-quic-handshake",
                    "type": "endpoint"
                },
                "title": "ATP QUIC Handshake",
                "description": "QUIC handshake state machine trace",
                "configuration": {
                    "time_offset": 0,
                    "time_units": "ms"
                },
                "events": events
            }]
        })
    }

    /// Generate summary statistics
    pub fn summary(&self) -> Value {
        let mut event_counts = std::collections::HashMap::new();
        let mut category_counts = std::collections::HashMap::new();
        let mut level_counts = std::collections::HashMap::new();

        for entry in &self.entries {
            *event_counts.entry(entry.event.clone()).or_insert(0) += 1;
            *category_counts.entry(entry.category.clone()).or_insert(0) += 1;
            *level_counts
                .entry(format!("{:?}", entry.level))
                .or_insert(0) += 1;
        }

        let total_duration = self.entries.last().map_or(0, |e| e.timestamp_ms);

        json!({
            "total_events": self.entries.len(),
            "total_duration_ms": total_duration,
            "event_counts": event_counts,
            "category_counts": category_counts,
            "level_counts": level_counts,
            "start_time": self.start_time.duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs()
        })
    }

    /// Get all trace entries
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.start_time = SystemTime::now();
    }

    /// Filter entries by level
    pub fn filter_by_level(&self, min_level: TraceLevel) -> Vec<&TraceEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.level <= min_level)
            .collect()
    }

    /// Filter entries by category
    pub fn filter_by_category(&self, category: &str) -> Vec<&TraceEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.category == category)
            .collect()
    }
}

impl Default for HandshakeTracer {
    fn default() -> Self {
        Self::default()
    }
}

/// Utilities for trace analysis and debugging
pub struct TraceAnalyzer;

impl TraceAnalyzer {
    /// Find handshake completion time
    pub fn find_completion_time(entries: &[TraceEntry]) -> Option<u64> {
        entries
            .iter()
            .find(|entry| entry.event == "completed")
            .map(|entry| entry.timestamp_ms)
    }

    /// Find handshake failure information
    pub fn find_failure_info(entries: &[TraceEntry]) -> Option<(&TraceEntry, String)> {
        entries
            .iter()
            .find(|entry| entry.event == "failed")
            .and_then(|entry| {
                entry
                    .data
                    .get("error")
                    .and_then(|e| e.as_str())
                    .map(|error| (entry, error.to_string()))
            })
    }

    /// Count packets by space
    pub fn count_packets_by_space(
        entries: &[TraceEntry],
    ) -> std::collections::HashMap<PacketSpace, usize> {
        let mut counts = std::collections::HashMap::new();

        for entry in entries {
            if entry.category == "handshake"
                && (entry.event == "initial_packet" || entry.event == "handshake_packet")
            {
                if let Some(space) = entry.packet_space {
                    *counts.entry(space).or_insert(0) += 1;
                }
            }
        }

        counts
    }

    /// Validate trace for common issues
    pub fn validate_trace(entries: &[TraceEntry]) -> Vec<String> {
        let mut issues = Vec::new();

        // Check if handshake completed
        let completed = entries.iter().any(|e| e.event == "completed");
        let failed = entries.iter().any(|e| e.event == "failed");

        if !completed && !failed {
            issues.push("Handshake neither completed nor failed".to_string());
        }

        // Check for proper packet progression
        let initial_packets = entries
            .iter()
            .filter(|e| e.packet_space == Some(PacketSpace::Initial))
            .count();
        let handshake_packets = entries
            .iter()
            .filter(|e| e.packet_space == Some(PacketSpace::Handshake))
            .count();

        if handshake_packets > 0 && initial_packets == 0 {
            issues.push("Handshake packets without Initial packets".to_string());
        }

        // Check timestamp ordering
        for window in entries.windows(2) {
            if window[0].timestamp_ms > window[1].timestamp_ms {
                issues.push("Timestamp ordering violation".to_string());
                break;
            }
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::handshake::state_machine::EndpointRole;

    #[test]
    fn test_tracer_creation() {
        let tracer = HandshakeTracer::new(TraceLevel::Debug, 1000);
        assert_eq!(tracer.entries.len(), 0);
        assert_eq!(tracer.min_level, TraceLevel::Debug);
        assert_eq!(tracer.max_entries, 1000);
    }

    #[test]
    fn test_trace_filtering_by_level() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        let info_entry = TraceEntry::new(0, TraceLevel::Info, "test", "info_event", json!({}));
        let error_entry = TraceEntry::new(1, TraceLevel::Error, "test", "error_event", json!({}));
        let verbose_entry =
            TraceEntry::new(2, TraceLevel::Verbose, "test", "verbose_event", json!({}));

        tracer.trace(info_entry);
        tracer.trace(error_entry);
        tracer.trace(verbose_entry); // Should be filtered out

        assert_eq!(tracer.entries.len(), 2);
    }

    #[test]
    fn test_handshake_event_tracing() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        let event = HandshakeEvent::Started {
            role: EndpointRole::Client,
            initial_version: 0x00000001,
            region_id: "test-region".to_string(),
        };

        tracer.trace_handshake_event(&event, Some("test-region".to_string()));

        assert_eq!(tracer.entries.len(), 1);
        assert_eq!(tracer.entries[0].category, "handshake");
        assert_eq!(tracer.entries[0].event, "started");
    }

    #[test]
    fn test_qlog_generation() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        let entry = TraceEntry::new(
            0,
            TraceLevel::Info,
            "handshake",
            "started",
            json!({"role": "Client"}),
        );
        tracer.trace(entry);

        let qlog = tracer.to_qlog();
        assert!(qlog.get("qlog_version").is_some());
        assert!(qlog.get("traces").is_some());
    }

    #[test]
    fn test_trace_analysis() {
        let entries = vec![
            TraceEntry::new(0, TraceLevel::Info, "handshake", "started", json!({})),
            TraceEntry::new(100, TraceLevel::Info, "handshake", "completed", json!({})),
        ];

        let completion_time = TraceAnalyzer::find_completion_time(&entries);
        assert_eq!(completion_time, Some(100));

        let failure_info = TraceAnalyzer::find_failure_info(&entries);
        assert!(failure_info.is_none());
    }

    #[test]
    fn test_trace_validation() {
        // Valid trace
        let valid_entries = vec![
            TraceEntry::new(0, TraceLevel::Info, "handshake", "started", json!({})),
            TraceEntry::new(100, TraceLevel::Info, "handshake", "completed", json!({})),
        ];

        let issues = TraceAnalyzer::validate_trace(&valid_entries);
        assert!(issues.is_empty());

        // Invalid trace - no completion
        let invalid_entries = vec![TraceEntry::new(
            0,
            TraceLevel::Info,
            "handshake",
            "started",
            json!({}),
        )];

        let issues = TraceAnalyzer::validate_trace(&invalid_entries);
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_summary_generation() {
        let mut tracer = HandshakeTracer::new(TraceLevel::Debug, 100);

        tracer.trace(TraceEntry::new(
            0,
            TraceLevel::Info,
            "handshake",
            "started",
            json!({}),
        ));
        tracer.trace(TraceEntry::new(
            50,
            TraceLevel::Debug,
            "protection",
            "encrypt",
            json!({}),
        ));
        tracer.trace(TraceEntry::new(
            100,
            TraceLevel::Info,
            "handshake",
            "completed",
            json!({}),
        ));

        let summary = tracer.summary();
        assert_eq!(summary["total_events"], 3);
        assert_eq!(summary["total_duration_ms"], 100);
    }
}
