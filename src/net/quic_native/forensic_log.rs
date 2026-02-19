//! Structured NDJSON forensic logger and artifact emission helpers for QUIC/H3
//! E2E test scenarios (QH3-L2 bead).
//!
//! This module provides:
//! - [`QuicH3Event`]: typed event enum matching `quic_h3_forensic_log_schema_v1`
//! - [`QuicH3ForensicLogger`]: thread-safe event collector with NDJSON emission
//! - [`QuicH3ScenarioManifest`]: per-scenario artifact manifest
//!
//! All types are synchronous (no tokio / async). Thread safety is provided via
//! `parking_lot::Mutex`.

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

// ============================================================================
// Schema constants
// ============================================================================

/// NDJSON envelope schema version, aligned with `TRACE_EVENT_SCHEMA_VERSION`.
pub const FORENSIC_SCHEMA_VERSION: u32 = 1;

/// Schema ID for the forensic manifest.
pub const FORENSIC_MANIFEST_SCHEMA_ID: &str = "quic-h3-forensic-manifest.v1";

/// Subsystem tag for all events emitted by this logger.
pub const SUBSYSTEM: &str = "quic_h3_native";

// ============================================================================
// QuicH3Event
// ============================================================================

/// Structured event types matching the `quic_h3_forensic_log_schema_v1`
/// event categories.
///
/// Each variant carries its typed payload and serializes via `serde`.
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum QuicH3Event {
    // -- Transport events (quic_transport) ----------------------------------
    PacketSent {
        pn_space: String,
        packet_number: u64,
        size_bytes: u64,
        ack_eliciting: bool,
        in_flight: bool,
        send_time_us: u64,
    },
    AckReceived {
        pn_space: String,
        acked_ranges: Vec<(u64, u64)>,
        ack_delay_us: u64,
        acked_packets: u64,
        acked_bytes: u64,
    },
    LossDetected {
        pn_space: String,
        lost_packets: u64,
        lost_bytes: u64,
        detection_method: String,
    },
    PtoFired {
        pto_count: u32,
        backoff_multiplier: u32,
        deadline_us: u64,
        probe_space: String,
    },
    CwndUpdated {
        old_cwnd: u64,
        new_cwnd: u64,
        ssthresh: u64,
        bytes_in_flight: u64,
        reason: String,
    },
    RttUpdated {
        latest_rtt_us: u64,
        smoothed_rtt_us: u64,
        rttvar_us: u64,
        min_rtt_us: u64,
        ack_delay_us: u64,
    },

    // -- Stream events (quic_stream) ----------------------------------------
    StreamOpened {
        stream_id: u64,
        direction: String,
        role: String,
        is_local: bool,
    },
    StreamDataSent {
        stream_id: u64,
        offset: u64,
        length: u64,
        is_fin: bool,
    },
    StreamDataReceived {
        stream_id: u64,
        offset: u64,
        length: u64,
        is_fin: bool,
        contiguous_offset: u64,
    },
    StreamReset {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    StreamStopSending {
        stream_id: u64,
        error_code: u64,
    },
    FlowControlUpdated {
        stream_id: u64,
        send_credit: u64,
        recv_credit: u64,
        connection_send_remaining: u64,
        connection_recv_remaining: u64,
    },

    // -- Connection events (quic_connection) --------------------------------
    StateChanged {
        from_state: String,
        to_state: String,
        trigger: String,
    },
    HandshakeStep {
        step: String,
        role: String,
    },
    CloseInitiated {
        close_code: u64,
        close_method: String,
        drain_timeout_us: u64,
    },
    KeyUpdate {
        generation: u32,
        old_phase: String,
        new_phase: String,
        initiator: String,
    },

    // -- H3 control events (h3_control) -------------------------------------
    SettingsExchanged {
        direction: String,
        max_field_section_size: u64,
        qpack_max_table_capacity: u64,
        qpack_blocked_streams: u64,
    },
    GoawayReceived {
        stream_id: u64,
        direction: String,
    },

    // -- H3 request events (h3_request) -------------------------------------
    RequestStarted {
        stream_id: u64,
        method: String,
        scheme: String,
        authority: String,
        path: String,
    },
    RequestHeadersSent {
        stream_id: u64,
        header_count: u32,
        qpack_indexed_count: u32,
        wire_bytes: u64,
    },
    RequestDataSent {
        stream_id: u64,
        body_bytes: u64,
        is_end_stream: bool,
    },
    ResponseReceived {
        stream_id: u64,
        status_code: u32,
        header_count: u32,
        body_bytes: u64,
    },
    RequestStreamStateChanged {
        stream_id: u64,
        from_state: String,
        to_state: String,
    },

    // -- H3 frame events (h3_frame) -----------------------------------------
    FrameEncoded {
        frame_type: String,
        wire_bytes: u64,
        stream_id: u64,
    },
    FrameDecoded {
        frame_type: String,
        wire_bytes: u64,
        stream_id: u64,
    },
    FrameError {
        frame_type: String,
        error_kind: String,
        error_message: String,
        stream_id: u64,
    },

    // -- Test harness events (test_harness) ----------------------------------
    ScenarioStarted {
        scenario_id: String,
        seed: u64,
        config_hash: String,
        test_file: String,
        test_function: String,
    },
    InvariantCheckpoint {
        invariant_id: String,
        verdict: String,
        details: String,
    },
    ScenarioCompleted {
        scenario_id: String,
        seed: u64,
        passed: bool,
        duration_us: u64,
        event_count: u64,
        failure_class: String,
    },
}

impl QuicH3Event {
    /// Returns the stable snake_case event name for the NDJSON envelope.
    #[must_use]
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::PacketSent { .. } => "packet_sent",
            Self::AckReceived { .. } => "ack_received",
            Self::LossDetected { .. } => "loss_detected",
            Self::PtoFired { .. } => "pto_fired",
            Self::CwndUpdated { .. } => "cwnd_updated",
            Self::RttUpdated { .. } => "rtt_updated",
            Self::StreamOpened { .. } => "stream_opened",
            Self::StreamDataSent { .. } => "stream_data_sent",
            Self::StreamDataReceived { .. } => "stream_data_received",
            Self::StreamReset { .. } => "stream_reset",
            Self::StreamStopSending { .. } => "stream_stop_sending",
            Self::FlowControlUpdated { .. } => "flow_control_updated",
            Self::StateChanged { .. } => "state_changed",
            Self::HandshakeStep { .. } => "handshake_step",
            Self::CloseInitiated { .. } => "close_initiated",
            Self::KeyUpdate { .. } => "key_update",
            Self::SettingsExchanged { .. } => "settings_exchanged",
            Self::GoawayReceived { .. } => "goaway_received",
            Self::RequestStarted { .. } => "request_started",
            Self::RequestHeadersSent { .. } => "request_headers_sent",
            Self::RequestDataSent { .. } => "request_data_sent",
            Self::ResponseReceived { .. } => "response_received",
            Self::RequestStreamStateChanged { .. } => "request_stream_state_changed",
            Self::FrameEncoded { .. } => "frame_encoded",
            Self::FrameDecoded { .. } => "frame_decoded",
            Self::FrameError { .. } => "frame_error",
            Self::ScenarioStarted { .. } => "scenario_started",
            Self::InvariantCheckpoint { .. } => "invariant_checkpoint",
            Self::ScenarioCompleted { .. } => "scenario_completed",
        }
    }

    /// Returns the default log level for this event type per the schema.
    #[must_use]
    pub fn default_level(&self) -> &'static str {
        match self {
            Self::PacketSent { .. }
            | Self::AckReceived { .. }
            | Self::RttUpdated { .. }
            | Self::StreamOpened { .. }
            | Self::FlowControlUpdated { .. }
            | Self::HandshakeStep { .. }
            | Self::RequestHeadersSent { .. }
            | Self::RequestDataSent { .. }
            | Self::RequestStreamStateChanged { .. } => "DEBUG",

            Self::StreamDataSent { .. }
            | Self::StreamDataReceived { .. }
            | Self::FrameEncoded { .. }
            | Self::FrameDecoded { .. } => "TRACE",

            Self::FrameError { .. } => "WARN",

            // Everything else is INFO.
            _ => "INFO",
        }
    }
}

// ============================================================================
// NDJSON envelope
// ============================================================================

/// A single NDJSON line following the forensic log envelope schema.
#[derive(Debug, Clone, Serialize)]
struct ForensicNdjsonLine<'a> {
    v: u32,
    ts_us: u64,
    level: &'a str,
    category: &'a str,
    event: &'a str,
    test_id: &'a str,
    seed: String,
    subsystem: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    invariant: Option<&'a str>,
    thread_id: u64,
    message: String,
    data: &'a QuicH3Event,
}

// ============================================================================
// Internal record
// ============================================================================

/// A single logged event with its metadata.
#[derive(Clone, Debug)]
struct ForensicRecord {
    ts_us: u64,
    category: String,
    level: String,
    event: QuicH3Event,
}

// ============================================================================
// QuicH3ForensicLogger
// ============================================================================

/// Thread-safe forensic event logger for QUIC/H3 E2E test scenarios.
///
/// Collects structured events during a test execution and emits them as
/// NDJSON for CI parsing and failure triage.
pub struct QuicH3ForensicLogger {
    scenario_id: String,
    seed: u64,
    test_function: String,
    records: Mutex<Vec<ForensicRecord>>,
}

impl std::fmt::Debug for QuicH3ForensicLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.records.lock().len();
        f.debug_struct("QuicH3ForensicLogger")
            .field("scenario_id", &self.scenario_id)
            .field("seed", &self.seed)
            .field("test_function", &self.test_function)
            .field("event_count", &count)
            .finish()
    }
}

impl QuicH3ForensicLogger {
    /// Create a new forensic logger for a test scenario.
    #[must_use]
    pub fn new(scenario_id: &str, seed: u64, test_function: &str) -> Self {
        Self {
            scenario_id: scenario_id.to_string(),
            seed,
            test_function: test_function.to_string(),
            records: Mutex::new(Vec::new()),
        }
    }

    /// Log a structured event with explicit timestamp and category.
    pub fn log(&self, ts_us: u64, category: &str, event: QuicH3Event) {
        let level = event.default_level().to_string();
        self.records.lock().push(ForensicRecord {
            ts_us,
            category: category.to_string(),
            level,
            event,
        });
    }

    /// Convenience: log an `InvariantCheckpoint` event.
    pub fn log_invariant(&self, ts_us: u64, invariant_id: &str, verdict: &str, details: &str) {
        self.log(
            ts_us,
            "test_harness",
            QuicH3Event::InvariantCheckpoint {
                invariant_id: invariant_id.to_string(),
                verdict: verdict.to_string(),
                details: details.to_string(),
            },
        );
    }

    /// Returns the total number of recorded events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.records.lock().len()
    }

    /// Returns event counts grouped by category.
    #[must_use]
    pub fn events_by_category(&self) -> BTreeMap<String, u64> {
        let records = self.records.lock();
        let mut map = BTreeMap::new();
        for r in records.iter() {
            *map.entry(r.category.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Returns event counts grouped by log level.
    #[must_use]
    pub fn events_by_level(&self) -> BTreeMap<String, u64> {
        let records = self.records.lock();
        let mut map = BTreeMap::new();
        for r in records.iter() {
            *map.entry(r.level.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Returns the scenario ID.
    #[must_use]
    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    /// Returns the seed.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the test function name.
    #[must_use]
    pub fn test_function(&self) -> &str {
        &self.test_function
    }

    /// Write all recorded events as NDJSON to the given path.
    ///
    /// Each line is a self-contained JSON object following the forensic log
    /// envelope schema.
    pub fn write_ndjson(&self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut writer = std::io::BufWriter::new(file);

        let records = self.records.lock();
        let seed_hex = format!("0x{:X}", self.seed);
        let thread_id = current_thread_id();

        for r in records.iter() {
            let line = ForensicNdjsonLine {
                v: FORENSIC_SCHEMA_VERSION,
                ts_us: r.ts_us,
                level: &r.level,
                category: &r.category,
                event: r.event.event_name(),
                test_id: &self.test_function,
                seed: seed_hex.clone(),
                subsystem: SUBSYSTEM,
                invariant: match &r.event {
                    QuicH3Event::InvariantCheckpoint { invariant_id, .. } => {
                        Some(invariant_id.as_str())
                    }
                    _ => None,
                },
                thread_id,
                message: format!("[{}] {}", r.category, r.event.event_name()),
                data: &r.event,
            };

            serde_json::to_writer(&mut writer, &line)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            writer.write_all(b"\n")?;
        }

        writer.flush()
    }

    /// Returns a snapshot of all recorded events (for building the manifest).
    fn snapshot(&self) -> Vec<ForensicRecord> {
        self.records.lock().clone()
    }
}

/// Get the current OS thread ID as u64.
fn current_thread_id() -> u64 {
    let id = std::thread::current().id();
    let s = format!("{id:?}");
    s.trim_start_matches("ThreadId(")
        .trim_end_matches(')')
        .parse::<u64>()
        .unwrap_or_default()
}

// ============================================================================
// QuicH3ScenarioManifest
// ============================================================================

/// Per-scenario manifest emitted at test completion.
///
/// Extends the base `ReproManifest` concept with QUIC/H3-specific summaries,
/// matching the `scenario_manifest` section of the forensic log schema.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize)]
pub struct QuicH3ScenarioManifest {
    pub schema_id: String,
    pub schema_version: u32,
    pub scenario_id: String,
    pub seed: String,
    pub config_hash: String,
    pub trace_fingerprint: String,
    pub replay_command: String,
    pub failure_class: String,
    pub invariant_ids: Vec<String>,
    pub invariant_verdicts: Vec<InvariantVerdict>,
    pub artifact_paths: Vec<String>,
    pub event_timeline: EventTimeline,
    pub transport_summary: TransportSummary,
    pub h3_summary: H3Summary,
    pub connection_lifecycle: Vec<LifecycleTransition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_fingerprint: Option<FailureFingerprint>,
    pub passed: bool,
    pub duration_us: u64,
    pub profile_tags: Vec<String>,
}

/// A single invariant verdict entry.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize)]
pub struct InvariantVerdict {
    pub invariant_id: String,
    pub verdict: String,
    pub details: String,
}

/// Summary of event counts by category and level.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize)]
pub struct EventTimeline {
    pub total_events: u64,
    pub by_category: BTreeMap<String, u64>,
    pub by_level: BTreeMap<String, u64>,
}

/// QUIC transport metrics snapshot at scenario end.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize)]
pub struct TransportSummary {
    pub packets_sent: u64,
    pub packets_acked: u64,
    pub packets_lost: u64,
    pub bytes_sent: u64,
    pub bytes_acked: u64,
    pub bytes_lost: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoothed_rtt_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rtt_us: Option<u64>,
    pub cwnd: u64,
    pub ssthresh: u64,
    pub pto_count: u32,
    pub final_state: String,
}

impl Default for TransportSummary {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            packets_acked: 0,
            packets_lost: 0,
            bytes_sent: 0,
            bytes_acked: 0,
            bytes_lost: 0,
            smoothed_rtt_us: None,
            min_rtt_us: None,
            cwnd: 0,
            ssthresh: 0,
            pto_count: 0,
            final_state: "idle".to_string(),
        }
    }
}

/// H3-level metrics at scenario end.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize)]
pub struct H3Summary {
    pub requests_sent: u32,
    pub responses_received: u32,
    pub streams_opened: u32,
    pub streams_reset: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goaway_id: Option<u64>,
    pub settings_exchanged: bool,
    pub protocol_errors: u32,
}

impl Default for H3Summary {
    fn default() -> Self {
        Self {
            requests_sent: 0,
            responses_received: 0,
            streams_opened: 0,
            streams_reset: 0,
            goaway_id: None,
            settings_exchanged: false,
            protocol_errors: 0,
        }
    }
}

/// An entry in the connection lifecycle state transition log.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize)]
pub struct LifecycleTransition {
    pub from_state: String,
    pub to_state: String,
    pub ts_us: u64,
    pub trigger: String,
}

/// Failure fingerprint for post-mortem triage (populated only on failure).
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize)]
pub struct FailureFingerprint {
    pub bucket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backtrace_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_before_failure: Option<serde_json::Value>,
}

impl QuicH3ScenarioManifest {
    /// Build a manifest from a completed logger session.
    ///
    /// Walks the recorded events to populate transport/h3 summaries,
    /// invariant verdicts, and connection lifecycle transitions.
    #[must_use]
    pub fn from_logger(logger: &QuicH3ForensicLogger, passed: bool, duration_us: u64) -> Self {
        let records = logger.snapshot();

        // -- Invariant verdicts & IDs ----------------------------------------
        let mut invariant_verdicts = Vec::new();
        let mut invariant_ids = Vec::new();
        for r in &records {
            if let QuicH3Event::InvariantCheckpoint {
                invariant_id,
                verdict,
                details,
            } = &r.event
            {
                invariant_ids.push(invariant_id.clone());
                invariant_verdicts.push(InvariantVerdict {
                    invariant_id: invariant_id.clone(),
                    verdict: verdict.clone(),
                    details: details.clone(),
                });
            }
        }
        invariant_ids.sort_unstable();
        invariant_ids.dedup();

        // -- Transport summary from events -----------------------------------
        let mut transport = TransportSummary::default();
        for r in &records {
            match &r.event {
                QuicH3Event::PacketSent { size_bytes, .. } => {
                    transport.packets_sent += 1;
                    transport.bytes_sent += size_bytes;
                }
                QuicH3Event::AckReceived {
                    acked_packets,
                    acked_bytes,
                    ..
                } => {
                    transport.packets_acked += acked_packets;
                    transport.bytes_acked += acked_bytes;
                }
                QuicH3Event::LossDetected {
                    lost_packets,
                    lost_bytes,
                    ..
                } => {
                    transport.packets_lost += lost_packets;
                    transport.bytes_lost += lost_bytes;
                }
                QuicH3Event::RttUpdated {
                    smoothed_rtt_us,
                    min_rtt_us,
                    ..
                } => {
                    transport.smoothed_rtt_us = Some(*smoothed_rtt_us);
                    transport.min_rtt_us = Some(*min_rtt_us);
                }
                QuicH3Event::CwndUpdated {
                    new_cwnd, ssthresh, ..
                } => {
                    transport.cwnd = *new_cwnd;
                    transport.ssthresh = *ssthresh;
                }
                QuicH3Event::PtoFired { pto_count, .. } => {
                    transport.pto_count = *pto_count;
                }
                QuicH3Event::StateChanged { to_state, .. } => {
                    transport.final_state = to_state.clone();
                }
                _ => {}
            }
        }

        // -- H3 summary from events ------------------------------------------
        let mut h3 = H3Summary::default();
        for r in &records {
            match &r.event {
                QuicH3Event::RequestStarted { .. } => {
                    h3.requests_sent += 1;
                }
                QuicH3Event::ResponseReceived { .. } => {
                    h3.responses_received += 1;
                }
                QuicH3Event::StreamOpened { .. } => {
                    h3.streams_opened += 1;
                }
                QuicH3Event::StreamReset { .. } => {
                    h3.streams_reset += 1;
                }
                QuicH3Event::GoawayReceived { stream_id, .. } => {
                    h3.goaway_id = Some(*stream_id);
                }
                QuicH3Event::SettingsExchanged { .. } => {
                    h3.settings_exchanged = true;
                }
                QuicH3Event::FrameError { .. } => {
                    h3.protocol_errors += 1;
                }
                _ => {}
            }
        }

        // -- Connection lifecycle transitions ---------------------------------
        let mut lifecycle = Vec::new();
        for r in &records {
            if let QuicH3Event::StateChanged {
                from_state,
                to_state,
                trigger,
            } = &r.event
            {
                lifecycle.push(LifecycleTransition {
                    from_state: from_state.clone(),
                    to_state: to_state.clone(),
                    ts_us: r.ts_us,
                    trigger: trigger.clone(),
                });
            }
        }

        // -- Event timeline --------------------------------------------------
        let by_category = logger.events_by_category();
        let by_level = logger.events_by_level();
        let total_events = records.len() as u64;

        // -- Trace fingerprint (deterministic hash of event names + timestamps)
        let trace_fingerprint = {
            const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
            const FNV_PRIME: u64 = 0x0100_0000_01b3;
            let mut h = FNV_OFFSET;
            for r in &records {
                for b in r.ts_us.to_le_bytes() {
                    h ^= u64::from(b);
                    h = h.wrapping_mul(FNV_PRIME);
                }
                for b in r.event.event_name().as_bytes() {
                    h ^= u64::from(*b);
                    h = h.wrapping_mul(FNV_PRIME);
                }
            }
            format!("{h:016x}")
        };

        let failure_class = if passed {
            "passed".to_string()
        } else {
            "assertion_failure".to_string()
        };

        let replay_command = format!(
            "ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
            logger.seed(),
            logger.test_function(),
        );

        Self {
            schema_id: FORENSIC_MANIFEST_SCHEMA_ID.to_string(),
            schema_version: FORENSIC_SCHEMA_VERSION,
            scenario_id: logger.scenario_id().to_string(),
            seed: format!("0x{:016X}", logger.seed()),
            config_hash: String::new(),
            trace_fingerprint,
            replay_command,
            failure_class,
            invariant_ids,
            invariant_verdicts,
            artifact_paths: Vec::new(),
            event_timeline: EventTimeline {
                total_events,
                by_category,
                by_level,
            },
            transport_summary: transport,
            h3_summary: h3,
            connection_lifecycle: lifecycle,
            failure_fingerprint: if passed {
                None
            } else {
                Some(FailureFingerprint {
                    bucket: "assertion_failure".to_string(),
                    assertion: None,
                    backtrace_hash: None,
                    last_event_before_failure: records
                        .last()
                        .map(|r| serde_json::to_value(&r.event).unwrap_or(serde_json::Value::Null)),
                })
            },
            passed,
            duration_us,
            profile_tags: Vec::new(),
        }
    }

    /// Serialize the manifest as pretty-printed JSON to the given path.
    pub fn write_json(&self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_logger_records_events() {
        init_test("test_logger_records_events");

        let logger = QuicH3ForensicLogger::new("QH3-E2-TEST", 0xCAFE, "test_logger_records_events");

        logger.log(
            100,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "initial".into(),
                packet_number: 0,
                size_bytes: 1200,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: 100,
            },
        );
        logger.log(
            200,
            "quic_transport",
            QuicH3Event::AckReceived {
                pn_space: "initial".into(),
                acked_ranges: vec![(0, 0)],
                ack_delay_us: 50,
                acked_packets: 1,
                acked_bytes: 1200,
            },
        );
        logger.log(
            300,
            "quic_stream",
            QuicH3Event::StreamOpened {
                stream_id: 0,
                direction: "bidi".into(),
                role: "client".into(),
                is_local: true,
            },
        );
        logger.log(
            400,
            "h3_request",
            QuicH3Event::RequestStarted {
                stream_id: 0,
                method: "GET".into(),
                scheme: "https".into(),
                authority: "localhost".into(),
                path: "/".into(),
            },
        );

        assert_eq!(logger.event_count(), 4);

        let by_cat = logger.events_by_category();
        assert_eq!(by_cat.get("quic_transport"), Some(&2));
        assert_eq!(by_cat.get("quic_stream"), Some(&1));
        assert_eq!(by_cat.get("h3_request"), Some(&1));

        crate::test_complete!("test_logger_records_events");
    }

    #[test]
    fn test_ndjson_roundtrip() {
        init_test("test_ndjson_roundtrip");

        let logger = QuicH3ForensicLogger::new("QH3-ROUNDTRIP", 0xBEEF, "test_ndjson_roundtrip");

        logger.log(
            0,
            "test_harness",
            QuicH3Event::ScenarioStarted {
                scenario_id: "QH3-ROUNDTRIP".into(),
                seed: 0xBEEF,
                config_hash: "abc123".into(),
                test_file: "forensic_log.rs".into(),
                test_function: "test_ndjson_roundtrip".into(),
            },
        );
        logger.log(
            1000,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "handshake".into(),
                packet_number: 0,
                size_bytes: 1200,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: 1000,
            },
        );
        logger.log(
            2000,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "idle".into(),
                to_state: "handshaking".into(),
                trigger: "begin_handshake".into(),
            },
        );

        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let ndjson_path = tmp.path().join("events.ndjson");

        logger.write_ndjson(&ndjson_path).expect("write ndjson");

        // Read back and verify
        let contents = std::fs::read_to_string(&ndjson_path).expect("read ndjson");
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "expected 3 NDJSON lines, got {}",
            lines.len()
        );

        // Verify each line is valid JSON with correct envelope fields
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(parsed["v"], 1);
            assert_eq!(parsed["subsystem"], "quic_h3_native");
            assert_eq!(parsed["test_id"], "test_ndjson_roundtrip");
            assert_eq!(parsed["seed"], "0xBEEF");
        }

        // Verify first event is scenario_started
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "scenario_started");
        assert_eq!(first["category"], "test_harness");

        // Verify second event has correct data
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "packet_sent");
        assert_eq!(second["data"]["pn_space"], "handshake");

        crate::test_complete!("test_ndjson_roundtrip");
    }

    #[test]
    fn test_manifest_from_logger() {
        init_test("test_manifest_from_logger");

        let logger =
            QuicH3ForensicLogger::new("QH3-E2-MANIFEST", 0xDEAD_BEEF, "test_manifest_from_logger");

        // Transport events
        logger.log(
            100,
            "quic_transport",
            QuicH3Event::PacketSent {
                pn_space: "initial".into(),
                packet_number: 0,
                size_bytes: 1200,
                ack_eliciting: true,
                in_flight: true,
                send_time_us: 100,
            },
        );
        logger.log(
            200,
            "quic_transport",
            QuicH3Event::AckReceived {
                pn_space: "initial".into(),
                acked_ranges: vec![(0, 0)],
                ack_delay_us: 50,
                acked_packets: 1,
                acked_bytes: 1200,
            },
        );
        logger.log(
            300,
            "quic_transport",
            QuicH3Event::RttUpdated {
                latest_rtt_us: 20_000,
                smoothed_rtt_us: 20_000,
                rttvar_us: 10_000,
                min_rtt_us: 20_000,
                ack_delay_us: 50,
            },
        );
        logger.log(
            400,
            "quic_transport",
            QuicH3Event::CwndUpdated {
                old_cwnd: 14_720,
                new_cwnd: 15_920,
                ssthresh: u64::MAX,
                bytes_in_flight: 1200,
                reason: "slow_start".into(),
            },
        );

        // Connection lifecycle
        logger.log(
            50,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "idle".into(),
                to_state: "handshaking".into(),
                trigger: "begin_handshake".into(),
            },
        );
        logger.log(
            500,
            "quic_connection",
            QuicH3Event::StateChanged {
                from_state: "handshaking".into(),
                to_state: "established".into(),
                trigger: "handshake_confirmed".into(),
            },
        );

        // H3 events
        logger.log(
            600,
            "quic_stream",
            QuicH3Event::StreamOpened {
                stream_id: 0,
                direction: "bidi".into(),
                role: "client".into(),
                is_local: true,
            },
        );
        logger.log(
            700,
            "h3_request",
            QuicH3Event::RequestStarted {
                stream_id: 0,
                method: "GET".into(),
                scheme: "https".into(),
                authority: "localhost".into(),
                path: "/index.html".into(),
            },
        );
        logger.log(
            800,
            "h3_request",
            QuicH3Event::ResponseReceived {
                stream_id: 0,
                status_code: 200,
                header_count: 3,
                body_bytes: 4096,
            },
        );
        logger.log(
            900,
            "h3_control",
            QuicH3Event::SettingsExchanged {
                direction: "sent".into(),
                max_field_section_size: 65536,
                qpack_max_table_capacity: 0,
                qpack_blocked_streams: 0,
            },
        );

        // Invariants
        logger.log_invariant(
            1000,
            "inv.quic.handshake_completes",
            "pass",
            "Both endpoints reached Established",
        );
        logger.log_invariant(
            1100,
            "inv.quic.rtt_positive",
            "pass",
            "smoothed_rtt=20000us",
        );

        let manifest = QuicH3ScenarioManifest::from_logger(&logger, true, 1_100_000);

        // Verify basic fields
        assert_eq!(manifest.schema_id, FORENSIC_MANIFEST_SCHEMA_ID);
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.scenario_id, "QH3-E2-MANIFEST");
        assert_eq!(manifest.seed, "0x00000000DEADBEEF");
        assert!(manifest.passed);
        assert_eq!(manifest.duration_us, 1_100_000);
        assert_eq!(manifest.failure_class, "passed");
        assert!(manifest.failure_fingerprint.is_none());

        // Verify transport summary
        assert_eq!(manifest.transport_summary.packets_sent, 1);
        assert_eq!(manifest.transport_summary.packets_acked, 1);
        assert_eq!(manifest.transport_summary.bytes_sent, 1200);
        assert_eq!(manifest.transport_summary.bytes_acked, 1200);
        assert_eq!(manifest.transport_summary.smoothed_rtt_us, Some(20_000));
        assert_eq!(manifest.transport_summary.min_rtt_us, Some(20_000));
        assert_eq!(manifest.transport_summary.cwnd, 15_920);
        assert_eq!(manifest.transport_summary.final_state, "established");

        // Verify H3 summary
        assert_eq!(manifest.h3_summary.requests_sent, 1);
        assert_eq!(manifest.h3_summary.responses_received, 1);
        assert_eq!(manifest.h3_summary.streams_opened, 1);
        assert!(manifest.h3_summary.settings_exchanged);

        // Verify connection lifecycle
        assert_eq!(manifest.connection_lifecycle.len(), 2);
        assert_eq!(manifest.connection_lifecycle[0].from_state, "idle");
        assert_eq!(manifest.connection_lifecycle[0].to_state, "handshaking");
        assert_eq!(manifest.connection_lifecycle[1].to_state, "established");

        // Verify invariants
        assert_eq!(manifest.invariant_ids.len(), 2);
        assert!(
            manifest
                .invariant_ids
                .contains(&"inv.quic.handshake_completes".to_string())
        );
        assert!(
            manifest
                .invariant_ids
                .contains(&"inv.quic.rtt_positive".to_string())
        );
        assert_eq!(manifest.invariant_verdicts.len(), 2);
        assert_eq!(manifest.invariant_verdicts[0].verdict, "pass");

        // Verify event timeline
        assert_eq!(manifest.event_timeline.total_events, 12);
        assert_eq!(
            manifest.event_timeline.by_category.get("quic_transport"),
            Some(&4)
        );

        // Verify replay command
        assert!(
            manifest
                .replay_command
                .contains("ASUPERSYNC_SEED=0xDEADBEEF")
        );
        assert!(
            manifest
                .replay_command
                .contains("test_manifest_from_logger")
        );

        // Verify trace fingerprint is non-empty
        assert!(!manifest.trace_fingerprint.is_empty());

        // Verify manifest can be written and read back as JSON
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let manifest_path = tmp.path().join("manifest.json");
        manifest.write_json(&manifest_path).expect("write manifest");

        let contents = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let parsed: serde_json::Value =
            serde_json::from_str(&contents).expect("valid manifest JSON");
        assert_eq!(parsed["schema_id"], FORENSIC_MANIFEST_SCHEMA_ID);
        assert_eq!(parsed["passed"], true);

        crate::test_complete!("test_manifest_from_logger");
    }

    #[test]
    fn test_invariant_logging() {
        init_test("test_invariant_logging");

        let logger = QuicH3ForensicLogger::new("QH3-INV-TEST", 0xFACE, "test_invariant_logging");

        logger.log_invariant(
            100,
            "inv.quic.handshake_completes",
            "pass",
            "Handshake completed on both sides",
        );
        logger.log_invariant(
            200,
            "inv.quic.rtt_positive",
            "pass",
            "smoothed_rtt=15000us after first ACK",
        );
        logger.log_invariant(
            300,
            "inv.h3.settings_before_other_frames",
            "fail",
            "DATA frame preceded SETTINGS on control stream",
        );
        logger.log_invariant(
            400,
            "inv.quic.cwnd_never_below_minimum",
            "skip",
            "No cwnd events",
        );

        assert_eq!(logger.event_count(), 4);

        let by_cat = logger.events_by_category();
        assert_eq!(by_cat.get("test_harness"), Some(&4));

        // Build manifest and check invariant fields
        let manifest = QuicH3ScenarioManifest::from_logger(&logger, false, 500_000);
        assert!(!manifest.passed);
        assert_eq!(manifest.failure_class, "assertion_failure");

        // Invariant IDs should be sorted and deduped
        assert_eq!(manifest.invariant_ids.len(), 4);
        assert_eq!(
            manifest.invariant_ids[0],
            "inv.h3.settings_before_other_frames"
        );
        assert_eq!(
            manifest.invariant_ids[1],
            "inv.quic.cwnd_never_below_minimum"
        );
        assert_eq!(manifest.invariant_ids[2], "inv.quic.handshake_completes");
        assert_eq!(manifest.invariant_ids[3], "inv.quic.rtt_positive");

        // Verdicts preserve insertion order
        assert_eq!(manifest.invariant_verdicts.len(), 4);
        assert_eq!(
            manifest.invariant_verdicts[0].invariant_id,
            "inv.quic.handshake_completes"
        );
        assert_eq!(manifest.invariant_verdicts[0].verdict, "pass");
        assert_eq!(
            manifest.invariant_verdicts[2].invariant_id,
            "inv.h3.settings_before_other_frames"
        );
        assert_eq!(manifest.invariant_verdicts[2].verdict, "fail");
        assert_eq!(manifest.invariant_verdicts[3].verdict, "skip");

        // Failure fingerprint should be populated on failure
        assert!(manifest.failure_fingerprint.is_some());
        let fp = manifest.failure_fingerprint.as_ref().unwrap();
        assert_eq!(fp.bucket, "assertion_failure");

        // Write NDJSON and verify invariant events have the invariant field set
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let ndjson_path = tmp.path().join("invariants.ndjson");
        logger.write_ndjson(&ndjson_path).expect("write ndjson");

        let contents = std::fs::read_to_string(&ndjson_path).expect("read ndjson");
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 4);

        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(parsed["event"], "invariant_checkpoint");
            assert_eq!(parsed["category"], "test_harness");
            // The invariant field should be set for checkpoint events
            assert!(
                parsed["invariant"].is_string(),
                "invariant field should be set"
            );
        }

        // Verify specific invariant fields in the first event
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["invariant"], "inv.quic.handshake_completes");
        assert_eq!(first["data"]["verdict"], "pass");

        crate::test_complete!("test_invariant_logging");
    }

    #[test]
    fn quic_h3_event_debug_clone() {
        let ev = QuicH3Event::PacketSent {
            pn_space: "initial".into(),
            packet_number: 0,
            size_bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            send_time_us: 100,
        };
        let dbg = format!("{ev:?}");
        assert!(dbg.contains("PacketSent"), "{dbg}");
        let cloned = ev.clone();
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn invariant_verdict_debug_clone() {
        let v = InvariantVerdict {
            invariant_id: "inv.test".into(),
            verdict: "pass".into(),
            details: "ok".into(),
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("inv.test"), "{dbg}");
        let cloned = v.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn event_timeline_debug_clone() {
        let t = EventTimeline {
            total_events: 42,
            by_category: BTreeMap::new(),
            by_level: BTreeMap::new(),
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("42"), "{dbg}");
        let cloned = t.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn transport_summary_debug_clone_default() {
        let s = TransportSummary::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TransportSummary"), "{dbg}");
        assert_eq!(s.packets_sent, 0);
        let cloned = s.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn h3_summary_debug_clone_default() {
        let h = H3Summary::default();
        let dbg = format!("{h:?}");
        assert!(dbg.contains("H3Summary"), "{dbg}");
        assert_eq!(h.requests_sent, 0);
        assert!(!h.settings_exchanged);
        let cloned = h.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn lifecycle_transition_debug_clone() {
        let t = LifecycleTransition {
            from_state: "idle".into(),
            to_state: "handshaking".into(),
            ts_us: 100,
            trigger: "begin".into(),
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("idle"), "{dbg}");
        let cloned = t.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn failure_fingerprint_debug_clone() {
        let f = FailureFingerprint {
            bucket: "timeout".into(),
            assertion: Some("expected ok".into()),
            backtrace_hash: None,
            last_event_before_failure: None,
        };
        let dbg = format!("{f:?}");
        assert!(dbg.contains("timeout"), "{dbg}");
        let cloned = f.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }
}
