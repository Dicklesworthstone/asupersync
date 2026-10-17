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
    PathValidationStarted {
        path_id: String,
        local_addr: String,
        remote_addr: String,
        challenge_len: u32,
    },
    PathValidationCompleted {
        path_id: String,
        validated: bool,
        reason: String,
        new_active_path: bool,
    },
    MigrationObserved {
        from_path_id: String,
        to_path_id: String,
        reason: String,
        stream_state_preserved: bool,
    },
    CancelRequested {
        scope: String,
        reason: String,
        trigger: String,
    },
    RegionStateChanged {
        region_id: u64,
        from_state: String,
        to_state: String,
        live_children: u32,
        outstanding_obligations: u32,
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
            Self::PathValidationStarted { .. } => "path_validation_started",
            Self::PathValidationCompleted { .. } => "path_validation_completed",
            Self::MigrationObserved { .. } => "migration_observed",
            Self::CancelRequested { .. } => "cancel_requested",
            Self::RegionStateChanged { .. } => "region_state_changed",
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
            | Self::RegionStateChanged { .. }
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
        drop(records);
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
        drop(records);
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

        let records = self.records.lock().clone();
        let seed_hex = format!("0x{:X}", self.seed);
        let thread_id = current_thread_id();

        for r in &records {
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

            serde_json::to_writer(&mut writer, &line).map_err(std::io::Error::other)?;
            writer.write_all(b"\n")?;
        }

        writer.flush()
    }

    /// Return a qlog-style JSON document for native QUIC/H3 forensic events.
    ///
    /// The output intentionally keeps the existing event payloads intact while
    /// wrapping them in a qlog-compatible `traces[].events[]` shape. This gives
    /// release and failure tooling one artifact that preserves packet evidence,
    /// path/migration events, cancellation context, seed, and replay metadata.
    #[must_use]
    pub fn to_qlog_json(&self) -> serde_json::Value {
        let records = self.records.lock().clone();
        let seed_hex = format!("0x{:016X}", self.seed);
        let replay_command = format!(
            "ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
            self.seed, self.test_function
        );
        let events = records
            .iter()
            .map(|r| {
                serde_json::json!([
                    r.ts_us,
                    qlog_category(&r.category),
                    r.event.event_name(),
                    serde_json::to_value(&r.event).unwrap_or(serde_json::Value::Null)
                ])
            })
            .collect::<Vec<_>>();

        serde_json::json!({
            "qlog_version": "0.3",
            "qlog_format": "JSON",
            "title": self.scenario_id,
            "traces": [{
                "vantage_point": {
                    "type": "endpoint",
                    "name": SUBSYSTEM
                },
                "title": self.scenario_id,
                "common_fields": {
                    "protocol_type": "QUIC_HTTP3",
                    "scenario_id": self.scenario_id,
                    "seed": seed_hex,
                    "test_id": self.test_function,
                    "replay_command": replay_command,
                    "time_format": "relative_us"
                },
                "events": events
            }]
        })
    }

    /// Write a qlog-style JSON document to the given path.
    pub fn write_qlog_json(&self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.to_qlog_json()).map_err(std::io::Error::other)
    }

    /// Returns a snapshot of all recorded events (for building the manifest).
    fn snapshot(&self) -> Vec<ForensicRecord> {
        self.records.lock().clone()
    }
}

fn qlog_category(category: &str) -> &'static str {
    match category {
        "quic_transport" | "quic_stream" => "transport",
        "quic_connection" | "quic_path" => "connectivity",
        "cancel_region" => "recovery",
        "h3_control" | "h3_request" | "h3_frame" => "http",
        "test_harness" => "simulation",
        _ => "generic",
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
    pub cancel_region_summary: CancelRegionSummary,
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
#[derive(Debug, Clone, Default, Serialize)]
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

/// Correlated cancellation and region-lifecycle signal summary.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, Serialize)]
pub struct CancelRegionSummary {
    pub cancellation_requests: u32,
    pub region_transitions: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_cancel_ts_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_close_initiated_ts_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_to_close_latency_us: Option<u64>,
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
        let (invariant_ids, invariant_verdicts) = Self::extract_invariants(&records);
        let transport = Self::extract_transport(&records);
        let h3 = Self::extract_h3(&records);
        let cancel_region = Self::extract_cancel_region(&records);
        let lifecycle = Self::extract_lifecycle(&records);
        let trace_fingerprint = Self::compute_trace_fingerprint(&records);

        let failure_class = if passed {
            "passed"
        } else {
            "assertion_failure"
        }
        .to_string();
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
                total_events: records.len() as u64,
                by_category: logger.events_by_category(),
                by_level: logger.events_by_level(),
            },
            transport_summary: transport,
            h3_summary: h3,
            cancel_region_summary: cancel_region,
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

    fn extract_invariants(records: &[ForensicRecord]) -> (Vec<String>, Vec<InvariantVerdict>) {
        let mut verdicts = Vec::new();
        let mut ids = Vec::new();
        for r in records {
            if let QuicH3Event::InvariantCheckpoint {
                invariant_id,
                verdict,
                details,
            } = &r.event
            {
                ids.push(invariant_id.clone());
                verdicts.push(InvariantVerdict {
                    invariant_id: invariant_id.clone(),
                    verdict: verdict.clone(),
                    details: details.clone(),
                });
            }
        }
        ids.sort_unstable();
        ids.dedup();
        (ids, verdicts)
    }

    fn extract_transport(records: &[ForensicRecord]) -> TransportSummary {
        let mut t = TransportSummary::default();
        for r in records {
            match &r.event {
                QuicH3Event::PacketSent { size_bytes, .. } => {
                    t.packets_sent += 1;
                    t.bytes_sent += size_bytes;
                }
                QuicH3Event::AckReceived {
                    acked_packets,
                    acked_bytes,
                    ..
                } => {
                    t.packets_acked += acked_packets;
                    t.bytes_acked += acked_bytes;
                }
                QuicH3Event::LossDetected {
                    lost_packets,
                    lost_bytes,
                    ..
                } => {
                    t.packets_lost += lost_packets;
                    t.bytes_lost += lost_bytes;
                }
                QuicH3Event::RttUpdated {
                    smoothed_rtt_us,
                    min_rtt_us,
                    ..
                } => {
                    t.smoothed_rtt_us = Some(*smoothed_rtt_us);
                    t.min_rtt_us = Some(*min_rtt_us);
                }
                QuicH3Event::CwndUpdated {
                    new_cwnd, ssthresh, ..
                } => {
                    t.cwnd = *new_cwnd;
                    t.ssthresh = *ssthresh;
                }
                QuicH3Event::PtoFired { pto_count, .. } => {
                    t.pto_count = *pto_count;
                }
                QuicH3Event::StateChanged { to_state, .. } => {
                    t.final_state.clone_from(to_state);
                }
                _ => {}
            }
        }
        t
    }

    fn extract_h3(records: &[ForensicRecord]) -> H3Summary {
        let mut h3 = H3Summary::default();
        for r in records {
            match &r.event {
                QuicH3Event::RequestStarted { .. } => h3.requests_sent += 1,
                QuicH3Event::ResponseReceived { .. } => h3.responses_received += 1,
                QuicH3Event::StreamOpened { .. } => h3.streams_opened += 1,
                QuicH3Event::StreamReset { .. } => h3.streams_reset += 1,
                QuicH3Event::GoawayReceived { stream_id, .. } => {
                    h3.goaway_id = Some(*stream_id);
                }
                QuicH3Event::SettingsExchanged { .. } => h3.settings_exchanged = true,
                QuicH3Event::FrameError { .. } => h3.protocol_errors += 1,
                _ => {}
            }
        }
        h3
    }

    fn extract_cancel_region(records: &[ForensicRecord]) -> CancelRegionSummary {
        let mut summary = CancelRegionSummary::default();
        for r in records {
            match &r.event {
                QuicH3Event::CancelRequested { .. } => {
                    summary.cancellation_requests += 1;
                    if summary.first_cancel_ts_us.is_none() {
                        summary.first_cancel_ts_us = Some(r.ts_us);
                    }
                }
                QuicH3Event::RegionStateChanged { .. } => {
                    summary.region_transitions += 1;
                }
                QuicH3Event::CloseInitiated { .. }
                    if summary.first_close_initiated_ts_us.is_none() =>
                {
                    summary.first_close_initiated_ts_us = Some(r.ts_us);
                }
                _ => {}
            }
        }

        if let (Some(cancel_ts), Some(close_ts)) = (
            summary.first_cancel_ts_us,
            summary.first_close_initiated_ts_us,
        ) {
            if close_ts >= cancel_ts {
                summary.cancel_to_close_latency_us = Some(close_ts - cancel_ts);
            }
        }

        summary
    }

    fn extract_lifecycle(records: &[ForensicRecord]) -> Vec<LifecycleTransition> {
        records
            .iter()
            .filter_map(|r| {
                if let QuicH3Event::StateChanged {
                    from_state,
                    to_state,
                    trigger,
                } = &r.event
                {
                    Some(LifecycleTransition {
                        from_state: from_state.clone(),
                        to_state: to_state.clone(),
                        ts_us: r.ts_us,
                        trigger: trigger.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn compute_trace_fingerprint(records: &[ForensicRecord]) -> String {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for r in records {
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
    }

    /// Serialize the manifest as pretty-printed JSON to the given path.
    pub fn write_json(&self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self).map_err(std::io::Error::other)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "forensic_log_inline_tests.rs"]
mod tests;
