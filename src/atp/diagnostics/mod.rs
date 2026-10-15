//! ATP runtime-evidence diagnostics bridge.
//!
//! The bridge turns Asupersync runtime evidence into ATP-facing diagnostic
//! documents. Runtime facts that prove a protocol/runtime invariant are kept
//! separate from advisory risk signals such as spectral health, conformal
//! bounds, and e-process alerts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Stable schema for ATP runtime-evidence diagnostic envelopes.
pub const ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA: &str =
    "asupersync.atp.diagnostics.runtime_evidence.v1";

/// Stable schema for rendered ATP runtime-evidence explanations.
pub const ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA: &str =
    "asupersync.atp.diagnostics.runtime_explanation.v1";

/// Stable schema for ATP practical network-truth pressure evidence.
pub const ATP_NETWORK_TRUTH_PRESSURE_SCHEMA: &str =
    "asupersync.atp.diagnostics.network_truth_pressure.v1";

/// Maximum network-truth signals carried by one diagnostic envelope.
pub const ATP_NETWORK_TRUTH_MAX_SIGNALS: usize = 16;

const REDACTED: &str = "<redacted>";

/// Classification for a runtime evidence signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpRuntimeSignalClass {
    /// Evidence that directly proves an ATP protocol invariant.
    ProtocolProof,
    /// Evidence that directly proves an Asupersync runtime invariant.
    RuntimeProof,
    /// Calibrated or heuristic evidence that must not be worded as proof.
    AdvisoryRisk,
    /// Signal was expected but unavailable for this transfer.
    Unavailable,
}

impl AtpRuntimeSignalClass {
    /// Returns true when this signal may appear in `proof_claims`.
    #[must_use]
    pub const fn is_proof(self) -> bool {
        matches!(self, Self::ProtocolProof | Self::RuntimeProof)
    }

    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolProof => "protocol_proof",
            Self::RuntimeProof => "runtime_proof",
            Self::AdvisoryRisk => "advisory_risk",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Source family for ATP runtime evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpRuntimeSignalSource {
    /// Cx/region identity and structured-concurrency ownership.
    CxRegion,
    /// Transfer actor lifecycle identity.
    TransferActor,
    /// Obligation and futurelock accounting.
    ObligationTracker,
    /// Cancellation drain/finalizer evidence.
    CancellationDrain,
    /// Deterministic lab replay or crashpack pointer.
    ReplayCrashpack,
    /// Spectral wait-graph health.
    SpectralWaitGraph,
    /// Conformal calibration bound.
    ConformalAlert,
    /// Anytime-valid e-process alert.
    EProcessAlert,
    /// FrankenEvidence or decision-ledger row.
    EvidenceLedger,
}

impl AtpRuntimeSignalSource {
    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CxRegion => "cx_region",
            Self::TransferActor => "transfer_actor",
            Self::ObligationTracker => "obligation_tracker",
            Self::CancellationDrain => "cancellation_drain",
            Self::ReplayCrashpack => "replay_crashpack",
            Self::SpectralWaitGraph => "spectral_wait_graph",
            Self::ConformalAlert => "conformal_alert",
            Self::EProcessAlert => "eprocess_alert",
            Self::EvidenceLedger => "evidence_ledger",
        }
    }
}

/// Evidence quality for one practical network-truth signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpNetworkTruthSignalKind {
    /// Directly measured by ATP or the runtime.
    MeasuredFact,
    /// Inferred from multiple measured facts.
    InferredPressure,
    /// Useful estimate that must not be presented as measured fact.
    AdvisoryEstimate,
    /// Expected signal is unavailable on this platform/path.
    Unsupported,
}

impl AtpNetworkTruthSignalKind {
    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MeasuredFact => "measured_fact",
            Self::InferredPressure => "inferred_pressure",
            Self::AdvisoryEstimate => "advisory_estimate",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Practical network-truth metric families used by ATP diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpNetworkTruthMetric {
    /// Round-trip time.
    Rtt,
    /// ACK delay.
    AckDelay,
    /// Packet or symbol loss.
    Loss,
    /// Probe timeout pressure.
    Pto,
    /// Congestion window, when available.
    CongestionWindow,
    /// Bytes in flight, when available.
    BytesInFlight,
    /// Socket send/receive pressure.
    SocketPressure,
    /// Disk write/read lag pressure.
    DiskLag,
    /// CPU pressure from encode/decode work.
    CpuEncodeDecodePressure,
    /// Repair return-on-investment estimate.
    RepairRoi,
    /// Relay-vs-direct path delta.
    RelayDirectDelta,
    /// Path migration events.
    PathMigration,
    /// Cancellation pressure.
    CancellationPressure,
    /// Obligation drain latency.
    ObligationDrainLatency,
}

impl AtpNetworkTruthMetric {
    /// Every required metric family in deterministic order.
    pub const ALL: [Self; 14] = [
        Self::Rtt,
        Self::AckDelay,
        Self::Loss,
        Self::Pto,
        Self::CongestionWindow,
        Self::BytesInFlight,
        Self::SocketPressure,
        Self::DiskLag,
        Self::CpuEncodeDecodePressure,
        Self::RepairRoi,
        Self::RelayDirectDelta,
        Self::PathMigration,
        Self::CancellationPressure,
        Self::ObligationDrainLatency,
    ];

    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rtt => "rtt",
            Self::AckDelay => "ack_delay",
            Self::Loss => "loss",
            Self::Pto => "pto",
            Self::CongestionWindow => "congestion_window",
            Self::BytesInFlight => "bytes_in_flight",
            Self::SocketPressure => "socket_pressure",
            Self::DiskLag => "disk_lag",
            Self::CpuEncodeDecodePressure => "cpu_encode_decode_pressure",
            Self::RepairRoi => "repair_roi",
            Self::RelayDirectDelta => "relay_direct_delta",
            Self::PathMigration => "path_migration",
            Self::CancellationPressure => "cancellation_pressure",
            Self::ObligationDrainLatency => "obligation_drain_latency",
        }
    }
}

/// Aggregated ATP network pressure level.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpNetworkPressureLevel {
    /// No meaningful pressure detected.
    Nominal,
    /// Pressure is visible but not yet transfer-degrading.
    Watch,
    /// Pressure is likely affecting transfer quality.
    Degraded,
    /// Pressure is high enough to require conservative behavior.
    Critical,
}

impl AtpNetworkPressureLevel {
    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Watch => "watch",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
        }
    }
}

/// One practical network-truth signal for ATP diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpNetworkTruthSignal {
    /// Metric family.
    pub metric: AtpNetworkTruthMetric,
    /// Evidence quality.
    pub kind: AtpNetworkTruthSignalKind,
    /// Integer value in the declared unit, if available.
    pub value: Option<i64>,
    /// Stable unit label, such as `micros`, `permille`, `bytes`, or `ppm`.
    pub unit: String,
    /// Pressure contribution in parts-per-million, clamped to 0..=1_000_000.
    pub pressure_score_ppm: u32,
    /// Source reference, such as a pathlog row or proof bundle id.
    pub source_ref: Option<String>,
    /// Short operator-facing detail.
    pub detail: Option<String>,
}

impl AtpNetworkTruthSignal {
    /// Builds a network-truth signal.
    #[must_use]
    pub fn new(
        metric: AtpNetworkTruthMetric,
        kind: AtpNetworkTruthSignalKind,
        value: Option<i64>,
        unit: impl Into<String>,
        pressure_score_ppm: u32,
        source_ref: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            metric,
            kind,
            value,
            unit: unit.into(),
            pressure_score_ppm: pressure_score_ppm.min(1_000_000),
            source_ref,
            detail,
        }
    }

    /// Builds a directly measured fact.
    #[must_use]
    pub fn measured(
        metric: AtpNetworkTruthMetric,
        value: i64,
        unit: impl Into<String>,
        pressure_score_ppm: u32,
        source_ref: impl Into<String>,
    ) -> Self {
        Self::new(
            metric,
            AtpNetworkTruthSignalKind::MeasuredFact,
            Some(value),
            unit,
            pressure_score_ppm,
            Some(source_ref.into()),
            None,
        )
    }

    /// Builds an inferred pressure signal.
    #[must_use]
    pub fn inferred(
        metric: AtpNetworkTruthMetric,
        value: i64,
        unit: impl Into<String>,
        pressure_score_ppm: u32,
        source_ref: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            metric,
            AtpNetworkTruthSignalKind::InferredPressure,
            Some(value),
            unit,
            pressure_score_ppm,
            Some(source_ref.into()),
            Some(detail.into()),
        )
    }

    /// Builds an advisory estimate.
    #[must_use]
    pub fn advisory(
        metric: AtpNetworkTruthMetric,
        value: i64,
        unit: impl Into<String>,
        pressure_score_ppm: u32,
        source_ref: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            metric,
            AtpNetworkTruthSignalKind::AdvisoryEstimate,
            Some(value),
            unit,
            pressure_score_ppm,
            Some(source_ref.into()),
            Some(detail.into()),
        )
    }

    /// Builds an unsupported-signal downgrade.
    #[must_use]
    pub fn unsupported(metric: AtpNetworkTruthMetric, reason: impl Into<String>) -> Self {
        Self::new(
            metric,
            AtpNetworkTruthSignalKind::Unsupported,
            None,
            "unsupported",
            0,
            None,
            Some(reason.into()),
        )
    }
}

/// Practical network-truth pressure evidence attached to ATP diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpNetworkTruthPressureModel {
    /// Stable schema version.
    pub schema_version: String,
    /// Path or route id, when available.
    pub path_id: Option<String>,
    /// Deterministic lab/runtime timestamp in microseconds.
    pub deterministic_timestamp_micros: u64,
    /// Bounded metric signals.
    pub signals: Vec<AtpNetworkTruthSignal>,
    /// Redaction policy applied before user display.
    pub redaction_policy: String,
}

impl AtpNetworkTruthPressureModel {
    /// Creates an empty pressure model at a deterministic timestamp.
    #[must_use]
    pub fn new(deterministic_timestamp_micros: u64) -> Self {
        Self {
            schema_version: ATP_NETWORK_TRUTH_PRESSURE_SCHEMA.to_string(),
            path_id: None,
            deterministic_timestamp_micros,
            signals: Vec::new(),
            redaction_policy: "atp-network-truth-default".to_string(),
        }
    }

    /// Adds a signal if the model has remaining cardinality budget.
    pub fn add_signal(&mut self, signal: AtpNetworkTruthSignal) -> bool {
        if self.signals.len() >= ATP_NETWORK_TRUTH_MAX_SIGNALS {
            return false;
        }
        self.signals.push(signal);
        true
    }

    /// Highest pressure contribution in parts-per-million.
    #[must_use]
    pub fn overall_pressure_score_ppm(&self) -> u32 {
        self.signals
            .iter()
            .map(|signal| signal.pressure_score_ppm)
            .max()
            .unwrap_or(0)
    }

    /// Pressure level without hysteresis.
    #[must_use]
    pub fn pressure_level(&self) -> AtpNetworkPressureLevel {
        pressure_level_for_score(self.overall_pressure_score_ppm())
    }

    /// Pressure level with conservative downshift hysteresis.
    #[must_use]
    pub fn pressure_level_with_hysteresis(
        &self,
        previous: Option<AtpNetworkPressureLevel>,
    ) -> AtpNetworkPressureLevel {
        let candidate = self.pressure_level();
        let Some(previous) = previous else {
            return candidate;
        };
        if previous > candidate && self.overall_pressure_score_ppm() >= retention_floor(previous) {
            previous
        } else {
            candidate
        }
    }

    /// Metrics represented as unsupported by this model.
    #[must_use]
    pub fn unsupported_metrics(&self) -> Vec<AtpNetworkTruthMetric> {
        let mut unsupported = self
            .signals
            .iter()
            .filter(|signal| signal.kind == AtpNetworkTruthSignalKind::Unsupported)
            .map(|signal| signal.metric)
            .collect::<Vec<_>>();
        unsupported.sort();
        unsupported.dedup();
        unsupported
    }

    /// Required metrics absent from this model.
    #[must_use]
    pub fn missing_required_metrics(&self) -> Vec<AtpNetworkTruthMetric> {
        let present = self
            .signals
            .iter()
            .map(|signal| signal.metric)
            .collect::<BTreeSet<_>>();
        AtpNetworkTruthMetric::ALL
            .into_iter()
            .filter(|metric| !present.contains(metric))
            .collect()
    }

    /// Concise operator-facing summary.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "network truth pressure {} score_ppm={} signals={} unsupported={} missing={}",
            self.pressure_level().as_str(),
            self.overall_pressure_score_ppm(),
            self.signals.len(),
            self.unsupported_metrics().len(),
            self.missing_required_metrics().len()
        )
    }

    /// Returns a user-safe copy with correlation ids and details redacted.
    #[must_use]
    pub fn redacted_for_user(&self) -> Self {
        let mut redacted = self.clone();
        redacted.path_id = redacted.path_id.as_deref().map(redact_token);
        for signal in &mut redacted.signals {
            signal.source_ref = signal.source_ref.as_deref().map(redact_token);
            signal.detail = signal.detail.as_deref().map(|_| REDACTED.to_string());
        }
        redacted.redaction_policy = format!("{}+user_safe", self.redaction_policy);
        redacted
    }
}

fn pressure_level_for_score(score_ppm: u32) -> AtpNetworkPressureLevel {
    match score_ppm {
        0..=200_000 => AtpNetworkPressureLevel::Nominal,
        200_001..=600_000 => AtpNetworkPressureLevel::Watch,
        600_001..=850_000 => AtpNetworkPressureLevel::Degraded,
        _ => AtpNetworkPressureLevel::Critical,
    }
}

fn retention_floor(level: AtpNetworkPressureLevel) -> u32 {
    match level {
        AtpNetworkPressureLevel::Nominal => 0,
        AtpNetworkPressureLevel::Watch => 150_000,
        AtpNetworkPressureLevel::Degraded => 500_000,
        AtpNetworkPressureLevel::Critical => 750_000,
    }
}

/// Obligation and futurelock counts captured for one ATP transfer.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpObligationEvidenceCounts {
    /// Number of obligations created by the transfer session.
    pub created: u64,
    /// Number of obligations committed successfully.
    pub committed: u64,
    /// Number of obligations aborted during cleanup.
    pub aborted: u64,
    /// Number of obligations still outstanding at diagnostic time.
    pub outstanding: u64,
    /// Number of futurelock or wait-for edges observed.
    pub futurelock_waiters: u64,
}

impl AtpObligationEvidenceCounts {
    /// Returns true if obligation accounting proves no outstanding obligation.
    #[must_use]
    pub const fn proves_no_obligation_leak(&self) -> bool {
        self.outstanding == 0 && self.created == self.committed.saturating_add(self.aborted)
    }
}

/// Cancellation drain evidence for an ATP transfer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpCancellationDrainEvidence {
    /// Whether cancellation was requested.
    pub requested: bool,
    /// Whether all loser/child work drained.
    pub drained: bool,
    /// Number of loser tasks drained after cancellation or path race.
    pub losers_drained: u64,
    /// Deterministic drain certificate id, when available.
    pub drain_certificate_id: Option<String>,
    /// Short machine-readable reason.
    pub reason: String,
}

impl AtpCancellationDrainEvidence {
    /// Returns true when cancellation evidence is a runtime proof.
    #[must_use]
    pub const fn proves_drain(&self) -> bool {
        !self.requested || self.drained
    }
}

/// Finalizer outcome captured for one ATP transfer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpFinalizerEvidence {
    /// Whether finalizers ran.
    pub ran: bool,
    /// Whether finalizers completed successfully.
    pub completed: bool,
    /// Short finalizer status label.
    pub outcome: String,
}

/// Deterministic replay or crashpack pointer for ATP diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpReplayEvidencePointer {
    /// Trace identifier, if the runtime provided one.
    pub trace_id: Option<String>,
    /// Crashpack identifier, if one was emitted.
    pub crashpack_id: Option<String>,
    /// Exact replay command for this diagnostic.
    pub replay_command: String,
    /// Redaction policy used for replay artifacts.
    pub redaction_policy: String,
}

/// One runtime evidence signal attached to an ATP diagnostic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpRuntimeEvidenceSignal {
    /// Stable signal id within the transfer.
    pub signal_id: String,
    /// Source family for the signal.
    pub source: AtpRuntimeSignalSource,
    /// Proof/advisory/unavailable classification.
    pub class: AtpRuntimeSignalClass,
    /// Short operator-facing summary.
    pub summary: String,
    /// Machine-readable evidence reference, when available.
    pub evidence_ref: Option<String>,
    /// Explicit reason when the signal is unavailable.
    pub unavailable_reason: Option<String>,
}

impl AtpRuntimeEvidenceSignal {
    /// Builds a proof-bearing runtime evidence signal.
    #[must_use]
    pub fn proof(
        signal_id: impl Into<String>,
        source: AtpRuntimeSignalSource,
        summary: impl Into<String>,
        evidence_ref: impl Into<String>,
    ) -> Self {
        Self {
            signal_id: signal_id.into(),
            source,
            class: AtpRuntimeSignalClass::RuntimeProof,
            summary: summary.into(),
            evidence_ref: Some(evidence_ref.into()),
            unavailable_reason: None,
        }
    }

    /// Builds an advisory risk signal.
    #[must_use]
    pub fn advisory(
        signal_id: impl Into<String>,
        source: AtpRuntimeSignalSource,
        summary: impl Into<String>,
        evidence_ref: impl Into<String>,
    ) -> Self {
        Self {
            signal_id: signal_id.into(),
            source,
            class: AtpRuntimeSignalClass::AdvisoryRisk,
            summary: summary.into(),
            evidence_ref: Some(evidence_ref.into()),
            unavailable_reason: None,
        }
    }

    /// Builds an unavailable-signal downgrade entry.
    #[must_use]
    pub fn unavailable(
        signal_id: impl Into<String>,
        source: AtpRuntimeSignalSource,
        reason: impl Into<String>,
    ) -> Self {
        let reason = reason.into();
        Self {
            signal_id: signal_id.into(),
            source,
            class: AtpRuntimeSignalClass::Unavailable,
            summary: format!("{} unavailable: {reason}", source.as_str()),
            evidence_ref: None,
            unavailable_reason: Some(reason),
        }
    }
}

/// Structured runtime evidence envelope carried by ATP diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpRuntimeEvidenceEnvelope {
    /// Stable schema version.
    pub schema_version: String,
    /// ATP transfer id.
    pub transfer_id: String,
    /// Cx region id that owns the transfer, when available.
    pub cx_region_id: Option<String>,
    /// Transfer actor id, when available.
    pub transfer_actor_id: Option<String>,
    /// Obligation/futurelock counts.
    pub obligation_counts: AtpObligationEvidenceCounts,
    /// Cancellation drain evidence.
    pub cancellation: Option<AtpCancellationDrainEvidence>,
    /// Finalizer evidence.
    pub finalizer: Option<AtpFinalizerEvidence>,
    /// Deterministic replay or crashpack pointer.
    pub replay: Option<AtpReplayEvidencePointer>,
    /// Runtime evidence signals.
    pub signals: Vec<AtpRuntimeEvidenceSignal>,
    /// Practical network-truth pressure evidence.
    pub network_truth: Option<AtpNetworkTruthPressureModel>,
    /// Redaction policy applied before user display.
    pub redaction_policy: String,
}

impl AtpRuntimeEvidenceEnvelope {
    /// Creates a new ATP runtime evidence envelope.
    #[must_use]
    pub fn new(transfer_id: impl Into<String>) -> Self {
        Self {
            schema_version: ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA.to_string(),
            transfer_id: transfer_id.into(),
            cx_region_id: None,
            transfer_actor_id: None,
            obligation_counts: AtpObligationEvidenceCounts::default(),
            cancellation: None,
            finalizer: None,
            replay: None,
            signals: Vec::new(),
            network_truth: None,
            redaction_policy: "atp-runtime-evidence-default".to_string(),
        }
    }

    /// Returns a user-safe copy of the envelope with correlation ids redacted.
    #[must_use]
    pub fn redacted_for_user(&self) -> Self {
        let mut redacted = self.clone();
        redacted.transfer_id = redact_token(&redacted.transfer_id);
        redacted.cx_region_id = redacted.cx_region_id.as_deref().map(redact_token);
        redacted.transfer_actor_id = redacted.transfer_actor_id.as_deref().map(redact_token);
        if let Some(replay) = &mut redacted.replay {
            replay.trace_id = replay.trace_id.as_deref().map(redact_token);
            replay.crashpack_id = replay.crashpack_id.as_deref().map(redact_token);
            replay.replay_command = REDACTED.to_string();
        }
        for signal in &mut redacted.signals {
            signal.evidence_ref = signal.evidence_ref.as_deref().map(redact_token);
        }
        redacted.network_truth = redacted
            .network_truth
            .as_ref()
            .map(AtpNetworkTruthPressureModel::redacted_for_user);
        redacted.redaction_policy = format!("{}+user_safe", self.redaction_policy);
        redacted
    }
}

/// User-facing runtime diagnostic document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpRuntimeDiagnosticDocument {
    /// Stable schema version.
    pub schema_version: String,
    /// ATP transfer id.
    pub transfer_id: String,
    /// One-line headline.
    pub headline: String,
    /// Concise human explanation.
    pub human_summary: String,
    /// Claims backed by protocol or runtime proof evidence.
    pub proof_claims: Vec<String>,
    /// Advisory risks that must not be described as proof.
    pub advisory_risks: Vec<String>,
    /// Practical network-truth explanations that are facts/estimates, not proof claims.
    pub network_truth_explanations: Vec<String>,
    /// Signals expected by the diagnostic but unavailable.
    pub unavailable_signals: Vec<String>,
    /// Structured evidence envelope used to build the document.
    pub evidence: AtpRuntimeEvidenceEnvelope,
}

/// Bridge from runtime evidence envelopes to ATP diagnostic explanations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AtpRuntimeEvidenceBridge;

impl AtpRuntimeEvidenceBridge {
    /// Builds a diagnostic document from structured runtime evidence.
    #[must_use]
    pub fn explain(envelope: AtpRuntimeEvidenceEnvelope) -> AtpRuntimeDiagnosticDocument {
        let mut proof_claims = Vec::new();
        let mut advisory_risks = Vec::new();
        let mut network_truth_explanations = Vec::new();
        let mut unavailable_signals = Vec::new();

        if let Some(region_id) = &envelope.cx_region_id {
            proof_claims.push(format!("transfer is owned by Cx region {region_id}"));
        }
        if let Some(actor_id) = &envelope.transfer_actor_id {
            proof_claims.push(format!("transfer actor {actor_id} is recorded"));
        }
        if envelope.obligation_counts.proves_no_obligation_leak() {
            proof_claims.push(format!(
                "obligation accounting closed cleanly: created={} committed={} aborted={} outstanding=0",
                envelope.obligation_counts.created,
                envelope.obligation_counts.committed,
                envelope.obligation_counts.aborted
            ));
        } else {
            advisory_risks.push(format!(
                "obligation accounting is incomplete: outstanding={} futurelock_waiters={}",
                envelope.obligation_counts.outstanding,
                envelope.obligation_counts.futurelock_waiters
            ));
        }
        if let Some(cancellation) = &envelope.cancellation {
            if cancellation.proves_drain() {
                proof_claims.push(format!(
                    "cancellation drain completed: requested={} losers_drained={}",
                    cancellation.requested, cancellation.losers_drained
                ));
            } else {
                advisory_risks.push(format!(
                    "cancellation requested but drain is not proven: {}",
                    cancellation.reason
                ));
            }
        }
        if let Some(finalizer) = &envelope.finalizer {
            if finalizer.ran && finalizer.completed {
                proof_claims.push(format!("finalizers completed: {}", finalizer.outcome));
            } else {
                advisory_risks.push(format!("finalizers incomplete: {}", finalizer.outcome));
            }
        }
        if let Some(replay) = &envelope.replay {
            proof_claims.push(format!(
                "deterministic replay pointer is present: command={}",
                replay.replay_command
            ));
        }

        for signal in &envelope.signals {
            let line = format!(
                "{} [{}]: {}",
                signal.source.as_str(),
                signal.class.as_str(),
                signal.summary
            );
            match signal.class {
                class if class.is_proof() => proof_claims.push(line),
                AtpRuntimeSignalClass::AdvisoryRisk => advisory_risks.push(line),
                AtpRuntimeSignalClass::Unavailable => {
                    unavailable_signals.push(signal.unavailable_reason.clone().unwrap_or(line));
                }
                AtpRuntimeSignalClass::ProtocolProof | AtpRuntimeSignalClass::RuntimeProof => {
                    unreachable!("proof classes handled by is_proof")
                }
            }
        }
        if let Some(network_truth) = &envelope.network_truth {
            network_truth_explanations.push(network_truth.summary_line());
            for metric in network_truth.unsupported_metrics() {
                unavailable_signals.push(format!("network truth {} unsupported", metric.as_str()));
            }
            for metric in network_truth.missing_required_metrics() {
                unavailable_signals.push(format!("network truth {} missing", metric.as_str()));
            }
            if network_truth.pressure_level() >= AtpNetworkPressureLevel::Watch {
                advisory_risks.push(format!(
                    "network truth pressure is {} (score_ppm={})",
                    network_truth.pressure_level().as_str(),
                    network_truth.overall_pressure_score_ppm()
                ));
            }
        }

        proof_claims.sort();
        proof_claims.dedup();
        advisory_risks.sort();
        advisory_risks.dedup();
        network_truth_explanations.sort();
        network_truth_explanations.dedup();
        unavailable_signals.sort();
        unavailable_signals.dedup();

        let headline = if advisory_risks.is_empty() && unavailable_signals.is_empty() {
            "ATP runtime evidence supports the transfer explanation".to_string()
        } else {
            "ATP runtime evidence includes advisory or unavailable signals".to_string()
        };
        let human_summary = render_summary(
            &headline,
            &proof_claims,
            &advisory_risks,
            &network_truth_explanations,
        );

        AtpRuntimeDiagnosticDocument {
            schema_version: ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA.to_string(),
            transfer_id: envelope.transfer_id.clone(),
            headline,
            human_summary,
            proof_claims,
            advisory_risks,
            network_truth_explanations,
            unavailable_signals,
            evidence: envelope,
        }
    }

    /// Builds a user-safe diagnostic document.
    #[must_use]
    pub fn explain_for_user(envelope: &AtpRuntimeEvidenceEnvelope) -> AtpRuntimeDiagnosticDocument {
        Self::explain(envelope.redacted_for_user())
    }
}

fn render_summary(
    headline: &str,
    proof_claims: &[String],
    advisory_risks: &[String],
    network_truth_explanations: &[String],
) -> String {
    let mut parts = vec![headline.to_string()];
    if let Some(first_proof) = proof_claims.first() {
        parts.push(format!("Proof: {first_proof}."));
    }
    if let Some(first_risk) = advisory_risks.first() {
        parts.push(format!("Advisory: {first_risk}."));
    }
    if let Some(first_network_truth) = network_truth_explanations.first() {
        parts.push(format!("Network truth: {first_network_truth}."));
    }
    parts.join(" ")
}

fn redact_token(value: &str) -> String {
    if value.is_empty() {
        return REDACTED.to_string();
    }
    let suffix = value
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{REDACTED}:{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> AtpRuntimeEvidenceEnvelope {
        let mut envelope = AtpRuntimeEvidenceEnvelope::new("transfer-abcdef123456");
        envelope.cx_region_id = Some("region-root-42".to_string());
        envelope.transfer_actor_id = Some("actor-send-7".to_string());
        envelope.obligation_counts = AtpObligationEvidenceCounts {
            created: 3,
            committed: 2,
            aborted: 1,
            outstanding: 0,
            futurelock_waiters: 0,
        };
        envelope.cancellation = Some(AtpCancellationDrainEvidence {
            requested: true,
            drained: true,
            losers_drained: 2,
            drain_certificate_id: Some("drain-cert-1".to_string()),
            reason: "operator_cancel".to_string(),
        });
        envelope.finalizer = Some(AtpFinalizerEvidence {
            ran: true,
            completed: true,
            outcome: "all_finalizers_joined".to_string(),
        });
        envelope.replay = Some(AtpReplayEvidencePointer {
            trace_id: Some("trace-123456789".to_string()),
            crashpack_id: Some("crashpack-abcdef".to_string()),
            replay_command: "asupersync lab replay trace-123456789 --redacted".to_string(),
            redaction_policy: "atp-runtime-evidence-default".to_string(),
        });
        envelope.signals.push(AtpRuntimeEvidenceSignal::proof(
            "decision-ledger",
            AtpRuntimeSignalSource::EvidenceLedger,
            "decision ledger row binds path choice to transfer evidence",
            "evidence-ledger-row-1",
        ));
        envelope.signals.push(AtpRuntimeEvidenceSignal::advisory(
            "spectral-risk",
            AtpRuntimeSignalSource::SpectralWaitGraph,
            "spectral wait graph is degraded but not a correctness proof",
            "spectral-report-1",
        ));
        envelope.signals.push(AtpRuntimeEvidenceSignal::unavailable(
            "conformal-risk",
            AtpRuntimeSignalSource::ConformalAlert,
            "insufficient calibration window",
        ));
        envelope
    }

    #[test]
    fn bridge_keeps_proof_claims_separate_from_advisory_risk() {
        let doc = AtpRuntimeEvidenceBridge::explain(sample_envelope());
        assert_eq!(doc.schema_version, ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA);
        assert!(
            doc.proof_claims
                .iter()
                .any(|claim| claim.contains("obligation accounting closed cleanly"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .any(|claim| claim.contains("cancellation drain completed"))
        );
        assert!(
            doc.advisory_risks
                .iter()
                .any(|risk| risk.contains("spectral_wait_graph [advisory_risk]"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .all(|claim| !claim.contains("advisory_risk")),
            "advisory signals must not be upgraded to proof claims"
        );
        assert_eq!(
            doc.unavailable_signals,
            vec!["insufficient calibration window".to_string()]
        );
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let envelope = sample_envelope();
        let encoded = serde_json::to_string(&envelope).expect("serialize envelope");
        let decoded: AtpRuntimeEvidenceEnvelope =
            serde_json::from_str(&encoded).expect("deserialize envelope");
        assert_eq!(decoded, envelope);
        assert_eq!(
            decoded.schema_version,
            ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA
        );
    }

    #[test]
    fn user_explanation_redacts_correlation_ids_and_replay_command() {
        let envelope = sample_envelope();
        let doc = AtpRuntimeEvidenceBridge::explain_for_user(&envelope);
        assert!(doc.transfer_id.starts_with(REDACTED));
        assert_eq!(
            doc.evidence
                .replay
                .as_ref()
                .expect("replay pointer")
                .replay_command,
            REDACTED
        );
        assert!(
            doc.human_summary.len() < 400,
            "human explanation must stay concise"
        );
    }

    #[test]
    fn incomplete_obligations_downgrade_to_advisory_risk() {
        let mut envelope = sample_envelope();
        envelope.obligation_counts.outstanding = 1;
        let doc = AtpRuntimeEvidenceBridge::explain(envelope);
        assert!(
            doc.advisory_risks
                .iter()
                .any(|risk| risk.contains("obligation accounting is incomplete"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .all(|claim| !claim.contains("obligation accounting closed cleanly"))
        );
    }

    #[test]
    fn network_truth_pressure_keeps_measurements_out_of_proof_claims() {
        let mut envelope = sample_envelope();
        let mut network_truth = AtpNetworkTruthPressureModel::new(42_000);
        network_truth.path_id = Some("path-local-correlation-123456".to_string());
        assert!(network_truth.add_signal(AtpNetworkTruthSignal::measured(
            AtpNetworkTruthMetric::Rtt,
            25_000,
            "micros",
            120_000,
            "pathlog-rtt-123456",
        )));
        assert!(network_truth.add_signal(AtpNetworkTruthSignal::inferred(
            AtpNetworkTruthMetric::Loss,
            22,
            "permille",
            720_000,
            "pathlog-loss-123456",
            "loss inferred from ACK gap and retransmit evidence",
        )));
        assert!(network_truth.add_signal(AtpNetworkTruthSignal::unsupported(
            AtpNetworkTruthMetric::CongestionWindow,
            "platform did not expose cwnd",
        )));
        envelope.network_truth = Some(network_truth);

        let doc = AtpRuntimeEvidenceBridge::explain(envelope);
        assert!(
            doc.network_truth_explanations
                .iter()
                .any(|line| line.contains("network truth pressure degraded"))
        );
        assert!(
            doc.advisory_risks
                .iter()
                .any(|risk| risk.contains("network truth pressure is degraded"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .all(|claim| !claim.contains("network truth")),
            "measured network facts must not become proof claims"
        );
        assert!(
            doc.unavailable_signals
                .iter()
                .any(|signal| signal == "network truth congestion_window unsupported")
        );
    }

    #[test]
    fn network_truth_model_bounds_cardinality_and_redacts_user_view() {
        let mut model = AtpNetworkTruthPressureModel::new(7);
        model.path_id = Some("path-sensitive-abcdef".to_string());
        for idx in 0..ATP_NETWORK_TRUTH_MAX_SIGNALS {
            assert!(model.add_signal(AtpNetworkTruthSignal::advisory(
                AtpNetworkTruthMetric::RelayDirectDelta,
                i64::try_from(idx).expect("idx fits"),
                "ppm",
                250_000,
                format!("relay-delta-sensitive-{idx}"),
                "relay path id contained a local endpoint",
            )));
        }
        assert!(!model.add_signal(AtpNetworkTruthSignal::measured(
            AtpNetworkTruthMetric::Rtt,
            1,
            "micros",
            1,
            "overflow",
        )));

        let redacted = model.redacted_for_user();
        assert_eq!(redacted.signals.len(), ATP_NETWORK_TRUTH_MAX_SIGNALS);
        assert!(
            redacted
                .path_id
                .as_deref()
                .unwrap_or_default()
                .starts_with(REDACTED)
        );
        assert!(
            redacted
                .signals
                .iter()
                .all(|signal| signal.detail.as_deref() == Some(REDACTED))
        );
    }

    #[test]
    fn network_truth_pressure_hysteresis_prevents_noisy_downshift() {
        let mut model = AtpNetworkTruthPressureModel::new(99);
        assert!(model.add_signal(AtpNetworkTruthSignal::inferred(
            AtpNetworkTruthMetric::DiskLag,
            510_000,
            "ppm",
            510_000,
            "disk-lag-row",
            "disk write lag remained near degraded threshold",
        )));
        assert_eq!(model.pressure_level(), AtpNetworkPressureLevel::Watch);
        assert_eq!(
            model.pressure_level_with_hysteresis(Some(AtpNetworkPressureLevel::Degraded)),
            AtpNetworkPressureLevel::Degraded
        );
    }
}
