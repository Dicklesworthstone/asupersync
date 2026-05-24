//! ATP runtime-evidence diagnostics bridge.
//!
//! The bridge turns Asupersync runtime evidence into ATP-facing diagnostic
//! documents. Runtime facts that prove a protocol/runtime invariant are kept
//! separate from advisory risk signals such as spectral health, conformal
//! bounds, and e-process alerts.

use serde::{Deserialize, Serialize};

/// Stable schema for ATP runtime-evidence diagnostic envelopes.
pub const ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA: &str =
    "asupersync.atp.diagnostics.runtime_evidence.v1";

/// Stable schema for rendered ATP runtime-evidence explanations.
pub const ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA: &str =
    "asupersync.atp.diagnostics.runtime_explanation.v1";

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

        proof_claims.sort();
        proof_claims.dedup();
        advisory_risks.sort();
        advisory_risks.dedup();
        unavailable_signals.sort();
        unavailable_signals.dedup();

        let headline = if advisory_risks.is_empty() && unavailable_signals.is_empty() {
            "ATP runtime evidence supports the transfer explanation".to_string()
        } else {
            "ATP runtime evidence includes advisory or unavailable signals".to_string()
        };
        let human_summary = render_summary(&headline, &proof_claims, &advisory_risks);

        AtpRuntimeDiagnosticDocument {
            schema_version: ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA.to_string(),
            transfer_id: envelope.transfer_id.clone(),
            headline,
            human_summary,
            proof_claims,
            advisory_risks,
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

fn render_summary(headline: &str, proof_claims: &[String], advisory_risks: &[String]) -> String {
    let mut parts = vec![headline.to_string()];
    if let Some(first_proof) = proof_claims.first() {
        parts.push(format!("Proof: {first_proof}."));
    }
    if let Some(first_risk) = advisory_risks.first() {
        parts.push(format!("Advisory: {first_risk}."));
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
}
