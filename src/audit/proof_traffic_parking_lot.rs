//! Proof-traffic parking lot and resumable retry manifest (PROOF-TRAFFIC A4).
//!
//! Parked proof attempts are not green evidence. They are resumable operator
//! packets: exact command intent, blocker classification, retry predicate,
//! handoff context, and no-claim boundaries. This module keeps that packet
//! deterministic and groups duplicate blockers without losing per-attempt
//! command details.

use super::proof_traffic_receipt::ProofTrafficDecision;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Stable schema version for proof-traffic parking lots.
pub const PROOF_TRAFFIC_PARKING_LOT_SCHEMA_VERSION: &str = "proof-traffic-parking-lot-v1";

const NO_CLAIM_BOUNDARIES: &[&str] = &[
    "No release-readiness claim.",
    "No broad workspace-health claim.",
    "No runtime-correctness claim.",
    "No performance-improvement claim.",
    "No live RCH fleet-availability claim.",
    "No local Cargo fallback approval.",
    "No peer-owned build cancellation authority.",
    "Parked, refused, or stale attempts are not green proof evidence.",
];

/// Retry predicate controlling whether a parked attempt may emit its exact
/// command again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficRetryPredicate {
    /// Stable predicate id used by reports and grouping.
    pub predicate_id: String,
    /// Human-readable condition that must be true before resume.
    pub condition: String,
    /// Fresh evidence signal expected from the next operator.
    pub required_signal: String,
    /// Whether the predicate is currently satisfied.
    pub satisfied: bool,
}

impl ProofTrafficRetryPredicate {
    /// Construct a retry predicate.
    #[must_use]
    pub fn new(
        predicate_id: impl Into<String>,
        condition: impl Into<String>,
        required_signal: impl Into<String>,
        satisfied: bool,
    ) -> Self {
        Self {
            predicate_id: predicate_id.into(),
            condition: condition.into(),
            required_signal: required_signal.into(),
            satisfied,
        }
    }
}

/// One parked focused-proof attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedProofAttempt {
    /// Stable attempt id.
    pub attempt_id: String,
    /// Duplicate-grouping key for the blocker.
    pub blocker_key: String,
    /// `HEAD` commit the attempt was based on.
    pub head_commit: String,
    /// Original command intent.
    pub command_intent: String,
    /// Exact RCH command, when it is safe to render after predicate satisfaction.
    pub exact_rch_command: Option<String>,
    /// Blocker marker emitted while parked or when no exact command is recorded.
    pub blocker_marker: String,
    /// `CARGO_TARGET_DIR` intended for the proof.
    pub target_dir: String,
    /// Owned paths selected by the attempt.
    pub owned_paths: Vec<String>,
    /// Reservation evidence for the owned paths.
    pub reservation_evidence: Vec<String>,
    /// Fail-closed blocker classification.
    pub blocker_class: ProofTrafficDecision,
    /// Optional blocker owner, usually another agent/build owner.
    pub blocker_owner: Option<String>,
    /// Optional Agent Mail or `br` handoff thread id.
    pub handoff_thread: Option<String>,
    /// Retry predicate gating resume output.
    pub retry_predicate: ProofTrafficRetryPredicate,
    /// Honest no-claim boundaries.
    pub no_claim_boundaries: Vec<String>,
}

impl ParkedProofAttempt {
    /// Construct a parked proof attempt.
    #[must_use]
    pub fn new(
        attempt_id: impl Into<String>,
        blocker_key: impl Into<String>,
        head_commit: impl Into<String>,
        command_intent: impl Into<String>,
        target_dir: impl Into<String>,
        blocker_class: ProofTrafficDecision,
        retry_predicate: ProofTrafficRetryPredicate,
    ) -> Self {
        Self {
            attempt_id: attempt_id.into(),
            blocker_key: blocker_key.into(),
            head_commit: head_commit.into(),
            command_intent: command_intent.into(),
            exact_rch_command: None,
            blocker_marker: "# PARKED: no proof command emitted".to_string(),
            target_dir: target_dir.into(),
            owned_paths: Vec::new(),
            reservation_evidence: Vec::new(),
            blocker_class,
            blocker_owner: None,
            handoff_thread: None,
            retry_predicate,
            no_claim_boundaries: NO_CLAIM_BOUNDARIES
                .iter()
                .map(|boundary| (*boundary).to_string())
                .collect(),
        }
    }

    /// Attach an exact RCH command to emit only after the retry predicate is
    /// satisfied.
    #[must_use]
    pub fn with_exact_rch_command(mut self, command: impl Into<String>) -> Self {
        self.exact_rch_command = Some(command.into());
        self
    }

    /// Attach a blocker marker for parked/unsatisfied states.
    #[must_use]
    pub fn with_blocker_marker(mut self, marker: impl Into<String>) -> Self {
        self.blocker_marker = marker.into();
        self
    }

    /// Attach owned paths and reservation evidence.
    #[must_use]
    pub fn with_paths(
        mut self,
        owned_paths: Vec<String>,
        reservation_evidence: Vec<String>,
    ) -> Self {
        self.owned_paths = sorted_unique(owned_paths);
        self.reservation_evidence = sorted_unique(reservation_evidence);
        self
    }

    /// Attach blocker owner and handoff thread context.
    #[must_use]
    pub fn with_handoff(
        mut self,
        blocker_owner: Option<String>,
        handoff_thread: Option<String>,
    ) -> Self {
        self.blocker_owner = blocker_owner;
        self.handoff_thread = handoff_thread;
        self
    }

    /// Parked attempts are never green proof evidence.
    #[must_use]
    pub fn can_be_cited_as_green(&self) -> bool {
        false
    }

    /// Stable status label for report rendering.
    #[must_use]
    pub fn status_label(&self) -> &'static str {
        if self.retry_predicate.satisfied {
            "retry-ready"
        } else {
            "parked"
        }
    }
}

/// Duplicate group for attempts sharing the same blocker key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedProofGroup {
    /// Shared blocker key.
    pub blocker_key: String,
    /// Attempt ids in this group.
    pub attempt_ids: Vec<String>,
    /// Distinct command intents represented in this group.
    pub command_intents: Vec<String>,
    /// Distinct owned paths represented in this group.
    pub owned_paths: Vec<String>,
    /// Number of attempts in this group.
    pub attempt_count: usize,
}

/// Deterministic parking lot manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficParkingLot {
    /// Stable schema version.
    pub schema_version: String,
    /// Stable parking lot id.
    pub lot_id: String,
    /// Parked proof attempts, sorted by attempt id.
    pub attempts: Vec<ParkedProofAttempt>,
    /// Duplicate groups, sorted by blocker key.
    pub groups: Vec<ParkedProofGroup>,
    /// Honest no-claim boundaries.
    pub no_claim_boundaries: Vec<String>,
}

impl ProofTrafficParkingLot {
    /// Build a deterministic parking lot from parked attempts.
    #[must_use]
    pub fn new(lot_id: impl Into<String>, attempts: Vec<ParkedProofAttempt>) -> Self {
        let mut attempts = attempts;
        attempts.sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
        let groups = group_attempts(&attempts);
        Self {
            schema_version: PROOF_TRAFFIC_PARKING_LOT_SCHEMA_VERSION.to_string(),
            lot_id: lot_id.into(),
            attempts,
            groups,
            no_claim_boundaries: NO_CLAIM_BOUNDARIES
                .iter()
                .map(|boundary| (*boundary).to_string())
                .collect(),
        }
    }

    /// Render a resume command for an attempt.
    ///
    /// The exact command is emitted only when the retry predicate is satisfied
    /// and an exact RCH command was recorded. Otherwise this returns a fresh
    /// blocker marker that cannot be mistaken for proof evidence.
    #[must_use]
    pub fn render_resume(&self, attempt_id: &str) -> Option<String> {
        let attempt = self
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == attempt_id)?;
        if attempt.retry_predicate.satisfied {
            if let Some(command) = &attempt.exact_rch_command {
                return Some(command.clone());
            }
        }
        Some(render_fresh_blocker(attempt))
    }

    /// Render deterministic Markdown for the whole parking lot.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("## Proof-traffic parking lot - ");
        out.push_str(&self.lot_id);
        out.push_str("\n\n");
        out.push_str(&format!(
            "- schema_version: `{}`\n- attempt_count: `{}`\n- group_count: `{}`\n\n",
            self.schema_version,
            self.attempts.len(),
            self.groups.len()
        ));

        out.push_str("### groups\n");
        if self.groups.is_empty() {
            out.push_str("- _none_\n");
        } else {
            for group in &self.groups {
                out.push_str("- `");
                out.push_str(&group.blocker_key);
                out.push_str("` attempts=");
                out.push_str(&group.attempt_ids.join(","));
                out.push_str(" count=");
                out.push_str(&group.attempt_count.to_string());
                out.push('\n');
            }
        }
        out.push('\n');

        out.push_str("### attempts\n");
        if self.attempts.is_empty() {
            out.push_str("- _none_\n");
        } else {
            for attempt in &self.attempts {
                out.push_str("- `");
                out.push_str(&attempt.attempt_id);
                out.push_str("` status=`");
                out.push_str(attempt.status_label());
                out.push_str("` blocker=`");
                out.push_str(attempt.blocker_class.label());
                out.push_str("` retry=`");
                out.push_str(&attempt.retry_predicate.predicate_id);
                out.push_str("`\n");
            }
        }
        out.push('\n');

        push_string_section(&mut out, "no_claim_boundaries", &self.no_claim_boundaries);
        out
    }

    /// Render Agent Mail body with structured fields.
    #[must_use]
    pub fn agent_mail_body(&self) -> String {
        let mut out = String::new();
        out.push_str("proof_traffic_parking_lot:\n");
        out.push_str(&format!(
            "- lot_id: `{}`\n- attempt_count: `{}`\n- group_count: `{}`\n",
            self.lot_id,
            self.attempts.len(),
            self.groups.len()
        ));
        for group in &self.groups {
            out.push_str("- blocker_key: `");
            out.push_str(&group.blocker_key);
            out.push_str("` attempts: `");
            out.push_str(&group.attempt_ids.join(","));
            out.push_str("`\n");
        }
        out
    }

    /// Render `br comment` body with structured fields.
    #[must_use]
    pub fn br_comment_body(&self) -> String {
        let mut out = String::new();
        out.push_str("Proof-traffic parking lot\n\n");
        out.push_str(&format!(
            "- lot_id: `{}`\n- attempt_count: `{}`\n- group_count: `{}`\n",
            self.lot_id,
            self.attempts.len(),
            self.groups.len()
        ));
        out
    }
}

fn group_attempts(attempts: &[ParkedProofAttempt]) -> Vec<ParkedProofGroup> {
    let mut by_key: BTreeMap<String, Vec<&ParkedProofAttempt>> = BTreeMap::new();
    for attempt in attempts {
        by_key
            .entry(attempt.blocker_key.clone())
            .or_default()
            .push(attempt);
    }

    by_key
        .into_iter()
        .map(|(blocker_key, attempts)| {
            let attempt_ids = attempts
                .iter()
                .map(|attempt| attempt.attempt_id.clone())
                .collect::<Vec<_>>();
            let command_intents = attempts
                .iter()
                .map(|attempt| attempt.command_intent.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let owned_paths = attempts
                .iter()
                .flat_map(|attempt| attempt.owned_paths.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            ParkedProofGroup {
                blocker_key,
                attempt_count: attempt_ids.len(),
                attempt_ids,
                command_intents,
                owned_paths,
            }
        })
        .collect()
}

fn render_fresh_blocker(attempt: &ParkedProofAttempt) -> String {
    format!(
        "# PARKED: blocker={} retry_predicate={} satisfied={} required_signal={}; no proof command emitted",
        attempt.blocker_class.label(),
        attempt.retry_predicate.predicate_id,
        attempt.retry_predicate.satisfied,
        attempt.retry_predicate.required_signal
    )
}

fn push_string_section(out: &mut String, title: &str, values: &[String]) {
    out.push_str(&format!("### {title} ({})\n", values.len()));
    if values.is_empty() {
        out.push_str("- _none_\n");
    } else {
        for value in values {
            out.push_str("- ");
            out.push_str(value);
            out.push('\n');
        }
    }
    out.push('\n');
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}
