//! Semantic degradation policy for the FABRIC lane.

use super::class::{DeliveryClass, DeliveryClassPolicy, DeliveryClassPolicyError};
use super::service::{CancellationObligations, CleanupUrgency};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::time::Duration;
use thiserror::Error;

/// Operator-visible workload classes used when overload decisions are driven by
/// semantic damage rather than raw queue depth alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticServiceClass {
    /// Recovery, drain, and operator-intent traffic that must stay live.
    ControlRecovery,
    /// Request/reply work where failing mid-flight strands a caller.
    ReplyCritical,
    /// Lease renewal, cutover, and repair work that prevents semantic debt.
    LeaseRepair,
    /// Durable data-plane work with stronger contracts than packet-plane pub/sub.
    DurablePipeline,
    /// Ordinary interactive traffic without durable obligations.
    Interactive,
    /// Read-side materializations or derived views.
    ReadModel,
    /// Wide fanout where partial degradation is preferable to stronger contract loss.
    LowValueFanout,
    /// Replay-heavy or forensic work that is valuable but expensive to keep hot.
    ExpensiveReplay,
}

impl SemanticServiceClass {
    fn base_priority(self) -> u16 {
        match self {
            Self::ControlRecovery => 120,
            Self::LeaseRepair => 110,
            Self::ReplyCritical => 100,
            Self::DurablePipeline => 80,
            Self::Interactive => 65,
            Self::ReadModel => 35,
            Self::LowValueFanout => 20,
            Self::ExpensiveReplay => 10,
        }
    }

    fn uses_reserved_capacity(self) -> bool {
        matches!(self, Self::ControlRecovery | Self::LeaseRepair)
    }
}

/// Obligation load carried by a workload slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationLoad {
    /// No semantic obligation beyond packet delivery.
    #[default]
    None,
    /// A reply obligation is outstanding.
    Reply,
    /// A lease or stewardship obligation is outstanding.
    Lease,
    /// Both reply and lease obligations are in play.
    ReplyAndLease,
}

impl ObligationLoad {
    fn priority_boost(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Reply => 16,
            Self::Lease => 22,
            Self::ReplyAndLease => 30,
        }
    }

    fn prefers_repair_widening(self) -> bool {
        matches!(self, Self::Lease | Self::ReplyAndLease)
    }
}

/// One schedulable traffic slice considered by a degradation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSlice {
    /// Operator-facing identifier for the slice.
    pub name: String,
    /// Semantic workload class.
    pub service_class: SemanticServiceClass,
    /// Requested delivery class.
    pub delivery_class: DeliveryClass,
    /// Cleanup urgency if the slice is cancelled.
    pub cleanup_urgency: CleanupUrgency,
    /// Cancellation semantics promised at the boundary.
    pub cancellation_obligations: CancellationObligations,
    /// Outstanding reply or lease load.
    pub obligation_load: ObligationLoad,
    /// Relative deadline carried by the work, when present.
    pub deadline: Option<Duration>,
    /// Slots of degraded-capacity budget needed to keep this slice admitted.
    pub required_slots: u32,
}

impl TrafficSlice {
    /// Construct a new traffic slice with bounded defaults.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        service_class: SemanticServiceClass,
        delivery_class: DeliveryClass,
    ) -> Self {
        Self {
            name: name.into(),
            service_class,
            delivery_class,
            cleanup_urgency: CleanupUrgency::Prompt,
            cancellation_obligations: CancellationObligations::DrainBeforeReply,
            obligation_load: ObligationLoad::None,
            deadline: None,
            required_slots: 1,
        }
    }

    /// Override the cleanup urgency for this slice.
    #[must_use]
    pub fn with_cleanup_urgency(mut self, cleanup_urgency: CleanupUrgency) -> Self {
        self.cleanup_urgency = cleanup_urgency;
        self
    }

    /// Override the cancellation semantics for this slice.
    #[must_use]
    pub fn with_cancellation_obligations(
        mut self,
        cancellation_obligations: CancellationObligations,
    ) -> Self {
        self.cancellation_obligations = cancellation_obligations;
        self
    }

    /// Attach reply or lease obligation load.
    #[must_use]
    pub fn with_obligation_load(mut self, obligation_load: ObligationLoad) -> Self {
        self.obligation_load = obligation_load;
        self
    }

    /// Attach a relative deadline to the slice.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Override the slot cost for the slice.
    #[must_use]
    pub fn with_required_slots(mut self, required_slots: u32) -> Self {
        self.required_slots = required_slots.max(1);
        self
    }

    fn priority_score(&self) -> u16 {
        self.service_class
            .base_priority()
            .saturating_add(self.delivery_boost())
            .saturating_add(self.cleanup_boost())
            .saturating_add(self.cancellation_boost())
            .saturating_add(self.obligation_load.priority_boost())
            .saturating_add(self.deadline_boost())
    }

    fn delivery_boost(&self) -> u16 {
        match self.delivery_class {
            DeliveryClass::EphemeralInteractive => 0,
            DeliveryClass::DurableOrdered => 6,
            DeliveryClass::ObligationBacked => 10,
            DeliveryClass::MobilitySafe => 12,
            DeliveryClass::ForensicReplayable => 8,
        }
    }

    fn cleanup_boost(&self) -> u16 {
        match self.cleanup_urgency {
            CleanupUrgency::Background => 0,
            CleanupUrgency::Prompt => 8,
            CleanupUrgency::Immediate => 14,
        }
    }

    fn cancellation_boost(&self) -> u16 {
        match self.cancellation_obligations {
            CancellationObligations::BestEffortDrain => 0,
            CancellationObligations::DrainBeforeReply => 6,
            CancellationObligations::DrainAndCompensate => 12,
        }
    }

    fn deadline_boost(&self) -> u16 {
        match self.deadline {
            Some(deadline) if deadline <= Duration::from_millis(100) => 24,
            Some(deadline) if deadline <= Duration::from_secs(1) => 18,
            Some(deadline) if deadline <= Duration::from_secs(5) => 10,
            Some(_) => 4,
            None => 0,
        }
    }

    fn degradation_disposition(&self) -> DegradationDisposition {
        match self.service_class {
            // Control/recovery and lease/repair traffic "must stay live" — widen
            // the repair budget rather than rejecting work that prevents semantic
            // debt growth.
            SemanticServiceClass::ControlRecovery | SemanticServiceClass::LeaseRepair => {
                DegradationDisposition::WidenRepair
            }
            SemanticServiceClass::LowValueFanout => DegradationDisposition::ReduceFanout,
            SemanticServiceClass::ReadModel => DegradationDisposition::Defer,
            SemanticServiceClass::ExpensiveReplay => DegradationDisposition::PauseReplay,
            SemanticServiceClass::ReplyCritical
                if self.obligation_load.prefers_repair_widening() =>
            {
                DegradationDisposition::WidenRepair
            }
            _ => DegradationDisposition::RejectNew,
        }
    }
}

/// Degradation action recommended for a slice that is not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationDisposition {
    /// Preserve the slice under the current degraded operating point.
    Preserve,
    /// Reject new work at admission.
    RejectNew,
    /// Defer the work until pressure clears.
    Defer,
    /// Keep control metadata live but reduce wide fanout.
    ReduceFanout,
    /// Pause replay-heavy work.
    PauseReplay,
    /// Admit compensating repair or cleanup because semantic debt would grow.
    WidenRepair,
}

/// One admission or degradation decision for a named traffic slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradationDecision {
    /// Slice name.
    pub slice: String,
    /// Decision chosen by the policy.
    pub disposition: DegradationDisposition,
    /// Deterministic priority score used to rank the slice.
    pub priority_score: u16,
    /// Slots requested by the slice.
    pub required_slots: u32,
    /// Whether admission came from the reserved control/recovery pool.
    pub reserved_lane: bool,
}

/// Admission output for a degradation policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradationPlan {
    /// Admitted slices in policy order.
    pub admitted: Vec<DegradationDecision>,
    /// Rejected or degraded slices in policy order.
    pub degraded: Vec<DegradationDecision>,
    /// Remaining unallocated slots after planning.
    pub remaining_slots: u32,
}

/// Capacity-aware overload policy for semantic degradation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradationPolicy {
    /// Total slots available under the current degraded operating point.
    pub total_slots: u32,
    /// Minimum slots held for control and recovery lanes.
    pub reserved_control_slots: u32,
}

impl Default for DegradationPolicy {
    fn default() -> Self {
        Self::new(4, 1)
    }
}

impl DegradationPolicy {
    /// Construct a bounded degradation policy.
    #[must_use]
    pub const fn new(total_slots: u32, reserved_control_slots: u32) -> Self {
        Self {
            total_slots,
            reserved_control_slots,
        }
    }

    /// Produce a deterministic admission and degradation plan.
    #[must_use]
    pub fn plan(&self, slices: &[TrafficSlice]) -> DegradationPlan {
        let mut candidates = slices
            .iter()
            .enumerate()
            .map(|(ordinal, slice)| Candidate {
                ordinal,
                slice: slice.clone(),
                priority_score: slice.priority_score(),
            })
            .collect::<Vec<_>>();
        sort_candidates(&mut candidates);

        let mut admitted = Vec::new();
        let mut degraded = Vec::new();
        let mut remaining_slots = self.total_slots;
        let mut remaining_reserved = self.reserved_control_slots.min(self.total_slots);
        let mut admitted_ordinals = std::collections::BTreeSet::new();

        for candidate in &candidates {
            if !candidate.slice.service_class.uses_reserved_capacity() {
                continue;
            }
            if candidate.slice.required_slots <= remaining_reserved
                && candidate.slice.required_slots <= remaining_slots
            {
                remaining_reserved -= candidate.slice.required_slots;
                remaining_slots -= candidate.slice.required_slots;
                admitted_ordinals.insert(candidate.ordinal);
                admitted.push(candidate.admit(true));
            }
        }

        for candidate in candidates {
            if admitted_ordinals.contains(&candidate.ordinal) {
                continue;
            }
            if candidate.slice.required_slots <= remaining_slots {
                remaining_slots -= candidate.slice.required_slots;
                admitted.push(candidate.admit(false));
            } else {
                degraded.push(candidate.degrade());
            }
        }

        DegradationPlan {
            admitted,
            degraded,
            remaining_slots,
        }
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    ordinal: usize,
    slice: TrafficSlice,
    priority_score: u16,
}

impl Candidate {
    fn admit(&self, reserved_lane: bool) -> DegradationDecision {
        DegradationDecision {
            slice: self.slice.name.clone(),
            disposition: DegradationDisposition::Preserve,
            priority_score: self.priority_score,
            required_slots: self.slice.required_slots,
            reserved_lane,
        }
    }

    fn degrade(&self) -> DegradationDecision {
        DegradationDecision {
            slice: self.slice.name.clone(),
            disposition: self.slice.degradation_disposition(),
            priority_score: self.priority_score,
            required_slots: self.slice.required_slots,
            reserved_lane: false,
        }
    }
}

fn sort_candidates(candidates: &mut [Candidate]) {
    candidates.sort_by(
        |left, right| match right.priority_score.cmp(&left.priority_score) {
            Ordering::Equal => match left.slice.required_slots.cmp(&right.slice.required_slots) {
                Ordering::Equal => match left.slice.name.cmp(&right.slice.name) {
                    Ordering::Equal => left.ordinal.cmp(&right.ordinal),
                    other => other,
                },
                other => other,
            },
            other => other,
        },
    );
}

/// Envelope constraining adaptive reliability tuning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafetyEnvelope {
    /// Minimum steward quorum size the controller may choose.
    pub min_stewards: usize,
    /// Maximum steward quorum size the controller may choose.
    pub max_stewards: usize,
    /// Minimum repair-symbol depth allowed by policy.
    pub min_repair_depth: u16,
    /// Maximum repair-symbol depth allowed by policy.
    pub max_repair_depth: u16,
    /// Minimum relay-placement budget.
    pub min_relay_budget: u16,
    /// Maximum relay-placement budget.
    pub max_relay_budget: u16,
    /// Weakest delivery class the controller may select.
    pub min_delivery_class: DeliveryClass,
    /// Strongest delivery class the controller may select.
    pub max_delivery_class: DeliveryClass,
    /// Minimum redelivery-attempt budget.
    pub min_redelivery_attempts: u16,
    /// Maximum redelivery-attempt budget.
    pub max_redelivery_attempts: u16,
    /// Minimum replay-buffer allocation.
    pub min_replay_buffer_events: u32,
    /// Maximum replay-buffer allocation.
    pub max_replay_buffer_events: u32,
    /// Minimum evidence/confidence required before shifting policy.
    pub evidence_threshold: f64,
    /// Violation rate that forces rollback to the last stable policy.
    pub rollback_violation_threshold: f64,
}

impl Default for SafetyEnvelope {
    fn default() -> Self {
        Self {
            min_stewards: 1,
            max_stewards: 5,
            min_repair_depth: 0,
            max_repair_depth: 8,
            min_relay_budget: 0,
            max_relay_budget: 4,
            min_delivery_class: DeliveryClass::EphemeralInteractive,
            max_delivery_class: DeliveryClass::MobilitySafe,
            min_redelivery_attempts: 1,
            max_redelivery_attempts: 6,
            min_replay_buffer_events: 32,
            max_replay_buffer_events: 2048,
            evidence_threshold: 0.8,
            rollback_violation_threshold: 0.25,
        }
    }
}

impl SafetyEnvelope {
    /// Validate that the envelope is well formed.
    pub fn validate(&self) -> Result<(), ReliabilityControlError> {
        validate_probability("evidence_threshold", self.evidence_threshold)?;
        validate_probability(
            "rollback_violation_threshold",
            self.rollback_violation_threshold,
        )?;
        validate_envelope_range("stewards", self.min_stewards, self.max_stewards, true)?;
        validate_envelope_range(
            "repair_depth",
            self.min_repair_depth,
            self.max_repair_depth,
            false,
        )?;
        validate_envelope_range(
            "relay_budget",
            self.min_relay_budget,
            self.max_relay_budget,
            false,
        )?;
        validate_envelope_range(
            "redelivery_attempts",
            self.min_redelivery_attempts,
            self.max_redelivery_attempts,
            true,
        )?;
        validate_envelope_range(
            "replay_buffer_events",
            self.min_replay_buffer_events,
            self.max_replay_buffer_events,
            true,
        )?;
        if self.min_delivery_class > self.max_delivery_class {
            return Err(ReliabilityControlError::InvalidEnvelopeRange {
                field: "delivery_class",
            });
        }
        Ok(())
    }
}

/// Concrete reliability settings chosen inside one safety envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilitySettings {
    /// Active steward quorum size.
    pub steward_count: usize,
    /// Repair-symbol depth or equivalent redundancy budget.
    pub repair_depth: u16,
    /// Relay-placement budget for delegated serving.
    pub relay_budget: u16,
    /// Delivery class currently selected for this workload.
    pub delivery_class: DeliveryClass,
    /// Maximum redelivery attempts before dead-lettering or escalation.
    pub redelivery_attempts: u16,
    /// Replay-buffer capacity reserved for this lane.
    pub replay_buffer_events: u32,
}

impl Default for ReliabilitySettings {
    fn default() -> Self {
        Self {
            steward_count: 1,
            repair_depth: 0,
            relay_budget: 0,
            delivery_class: DeliveryClass::EphemeralInteractive,
            redelivery_attempts: 1,
            replay_buffer_events: 64,
        }
    }
}

impl ReliabilitySettings {
    /// Validate that the settings stay inside the envelope.
    pub fn validate_within(
        &self,
        envelope: &SafetyEnvelope,
    ) -> Result<(), ReliabilityControlError> {
        envelope.validate()?;
        validate_setting_range(
            "steward_count",
            self.steward_count,
            envelope.min_stewards,
            envelope.max_stewards,
        )?;
        validate_setting_range(
            "repair_depth",
            self.repair_depth,
            envelope.min_repair_depth,
            envelope.max_repair_depth,
        )?;
        validate_setting_range(
            "relay_budget",
            self.relay_budget,
            envelope.min_relay_budget,
            envelope.max_relay_budget,
        )?;
        validate_setting_range(
            "redelivery_attempts",
            self.redelivery_attempts,
            envelope.min_redelivery_attempts,
            envelope.max_redelivery_attempts,
        )?;
        validate_setting_range(
            "replay_buffer_events",
            self.replay_buffer_events,
            envelope.min_replay_buffer_events,
            envelope.max_replay_buffer_events,
        )?;
        if self.delivery_class < envelope.min_delivery_class
            || self.delivery_class > envelope.max_delivery_class
        {
            return Err(ReliabilityControlError::SettingOutsideEnvelope {
                field: "delivery_class",
            });
        }
        Ok(())
    }
}

/// Evidence snapshot that justifies an adaptive reliability decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReliabilityEvidence {
    /// Aggregate evidence score synthesized from replay, telemetry, and audits.
    pub evidence_score: f64,
    /// Confidence attached to the evidence packet.
    pub confidence: f64,
    /// Fraction of requests missing their declared SLO in the current window.
    pub latency_violation_rate: f64,
    /// Pressure coming from repair/backfill debt.
    pub repair_pressure: f64,
    /// Pressure indicating delegated relay serving is saturated or beneficial.
    pub relay_pressure: f64,
    /// Pressure indicating replay buffers are under stress.
    pub replay_pressure: f64,
    /// Number of observations contributing to the packet.
    pub observation_window: u32,
}

impl ReliabilityEvidence {
    /// Validate the evidence packet.
    pub fn validate(&self) -> Result<(), ReliabilityControlError> {
        validate_probability("evidence_score", self.evidence_score)?;
        validate_probability("confidence", self.confidence)?;
        validate_probability("latency_violation_rate", self.latency_violation_rate)?;
        validate_probability("repair_pressure", self.repair_pressure)?;
        validate_probability("relay_pressure", self.relay_pressure)?;
        validate_probability("replay_pressure", self.replay_pressure)?;
        if self.observation_window == 0 {
            return Err(ReliabilityControlError::ZeroObservationWindow);
        }
        Ok(())
    }

    fn supports_shift(&self, threshold: f64) -> bool {
        self.evidence_score >= threshold && self.confidence >= threshold
    }
}

/// One operator-auditable policy change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReliabilityDecision {
    /// Material action taken by the controller.
    pub action: ReliabilityAction,
    /// Settings before the decision.
    pub previous: ReliabilitySettings,
    /// Settings after the decision.
    pub next: ReliabilitySettings,
    /// Evidence packet that justified the decision.
    pub evidence: ReliabilityEvidence,
    /// Human-readable explanation for operators and replay logs.
    pub reason: String,
    /// Rollback target retained after a forward shift.
    pub rollback_target: Option<ReliabilitySettings>,
}

impl ReliabilityDecision {
    /// Returns true when the decision materially changes settings.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.previous != self.next
    }
}

/// Controller action chosen for one evidence packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliabilityAction {
    /// Keep the current policy unchanged.
    Hold,
    /// Tighten reliability inside the envelope.
    Tighten,
    /// Relax reliability overhead inside the envelope.
    Relax,
    /// Roll back to the previous stable policy.
    Rollback,
}

/// Stateful bounded-regret controller for FABRIC reliability knobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundedRegretReliabilityController {
    /// Safety envelope constraining all adaptation.
    pub envelope: SafetyEnvelope,
    /// Current selected settings.
    pub current: ReliabilitySettings,
    rollback_target: Option<ReliabilitySettings>,
}

impl BoundedRegretReliabilityController {
    /// Build a new controller from one envelope and initial settings.
    pub fn new(
        envelope: SafetyEnvelope,
        current: ReliabilitySettings,
    ) -> Result<Self, ReliabilityControlError> {
        current.validate_within(&envelope)?;
        Ok(Self {
            envelope,
            current,
            rollback_target: None,
        })
    }

    /// Inspect the currently retained rollback target, if any.
    #[must_use]
    pub fn rollback_target(&self) -> Option<&ReliabilitySettings> {
        self.rollback_target.as_ref()
    }

    /// Apply one evidence packet and return the resulting operator-visible decision.
    pub fn apply(
        &mut self,
        evidence: ReliabilityEvidence,
    ) -> Result<ReliabilityDecision, ReliabilityControlError> {
        evidence.validate()?;

        if evidence.latency_violation_rate >= self.envelope.rollback_violation_threshold
            && let Some(rollback_target) = self.rollback_target.take()
        {
            let previous = self.current.clone();
            let reason = format!(
                "rollback triggered by violation rate {:.3} crossing threshold {:.3}",
                evidence.latency_violation_rate, self.envelope.rollback_violation_threshold
            );
            self.current = rollback_target.clone();
            return Ok(ReliabilityDecision {
                action: ReliabilityAction::Rollback,
                previous,
                next: rollback_target,
                evidence,
                reason,
                rollback_target: None,
            });
        }

        if !evidence.supports_shift(self.envelope.evidence_threshold) {
            let reason = format!(
                "hold: evidence {:.3} / confidence {:.3} below threshold {:.3}",
                evidence.evidence_score, evidence.confidence, self.envelope.evidence_threshold
            );
            return Ok(ReliabilityDecision {
                action: ReliabilityAction::Hold,
                previous: self.current.clone(),
                next: self.current.clone(),
                evidence,
                reason,
                rollback_target: self.rollback_target.clone(),
            });
        }

        let previous = self.current.clone();
        let mut next = previous.clone();
        let action = if evidence.latency_violation_rate > 0.0
            || evidence.repair_pressure >= 0.5
            || evidence.relay_pressure >= 0.6
            || evidence.replay_pressure >= 0.6
        {
            tighten_reliability(&mut next, &self.envelope, &evidence);
            if next == previous {
                ReliabilityAction::Hold
            } else {
                ReliabilityAction::Tighten
            }
        } else {
            relax_reliability(&mut next, &self.envelope);
            if next == previous {
                ReliabilityAction::Hold
            } else {
                ReliabilityAction::Relax
            }
        };

        if action == ReliabilityAction::Hold {
            return Ok(ReliabilityDecision {
                action,
                previous: previous.clone(),
                next: previous,
                evidence,
                reason: "hold: settings already at the relevant envelope boundary".to_owned(),
                rollback_target: self.rollback_target.clone(),
            });
        }

        self.rollback_target = Some(previous.clone());
        self.current = next.clone();
        Ok(ReliabilityDecision {
            action,
            previous,
            next,
            evidence,
            reason: match action {
                ReliabilityAction::Tighten => {
                    "tighten reliability within envelope using evidence-backed pressure signals"
                        .to_owned()
                }
                ReliabilityAction::Relax => {
                    "relax reliability overhead within envelope after stable low-pressure evidence"
                        .to_owned()
                }
                ReliabilityAction::Hold | ReliabilityAction::Rollback => unreachable!(),
            },
            rollback_target: self.rollback_target.clone(),
        })
    }
}

/// Validation failures for bounded-regret reliability control.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ReliabilityControlError {
    /// A probability-like field must stay inside `[0.0, 1.0]`.
    #[error("field `{field}` must be finite and in [0.0, 1.0], got {value}")]
    InvalidProbability {
        /// Field that failed validation.
        field: &'static str,
        /// Rejected value.
        value: f64,
    },
    /// An envelope range is inverted or uses an invalid positive minimum.
    #[error("safety envelope range for `{field}` is invalid")]
    InvalidEnvelopeRange {
        /// Field whose range is invalid.
        field: &'static str,
    },
    /// A concrete setting is outside the declared safety envelope.
    #[error("setting `{field}` is outside the declared safety envelope")]
    SettingOutsideEnvelope {
        /// Setting that violated the envelope.
        field: &'static str,
    },
    /// Evidence packets must represent at least one observation.
    #[error("observation_window must be greater than zero")]
    ZeroObservationWindow,
}

fn validate_probability(field: &'static str, value: f64) -> Result<(), ReliabilityControlError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(ReliabilityControlError::InvalidProbability { field, value })
    }
}

fn validate_envelope_range<T>(
    field: &'static str,
    min: T,
    max: T,
    strictly_positive_min: bool,
) -> Result<(), ReliabilityControlError>
where
    T: Copy + Ord + Default,
{
    if min > max || (strictly_positive_min && min == T::default()) {
        Err(ReliabilityControlError::InvalidEnvelopeRange { field })
    } else {
        Ok(())
    }
}

fn validate_setting_range<T>(
    field: &'static str,
    value: T,
    min: T,
    max: T,
) -> Result<(), ReliabilityControlError>
where
    T: Copy + Ord,
{
    if value < min || value > max {
        Err(ReliabilityControlError::SettingOutsideEnvelope { field })
    } else {
        Ok(())
    }
}

fn tighten_reliability(
    next: &mut ReliabilitySettings,
    envelope: &SafetyEnvelope,
    evidence: &ReliabilityEvidence,
) {
    if evidence.latency_violation_rate > 0.0 {
        next.steward_count = next
            .steward_count
            .saturating_add(1)
            .min(envelope.max_stewards);
        next.redelivery_attempts = next
            .redelivery_attempts
            .saturating_add(1)
            .min(envelope.max_redelivery_attempts);
        next.delivery_class =
            promote_delivery_class(next.delivery_class, envelope.max_delivery_class);
    }
    if evidence.repair_pressure >= 0.5 {
        next.repair_depth = next
            .repair_depth
            .saturating_add(1)
            .min(envelope.max_repair_depth);
    }
    if evidence.relay_pressure >= 0.6 {
        next.relay_budget = next
            .relay_budget
            .saturating_add(1)
            .min(envelope.max_relay_budget);
    }
    if evidence.replay_pressure >= 0.6 {
        next.replay_buffer_events = next
            .replay_buffer_events
            .saturating_add(128)
            .min(envelope.max_replay_buffer_events);
    }
}

fn relax_reliability(next: &mut ReliabilitySettings, envelope: &SafetyEnvelope) {
    next.steward_count = next
        .steward_count
        .saturating_sub(1)
        .max(envelope.min_stewards);
    next.repair_depth = next
        .repair_depth
        .saturating_sub(1)
        .max(envelope.min_repair_depth);
    next.relay_budget = next
        .relay_budget
        .saturating_sub(1)
        .max(envelope.min_relay_budget);
    next.redelivery_attempts = next
        .redelivery_attempts
        .saturating_sub(1)
        .max(envelope.min_redelivery_attempts);
    next.replay_buffer_events = next
        .replay_buffer_events
        .saturating_sub(128)
        .max(envelope.min_replay_buffer_events);
    next.delivery_class = demote_delivery_class(next.delivery_class, envelope.min_delivery_class);
}

fn promote_delivery_class(current: DeliveryClass, max: DeliveryClass) -> DeliveryClass {
    let index = DeliveryClass::ALL
        .iter()
        .position(|class| *class == current)
        .expect("current delivery class must be canonical");
    let mut promoted = current;
    for class in DeliveryClass::ALL.iter().skip(index + 1) {
        if *class <= max {
            promoted = *class;
            break;
        }
    }
    promoted
}

fn demote_delivery_class(current: DeliveryClass, min: DeliveryClass) -> DeliveryClass {
    let index = DeliveryClass::ALL
        .iter()
        .position(|class| *class == current)
        .expect("current delivery class must be canonical");
    let mut demoted = current;
    for class in DeliveryClass::ALL[..index].iter().rev() {
        if *class >= min {
            demoted = *class;
            break;
        }
    }
    demoted
}

/// Sovereignty posture the operator wants the compiler to preserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SovereigntyMode {
    /// No additional sovereignty constraints beyond the class defaults.
    #[default]
    Relaxed,
    /// Prefer tenant-local placement and avoid unnecessary remote relays.
    PreferLocal,
    /// Keep policy decisions tenant-local unless explicitly certified otherwise.
    Strict,
}

/// Mobility bias selected by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobilityPreference {
    /// Let the compiler choose the default mobility posture for the workload.
    #[default]
    Balanced,
    /// Prefer quiescent handoff and cut-certified mobility over restart-style failover.
    PreferQuiescent,
    /// Allow restart-style failover when it is the cheaper safe option.
    PreferRestartFailover,
}

/// Cross-tenant trust boundary required by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossTenantTrafficPolicy {
    /// Cross-tenant traffic is permitted through the usual trusted-boundary checks.
    #[default]
    AllowTrusted,
    /// Every cross-tenant edge must carry an explicit certificate.
    RequireCertificates,
    /// Cross-tenant edges are not allowed for this intent.
    Deny,
}

/// Egress posture applied when compiling operator intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressBudgetMode {
    /// Use the default relay/egress posture for the service class.
    #[default]
    Balanced,
    /// Minimize egress whenever possible.
    Minimize,
    /// Minimize egress until recoverability would drop below the declared floor.
    MinimizeUnlessRecoverabilityDrops,
}

/// Explicit operator control over remote relay and egress posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressBudget {
    /// How aggressively the compiler should minimize egress.
    pub mode: EgressBudgetMode,
    /// Maximum number of remote relays the compiler may allocate.
    pub max_remote_relays: u16,
}

impl Default for EgressBudget {
    fn default() -> Self {
        Self {
            mode: EgressBudgetMode::Balanced,
            max_remote_relays: 2,
        }
    }
}

impl EgressBudget {
    /// Construct a concrete egress budget.
    #[must_use]
    pub const fn new(mode: EgressBudgetMode, max_remote_relays: u16) -> Self {
        Self {
            mode,
            max_remote_relays,
        }
    }
}

/// Narrow, auditable operator intent surface for FABRIC control policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorIntent {
    /// Human-readable intent name.
    pub name: String,
    /// Optional tail-latency objective carried by the intent.
    pub latency_objective: Option<Duration>,
    /// Sovereignty posture the operator wants preserved.
    pub sovereignty: SovereigntyMode,
    /// Mobility preference compiled into delivery and failover artifacts.
    pub mobility: MobilityPreference,
    /// Egress posture compiled into relay and federation constraints.
    pub egress_budget: EgressBudget,
    /// Minimum recoverability class to preserve before relaxing the egress posture.
    pub recoverability_floor: u8,
    /// Cross-tenant trust requirement.
    pub cross_tenant_policy: CrossTenantTrafficPolicy,
}

impl OperatorIntent {
    /// Build a new intent with conservative defaults.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            latency_objective: None,
            sovereignty: SovereigntyMode::Relaxed,
            mobility: MobilityPreference::Balanced,
            egress_budget: EgressBudget::default(),
            recoverability_floor: 0,
            cross_tenant_policy: CrossTenantTrafficPolicy::AllowTrusted,
        }
    }

    /// Attach a latency objective to the intent.
    #[must_use]
    pub fn with_latency_objective(mut self, latency_objective: Duration) -> Self {
        self.latency_objective = Some(latency_objective);
        self
    }

    /// Set the sovereignty posture.
    #[must_use]
    pub fn with_sovereignty(mut self, sovereignty: SovereigntyMode) -> Self {
        self.sovereignty = sovereignty;
        self
    }

    /// Set the mobility preference.
    #[must_use]
    pub fn with_mobility(mut self, mobility: MobilityPreference) -> Self {
        self.mobility = mobility;
        self
    }

    /// Override the egress budget.
    #[must_use]
    pub fn with_egress_budget(mut self, egress_budget: EgressBudget) -> Self {
        self.egress_budget = egress_budget;
        self
    }

    /// Require a minimum recoverability floor before relaxing egress constraints.
    #[must_use]
    pub fn with_recoverability_floor(mut self, recoverability_floor: u8) -> Self {
        self.recoverability_floor = recoverability_floor;
        self
    }

    /// Set the cross-tenant boundary policy.
    #[must_use]
    pub fn with_cross_tenant_policy(
        mut self,
        cross_tenant_policy: CrossTenantTrafficPolicy,
    ) -> Self {
        self.cross_tenant_policy = cross_tenant_policy;
        self
    }
}

/// Mobility artifact compiled from one operator intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobilityBudget {
    /// Whether quiescent handoff is preferred over restart-style failover.
    pub prefer_quiescent: bool,
    /// Whether restart-style failover remains allowed.
    pub allow_restart_failover: bool,
    /// Bounded retry budget for cutover and mobility handoff attempts.
    pub cutover_retry_budget: u16,
    /// Minimum recoverability class the mobility plan must preserve.
    pub recoverability_floor: u8,
}

/// Federation and placement constraints compiled from one operator intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationConstraints {
    /// Whether the compiler should preserve tenant-local placement whenever possible.
    pub preserve_sovereignty: bool,
    /// Cross-tenant traffic requirement.
    pub cross_tenant_policy: CrossTenantTrafficPolicy,
    /// Whether every cross-tenant edge must carry a certificate.
    pub require_certificate_edges: bool,
    /// Whether cross-tenant edges are allowed at all.
    pub allow_cross_tenant: bool,
    /// Maximum number of remote relays the plan may use.
    pub max_remote_relays: u16,
}

/// Approval posture for promoting a compiled control-capsule policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionApproval {
    /// The policy may promote automatically once evidence is sufficient.
    Automatic,
    /// A human operator must approve promotion.
    OperatorApprovalRequired,
}

/// Evidence mode required before promoting a control-capsule policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionEvidence {
    /// Inline evidence is sufficient.
    Inline,
    /// Replay evidence is required before promotion.
    ReplayBacked,
}

/// Violation response compiled for control-capsule policy changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationResponse {
    /// Hold the current policy and await operator intervention.
    Hold,
    /// Roll back automatically to the last stable policy.
    RollbackToStable,
}

/// Control-capsule promotion and rollback policy compiled from one intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlCapsulePolicy {
    /// Evidence threshold required before the control plane may promote changes automatically.
    pub evidence_threshold: f64,
    /// Approval posture for promotion.
    pub promotion_approval: PromotionApproval,
    /// Evidence mode required before promotion.
    pub promotion_evidence: PromotionEvidence,
    /// Response applied when the policy violates its declared envelope.
    pub violation_response: ViolationResponse,
    /// Recoverability floor that may justify relaxing a minimized-egress stance.
    pub recoverability_override_floor: Option<u8>,
}

/// Explicit policy artifacts compiled from one narrow operator intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledOperatorIntent {
    /// Service class selected for the intent.
    pub service_class: SemanticServiceClass,
    /// Caller/provider delivery policy compiled from the intent.
    pub delivery_policy: DeliveryClassPolicy,
    /// Degradation policy selected for overload control.
    pub degradation_policy: DegradationPolicy,
    /// Reliability envelope constraining adaptive policy changes.
    pub safety_envelope: SafetyEnvelope,
    /// Mobility policy compiled for cutover/failover decisions.
    pub mobility_budget: MobilityBudget,
    /// Federation boundary and placement constraints.
    pub federation_constraints: FederationConstraints,
    /// Control-capsule promotion/rollback rules.
    pub control_capsule_policy: ControlCapsulePolicy,
}

/// Stateless compiler turning narrow operator intent into explicit artifacts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OperatorIntentCompiler;

impl OperatorIntentCompiler {
    /// Compile one operator intent into explicit policy artifacts.
    pub fn compile(intent: &OperatorIntent) -> Result<CompiledOperatorIntent, IntentCompileError> {
        validate_operator_intent(intent)?;
        let service_class = compile_service_class(intent);
        let safety_envelope = compile_safety_envelope(intent, service_class);
        safety_envelope.validate()?;
        let delivery_policy = compile_delivery_policy(service_class, &safety_envelope)?;
        let degradation_policy = compile_degradation_policy(intent, service_class);
        let mobility_budget = compile_mobility_budget(intent, service_class);
        let federation_constraints = compile_federation_constraints(intent, &safety_envelope);
        let control_capsule_policy =
            compile_control_capsule_policy(intent, &safety_envelope, &federation_constraints);

        Ok(CompiledOperatorIntent {
            service_class,
            delivery_policy,
            degradation_policy,
            safety_envelope,
            mobility_budget,
            federation_constraints,
            control_capsule_policy,
        })
    }
}

/// Validation failures for operator-intent compilation.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum IntentCompileError {
    /// Latency objectives must be non-zero when present.
    #[error("latency objective must be greater than zero")]
    ZeroLatencyObjective,
    /// Recoverability floors must stay within the declared bounded range.
    #[error("recoverability floor must be in 1..=8 when required, got {value}")]
    InvalidRecoverabilityFloor {
        /// Rejected recoverability floor.
        value: u8,
    },
    /// Delivery-class policy validation failed during compilation.
    #[error(transparent)]
    InvalidDeliveryClassPolicy(#[from] DeliveryClassPolicyError),
    /// Safety-envelope validation failed during compilation.
    #[error(transparent)]
    InvalidSafetyEnvelope(#[from] ReliabilityControlError),
}

fn validate_operator_intent(intent: &OperatorIntent) -> Result<(), IntentCompileError> {
    if matches!(intent.latency_objective, Some(latency) if latency.is_zero()) {
        return Err(IntentCompileError::ZeroLatencyObjective);
    }
    if matches!(
        intent.egress_budget.mode,
        EgressBudgetMode::MinimizeUnlessRecoverabilityDrops
    ) {
        if !(1..=8).contains(&intent.recoverability_floor) {
            return Err(IntentCompileError::InvalidRecoverabilityFloor {
                value: intent.recoverability_floor,
            });
        }
    } else if intent.recoverability_floor > 8 {
        return Err(IntentCompileError::InvalidRecoverabilityFloor {
            value: intent.recoverability_floor,
        });
    }
    Ok(())
}

fn compile_service_class(intent: &OperatorIntent) -> SemanticServiceClass {
    if intent.mobility == MobilityPreference::PreferQuiescent {
        SemanticServiceClass::LeaseRepair
    } else if intent.latency_objective.is_some() {
        SemanticServiceClass::ReplyCritical
    } else if intent.cross_tenant_policy == CrossTenantTrafficPolicy::RequireCertificates
        || intent.sovereignty == SovereigntyMode::Strict
        || !matches!(intent.egress_budget.mode, EgressBudgetMode::Balanced)
    {
        SemanticServiceClass::DurablePipeline
    } else {
        SemanticServiceClass::Interactive
    }
}

fn compile_safety_envelope(
    intent: &OperatorIntent,
    service_class: SemanticServiceClass,
) -> SafetyEnvelope {
    let mut envelope = SafetyEnvelope::default();

    if let Some(latency_objective) = intent.latency_objective {
        if latency_objective <= Duration::from_millis(250) {
            envelope.min_stewards = envelope.min_stewards.max(2);
            envelope.min_redelivery_attempts = envelope.min_redelivery_attempts.max(2);
            envelope.evidence_threshold = envelope.evidence_threshold.max(0.85);
        }
        if latency_objective <= Duration::from_millis(100) {
            envelope.max_relay_budget = envelope.max_relay_budget.min(1);
            envelope.rollback_violation_threshold = envelope.rollback_violation_threshold.min(0.2);
        }
    }

    match intent.sovereignty {
        SovereigntyMode::Relaxed => {}
        SovereigntyMode::PreferLocal => {
            envelope.max_relay_budget = envelope.max_relay_budget.min(1);
        }
        SovereigntyMode::Strict => {
            envelope.max_relay_budget = 0;
            envelope.evidence_threshold = envelope.evidence_threshold.max(0.9);
            envelope.rollback_violation_threshold = envelope.rollback_violation_threshold.min(0.2);
        }
    }

    match intent.mobility {
        MobilityPreference::Balanced => {}
        MobilityPreference::PreferQuiescent => {
            envelope.min_delivery_class = DeliveryClass::MobilitySafe;
            envelope.max_delivery_class = DeliveryClass::MobilitySafe;
            envelope.min_stewards = envelope.min_stewards.max(2);
            envelope.min_redelivery_attempts = envelope.min_redelivery_attempts.max(2);
        }
        MobilityPreference::PreferRestartFailover => {
            envelope.max_delivery_class = envelope
                .max_delivery_class
                .min(DeliveryClass::ObligationBacked);
        }
    }

    match intent.egress_budget.mode {
        EgressBudgetMode::Balanced => {}
        EgressBudgetMode::Minimize => {
            envelope.max_relay_budget = envelope
                .max_relay_budget
                .min(intent.egress_budget.max_remote_relays.min(1));
        }
        EgressBudgetMode::MinimizeUnlessRecoverabilityDrops => {
            envelope.max_relay_budget = envelope
                .max_relay_budget
                .min(intent.egress_budget.max_remote_relays);
            if intent.recoverability_floor >= 4 {
                envelope.min_stewards = envelope.min_stewards.max(2);
            }
        }
    }

    match intent.cross_tenant_policy {
        CrossTenantTrafficPolicy::AllowTrusted => {}
        CrossTenantTrafficPolicy::RequireCertificates => {
            envelope.min_delivery_class = envelope
                .min_delivery_class
                .max(DeliveryClass::ObligationBacked);
            envelope.evidence_threshold = envelope.evidence_threshold.max(0.9);
        }
        CrossTenantTrafficPolicy::Deny => {
            envelope.max_relay_budget = 0;
        }
    }

    if service_class == SemanticServiceClass::LeaseRepair {
        envelope.min_delivery_class = DeliveryClass::MobilitySafe;
        envelope.max_delivery_class = DeliveryClass::MobilitySafe;
    }

    envelope
}

fn compile_delivery_policy(
    service_class: SemanticServiceClass,
    envelope: &SafetyEnvelope,
) -> Result<DeliveryClassPolicy, IntentCompileError> {
    let (mut default_class, mut admissible_classes) = match service_class {
        SemanticServiceClass::ControlRecovery => (
            DeliveryClass::ObligationBacked,
            vec![DeliveryClass::ObligationBacked, DeliveryClass::MobilitySafe],
        ),
        SemanticServiceClass::ReplyCritical => (
            DeliveryClass::ObligationBacked,
            vec![
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
                DeliveryClass::MobilitySafe,
            ],
        ),
        SemanticServiceClass::LeaseRepair => (
            DeliveryClass::MobilitySafe,
            vec![DeliveryClass::ObligationBacked, DeliveryClass::MobilitySafe],
        ),
        SemanticServiceClass::DurablePipeline => (
            DeliveryClass::DurableOrdered,
            vec![
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
                DeliveryClass::MobilitySafe,
            ],
        ),
        SemanticServiceClass::Interactive => (
            DeliveryClass::EphemeralInteractive,
            vec![
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
                DeliveryClass::ObligationBacked,
            ],
        ),
        SemanticServiceClass::ReadModel => (
            DeliveryClass::DurableOrdered,
            vec![DeliveryClass::DurableOrdered],
        ),
        SemanticServiceClass::LowValueFanout => (
            DeliveryClass::EphemeralInteractive,
            vec![
                DeliveryClass::EphemeralInteractive,
                DeliveryClass::DurableOrdered,
            ],
        ),
        SemanticServiceClass::ExpensiveReplay => (
            DeliveryClass::ForensicReplayable,
            vec![
                DeliveryClass::ForensicReplayable,
                DeliveryClass::MobilitySafe,
            ],
        ),
    };

    admissible_classes.retain(|class| {
        *class >= envelope.min_delivery_class && *class <= envelope.max_delivery_class
    });

    default_class = default_class.clamp(envelope.min_delivery_class, envelope.max_delivery_class);
    if !admissible_classes.contains(&default_class) {
        admissible_classes.push(default_class);
    }

    DeliveryClassPolicy::new(default_class, admissible_classes).map_err(Into::into)
}

fn compile_degradation_policy(
    intent: &OperatorIntent,
    service_class: SemanticServiceClass,
) -> DegradationPolicy {
    let mut total_slots: u32 = if matches!(
        service_class,
        SemanticServiceClass::ReplyCritical | SemanticServiceClass::LeaseRepair
    ) {
        3
    } else {
        4
    };
    if !matches!(intent.egress_budget.mode, EgressBudgetMode::Balanced) {
        total_slots = total_slots.saturating_sub(1).max(1);
    }
    let reserved_control_slots = u32::from(
        matches!(
            service_class,
            SemanticServiceClass::ControlRecovery | SemanticServiceClass::LeaseRepair
        ) || intent.cross_tenant_policy == CrossTenantTrafficPolicy::RequireCertificates,
    );

    DegradationPolicy::new(total_slots, reserved_control_slots.min(total_slots))
}

fn compile_mobility_budget(
    intent: &OperatorIntent,
    service_class: SemanticServiceClass,
) -> MobilityBudget {
    let prefer_quiescent = intent.mobility == MobilityPreference::PreferQuiescent;
    MobilityBudget {
        prefer_quiescent,
        allow_restart_failover: intent.mobility != MobilityPreference::PreferQuiescent,
        cutover_retry_budget: if service_class == SemanticServiceClass::LeaseRepair {
            2
        } else {
            1
        },
        recoverability_floor: intent.recoverability_floor,
    }
}

fn compile_federation_constraints(
    intent: &OperatorIntent,
    safety_envelope: &SafetyEnvelope,
) -> FederationConstraints {
    let mut max_remote_relays = intent.egress_budget.max_remote_relays;
    if intent.sovereignty == SovereigntyMode::Strict {
        max_remote_relays = 0;
    } else if intent.sovereignty == SovereigntyMode::PreferLocal {
        max_remote_relays = max_remote_relays.min(1);
    }
    if intent.cross_tenant_policy == CrossTenantTrafficPolicy::Deny {
        max_remote_relays = 0;
    }
    max_remote_relays = max_remote_relays.min(safety_envelope.max_relay_budget);

    FederationConstraints {
        preserve_sovereignty: intent.sovereignty != SovereigntyMode::Relaxed,
        cross_tenant_policy: intent.cross_tenant_policy,
        require_certificate_edges: intent.cross_tenant_policy
            == CrossTenantTrafficPolicy::RequireCertificates,
        allow_cross_tenant: intent.cross_tenant_policy != CrossTenantTrafficPolicy::Deny,
        max_remote_relays,
    }
}

fn compile_control_capsule_policy(
    intent: &OperatorIntent,
    envelope: &SafetyEnvelope,
    federation_constraints: &FederationConstraints,
) -> ControlCapsulePolicy {
    ControlCapsulePolicy {
        evidence_threshold: envelope.evidence_threshold,
        promotion_approval: if federation_constraints.require_certificate_edges
            || intent.sovereignty == SovereigntyMode::Strict
            || intent.mobility == MobilityPreference::PreferQuiescent
        {
            PromotionApproval::OperatorApprovalRequired
        } else {
            PromotionApproval::Automatic
        },
        promotion_evidence: if federation_constraints.require_certificate_edges
            || intent.latency_objective.is_some()
        {
            PromotionEvidence::ReplayBacked
        } else {
            PromotionEvidence::Inline
        },
        violation_response: ViolationResponse::RollbackToStable,
        recoverability_override_floor: if matches!(
            intent.egress_budget.mode,
            EgressBudgetMode::MinimizeUnlessRecoverabilityDrops
        ) {
            Some(intent.recoverability_floor)
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string};

    fn slice(
        name: &str,
        service_class: SemanticServiceClass,
        delivery_class: DeliveryClass,
    ) -> TrafficSlice {
        TrafficSlice::new(name, service_class, delivery_class)
    }

    #[test]
    fn plan_reserves_capacity_for_control_and_recovery_lanes() {
        let policy = DegradationPolicy::new(2, 1);
        let control = slice(
            "control",
            SemanticServiceClass::ControlRecovery,
            DeliveryClass::EphemeralInteractive,
        );
        let fanout = slice(
            "fanout",
            SemanticServiceClass::LowValueFanout,
            DeliveryClass::EphemeralInteractive,
        )
        .with_required_slots(2);

        let plan = policy.plan(&[fanout, control]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "control");
        assert!(plan.admitted[0].reserved_lane);
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "fanout");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::ReduceFanout
        );
    }

    #[test]
    fn plan_prefers_reply_obligations_over_read_models() {
        let policy = DegradationPolicy::new(2, 0);
        let reply = slice(
            "reply",
            SemanticServiceClass::ReplyCritical,
            DeliveryClass::ObligationBacked,
        )
        .with_obligation_load(ObligationLoad::Reply)
        .with_deadline(Duration::from_millis(80));
        let durable = slice(
            "durable",
            SemanticServiceClass::DurablePipeline,
            DeliveryClass::DurableOrdered,
        );
        let read_model = slice(
            "read-model",
            SemanticServiceClass::ReadModel,
            DeliveryClass::DurableOrdered,
        );

        let plan = policy.plan(&[read_model, durable, reply]);

        assert_eq!(plan.admitted.len(), 2);
        assert_eq!(plan.admitted[0].slice, "reply");
        assert_eq!(plan.admitted[1].slice, "durable");
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "read-model");
        assert_eq!(plan.degraded[0].disposition, DegradationDisposition::Defer);
    }

    #[test]
    fn plan_widens_repair_for_lease_sensitive_work() {
        let policy = DegradationPolicy::new(0, 0);
        let lease = slice(
            "lease",
            SemanticServiceClass::LeaseRepair,
            DeliveryClass::ObligationBacked,
        )
        .with_obligation_load(ObligationLoad::Lease)
        .with_cleanup_urgency(CleanupUrgency::Immediate);

        let plan = policy.plan(&[lease]);

        assert!(plan.admitted.is_empty());
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "lease");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::WidenRepair
        );
    }

    #[test]
    fn plan_degrades_replay_before_stronger_contracts() {
        let policy = DegradationPolicy::new(1, 0);
        let replay = slice(
            "replay",
            SemanticServiceClass::ExpensiveReplay,
            DeliveryClass::ForensicReplayable,
        );
        let reply_critical = slice(
            "reply",
            SemanticServiceClass::ReplyCritical,
            DeliveryClass::ObligationBacked,
        )
        .with_obligation_load(ObligationLoad::Reply)
        .with_deadline(Duration::from_millis(50));

        let plan = policy.plan(&[replay, reply_critical]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "reply");
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "replay");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::PauseReplay
        );
    }

    #[test]
    fn plan_uses_deadlines_to_break_ties_within_same_service_class() {
        let policy = DegradationPolicy::new(1, 0);
        let urgent = slice(
            "urgent",
            SemanticServiceClass::DurablePipeline,
            DeliveryClass::DurableOrdered,
        )
        .with_deadline(Duration::from_millis(40));
        let relaxed = slice(
            "relaxed",
            SemanticServiceClass::DurablePipeline,
            DeliveryClass::DurableOrdered,
        )
        .with_deadline(Duration::from_secs(10));

        let plan = policy.plan(&[relaxed, urgent]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "urgent");
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "relaxed");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::RejectNew
        );
    }

    #[test]
    fn control_recovery_widens_repair_when_degraded() {
        // ControlRecovery is documented as "must stay live" traffic.
        // When it can't be admitted, its degradation disposition must be
        // WidenRepair (not RejectNew), because rejecting control/recovery
        // work grows semantic debt.
        let policy = DegradationPolicy::new(0, 0);
        let control = slice(
            "control",
            SemanticServiceClass::ControlRecovery,
            DeliveryClass::EphemeralInteractive,
        );

        let plan = policy.plan(&[control]);

        assert!(plan.admitted.is_empty());
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "control");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::WidenRepair
        );
    }

    #[test]
    fn plan_does_not_drop_distinct_slices_that_share_a_name() {
        let policy = DegradationPolicy::new(1, 1);
        let control = slice(
            "shared",
            SemanticServiceClass::ControlRecovery,
            DeliveryClass::EphemeralInteractive,
        );
        let fanout = slice(
            "shared",
            SemanticServiceClass::LowValueFanout,
            DeliveryClass::EphemeralInteractive,
        );

        let plan = policy.plan(&[control, fanout]);

        assert_eq!(plan.admitted.len(), 1);
        assert_eq!(plan.admitted[0].slice, "shared");
        assert!(plan.admitted[0].reserved_lane);
        assert_eq!(plan.degraded.len(), 1);
        assert_eq!(plan.degraded[0].slice, "shared");
        assert_eq!(
            plan.degraded[0].disposition,
            DegradationDisposition::ReduceFanout
        );
    }

    #[test]
    fn safety_envelope_rejects_invalid_ranges() {
        let invalid = SafetyEnvelope {
            min_stewards: 3,
            max_stewards: 2,
            ..SafetyEnvelope::default()
        };

        assert!(matches!(
            invalid.validate(),
            Err(ReliabilityControlError::InvalidEnvelopeRange { field: "stewards" })
        ));
    }

    #[test]
    fn reliability_controller_requires_strong_evidence_before_shifting() {
        let envelope = SafetyEnvelope::default();
        let current = ReliabilitySettings::default();
        let mut controller =
            BoundedRegretReliabilityController::new(envelope, current.clone()).expect("controller");

        let decision = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.6,
                confidence: 0.7,
                latency_violation_rate: 0.2,
                repair_pressure: 0.8,
                relay_pressure: 0.7,
                replay_pressure: 0.9,
                observation_window: 32,
            })
            .expect("decision");

        assert_eq!(decision.action, ReliabilityAction::Hold);
        assert_eq!(decision.previous, current);
        assert_eq!(decision.next, current);
        assert!(controller.rollback_target().is_none());
    }

    #[test]
    fn reliability_controller_tightens_within_envelope_and_records_rollback() {
        let envelope = SafetyEnvelope {
            max_stewards: 3,
            max_repair_depth: 2,
            max_relay_budget: 1,
            max_delivery_class: DeliveryClass::ObligationBacked,
            max_redelivery_attempts: 3,
            max_replay_buffer_events: 256,
            ..SafetyEnvelope::default()
        };
        let current = ReliabilitySettings {
            steward_count: 2,
            repair_depth: 1,
            relay_budget: 0,
            delivery_class: DeliveryClass::DurableOrdered,
            redelivery_attempts: 2,
            replay_buffer_events: 128,
        };
        let mut controller =
            BoundedRegretReliabilityController::new(envelope, current.clone()).expect("controller");

        let decision = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.95,
                confidence: 0.97,
                latency_violation_rate: 0.12,
                repair_pressure: 0.9,
                relay_pressure: 0.8,
                replay_pressure: 0.85,
                observation_window: 64,
            })
            .expect("decision");

        assert_eq!(decision.action, ReliabilityAction::Tighten);
        assert_eq!(decision.previous, current);
        assert_eq!(
            decision.next,
            ReliabilitySettings {
                steward_count: 3,
                repair_depth: 2,
                relay_budget: 1,
                delivery_class: DeliveryClass::ObligationBacked,
                redelivery_attempts: 3,
                replay_buffer_events: 256,
            }
        );
        assert_eq!(decision.rollback_target, Some(current));
        assert_eq!(controller.current, decision.next);
        assert_eq!(controller.rollback_target(), Some(&decision.previous));
    }

    #[test]
    fn reliability_controller_rolls_back_after_violation_spike() {
        let envelope = SafetyEnvelope {
            rollback_violation_threshold: 0.2,
            ..SafetyEnvelope::default()
        };
        let baseline = ReliabilitySettings::default();
        let mut controller = BoundedRegretReliabilityController::new(envelope, baseline.clone())
            .expect("controller");

        let tighten = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.95,
                confidence: 0.95,
                latency_violation_rate: 0.08,
                repair_pressure: 0.6,
                relay_pressure: 0.0,
                replay_pressure: 0.0,
                observation_window: 32,
            })
            .expect("tighten");
        assert_eq!(tighten.action, ReliabilityAction::Tighten);
        assert_ne!(controller.current, baseline);

        let rollback = controller
            .apply(ReliabilityEvidence {
                evidence_score: 0.99,
                confidence: 0.99,
                latency_violation_rate: 0.4,
                repair_pressure: 0.9,
                relay_pressure: 0.9,
                replay_pressure: 0.9,
                observation_window: 32,
            })
            .expect("rollback");

        assert_eq!(rollback.action, ReliabilityAction::Rollback);
        assert_eq!(rollback.next, baseline);
        assert_eq!(controller.current, baseline);
        assert!(controller.rollback_target().is_none());
    }

    #[test]
    fn compiler_maps_latency_plus_sovereignty_to_reply_critical_artifacts() {
        let intent = OperatorIntent::new("tenant-latency")
            .with_latency_objective(Duration::from_millis(120))
            .with_sovereignty(SovereigntyMode::Strict);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.service_class, SemanticServiceClass::ReplyCritical);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::ObligationBacked
        );
        assert_eq!(compiled.safety_envelope.max_relay_budget, 0);
        assert!(compiled.federation_constraints.preserve_sovereignty);
        assert_eq!(
            compiled.control_capsule_policy.promotion_approval,
            PromotionApproval::OperatorApprovalRequired
        );
        assert_eq!(
            compiled.control_capsule_policy.promotion_evidence,
            PromotionEvidence::ReplayBacked
        );
    }

    #[test]
    fn compiler_prefers_quiescent_mobility_over_restart_failover() {
        let intent = OperatorIntent::new("quiescent-mobility")
            .with_mobility(MobilityPreference::PreferQuiescent);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.service_class, SemanticServiceClass::LeaseRepair);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::MobilitySafe
        );
        assert_eq!(
            compiled.safety_envelope.min_delivery_class,
            DeliveryClass::MobilitySafe
        );
        assert_eq!(
            compiled.safety_envelope.max_delivery_class,
            DeliveryClass::MobilitySafe
        );
        assert!(compiled.mobility_budget.prefer_quiescent);
        assert!(!compiled.mobility_budget.allow_restart_failover);
        assert_eq!(
            compiled.control_capsule_policy.promotion_approval,
            PromotionApproval::OperatorApprovalRequired
        );
    }

    #[test]
    fn compiler_minimizes_egress_until_recoverability_floor() {
        let intent = OperatorIntent::new("minimize-egress")
            .with_egress_budget(EgressBudget::new(
                EgressBudgetMode::MinimizeUnlessRecoverabilityDrops,
                0,
            ))
            .with_recoverability_floor(5);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(
            compiled.service_class,
            SemanticServiceClass::DurablePipeline
        );
        assert_eq!(compiled.federation_constraints.max_remote_relays, 0);
        assert_eq!(compiled.mobility_budget.recoverability_floor, 5);
        assert_eq!(
            compiled
                .control_capsule_policy
                .recoverability_override_floor,
            Some(5)
        );
        assert_eq!(compiled.degradation_policy.total_slots, 3);
    }

    #[test]
    fn compiler_keeps_federation_relays_within_safety_envelope_budget() {
        let intent = OperatorIntent::new("relay-alignment")
            .with_latency_objective(Duration::from_millis(80))
            .with_egress_budget(EgressBudget::new(EgressBudgetMode::Minimize, 8));

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(compiled.safety_envelope.max_relay_budget, 1);
        assert_eq!(
            compiled.federation_constraints.max_remote_relays,
            compiled.safety_envelope.max_relay_budget
        );
    }

    #[test]
    fn compiler_requires_certificate_edges_for_cross_tenant_traffic() {
        let intent = OperatorIntent::new("certified-cross-tenant")
            .with_cross_tenant_policy(CrossTenantTrafficPolicy::RequireCertificates);

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled intent");

        assert_eq!(
            compiled.service_class,
            SemanticServiceClass::DurablePipeline
        );
        assert!(compiled.federation_constraints.allow_cross_tenant);
        assert!(compiled.federation_constraints.require_certificate_edges);
        assert_eq!(
            compiled.delivery_policy.default_class,
            DeliveryClass::ObligationBacked
        );
        assert_eq!(compiled.degradation_policy.reserved_control_slots, 1);
        assert_eq!(
            compiled.control_capsule_policy.promotion_approval,
            PromotionApproval::OperatorApprovalRequired
        );
    }

    #[test]
    fn intent_round_trip_preserves_compiled_artifacts() {
        let intent = OperatorIntent::new("round-trip")
            .with_latency_objective(Duration::from_millis(150))
            .with_sovereignty(SovereigntyMode::PreferLocal)
            .with_mobility(MobilityPreference::Balanced)
            .with_egress_budget(EgressBudget::new(EgressBudgetMode::Minimize, 1))
            .with_cross_tenant_policy(CrossTenantTrafficPolicy::AllowTrusted);

        let encoded = to_string(&intent).expect("serialize");
        let decoded: OperatorIntent = from_str(&encoded).expect("deserialize");

        let compiled = OperatorIntentCompiler::compile(&intent).expect("compiled original");
        let round_tripped = OperatorIntentCompiler::compile(&decoded).expect("compiled decoded");

        assert_eq!(decoded, intent);
        assert_eq!(round_tripped, compiled);
    }
}
