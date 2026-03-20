//! Semantic degradation policy for the FABRIC lane.

use super::class::DeliveryClass;
use super::service::{CancellationObligations, CleanupUrgency};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
