//! Explicit capacity-ticket admission helpers for swarm-facing work.
//!
//! Capacity tickets are deterministic value objects. They do not reserve host
//! resources by themselves; instead they bind an admitted capability-budget
//! envelope to the region/task owner that requested it and make release,
//! revocation, and unreleased-ticket receipts explicit. Child tickets are
//! admitted with the same meet semantics as [`CapabilityBudget::plan_child`].

use crate::cx::cx::Cx;
use crate::types::{
    CancelReason, CapabilityBudget, CapabilityBudgetRefusal, CapabilityBudgetRequirements,
    RegionId, TaskId,
};
use core::fmt;
use core::num::NonZeroU64;

/// Stable ticket identifier derived from explicit owner IDs, child lineage,
/// and a per-mint sibling nonce.
///
/// br-asupersync-audit-followups-2026-06-12-7tcipb (item 1): the prior id was
/// `(owner_region, owner_task, lineage)` only, which is **not** unique across
/// siblings — two `split()`/`lend_*` of the same parent share owner + lineage
/// depth, so they minted byte-identical ids. A receipt consumer matching
/// releases by `ticket_id` would then mis-close one sibling and stamp the leak
/// as closed, silently masking the other ticket's unreleased-obligation leak.
/// `nonce` is a deterministic path-fold (`fold_child_nonce`) of the parent
/// nonce and a per-parent monotonic child sequence, so every descendant in a
/// ticket tree (direct siblings *and* cousins at the same depth) gets a
/// distinct id, while two identical split sequences still reproduce the same
/// ids — the "deterministic value object" contract is preserved (no ambient
/// clock / RNG / global counter).
///
/// Root tickets include an explicit caller-supplied admission sequence in the
/// nonce, so independent root admissions for the same `(region, task)` no
/// longer silently collide. Derived tickets fold their parent nonce and
/// per-parent child sequence to keep siblings and cousins distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityTicketId {
    owner_region: RegionId,
    owner_task: TaskId,
    lineage: u64,
    nonce: u64,
}

impl CapacityTicketId {
    #[inline]
    const fn root(
        owner_region: RegionId,
        owner_task: TaskId,
        admission_sequence: NonZeroU64,
    ) -> Self {
        Self {
            owner_region,
            owner_task,
            lineage: 0,
            nonce: fold_child_nonce(0, admission_sequence.get()),
        }
    }

    #[inline]
    const fn child(self, owner_region: RegionId, owner_task: TaskId, child_seq: u64) -> Self {
        Self {
            owner_region,
            owner_task,
            lineage: self.lineage.saturating_add(1),
            nonce: fold_child_nonce(self.nonce, child_seq),
        }
    }

    /// Region that owns this ticket.
    #[inline]
    pub const fn owner_region(self) -> RegionId {
        self.owner_region
    }

    /// Task that owns this ticket.
    #[inline]
    pub const fn owner_task(self) -> TaskId {
        self.owner_task
    }

    /// Child lineage depth from the root ticket.
    #[inline]
    pub const fn lineage(self) -> u64 {
        self.lineage
    }

    /// Per-mint sibling nonce that disambiguates tickets sharing the same owner
    /// and lineage depth (see the type docs). Always `0` for root tickets.
    #[inline]
    pub const fn nonce(self) -> u64 {
        self.nonce
    }
}

/// Deterministic SplitMix64 fold of a parent nonce and a per-parent child
/// sequence into a child nonce (br-asupersync-audit-followups-2026-06-12-7tcipb
/// item 1). Pure function of its inputs: the same `(parent_nonce, child_seq)`
/// always yields the same value, so the capacity-ticket "deterministic value
/// object" contract is preserved (no clock / RNG / global counter). Because
/// distinct parents already carry distinct nonces, folding the parent nonce in
/// keeps cousins distinct — not just direct siblings — even when the per-parent
/// child sequence repeats across different parents.
#[inline]
const fn fold_child_nonce(parent_nonce: u64, child_seq: u64) -> u64 {
    // Combine the inputs, then run the SplitMix64 finalizer so structurally
    // close inputs (child_seq 1 vs 2) map to far-apart, well-mixed ids.
    let mut z = parent_nonce
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(child_seq)
        .wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Admission surface the ticket is being requested for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityTicketWorkKind {
    /// Core runtime work that must remain bounded by the parent context.
    CoreRuntime,
    /// Agent-swarm admission or coordination work.
    AgentSwarmAdmission,
    /// Proof, trace, or evidence artifact production.
    ProofArtifact,
    /// Operator-facing diagnostics or closeout reporting.
    OperatorDiagnostics,
    /// Optional background work that can be refused without affecting safety.
    OptionalBackground,
}

impl CapacityTicketWorkKind {
    /// Stable lower-case identifier for receipts and contract fixtures.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoreRuntime => "core_runtime",
            Self::AgentSwarmAdmission => "agent_swarm_admission",
            Self::ProofArtifact => "proof_artifact",
            Self::OperatorDiagnostics => "operator_diagnostics",
            Self::OptionalBackground => "optional_background",
        }
    }
}

/// Capacity-ticket admission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityTicketRequest {
    requested: CapabilityBudget,
    requirements: CapabilityBudgetRequirements,
    work_kind: CapacityTicketWorkKind,
    reason: String,
}

impl CapacityTicketRequest {
    /// Creates a request from an explicit budget and fail-closed requirements.
    #[inline]
    pub fn new(
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            requested,
            requirements,
            work_kind: CapacityTicketWorkKind::CoreRuntime,
            reason: reason.into(),
        }
    }

    /// Creates the default agent-swarm admission request shape.
    #[inline]
    pub fn agent_swarm_admission(requested: CapabilityBudget, reason: impl Into<String>) -> Self {
        Self::new(
            requested,
            CapabilityBudgetRequirements::new()
                .require_memory_bytes()
                .require_cpu_units()
                .require_artifact_bytes(),
            reason,
        )
        .with_work_kind(CapacityTicketWorkKind::AgentSwarmAdmission)
    }

    /// Creates a proof-artifact request that must carry artifact and cleanup envelopes.
    #[inline]
    pub fn proof_artifact(requested: CapabilityBudget, reason: impl Into<String>) -> Self {
        Self::new(
            requested,
            CapabilityBudgetRequirements::new()
                .require_artifact_bytes()
                .require_cleanup(),
            reason,
        )
        .with_work_kind(CapacityTicketWorkKind::ProofArtifact)
    }

    /// Overrides the work-kind taxonomy for the request.
    #[inline]
    pub fn with_work_kind(mut self, work_kind: CapacityTicketWorkKind) -> Self {
        self.work_kind = work_kind;
        self
    }

    /// Requested child capability envelope.
    #[inline]
    pub const fn requested(&self) -> CapabilityBudget {
        self.requested
    }

    /// Required dimensions for fail-closed admission.
    #[inline]
    pub const fn requirements(&self) -> CapabilityBudgetRequirements {
        self.requirements
    }

    /// Admission surface this request belongs to.
    #[inline]
    pub const fn work_kind(&self) -> CapacityTicketWorkKind {
        self.work_kind
    }

    /// Human-readable reason carried into receipts.
    #[inline]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Fail-closed refusal for capacity-ticket admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityTicketRefusal {
    owner_region: RegionId,
    owner_task: TaskId,
    parent_ticket_id: Option<CapacityTicketId>,
    requested: CapabilityBudget,
    requirements: CapabilityBudgetRequirements,
    work_kind: CapacityTicketWorkKind,
    request_reason: String,
    budget_refusal: CapabilityBudgetRefusal,
}

impl CapacityTicketRefusal {
    fn new(
        owner_region: RegionId,
        owner_task: TaskId,
        parent_ticket_id: Option<CapacityTicketId>,
        request: &CapacityTicketRequest,
        budget_refusal: CapabilityBudgetRefusal,
    ) -> Self {
        Self {
            owner_region,
            owner_task,
            parent_ticket_id,
            requested: request.requested,
            requirements: request.requirements,
            work_kind: request.work_kind,
            request_reason: request.reason.clone(),
            budget_refusal,
        }
    }

    /// Region whose request was refused.
    #[inline]
    pub const fn owner_region(&self) -> RegionId {
        self.owner_region
    }

    /// Task whose request was refused.
    #[inline]
    pub const fn owner_task(&self) -> TaskId {
        self.owner_task
    }

    /// Parent ticket, if the refusal came from split/lend admission.
    #[inline]
    pub const fn parent_ticket_id(&self) -> Option<CapacityTicketId> {
        self.parent_ticket_id
    }

    /// Budget requested by the refused ticket.
    #[inline]
    pub const fn requested(&self) -> CapabilityBudget {
        self.requested
    }

    /// Required dimensions used for fail-closed validation.
    #[inline]
    pub const fn requirements(&self) -> CapabilityBudgetRequirements {
        self.requirements
    }

    /// Admission surface of the refused request.
    #[inline]
    pub const fn work_kind(&self) -> CapacityTicketWorkKind {
        self.work_kind
    }

    /// Human-readable reason supplied by the caller.
    #[inline]
    pub fn request_reason(&self) -> &str {
        &self.request_reason
    }

    /// Underlying capability-budget planner refusal.
    #[inline]
    pub const fn budget_refusal(&self) -> CapabilityBudgetRefusal {
        self.budget_refusal
    }
}

impl fmt::Display for CapacityTicketRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "capacity ticket refused for {}: {}",
            self.work_kind.as_str(),
            self.budget_refusal
        )
    }
}

impl std::error::Error for CapacityTicketRefusal {}

/// Active admitted capacity ticket.
#[must_use = "capacity tickets must be released, revoked, or audited with unreleased_receipt"]
#[derive(Debug, PartialEq, Eq)]
pub struct CapacityTicket {
    ticket_id: CapacityTicketId,
    parent_ticket_id: Option<CapacityTicketId>,
    owner_region: RegionId,
    owner_task: TaskId,
    granted: CapabilityBudget,
    requirements: CapabilityBudgetRequirements,
    work_kind: CapacityTicketWorkKind,
    reason: String,
    /// Per-parent monotonic child sequence (br-asupersync-audit-followups-
    /// 2026-06-12-7tcipb item 1). Advanced once per successful `split`/`lend_*`
    /// so each derived child folds a distinct nonce into its [`CapacityTicketId`],
    /// keeping sibling tickets unique. Not part of ticket identity — it is mint
    /// bookkeeping carried by the live ticket value.
    next_child_seq: u64,
    terminal_observed: bool,
}

impl CapacityTicket {
    fn admitted(
        owner_region: RegionId,
        owner_task: TaskId,
        ticket_id: CapacityTicketId,
        parent_ticket_id: Option<CapacityTicketId>,
        granted: CapabilityBudget,
        request: CapacityTicketRequest,
    ) -> Self {
        Self {
            ticket_id,
            parent_ticket_id,
            owner_region,
            owner_task,
            granted,
            requirements: request.requirements,
            work_kind: request.work_kind,
            reason: request.reason,
            next_child_seq: 0,
            terminal_observed: false,
        }
    }

    /// Stable ticket identifier.
    #[inline]
    pub const fn id(&self) -> CapacityTicketId {
        self.ticket_id
    }

    /// Parent ticket, if this ticket was split or lent from another ticket.
    #[inline]
    pub const fn parent_id(&self) -> Option<CapacityTicketId> {
        self.parent_ticket_id
    }

    /// Region that owns this ticket.
    #[inline]
    pub const fn owner_region(&self) -> RegionId {
        self.owner_region
    }

    /// Task that owns this ticket.
    #[inline]
    pub const fn owner_task(&self) -> TaskId {
        self.owner_task
    }

    /// Effective admitted capability envelope.
    #[inline]
    pub const fn granted(&self) -> CapabilityBudget {
        self.granted
    }

    /// Required dimensions used at admission.
    #[inline]
    pub const fn requirements(&self) -> CapabilityBudgetRequirements {
        self.requirements
    }

    /// Admission surface this ticket belongs to.
    #[inline]
    pub const fn work_kind(&self) -> CapacityTicketWorkKind {
        self.work_kind
    }

    /// Human-readable reason supplied at admission.
    #[inline]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Splits this ticket for the same owner and work kind.
    ///
    /// Takes `&mut self` (br-asupersync-audit-followups-2026-06-12-7tcipb item 1)
    /// so the parent can advance its per-parent child sequence and mint a child
    /// with a distinct [`CapacityTicketId`] on every call.
    #[inline]
    pub fn split(
        &mut self,
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Result<Self, CapacityTicketRefusal> {
        let work_kind = self.work_kind;
        self.split_for(work_kind, requested, requirements, reason)
    }

    /// Splits this ticket for the same owner and an explicit child work kind.
    pub fn split_for(
        &mut self,
        work_kind: CapacityTicketWorkKind,
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Result<Self, CapacityTicketRefusal> {
        let owner_region = self.owner_region;
        let owner_task = self.owner_task;
        self.derive_child(
            owner_region,
            owner_task,
            CapacityTicketRequest::new(requested, requirements, reason).with_work_kind(work_kind),
        )
    }

    /// Lends a child ticket to another explicit owner with the same work kind.
    #[inline]
    pub fn lend_to(
        &mut self,
        owner_region: RegionId,
        owner_task: TaskId,
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Result<Self, CapacityTicketRefusal> {
        let work_kind = self.work_kind;
        self.lend_to_for(
            owner_region,
            owner_task,
            work_kind,
            requested,
            requirements,
            reason,
        )
    }

    /// Lends a child ticket to another explicit owner and work kind.
    pub fn lend_to_for(
        &mut self,
        owner_region: RegionId,
        owner_task: TaskId,
        work_kind: CapacityTicketWorkKind,
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Result<Self, CapacityTicketRefusal> {
        self.derive_child(
            owner_region,
            owner_task,
            CapacityTicketRequest::new(requested, requirements, reason).with_work_kind(work_kind),
        )
    }

    fn derive_child(
        &mut self,
        owner_region: RegionId,
        owner_task: TaskId,
        request: CapacityTicketRequest,
    ) -> Result<Self, CapacityTicketRefusal> {
        let granted = self
            .granted
            .plan_child(request.requested, request.requirements)
            .map_err(|budget_refusal| {
                CapacityTicketRefusal::new(
                    owner_region,
                    owner_task,
                    Some(self.ticket_id),
                    &request,
                    budget_refusal,
                )
            })?;

        // Advance the per-parent child sequence only after admission succeeds,
        // so a refused split does not perturb the sequence and the next
        // successful split still mints a fresh, distinct nonce.
        self.next_child_seq = self.next_child_seq.saturating_add(1);
        let child_seq = self.next_child_seq;

        Ok(Self::admitted(
            owner_region,
            owner_task,
            self.ticket_id.child(owner_region, owner_task, child_seq),
            Some(self.ticket_id),
            granted,
            request,
        ))
    }

    /// Releases this ticket and returns a leak-free receipt.
    #[inline]
    pub fn release(mut self) -> CapacityTicketReceipt {
        self.terminal_observed = true;
        self.receipt(CapacityTicketReceiptStatus::Released, None, true)
    }

    /// Revokes this ticket and returns a leak-free cancellation receipt.
    #[inline]
    pub fn revoke(mut self, cancel_reason: CancelReason) -> CapacityTicketReceipt {
        self.terminal_observed = true;
        self.receipt(
            CapacityTicketReceiptStatus::Revoked,
            Some(cancel_reason),
            true,
        )
    }

    /// Builds a fail-closed receipt for an active ticket that reached an audit
    /// boundary without release or revocation.
    #[inline]
    pub fn unreleased_receipt(&mut self) -> CapacityTicketReceipt {
        self.terminal_observed = true;
        self.receipt(CapacityTicketReceiptStatus::Unreleased, None, false)
    }

    fn receipt(
        &self,
        status: CapacityTicketReceiptStatus,
        cancel_reason: Option<CancelReason>,
        obligation_leak_free: bool,
    ) -> CapacityTicketReceipt {
        CapacityTicketReceipt {
            ticket_id: self.ticket_id,
            parent_ticket_id: self.parent_ticket_id,
            owner_region: self.owner_region,
            owner_task: self.owner_task,
            status,
            granted: self.granted,
            requirements: self.requirements,
            work_kind: self.work_kind,
            reason: self.reason.clone(),
            cancel_reason,
            obligation_leak_free,
            no_ambient_authority: true,
        }
    }
}

impl Drop for CapacityTicket {
    fn drop(&mut self) {
        debug_assert!(
            self.terminal_observed || std::thread::panicking(),
            "capacity ticket dropped without release, revoke, or unreleased_receipt audit"
        );
    }
}

/// Terminal receipt status for a capacity ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityTicketReceiptStatus {
    /// Ticket was explicitly released.
    Released,
    /// Ticket was explicitly revoked with a cancellation reason.
    Revoked,
    /// Ticket was still active at an audit boundary.
    Unreleased,
}

impl CapacityTicketReceiptStatus {
    /// Stable lower-case identifier for reports.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::Revoked => "revoked",
            Self::Unreleased => "unreleased",
        }
    }
}

/// Explicit terminal receipt for a capacity ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityTicketReceipt {
    /// Ticket ID this receipt closes or audits.
    pub ticket_id: CapacityTicketId,
    /// Parent ticket, if the ticket was split or lent.
    pub parent_ticket_id: Option<CapacityTicketId>,
    /// Region that owned the ticket.
    pub owner_region: RegionId,
    /// Task that owned the ticket.
    pub owner_task: TaskId,
    /// Terminal or audit status.
    pub status: CapacityTicketReceiptStatus,
    /// Effective admitted capability envelope.
    pub granted: CapabilityBudget,
    /// Required dimensions used at admission.
    pub requirements: CapabilityBudgetRequirements,
    /// Admission surface the ticket belonged to.
    pub work_kind: CapacityTicketWorkKind,
    /// Human-readable reason supplied at admission.
    pub reason: String,
    /// Cancellation reason for revoked tickets.
    pub cancel_reason: Option<CancelReason>,
    /// True only when the ticket was explicitly released or revoked.
    pub obligation_leak_free: bool,
    /// Always true: the API is driven by explicit owner IDs and capability budgets.
    pub no_ambient_authority: bool,
}

/// Requests a capacity ticket from an existing capability context.
#[inline]
pub fn request_capacity_ticket<Caps>(
    cx: &Cx<Caps>,
    admission_sequence: NonZeroU64,
    request: CapacityTicketRequest,
) -> Result<CapacityTicket, CapacityTicketRefusal> {
    let owner_region = cx.region_id();
    let owner_task = cx.task_id();
    let granted = cx
        .plan_child_capability_budget(request.requested, request.requirements)
        .map_err(|budget_refusal| {
            CapacityTicketRefusal::new(owner_region, owner_task, None, &request, budget_refusal)
        })?;

    Ok(CapacityTicket::admitted(
        owner_region,
        owner_task,
        CapacityTicketId::root(owner_region, owner_task, admission_sequence),
        None,
        granted,
        request,
    ))
}

/// Requests a capacity ticket from explicit owner IDs and a parent budget.
///
/// This is useful for deterministic contract tests and operator fixtures that
/// already have a captured budget envelope but are intentionally not allowed to
/// construct or look up a live `Cx`.
pub fn request_capacity_ticket_from_budget(
    owner_region: RegionId,
    owner_task: TaskId,
    admission_sequence: NonZeroU64,
    parent_budget: CapabilityBudget,
    request: CapacityTicketRequest,
) -> Result<CapacityTicket, CapacityTicketRefusal> {
    let granted = parent_budget
        .plan_child(request.requested, request.requirements)
        .map_err(|budget_refusal| {
            CapacityTicketRefusal::new(owner_region, owner_task, None, &request, budget_refusal)
        })?;

    Ok(CapacityTicket::admitted(
        owner_region,
        owner_task,
        CapacityTicketId::root(owner_region, owner_task, admission_sequence),
        None,
        granted,
        request,
    ))
}

#[cfg(test)]
#[path = "capacity_ticket_inline_tests.rs"]
mod tests;
