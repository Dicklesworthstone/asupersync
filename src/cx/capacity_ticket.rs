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

/// Stable ticket identifier derived from explicit owner IDs and child lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityTicketId {
    owner_region: RegionId,
    owner_task: TaskId,
    lineage: u64,
}

impl CapacityTicketId {
    #[inline]
    const fn root(owner_region: RegionId, owner_task: TaskId) -> Self {
        Self {
            owner_region,
            owner_task,
            lineage: 0,
        }
    }

    #[inline]
    const fn child(self, owner_region: RegionId, owner_task: TaskId) -> Self {
        Self {
            owner_region,
            owner_task,
            lineage: self.lineage.saturating_add(1),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityTicket {
    ticket_id: CapacityTicketId,
    parent_ticket_id: Option<CapacityTicketId>,
    owner_region: RegionId,
    owner_task: TaskId,
    granted: CapabilityBudget,
    requirements: CapabilityBudgetRequirements,
    work_kind: CapacityTicketWorkKind,
    reason: String,
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
    #[inline]
    pub fn split(
        &self,
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Result<Self, CapacityTicketRefusal> {
        self.split_for(self.work_kind, requested, requirements, reason)
    }

    /// Splits this ticket for the same owner and an explicit child work kind.
    pub fn split_for(
        &self,
        work_kind: CapacityTicketWorkKind,
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Result<Self, CapacityTicketRefusal> {
        self.derive_child(
            self.owner_region,
            self.owner_task,
            CapacityTicketRequest::new(requested, requirements, reason).with_work_kind(work_kind),
        )
    }

    /// Lends a child ticket to another explicit owner with the same work kind.
    #[inline]
    pub fn lend_to(
        &self,
        owner_region: RegionId,
        owner_task: TaskId,
        requested: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        reason: impl Into<String>,
    ) -> Result<Self, CapacityTicketRefusal> {
        self.lend_to_for(
            owner_region,
            owner_task,
            self.work_kind,
            requested,
            requirements,
            reason,
        )
    }

    /// Lends a child ticket to another explicit owner and work kind.
    pub fn lend_to_for(
        &self,
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
        &self,
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

        Ok(Self::admitted(
            owner_region,
            owner_task,
            self.ticket_id.child(owner_region, owner_task),
            Some(self.ticket_id),
            granted,
            request,
        ))
    }

    /// Releases this ticket and returns a leak-free receipt.
    #[inline]
    pub fn release(self) -> CapacityTicketReceipt {
        self.receipt(CapacityTicketReceiptStatus::Released, None, true)
    }

    /// Revokes this ticket and returns a leak-free cancellation receipt.
    #[inline]
    pub fn revoke(self, cancel_reason: CancelReason) -> CapacityTicketReceipt {
        self.receipt(
            CapacityTicketReceiptStatus::Revoked,
            Some(cancel_reason),
            true,
        )
    }

    /// Builds a fail-closed receipt for an active ticket that reached an audit
    /// boundary without release or revocation.
    #[inline]
    pub fn unreleased_receipt(&self) -> CapacityTicketReceipt {
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
        CapacityTicketId::root(owner_region, owner_task),
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
        CapacityTicketId::root(owner_region, owner_task),
        None,
        granted,
        request,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        CapacityTicketReceiptStatus, CapacityTicketRequest, CapacityTicketWorkKind,
        request_capacity_ticket, request_capacity_ticket_from_budget,
    };
    use crate::types::{
        Budget, CancelKind, CancelReason, CapabilityBudget, CapabilityBudgetDimension,
        CapabilityBudgetRefusal, CapabilityBudgetRequirements, RegionId, TaskId,
    };

    #[test]
    fn cx_ticket_admission_uses_context_owner_and_fail_closed_requirements() {
        let cx = crate::cx::Cx::for_testing();
        let request = CapacityTicketRequest::agent_swarm_admission(
            CapabilityBudget::new()
                .with_memory_bytes(1024)
                .with_cpu_units(4)
                .with_artifact_bytes(256),
            "swarm admission",
        );

        let ticket = request_capacity_ticket(&cx, request).expect("ticket admits");

        assert_eq!(ticket.owner_region(), cx.region_id());
        assert_eq!(ticket.owner_task(), cx.task_id());
        assert_eq!(ticket.id().lineage(), 0);
        assert_eq!(
            ticket.work_kind(),
            CapacityTicketWorkKind::AgentSwarmAdmission
        );

        let err = request_capacity_ticket(
            &cx,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_cpu_units(4)
                    .with_artifact_bytes(256),
                "missing memory",
            ),
        )
        .expect_err("missing required memory fails closed");
        assert_eq!(
            err.budget_refusal(),
            CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::MemoryBytes)
        );
    }

    #[test]
    fn split_and_lend_inherit_parent_budget_and_keep_explicit_owner() {
        let owner_region = RegionId::new_for_test(7, 1);
        let owner_task = TaskId::new_for_test(7, 0);
        let parent = request_capacity_ticket_from_budget(
            owner_region,
            owner_task,
            CapabilityBudget::UNSPECIFIED,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(4096)
                    .with_cpu_units(8)
                    .with_artifact_bytes(512),
                "root",
            ),
        )
        .expect("parent admits");

        let split = parent
            .split(
                CapabilityBudget::new()
                    .with_memory_bytes(8192)
                    .with_cpu_units(2)
                    .with_artifact_bytes(128),
                CapabilityBudgetRequirements::new()
                    .require_memory_bytes()
                    .require_cpu_units()
                    .require_artifact_bytes(),
                "split child",
            )
            .expect("split tightens by meet");
        assert_eq!(split.granted().memory_bytes, Some(4096));
        assert_eq!(split.granted().cpu_units, Some(2));
        assert_eq!(split.granted().artifact_bytes, Some(128));
        assert_eq!(split.parent_id(), Some(parent.id()));
        assert_eq!(split.owner_region(), owner_region);

        let borrower_region = RegionId::new_for_test(8, 1);
        let borrower_task = TaskId::new_for_test(8, 0);
        let lent = parent
            .lend_to_for(
                borrower_region,
                borrower_task,
                CapacityTicketWorkKind::ProofArtifact,
                CapabilityBudget::new()
                    .with_memory_bytes(2048)
                    .with_cpu_units(1)
                    .with_artifact_bytes(256)
                    .with_cleanup_budget(Budget::MINIMAL),
                CapabilityBudgetRequirements::new()
                    .require_memory_bytes()
                    .require_cpu_units()
                    .require_artifact_bytes()
                    .require_cleanup(),
                "borrowed proof",
            )
            .expect("lend admits under parent");
        assert_eq!(lent.owner_region(), borrower_region);
        assert_eq!(lent.owner_task(), borrower_task);
        assert_eq!(lent.parent_id(), Some(parent.id()));
        assert_eq!(lent.work_kind(), CapacityTicketWorkKind::ProofArtifact);
    }

    #[test]
    fn receipts_distinguish_release_revoke_and_unreleased_audit() {
        let ticket = request_capacity_ticket_from_budget(
            RegionId::new_for_test(9, 1),
            TaskId::new_for_test(9, 0),
            CapabilityBudget::UNSPECIFIED,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(1024)
                    .with_cpu_units(1)
                    .with_artifact_bytes(64),
                "receipt",
            ),
        )
        .expect("ticket admits");

        let audit = ticket.unreleased_receipt();
        assert_eq!(audit.status, CapacityTicketReceiptStatus::Unreleased);
        assert!(!audit.obligation_leak_free);
        assert!(audit.no_ambient_authority);

        let released = ticket.clone().release();
        assert_eq!(released.status, CapacityTicketReceiptStatus::Released);
        assert!(released.obligation_leak_free);
        assert!(released.cancel_reason.is_none());

        let revoked = ticket.revoke(CancelReason::new(CancelKind::User));
        assert_eq!(revoked.status, CapacityTicketReceiptStatus::Revoked);
        assert!(revoked.obligation_leak_free);
        assert_eq!(
            revoked.cancel_reason.as_ref().map(|reason| reason.kind),
            Some(CancelKind::User)
        );
    }
}
