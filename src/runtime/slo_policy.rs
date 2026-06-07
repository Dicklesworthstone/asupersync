//! Explicit runtime bridge for SLO policy admission decisions.
//!
//! The SLO artifact layer lives in [`crate::types::slo_policy`]. This module
//! is the runtime-facing seam: callers pass a concrete [`Cx`] and an explicit
//! work kind, then receive the admission/brownout/no-win decision plus the
//! runtime budget projection that should guard admitted work.

use crate::cx::Cx;
use crate::types::{
    Budget, SloRuntimeAdmissionOutcome, SloRuntimeAdmissionRequest, SloRuntimeAdmissionStatus,
    SloRuntimePolicyApplication,
};

/// Runtime work category evaluated by the SLO bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SloRuntimeWorkKind {
    /// Required user-visible or core runtime work.
    Required,
    /// Optional work that may brown out under soft pressure.
    Optional,
    /// Cleanup and finalizer work that must preserve drain/quiescence semantics.
    CleanupFinalizer,
    /// Proof, report, and evidence work attached to the SLO gate.
    ProofReporting,
}

impl SloRuntimeWorkKind {
    /// Stable label used by runtime evidence and contract tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::CleanupFinalizer => "cleanup_finalizer",
            Self::ProofReporting => "proof_reporting",
        }
    }

    /// Return true when this kind should be evaluated through optional-work brownout rules.
    #[must_use]
    pub const fn uses_optional_work_class(self) -> bool {
        matches!(self, Self::Optional)
    }
}

/// A single Cx-scoped SLO admission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SloRuntimePolicyBridgeRequest {
    /// Runtime work category for this admission decision.
    pub work_kind: SloRuntimeWorkKind,
    /// Existing artifact-backed admission request.
    pub admission: SloRuntimeAdmissionRequest,
}

impl SloRuntimePolicyBridgeRequest {
    /// Build a request from an explicit work kind and admission payload.
    #[must_use]
    pub const fn new(work_kind: SloRuntimeWorkKind, admission: SloRuntimeAdmissionRequest) -> Self {
        Self {
            work_kind,
            admission,
        }
    }

    /// Build a required-work request.
    #[must_use]
    pub const fn required(admission: SloRuntimeAdmissionRequest) -> Self {
        Self::new(SloRuntimeWorkKind::Required, admission)
    }

    /// Build an optional-work request.
    #[must_use]
    pub const fn optional(admission: SloRuntimeAdmissionRequest) -> Self {
        Self::new(SloRuntimeWorkKind::Optional, admission)
    }

    /// Build a cleanup/finalizer request.
    #[must_use]
    pub const fn cleanup_finalizer(admission: SloRuntimeAdmissionRequest) -> Self {
        Self::new(SloRuntimeWorkKind::CleanupFinalizer, admission)
    }

    /// Build a proof/reporting request.
    #[must_use]
    pub const fn proof_reporting(admission: SloRuntimeAdmissionRequest) -> Self {
        Self::new(SloRuntimeWorkKind::ProofReporting, admission)
    }

    fn normalized_for_cx<Caps>(&self, cx: &Cx<Caps>) -> SloRuntimeAdmissionRequest {
        let mut admission = self.admission.clone();
        admission.cancel_requested |= cx.is_cancel_requested();
        if !self.work_kind.uses_optional_work_class() {
            admission.optional_work_class = None;
        }
        admission
    }
}

/// Runtime result produced by the Cx-scoped SLO bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SloRuntimePolicyBridgeDecision {
    /// Runtime work category that was evaluated.
    pub work_kind: SloRuntimeWorkKind,
    /// Artifact-backed admission outcome.
    pub outcome: SloRuntimeAdmissionOutcome,
    /// Runtime budget projected from the compiled SLO policy.
    pub runtime_budget: Budget,
    /// True only when this work is admitted and may begin.
    pub work_may_start: bool,
    /// True when the passed Cx was already cancelled at admission time.
    pub cx_cancel_observed: bool,
    /// True when denied work must preserve an explicit non-start/drain receipt.
    pub explicit_receipt_required: bool,
    /// Region close remains quiescence-bound for every bridge decision.
    pub region_close_requires_quiescence: bool,
}

impl SloRuntimePolicyBridgeDecision {
    fn from_outcome(
        work_kind: SloRuntimeWorkKind,
        outcome: SloRuntimeAdmissionOutcome,
        cx_cancel_observed: bool,
    ) -> Self {
        let work_may_start = outcome.status == SloRuntimeAdmissionStatus::Admitted;
        let runtime_budget = outcome.budget.to_budget();
        Self {
            work_kind,
            outcome,
            runtime_budget,
            work_may_start,
            cx_cancel_observed,
            explicit_receipt_required: !work_may_start,
            region_close_requires_quiescence: true,
        }
    }

    /// Return true when optional work was explicitly browned out.
    #[must_use]
    pub fn optional_work_browned_out(&self) -> bool {
        self.work_kind == SloRuntimeWorkKind::Optional
            && self.outcome.status == SloRuntimeAdmissionStatus::Brownout
    }

    /// Return true when the decision is a no-win fallback receipt.
    #[must_use]
    pub fn no_win_fallback_selected(&self) -> bool {
        self.outcome.status == SloRuntimeAdmissionStatus::NoWin
    }
}

/// Borrowed runtime bridge over a compiled SLO policy application.
#[derive(Debug, Clone, Copy)]
pub struct SloRuntimePolicyBridge<'a> {
    application: &'a SloRuntimePolicyApplication,
}

impl<'a> SloRuntimePolicyBridge<'a> {
    /// Build a bridge from the explicit runtime policy application.
    #[must_use]
    pub const fn new(application: &'a SloRuntimePolicyApplication) -> Self {
        Self { application }
    }

    /// Return the policy application backing this bridge.
    #[must_use]
    pub const fn application(&self) -> &'a SloRuntimePolicyApplication {
        self.application
    }

    /// Evaluate an admission request against the passed Cx and policy application.
    ///
    /// Cancellation is observed from the Cx at the boundary and folded into the
    /// artifact-backed admission request. Optional work is the only work kind
    /// that carries an optional work class into brownout evaluation; required,
    /// cleanup/finalizer, and proof/reporting work use the required-work path.
    #[must_use]
    pub fn evaluate<Caps>(
        &self,
        cx: &Cx<Caps>,
        request: &SloRuntimePolicyBridgeRequest,
    ) -> SloRuntimePolicyBridgeDecision {
        let cx_cancel_observed = cx.is_cancel_requested();
        let admission = request.normalized_for_cx(cx);
        let outcome = self.application.evaluate_admission(&admission);
        SloRuntimePolicyBridgeDecision::from_outcome(request.work_kind, outcome, cx_cancel_observed)
    }
}
