//! Explicit runtime bridge for SLO policy admission decisions.
//!
//! The SLO artifact layer lives in [`crate::types::slo_policy`]. This module
//! is the runtime-facing seam: callers pass a concrete [`Cx`] and an explicit
//! work kind, then receive the admission/brownout/no-win decision plus the
//! runtime budget projection that should guard admitted work. The fourth-wave
//! governor bridge stays opt-in by requiring a replayable decision receipt at
//! the call boundary; evaluating the pure governor alone never mutates runtime
//! admission behavior.

use crate::cx::Cx;
use crate::observability::swarm_pressure_governor::{
    FourthWaveGovernorAction, FourthWaveGovernorDecisionReceipt,
};
use crate::types::{
    Budget, SloRuntimeAdmissionIssueKind, SloRuntimeAdmissionOutcome, SloRuntimeAdmissionRequest,
    SloRuntimeAdmissionStatus, SloRuntimeOptionalWorkDecision, SloRuntimePolicyApplication,
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

/// Runtime decision produced by the explicit fourth-wave bridge adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourthWaveRuntimeBridgeDecision {
    /// Cx-scoped SLO runtime decision after applying the fourth-wave receipt.
    pub runtime_decision: SloRuntimePolicyBridgeDecision,
    /// Fourth-wave decision id copied from the replayable receipt.
    pub fourth_wave_decision_id: String,
    /// Fourth-wave snapshot id copied from the replayable receipt.
    pub fourth_wave_snapshot_id: String,
    /// Fourth-wave selected rule id.
    pub fourth_wave_rule_id: &'static str,
    /// Fourth-wave selected action.
    pub selected_action: FourthWaveGovernorAction,
    /// Redacted rollback, delay, brownout, or non-start reason.
    pub rollback_reason: Option<String>,
    /// True because this adapter is only reached through the explicit opt-in method.
    pub opt_in_bridge_enabled: bool,
    /// True when runtime work is delayed because remote-required proof work had no worker.
    pub delay_required: bool,
    /// True when the bridge deliberately falls back to observe-only/non-start behavior.
    pub rollback_to_observe_only: bool,
    /// Obligation cleanup remains required for every adapter decision.
    pub obligation_cleanup_required: bool,
    /// Runtime receipts must stay redacted before operator logging.
    pub receipt_redaction_required: bool,
    /// Claim boundaries carried by the adapter receipt.
    pub non_claims: Vec<&'static str>,
}

impl FourthWaveRuntimeBridgeDecision {
    /// Return true when runtime work may start.
    #[must_use]
    pub const fn work_may_start(&self) -> bool {
        self.runtime_decision.work_may_start
    }

    /// Return true when a non-start/drain receipt must be preserved.
    #[must_use]
    pub const fn explicit_receipt_required(&self) -> bool {
        self.runtime_decision.explicit_receipt_required
    }

    /// Return true when the fourth-wave receipt selected a fail-closed action.
    #[must_use]
    pub const fn fail_closed(&self) -> bool {
        self.selected_action.fail_closed()
    }

    /// Return true when the adapter selected a rollback/delay/non-start path.
    #[must_use]
    pub fn rollback_required(&self) -> bool {
        self.rollback_reason.is_some() || self.rollback_to_observe_only
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

    /// Apply a fourth-wave governor receipt to an explicit runtime admission request.
    ///
    /// This method is the opt-in control seam for the fourth-wave governor. It
    /// still starts by evaluating the normal SLO bridge through the passed
    /// [`Cx`]. The fourth-wave receipt can only narrow behavior: optional work
    /// may brown out, remote-required work may be delayed with a no-win receipt,
    /// and unsupported/malformed/stale/local-fallback evidence fails closed
    /// before work starts. Cancellation observed at the `Cx` boundary preempts
    /// every fourth-wave action.
    #[must_use]
    pub fn evaluate_fourth_wave<Caps>(
        &self,
        cx: &Cx<Caps>,
        request: &SloRuntimePolicyBridgeRequest,
        receipt: &FourthWaveGovernorDecisionReceipt,
    ) -> FourthWaveRuntimeBridgeDecision {
        let base = self.evaluate(cx, request);
        let (runtime_decision, rollback_reason, delay_required, rollback_to_observe_only) =
            if base.cx_cancel_observed {
                (
                    base,
                    Some("cx-cancelled-before-start".to_string()),
                    false,
                    true,
                )
            } else {
                Self::apply_fourth_wave_action(base, request, receipt)
            };

        FourthWaveRuntimeBridgeDecision {
            runtime_decision,
            fourth_wave_decision_id: receipt.decision_id.clone(),
            fourth_wave_snapshot_id: receipt.snapshot_id.clone(),
            fourth_wave_rule_id: receipt.rule_id,
            selected_action: receipt.selected_action,
            rollback_reason,
            opt_in_bridge_enabled: true,
            delay_required,
            rollback_to_observe_only,
            obligation_cleanup_required: true,
            receipt_redaction_required: true,
            non_claims: fourth_wave_runtime_non_claims(receipt),
        }
    }

    fn apply_fourth_wave_action(
        base: SloRuntimePolicyBridgeDecision,
        request: &SloRuntimePolicyBridgeRequest,
        receipt: &FourthWaveGovernorDecisionReceipt,
    ) -> (SloRuntimePolicyBridgeDecision, Option<String>, bool, bool) {
        match receipt.selected_action {
            FourthWaveGovernorAction::AdmitRequiredWork => (base, None, false, false),
            FourthWaveGovernorAction::BrownoutOptionalWork
                if request.work_kind.uses_optional_work_class() =>
            {
                let reason = fourth_wave_runtime_reason(receipt)
                    .unwrap_or_else(|| "fourth-wave optional brownout".to_string());
                (force_fourth_wave_brownout(base), Some(reason), false, true)
            }
            FourthWaveGovernorAction::BrownoutOptionalWork => (base, None, false, false),
            FourthWaveGovernorAction::DeferNoRemoteWorker => {
                let reason = fourth_wave_runtime_reason(receipt).unwrap_or_else(|| {
                    "remote-required lane has no admissible remote worker".to_string()
                });
                (
                    force_fourth_wave_no_win(base, reason.clone()),
                    Some(reason),
                    true,
                    true,
                )
            }
            FourthWaveGovernorAction::FailClosedAdvisoryOnly
            | FourthWaveGovernorAction::FailClosedLocalRchFallback
            | FourthWaveGovernorAction::FailClosedMalformedInput
            | FourthWaveGovernorAction::FailClosedMissingEvidence
            | FourthWaveGovernorAction::FailClosedStaleEvidence => {
                let reason = fourth_wave_runtime_reason(receipt)
                    .unwrap_or_else(|| receipt.selected_action.as_str().to_string());
                (
                    force_fourth_wave_blocked(base, reason.clone()),
                    Some(reason),
                    false,
                    true,
                )
            }
        }
    }
}

fn force_fourth_wave_brownout(
    mut decision: SloRuntimePolicyBridgeDecision,
) -> SloRuntimePolicyBridgeDecision {
    force_fourth_wave_non_start(
        &mut decision,
        SloRuntimeAdmissionStatus::Brownout,
        Some(SloRuntimeOptionalWorkDecision::Brownout),
        None,
        vec![SloRuntimeAdmissionIssueKind::OptionalWorkBrownout],
    );
    decision
}

fn force_fourth_wave_no_win(
    mut decision: SloRuntimePolicyBridgeDecision,
    reason: String,
) -> SloRuntimePolicyBridgeDecision {
    force_fourth_wave_non_start(
        &mut decision,
        SloRuntimeAdmissionStatus::NoWin,
        None,
        Some(reason),
        vec![SloRuntimeAdmissionIssueKind::NoWinFallback],
    );
    decision
}

fn force_fourth_wave_blocked(
    mut decision: SloRuntimePolicyBridgeDecision,
    reason: String,
) -> SloRuntimePolicyBridgeDecision {
    force_fourth_wave_non_start(
        &mut decision,
        SloRuntimeAdmissionStatus::Blocked,
        None,
        Some(reason),
        vec![SloRuntimeAdmissionIssueKind::ApplicationInvalid],
    );
    decision
}

fn force_fourth_wave_non_start(
    decision: &mut SloRuntimePolicyBridgeDecision,
    status: SloRuntimeAdmissionStatus,
    optional_work_decision: Option<SloRuntimeOptionalWorkDecision>,
    fallback_reason: Option<String>,
    issue_kinds: Vec<SloRuntimeAdmissionIssueKind>,
) {
    let total_work_units = decision
        .outcome
        .admitted_work_units
        .saturating_add(decision.outcome.rejected_work_units);
    decision.outcome.status = status;
    decision.outcome.optional_work_decision = optional_work_decision;
    decision.outcome.fallback_reason = fallback_reason;
    decision.outcome.admitted_work_units = 0;
    decision.outcome.rejected_work_units = total_work_units;
    decision.outcome.issue_kinds = issue_kinds;
    decision.work_may_start = false;
    decision.explicit_receipt_required = true;
    decision.region_close_requires_quiescence = true;
}

fn fourth_wave_runtime_reason(receipt: &FourthWaveGovernorDecisionReceipt) -> Option<String> {
    let reason = receipt.non_action_reason.trim();
    if reason.is_empty() {
        None
    } else {
        Some(redact_secret_like_reason(reason))
    }
}

fn redact_secret_like_reason(reason: &str) -> String {
    const SECRET_LIKE_REASON_MARKERS: [&str; 6] = [
        "authorization",
        "bearer",
        "password",
        "secret",
        "token",
        "api_key",
    ];
    let lower = reason.to_ascii_lowercase();
    if SECRET_LIKE_REASON_MARKERS
        .iter()
        .any(|marker| lower.contains(*marker))
    {
        "<redacted>".to_string()
    } else {
        reason.to_string()
    }
}

fn fourth_wave_runtime_non_claims(
    receipt: &FourthWaveGovernorDecisionReceipt,
) -> Vec<&'static str> {
    let mut non_claims = receipt.non_claims.clone();
    for claim in [
        "explicit opt-in runtime bridge only",
        "not production-on-by-default",
        "region close still requires quiescence",
        "obligation cleanup still required",
    ] {
        if !non_claims.contains(&claim) {
            non_claims.push(claim);
        }
    }
    non_claims
}
