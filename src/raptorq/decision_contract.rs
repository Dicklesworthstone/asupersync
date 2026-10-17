//! Concrete G7 decision contract for RaptorQ runtime governance.
//!
//! This module turns the artifact-only G7 contract into a live runtime policy
//! that can evaluate decoder pressure signals and emit deterministic telemetry
//! for rollout/hold/rollback/fallback decisions.

use std::fmt;
use std::hash::{Hash, Hasher};

use franken_decision::{
    DecisionContract, EvalContext, FallbackPolicy, LossMatrix, Posterior, ValidationError, evaluate,
};
use franken_kernel::{DecisionId, TraceId};

use crate::util::DetHasher;

/// Replay pointer for runtime G7 decisions.
pub const G7_DECISION_REPLAY_REF: &str = "replay:rq-track-g-expected-loss-v1";

const PERMILLE_SCALE: u32 = 1000;
const HEALTHY_FLOOR: u32 = 20;
const MODE_MARGIN_CAP: u32 = 400;
const ACTION_MARGIN_CAP: u32 = 200;
const FALLBACK_REASON_POLICY_BUDGET_EXHAUSTED: &str = "policy_budget_exhausted";
const FALLBACK_REASON_UNKNOWN_LOW_CONFIDENCE: &str = "unknown_state_with_low_confidence";
const FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE: &str = "regression_state_with_low_confidence";
const FALLBACK_REASON_UNCLASSIFIED: &str = "conservative_fallback_reason_unclassified";
const MALFORMED_POSTERIOR_CONFIDENCE: u16 = 0;
const MALFORMED_POSTERIOR_UNCERTAINTY: u16 = 1000;
const MALFORMED_POSTERIOR_EXPECTED_LOSS_TERMS: [u32; action::COUNT] =
    [u32::MAX, u32::MAX, u32::MAX, 0];

/// Canonical fallback reasons the live G7 runtime can emit when fallback is active.
///
/// The broader artifact contract may list additional hard-trigger reasons owned by
/// downstream decode/replay validation surfaces. This list is intentionally narrower:
/// it describes only the reasons surfaced by [`GovernanceTelemetry`] today.
pub const G7_RUNTIME_FALLBACK_REASONS: &[&str] = &[
    FALLBACK_REASON_POLICY_BUDGET_EXHAUSTED,
    FALLBACK_REASON_UNKNOWN_LOW_CONFIDENCE,
    FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE,
    FALLBACK_REASON_UNCLASSIFIED,
];

/// State indices into the posterior.
pub mod state {
    /// Runtime signals are nominal and consistent with approved behavior.
    pub const HEALTHY: usize = 0;
    /// Runtime is still coherent but under material pressure.
    pub const DEGRADED: usize = 1;
    /// Runtime signals indicate likely regression or rollback conditions.
    pub const REGRESSION: usize = 2;
    /// Runtime signals are too ambiguous or conflict-heavy for promotion.
    pub const UNKNOWN: usize = 3;
    /// Total number of states.
    pub const COUNT: usize = 4;
}

/// Action indices.
pub mod action {
    /// Continue the currently selected optimized path.
    pub const CONTINUE: usize = 0;
    /// Hold rollout to a safer optimized path while collecting evidence.
    pub const CANARY_HOLD: usize = 1;
    /// Revert to the conservative approved comparator.
    pub const ROLLBACK: usize = 2;
    /// Force deterministic conservative fallback immediately.
    pub const FALLBACK: usize = 3;
    /// Total number of actions.
    pub const COUNT: usize = 4;
}

/// Fixed-width contributor used in runtime decision telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceEvidenceContributor {
    /// Canonical contributor name from the G7 artifact.
    pub name: &'static str,
    /// Relative weight in permille among the surfaced top contributors.
    pub contribution_permille: u16,
}

/// Deterministic runtime output for a single G7 decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceTelemetry {
    /// Unique deterministic identifier for this governance decision.
    pub decision_id: DecisionId,
    /// Trace identifier for correlating the decision with replay evidence.
    pub trace_id: TraceId,
    /// Posterior over G7 states in permille order `[healthy, degraded, regression, unknown]`.
    pub state_posterior_permille: [u16; state::COUNT],
    /// Expected-loss terms for actions `[continue, canary_hold, rollback, fallback]`.
    pub expected_loss_terms: [u32; action::COUNT],
    /// Action chosen by the live contract.
    pub chosen_action: &'static str,
    /// Confidence score in the canonical 0..=1000 range.
    pub confidence_score: u16,
    /// Uncertainty score in the canonical 0..=1000 range.
    pub uncertainty_score: u16,
    /// Whether the deterministic fallback trigger fired.
    pub deterministic_fallback_triggered: bool,
    /// Canonical reason for the fallback trigger, or `"none"`.
    pub deterministic_fallback_reason: &'static str,
    /// Canonical replay pointer for this runtime decision surface.
    pub replay_ref: &'static str,
    /// Top evidence contributors surfaced with deterministic tie-breaking.
    pub top_evidence_contributors: [GovernanceEvidenceContributor; 3],
}

/// Runtime inputs that feed the G7 governance contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GovernanceSnapshot {
    /// Dense-core row count at decision time.
    pub n_rows: usize,
    /// Dense-core column count at decision time.
    pub n_cols: usize,
    /// Dense-core density in permille.
    pub density_permille: usize,
    /// Rank-deficit pressure in permille.
    pub rank_deficit_permille: usize,
    /// Inactivation pressure in permille.
    pub inactivation_pressure_permille: usize,
    /// Row/column overhead ratio in permille.
    pub overhead_ratio_permille: usize,
    /// Whether feature extraction exhausted its strict budget.
    pub budget_exhausted: bool,
    /// Low-level conservative baseline loss.
    pub baseline_loss: u32,
    /// Low-level high-support loss.
    pub high_support_loss: u32,
    /// Low-level block-schur loss, or `u32::MAX` when unavailable.
    pub block_schur_loss: u32,
}

/// Live concrete G7 decision contract.
#[derive(Debug, Clone)]
pub struct RaptorQDecisionContract {
    states: Vec<String>,
    actions: Vec<String>,
    losses: LossMatrix,
    fallback: FallbackPolicy,
}

impl RaptorQDecisionContract {
    #[rustfmt::skip]
    const DEFAULT_LOSSES: [f64; 16] = [
        //                  continue  canary_hold  rollback  fallback
        /* healthy     */   10.0,     25.0,        90.0,     120.0,
        /* degraded    */   80.0,     35.0,        45.0,      50.0,
        /* regression  */  220.0,    120.0,        30.0,      20.0,
        /* unknown     */  170.0,     95.0,        55.0,      35.0,
    ];

    /// Build the canonical G7 decision contract.
    #[must_use]
    pub fn new() -> Self {
        let states = vec![
            "healthy".into(),
            "degraded".into(),
            "regression".into(),
            "unknown".into(),
        ];
        let actions = vec![
            "continue".into(),
            "canary_hold".into(),
            "rollback".into(),
            "fallback".into(),
        ];
        let losses = LossMatrix::new(
            states.clone(),
            actions.clone(),
            Self::DEFAULT_LOSSES.to_vec(),
        )
        .expect("RaptorQ G7 loss matrix should be valid");
        let fallback = FallbackPolicy::new(0.26, 2.1, 0.82)
            .expect("RaptorQ G7 fallback policy should be valid");
        Self {
            states,
            actions,
            losses,
            fallback,
        }
    }

    /// Compute the canonical G7 posterior in permille form.
    #[must_use]
    pub fn state_posterior_permille(snapshot: &GovernanceSnapshot) -> [u16; state::COUNT] {
        let density = clamp_permille(snapshot.density_permille);
        let rank = clamp_permille(snapshot.rank_deficit_permille);
        let inactivation = clamp_permille(snapshot.inactivation_pressure_permille);
        let overhead = clamp_permille(snapshot.overhead_ratio_permille);
        let conflict = policy_conflict_permille(snapshot);

        let budget_penalty = if snapshot.budget_exhausted { 400 } else { 0 };
        let healthy_penalty = density / 2
            + rank * 7 / 10
            + inactivation * 6 / 10
            + overhead * 4 / 10
            + budget_penalty;
        let healthy = HEALTHY_FLOOR.max(PERMILLE_SCALE.saturating_sub(healthy_penalty));
        let degraded =
            100 + density * 9 / 20 + inactivation * 7 / 20 + overhead / 4 + u32::from(conflict) / 5;
        let regression = 40
            + rank * 13 / 20
            + inactivation / 4
            + density * 3 / 20
            + if snapshot.budget_exhausted { 350 } else { 0 };
        let unknown = 20
            + u32::from(conflict) * 9 / 20
            + if snapshot.budget_exhausted { 420 } else { 0 }
            + if snapshot.block_schur_loss == u32::MAX {
                60
            } else {
                0
            };

        normalize_permille([healthy, degraded, regression, unknown])
    }

    /// Evaluate a runtime snapshot and return deterministic G7 telemetry.
    #[must_use]
    pub fn telemetry(&self, snapshot: &GovernanceSnapshot) -> GovernanceTelemetry {
        let posterior_permille = Self::state_posterior_permille(snapshot);
        let posterior = match posterior_from_permille(posterior_permille) {
            Ok(posterior) => posterior,
            Err(error) => {
                return Self::malformed_posterior_fallback_telemetry(
                    snapshot,
                    posterior_permille,
                    &error,
                );
            }
        };
        let expected_loss_terms = expected_loss_terms(&self.losses, &posterior);

        let concentration_score = concentration_score(posterior_permille);
        let action_margin_score = action_margin_score(expected_loss_terms);
        let preliminary_confidence = (((u32::from(concentration_score) * 7)
            + (u32::from(action_margin_score) * 3))
            / 10) as u16;
        let fallback_reason =
            deterministic_fallback_reason(snapshot, posterior_permille, preliminary_confidence);
        let clamped_fallback_confidence = preliminary_confidence.min(250);
        let clamped_fallback_uncertainty = 1000u16.saturating_sub(clamped_fallback_confidence);
        let confidence_score = if fallback_reason == "none" {
            preliminary_confidence
        } else {
            clamped_fallback_confidence
        };
        let uncertainty_score = 1000u16.saturating_sub(confidence_score);
        let ctx = eval_context(snapshot, confidence_score, uncertainty_score);
        // br-asupersync-g1pzep: evaluate now returns Result; for the
        // RaptorQ contract we control the action_set so this should
        // never produce ActionIndexOutOfRange in practice. On error we
        // fall back to the conservative FALLBACK action and emit a
        // canonical-registered reason so safety gates that key on
        // (chosen_action == "fallback" && deterministic_fallback_triggered)
        // engage as designed and is_runtime_fallback_reason returns true.
        // br-asupersync-dezwpc: previously emitted action::CONTINUE +
        // unregistered reason "contract_action_out_of_range" — fail-open
        // on contract evaluation error and broke G7 reason invariant.
        let outcome = match evaluate(self, &posterior, &ctx) {
            Ok(o) => o,
            Err(_) => {
                return GovernanceTelemetry {
                    decision_id: ctx.decision_id,
                    trace_id: ctx.trace_id,
                    state_posterior_permille: posterior_permille,
                    expected_loss_terms,
                    chosen_action: action_label(action::FALLBACK),
                    confidence_score: clamped_fallback_confidence,
                    uncertainty_score: clamped_fallback_uncertainty,
                    deterministic_fallback_triggered: true,
                    deterministic_fallback_reason: FALLBACK_REASON_UNCLASSIFIED,
                    replay_ref: G7_DECISION_REPLAY_REF,
                    top_evidence_contributors: top_evidence_contributors(snapshot),
                };
            }
        };

        let (confidence_score, uncertainty_score) =
            if outcome.fallback_active && fallback_reason == "none" {
                (clamped_fallback_confidence, clamped_fallback_uncertainty)
            } else {
                (confidence_score, uncertainty_score)
            };

        GovernanceTelemetry {
            decision_id: ctx.decision_id,
            trace_id: ctx.trace_id,
            state_posterior_permille: posterior_permille,
            expected_loss_terms,
            chosen_action: action_label(outcome.action_index),
            confidence_score,
            uncertainty_score,
            deterministic_fallback_triggered: outcome.fallback_active,
            deterministic_fallback_reason: if outcome.fallback_active {
                if fallback_reason == "none" {
                    FALLBACK_REASON_UNCLASSIFIED
                } else {
                    fallback_reason
                }
            } else {
                "none"
            },
            replay_ref: G7_DECISION_REPLAY_REF,
            top_evidence_contributors: top_evidence_contributors(snapshot),
        }
    }

    fn malformed_posterior_fallback_telemetry(
        snapshot: &GovernanceSnapshot,
        posterior_permille: [u16; state::COUNT],
        _error: &ValidationError,
    ) -> GovernanceTelemetry {
        crate::tracing_compat::warn!(
            target: "asupersync::raptorq::decision_contract",
            healthy_permille = posterior_permille[state::HEALTHY],
            degraded_permille = posterior_permille[state::DEGRADED],
            regression_permille = posterior_permille[state::REGRESSION],
            unknown_permille = posterior_permille[state::UNKNOWN],
            error = %_error,
            "raptorq G7 posterior conversion failed; emitting deterministic fallback telemetry"
        );

        let ctx = eval_context(
            snapshot,
            MALFORMED_POSTERIOR_CONFIDENCE,
            MALFORMED_POSTERIOR_UNCERTAINTY,
        );
        GovernanceTelemetry {
            decision_id: ctx.decision_id,
            trace_id: ctx.trace_id,
            state_posterior_permille: posterior_permille,
            expected_loss_terms: MALFORMED_POSTERIOR_EXPECTED_LOSS_TERMS,
            chosen_action: action_label(action::FALLBACK),
            confidence_score: MALFORMED_POSTERIOR_CONFIDENCE,
            uncertainty_score: MALFORMED_POSTERIOR_UNCERTAINTY,
            deterministic_fallback_triggered: true,
            deterministic_fallback_reason: FALLBACK_REASON_UNCLASSIFIED,
            replay_ref: G7_DECISION_REPLAY_REF,
            top_evidence_contributors: top_evidence_contributors(snapshot),
        }
    }
}

impl Default for RaptorQDecisionContract {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionContract for RaptorQDecisionContract {
    #[allow(clippy::unnecessary_literal_bound)]
    #[inline]
    fn name(&self) -> &str {
        "raptorq_expected_loss_governance"
    }

    #[inline]
    fn state_space(&self) -> &[String] {
        &self.states
    }

    #[inline]
    fn action_set(&self) -> &[String] {
        &self.actions
    }

    #[inline]
    fn loss_matrix(&self) -> &LossMatrix {
        &self.losses
    }

    fn update_posterior(
        &self,
        posterior: &mut Posterior,
        observation: usize,
    ) -> Result<(), franken_decision::UpdatePosteriorError> {
        // br-asupersync-u5uhpt: previously this returned `()` and silently
        // skipped on wrong-length posteriors, allowing stale beliefs to
        // drive subsequent choose_action calls. The trait now signals the
        // condition via a typed error so callers can re-initialise the
        // posterior or escalate to fallback. Tracing is still emitted to
        // preserve the diagnostic surface for SREs scanning logs.
        if posterior.len() != state::COUNT {
            crate::tracing_compat::warn!(
                expected = state::COUNT,
                actual = posterior.len(),
                observation = observation,
                "raptorq G7 update_posterior: wrong-length posterior — update skipped, \
                 next choose_action will fall back to the conservative action"
            );
            return Err(franken_decision::UpdatePosteriorError::LengthMismatch {
                expected: state::COUNT,
                actual: posterior.len(),
            });
        }
        if observation >= state::COUNT {
            crate::tracing_compat::warn!(
                state_count = state::COUNT,
                observation = observation,
                "raptorq G7 update_posterior: observation index out of range — update skipped"
            );
            return Err(
                franken_decision::UpdatePosteriorError::ObservationOutOfRange {
                    observation,
                    state_count: state::COUNT,
                },
            );
        }
        let mut likelihoods = [0.1; state::COUNT];
        likelihoods[observation] = 0.9;
        posterior.bayesian_update(&likelihoods);
        Ok(())
    }

    fn choose_action(&self, posterior: &Posterior) -> usize {
        if posterior.len() != state::COUNT {
            return self.fallback_action();
        }
        choose_action_from_expected_loss_terms(expected_loss_terms(&self.losses, posterior))
    }

    #[inline]
    fn fallback_action(&self) -> usize {
        action::FALLBACK
    }

    #[inline]
    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

impl GovernanceTelemetry {
    /// Format as a single-line structured log entry for forensic replay.
    ///
    /// Output format: `g7_decision: decision_id=<hex> trace_id=<hex>
    /// state_posterior=[h,d,r,u] expected_loss=[c,ch,rb,fb] action=<chosen>
    /// confidence=<n> uncertainty=<n> fallback=<bool> reason=<str> replay=<ref>
    /// top=[name1:w1,name2:w2,name3:w3]`
    #[must_use]
    pub fn to_structured_log(&self) -> String {
        format!(
            "g7_decision: decision_id={} trace_id={} \
             state_posterior=[{},{},{},{}] expected_loss=[{},{},{},{}] \
             action={} confidence={} uncertainty={} fallback={} reason={} \
             replay={} top=[{}:{},{}:{},{}:{}]",
            self.decision_id,
            self.trace_id,
            self.state_posterior_permille[state::HEALTHY],
            self.state_posterior_permille[state::DEGRADED],
            self.state_posterior_permille[state::REGRESSION],
            self.state_posterior_permille[state::UNKNOWN],
            self.expected_loss_terms[action::CONTINUE],
            self.expected_loss_terms[action::CANARY_HOLD],
            self.expected_loss_terms[action::ROLLBACK],
            self.expected_loss_terms[action::FALLBACK],
            self.chosen_action,
            self.confidence_score,
            self.uncertainty_score,
            self.deterministic_fallback_triggered,
            self.deterministic_fallback_reason,
            self.replay_ref,
            self.top_evidence_contributors[0].name,
            self.top_evidence_contributors[0].contribution_permille,
            self.top_evidence_contributors[1].name,
            self.top_evidence_contributors[1].contribution_permille,
            self.top_evidence_contributors[2].name,
            self.top_evidence_contributors[2].contribution_permille,
        )
    }
}

impl fmt::Display for GovernanceTelemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_structured_log())
    }
}

/// Evaluate a snapshot with the canonical G7 contract.
#[must_use]
pub fn evaluate_governance(snapshot: &GovernanceSnapshot) -> GovernanceTelemetry {
    RaptorQDecisionContract::new().telemetry(snapshot)
}

/// Returns true when `reason` is a canonical runtime-emittable G7 fallback reason.
#[must_use]
#[inline]
pub fn is_runtime_fallback_reason(reason: &str) -> bool {
    G7_RUNTIME_FALLBACK_REASONS.contains(&reason)
}

#[inline]
fn clamp_permille(value: usize) -> u32 {
    value.min(PERMILLE_SCALE as usize) as u32
}

fn normalize_permille_generic<const N: usize>(scores: [u32; N], zero_total: [u16; N]) -> [u16; N] {
    let total: u32 = scores.iter().sum();
    if total == 0 {
        return zero_total;
    }

    let mut normalized = [0u16; N];
    let mut remainders = [(0usize, 0u32); N];
    let mut assigned = 0u32;
    for (index, score) in scores.iter().copied().enumerate() {
        let scaled = score.saturating_mul(PERMILLE_SCALE);
        let base = scaled / total;
        // Cap to u16::MAX if base exceeds u16 range (pathological case)
        normalized[index] = u16::try_from(base).unwrap_or(u16::MAX);
        assigned = assigned.saturating_add(base);
        remainders[index] = (index, scaled % total);
    }

    let mut remaining = usize::try_from(PERMILLE_SCALE.saturating_sub(assigned)).unwrap_or(0); // fallback to 0 if conversion fails
    remainders.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, remainder) in remainders {
        if remaining == 0 || remainder == 0 {
            break;
        }
        normalized[index] = normalized[index].saturating_add(1);
        remaining -= 1;
    }

    normalized
}

#[inline]
fn normalize_permille(scores: [u32; state::COUNT]) -> [u16; state::COUNT] {
    normalize_permille_generic(scores, [250; state::COUNT])
}

#[inline]
fn normalize_contributor_permille(scores: [u32; 3]) -> [u16; 3] {
    normalize_permille_generic(scores, [0; 3])
}

#[inline]
fn posterior_from_permille(
    posterior_permille: [u16; state::COUNT],
) -> Result<Posterior, ValidationError> {
    Posterior::new(
        posterior_permille
            .into_iter()
            .map(|value| f64::from(value) / f64::from(PERMILLE_SCALE))
            .collect(),
    )
}

#[inline]
fn policy_conflict_permille(snapshot: &GovernanceSnapshot) -> u16 {
    let mut best = u32::MAX;
    let mut second = u32::MAX;
    for loss in [
        snapshot.baseline_loss,
        snapshot.high_support_loss,
        snapshot.block_schur_loss,
    ] {
        if loss == u32::MAX {
            continue;
        }
        if loss < best {
            second = best;
            best = loss;
        } else if loss < second {
            second = loss;
        }
    }

    if second == u32::MAX {
        return PERMILLE_SCALE as u16;
    }
    let margin = second.saturating_sub(best).min(MODE_MARGIN_CAP);
    ((MODE_MARGIN_CAP - margin) * PERMILLE_SCALE / MODE_MARGIN_CAP) as u16
}

fn expected_loss_terms(losses: &LossMatrix, posterior: &Posterior) -> [u32; action::COUNT] {
    let mut terms = [0u32; action::COUNT];
    for (index, term) in terms.iter_mut().enumerate() {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            *term = losses.expected_loss(posterior, index).round() as u32;
        }
    }
    terms
}

#[inline]
fn choose_action_from_expected_loss_terms(expected_loss_terms: [u32; action::COUNT]) -> usize {
    // G7 uses a conservative deterministic tie-breaker:
    // fallback > rollback > canary_hold > continue.
    (0..action::COUNT)
        .min_by(|&a, &b| {
            expected_loss_terms[a]
                .cmp(&expected_loss_terms[b])
                .then_with(|| b.cmp(&a))
        })
        .unwrap_or(action::FALLBACK)
}

#[inline]
fn concentration_score(posterior_permille: [u16; state::COUNT]) -> u16 {
    let max_prob = posterior_permille.into_iter().max().unwrap_or(250);
    if max_prob <= 250 {
        return 0;
    }
    ((u32::from(max_prob - 250) * PERMILLE_SCALE) / 750) as u16
}

#[inline]
fn action_margin_score(expected_loss_terms: [u32; action::COUNT]) -> u16 {
    let mut ordered = expected_loss_terms;
    ordered.sort_unstable();
    let gap = ordered[1].saturating_sub(ordered[0]).min(ACTION_MARGIN_CAP);
    (gap * PERMILLE_SCALE / ACTION_MARGIN_CAP) as u16
}

#[inline]
fn dominant_state(posterior_permille: [u16; state::COUNT]) -> usize {
    posterior_permille
        .iter()
        .copied()
        .enumerate()
        .max_by_key(|&(index, value)| (value, std::cmp::Reverse(index)))
        .map_or(state::HEALTHY, |(index, _)| index)
}

fn deterministic_fallback_reason(
    snapshot: &GovernanceSnapshot,
    posterior_permille: [u16; state::COUNT],
    confidence_score: u16,
) -> &'static str {
    if snapshot.budget_exhausted {
        return FALLBACK_REASON_POLICY_BUDGET_EXHAUSTED;
    }

    match dominant_state(posterior_permille) {
        state::UNKNOWN if confidence_score < 350 => FALLBACK_REASON_UNKNOWN_LOW_CONFIDENCE,
        state::REGRESSION if snapshot.rank_deficit_permille >= 600 && confidence_score < 500 => {
            FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE
        }
        _ => "none",
    }
}

fn eval_context(
    snapshot: &GovernanceSnapshot,
    confidence_score: u16,
    uncertainty_score: u16,
) -> EvalContext {
    let mut hasher = DetHasher::default();
    snapshot.hash(&mut hasher);
    confidence_score.hash(&mut hasher);
    uncertainty_score.hash(&mut hasher);
    let fingerprint = u128::from(hasher.finish());
    // br-asupersync-s2jxu0 — derive ts_unix_ms from a stable
    // DetHasher mix over the full bit width of n_rows + n_cols
    // rather than the prior bit-pack
    //   ((n_rows as u64) << 32) | ((n_cols as u64) & 0xFFFF_FFFF)
    // which silently truncated bits >= 32 of either dimension on
    // 64-bit targets, producing colliding ts_unix_ms (and hence
    // colliding DecisionId / TraceId) for distinct (n_rows, n_cols)
    // pairs differing only in those bits — a violation of the
    // unique-decision invariant the contract relies on for replay
    // and dedup. DetHasher.write_usize covers every bit of usize on
    // both 32- and 64-bit targets; the domain tag prevents this
    // mix from colliding with `fingerprint` (which already covers
    // the snapshot via snapshot.hash but with a different schema).
    let mut ts_hasher = DetHasher::default();
    ts_hasher.write_u64(0x7333_3273_6a78_7530); // domain tag "s2sjxu0"
    ts_hasher.write_usize(snapshot.n_rows);
    ts_hasher.write_usize(snapshot.n_cols);
    let ts_unix_ms = ts_hasher.finish();
    let e_process = 1.0
        + f64::from(
            snapshot
                .rank_deficit_permille
                .max(snapshot.inactivation_pressure_permille) as u32,
        ) / 450.0
        + if snapshot.budget_exhausted { 1.2 } else { 0.0 };

    EvalContext {
        calibration_score: f64::from(confidence_score) / f64::from(PERMILLE_SCALE),
        e_process,
        ci_width: f64::from(uncertainty_score) / f64::from(PERMILLE_SCALE),
        decision_id: DecisionId::from_parts(ts_unix_ms, fingerprint),
        trace_id: TraceId::from_parts(ts_unix_ms, fingerprint ^ 0xA5A5_A5A5_A5A5),
        ts_unix_ms,
    }
}

fn top_evidence_contributors(snapshot: &GovernanceSnapshot) -> [GovernanceEvidenceContributor; 3] {
    let density = clamp_permille(snapshot.density_permille);
    let rank = clamp_permille(snapshot.rank_deficit_permille);
    let inactivation = clamp_permille(snapshot.inactivation_pressure_permille);
    let overhead = clamp_permille(snapshot.overhead_ratio_permille);
    let conflict = u32::from(policy_conflict_permille(snapshot));

    let mut signals = [
        (
            0usize,
            "correctness_mismatch_signal",
            rank * 5 / 10 + if snapshot.budget_exhausted { 350 } else { 0 } + overhead / 10,
        ),
        (
            1usize,
            "performance_budget_signal",
            density * 3 / 10 + overhead * 7 / 20 + inactivation / 10,
        ),
        (
            2usize,
            "instability_signal",
            inactivation * 9 / 20 + if snapshot.budget_exhausted { 140 } else { 0 },
        ),
        (
            3usize,
            "cache_policy_signal",
            density * 3 / 20
                + if snapshot.block_schur_loss == u32::MAX {
                    80
                } else {
                    20
                },
        ),
        (
            4usize,
            "policy_conflict_signal",
            conflict / 2
                + if snapshot.block_schur_loss == u32::MAX {
                    40
                } else {
                    0
                },
        ),
    ];
    signals.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));

    let normalized = normalize_contributor_permille([signals[0].2, signals[1].2, signals[2].2]);

    [
        GovernanceEvidenceContributor {
            name: signals[0].1,
            contribution_permille: normalized[0],
        },
        GovernanceEvidenceContributor {
            name: signals[1].1,
            contribution_permille: normalized[1],
        },
        GovernanceEvidenceContributor {
            name: signals[2].1,
            contribution_permille: normalized[2],
        },
    ]
}

#[inline]
const fn action_label(index: usize) -> &'static str {
    match index {
        action::CONTINUE => "continue",
        action::CANARY_HOLD => "canary_hold",
        action::ROLLBACK => "rollback",
        // FALLBACK and any out-of-range index both map to fallback.
        _ => "fallback",
    }
}

#[cfg(test)]
#[path = "decision_contract_inline_tests.rs"]
mod tests;
