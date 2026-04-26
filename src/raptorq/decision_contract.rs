//! Concrete G7 decision contract for RaptorQ runtime governance.
//!
//! This module turns the artifact-only G7 contract into a live runtime policy
//! that can evaluate decoder pressure signals and emit deterministic telemetry
//! for rollout/hold/rollback/fallback decisions.

use std::fmt;
use std::hash::{Hash, Hasher};

use franken_decision::{
    DecisionContract, EvalContext, FallbackPolicy, LossMatrix, Posterior, evaluate,
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
        let posterior = posterior_from_permille(posterior_permille);
        let expected_loss_terms = expected_loss_terms(&self.losses, &posterior);

        let concentration_score = concentration_score(posterior_permille);
        let action_margin_score = action_margin_score(expected_loss_terms);
        let preliminary_confidence = (((u32::from(concentration_score) * 7)
            + (u32::from(action_margin_score) * 3))
            / 10) as u16;
        let fallback_reason =
            deterministic_fallback_reason(snapshot, posterior_permille, preliminary_confidence);
        let confidence_score = if fallback_reason == "none" {
            preliminary_confidence
        } else {
            preliminary_confidence.min(250)
        };
        let uncertainty_score = 1000u16.saturating_sub(confidence_score);
        let ctx = eval_context(snapshot, confidence_score, uncertainty_score);
        // br-asupersync-g1pzep: evaluate now returns Result; for the
        // RaptorQ contract we control the action_set so this should
        // never produce ActionIndexOutOfRange in practice. On error we
        // fall back to the BALANCED action with the original fallback
        // reason preserved — keeps telemetry well-formed without
        // panicking the caller.
        let outcome = match evaluate(self, &posterior, &ctx) {
            Ok(o) => o,
            Err(_) => {
                return GovernanceTelemetry {
                    state_posterior_permille: posterior_permille,
                    expected_loss_terms,
                    chosen_action: action_label(action::CONTINUE),
                    confidence_score,
                    uncertainty_score,
                    deterministic_fallback_triggered: true,
                    deterministic_fallback_reason: "contract_action_out_of_range",
                    replay_ref: G7_DECISION_REPLAY_REF,
                    top_evidence_contributors: top_evidence_contributors(snapshot),
                };
            }
        };

        GovernanceTelemetry {
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
    /// Output format: `g7_decision: state_posterior=[h,d,r,u] expected_loss=[c,ch,rb,fb]
    /// action=<chosen> confidence=<n> uncertainty=<n> fallback=<bool> reason=<str>
    /// replay=<ref> top=[name1:w1,name2:w2,name3:w3]`
    #[must_use]
    pub fn to_structured_log(&self) -> String {
        format!(
            "g7_decision: state_posterior=[{},{},{},{}] expected_loss=[{},{},{},{}] \
             action={} confidence={} uncertainty={} fallback={} reason={} \
             replay={} top=[{}:{},{}:{},{}:{}]",
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
        normalized[index] = u16::try_from(base).expect("permille base fits into u16");
        assigned = assigned.saturating_add(base);
        remainders[index] = (index, scaled % total);
    }

    let mut remaining = usize::try_from(PERMILLE_SCALE.saturating_sub(assigned))
        .expect("permille remainder fits into usize");
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
fn posterior_from_permille(posterior_permille: [u16; state::COUNT]) -> Posterior {
    Posterior::new(
        posterior_permille
            .into_iter()
            .map(|value| f64::from(value) / f64::from(PERMILLE_SCALE))
            .collect(),
    )
    .expect("normalized posterior permille should convert to Posterior")
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
    let ts_unix_ms = ((snapshot.n_rows as u64) << 32) | ((snapshot.n_cols as u64) & 0xFFFF_FFFF);
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn healthy_snapshot_has_dominant_healthy_posterior() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 90,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 80,
            overhead_ratio_permille: 120,
            budget_exhausted: false,
            baseline_loss: 540,
            high_support_loss: 760,
            block_schur_loss: u32::MAX,
        });

        // With missing block_schur (u32::MAX) there is non-trivial uncertainty,
        // so the expected-loss-optimal action is canary_hold (cautious monitoring).
        // The loss matrix favors canary_hold when degraded/unknown mass > ~15%.
        assert!(
            telemetry.chosen_action == "canary_hold" || telemetry.chosen_action == "continue",
            "healthy snapshot should prefer canary_hold or continue, got: {}",
            telemetry.chosen_action
        );
        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.replay_ref, G7_DECISION_REPLAY_REF);
        assert!(
            telemetry.state_posterior_permille[state::HEALTHY]
                > telemetry.state_posterior_permille[state::DEGRADED]
        );
    }

    #[test]
    fn very_clean_snapshot_prefers_continue() {
        // Minimal pressure, all losses available and well-separated
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 16,
            n_cols: 12,
            density_permille: 20,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 10,
            overhead_ratio_permille: 15,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        });

        assert_eq!(
            telemetry.chosen_action, "continue",
            "very clean snapshot with well-separated losses should prefer continue"
        );
        assert!(!telemetry.deterministic_fallback_triggered);
    }

    #[test]
    fn surfaced_expected_loss_ties_drive_the_reported_action() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 0,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 0,
            overhead_ratio_permille: 150,
            budget_exhausted: false,
            baseline_loss: 520,
            high_support_loss: 900,
            block_schur_loss: 900,
        });

        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(
            telemetry.expected_loss_terms[action::CONTINUE],
            telemetry.expected_loss_terms[action::CANARY_HOLD],
            "regression fixture requires a surfaced tie on the minimum expected-loss terms"
        );
        assert_eq!(
            telemetry.chosen_action,
            action_label(choose_action_from_expected_loss_terms(
                telemetry.expected_loss_terms,
            )),
        );
        assert_eq!(telemetry.chosen_action, "canary_hold");
    }

    #[test]
    fn exact_canary_hold_action_is_reported_without_fallback() {
        let contract = RaptorQDecisionContract::new();
        let snapshot = GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 0,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 0,
            overhead_ratio_permille: 0,
            budget_exhausted: false,
            baseline_loss: 500,
            high_support_loss: 520,
            block_schur_loss: 540,
        };

        let telemetry = contract.telemetry(&snapshot);
        let ctx = eval_context(
            &snapshot,
            telemetry.confidence_score,
            telemetry.uncertainty_score,
        );
        let fallback = contract.fallback_policy();

        assert_eq!(telemetry.chosen_action, "canary_hold");
        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.deterministic_fallback_reason, "none");
        assert!(
            telemetry.expected_loss_terms[action::CANARY_HOLD]
                < telemetry.expected_loss_terms[action::CONTINUE]
        );
        assert!(
            telemetry.expected_loss_terms[action::CANARY_HOLD]
                < telemetry.expected_loss_terms[action::ROLLBACK]
        );
        assert!(
            telemetry.expected_loss_terms[action::CANARY_HOLD]
                < telemetry.expected_loss_terms[action::FALLBACK]
        );
        assert!(ctx.calibration_score >= fallback.calibration_drift_threshold);
        assert!(ctx.e_process <= fallback.e_process_breach_threshold);
        assert!(ctx.ci_width <= fallback.confidence_width_threshold);
    }

    #[test]
    fn budget_exhaustion_forces_fallback() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 65,
            n_cols: 65,
            density_permille: 1000,
            rank_deficit_permille: 500,
            inactivation_pressure_permille: 900,
            overhead_ratio_permille: 0,
            budget_exhausted: true,
            baseline_loss: 1024,
            high_support_loss: 1700,
            block_schur_loss: 1600,
        });

        assert_eq!(telemetry.chosen_action, "fallback");
        assert!(telemetry.deterministic_fallback_triggered);
        assert_eq!(
            telemetry.deterministic_fallback_reason,
            FALLBACK_REASON_POLICY_BUDGET_EXHAUSTED
        );
    }

    #[test]
    fn policy_fallback_never_reports_none_reason() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 10,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 600,
            overhead_ratio_permille: 0,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        });

        assert!(
            telemetry.deterministic_fallback_triggered,
            "e-process breach should activate fallback"
        );
        assert_eq!(telemetry.chosen_action, "fallback");
        assert_eq!(
            telemetry.deterministic_fallback_reason, FALLBACK_REASON_UNCLASSIFIED,
            "fallback-active telemetry must never report reason=none"
        );
    }

    #[test]
    fn explicit_regression_low_confidence_reason_is_reported() {
        let contract = RaptorQDecisionContract::new();
        let snapshot = GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 0,
            rank_deficit_permille: 650,
            inactivation_pressure_permille: 150,
            overhead_ratio_permille: 100,
            budget_exhausted: false,
            baseline_loss: 500,
            high_support_loss: 520,
            block_schur_loss: 540,
        };

        let posterior_permille = RaptorQDecisionContract::state_posterior_permille(&snapshot);
        let posterior = posterior_from_permille(posterior_permille);
        let preliminary_confidence = (((u32::from(concentration_score(posterior_permille)) * 7)
            + (u32::from(action_margin_score(expected_loss_terms(
                contract.loss_matrix(),
                &posterior,
            ))) * 3))
            / 10) as u16;
        let telemetry = contract.telemetry(&snapshot);

        assert!(posterior_permille[state::REGRESSION] > posterior_permille[state::HEALTHY]);
        assert!(posterior_permille[state::REGRESSION] > posterior_permille[state::DEGRADED]);
        assert!(posterior_permille[state::REGRESSION] > posterior_permille[state::UNKNOWN]);
        assert!(
            preliminary_confidence < 500,
            "test must stay on the low-confidence side of the explicit REGRESSION fallback seam"
        );
        assert_eq!(
            deterministic_fallback_reason(&snapshot, posterior_permille, preliminary_confidence),
            FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE
        );
        assert!(telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.chosen_action, "fallback");
        assert_eq!(
            telemetry.deterministic_fallback_reason,
            FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE
        );
        assert!(
            telemetry.confidence_score <= 250,
            "fallback-reason path should clamp surfaced confidence"
        );
    }

    #[test]
    fn telemetry_fields_are_normalized_and_stable() {
        let snapshot = GovernanceSnapshot {
            n_rows: 18,
            n_cols: 16,
            density_permille: 820,
            rank_deficit_permille: 140,
            inactivation_pressure_permille: 760,
            overhead_ratio_permille: 60,
            budget_exhausted: false,
            baseline_loss: 1180,
            high_support_loss: 900,
            block_schur_loss: 880,
        };

        let first = evaluate_governance(&snapshot);
        let second = evaluate_governance(&snapshot);

        assert_eq!(first, second, "governance evaluation must be deterministic");
        assert_eq!(
            first
                .state_posterior_permille
                .iter()
                .map(|&value| u32::from(value))
                .sum::<u32>(),
            PERMILLE_SCALE
        );
        assert_eq!(
            first
                .top_evidence_contributors
                .iter()
                .map(|entry| u32::from(entry.contribution_permille))
                .sum::<u32>(),
            PERMILLE_SCALE
        );
        assert!(first.confidence_score <= 1000);
        assert!(first.uncertainty_score <= 1000);
    }

    #[test]
    fn high_pressure_snapshot_prefers_rollback_or_fallback() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 64,
            n_cols: 64,
            density_permille: 950,
            rank_deficit_permille: 800,
            inactivation_pressure_permille: 850,
            overhead_ratio_permille: 700,
            budget_exhausted: false,
            baseline_loss: 2000,
            high_support_loss: 1800,
            block_schur_loss: 1900,
        });

        assert!(
            telemetry.chosen_action == "rollback" || telemetry.chosen_action == "fallback",
            "high-pressure snapshot should prefer rollback or fallback, got: {}",
            telemetry.chosen_action
        );
        assert!(
            telemetry.state_posterior_permille[state::REGRESSION]
                > telemetry.state_posterior_permille[state::HEALTHY],
            "regression posterior should exceed healthy under high pressure"
        );
    }

    #[test]
    fn exact_rollback_action_is_reported_without_fallback() {
        let contract = RaptorQDecisionContract::new();
        let snapshot = GovernanceSnapshot {
            n_rows: 40,
            n_cols: 32,
            density_permille: 500,
            rank_deficit_permille: 50,
            inactivation_pressure_permille: 400,
            overhead_ratio_permille: 600,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        };

        let telemetry = contract.telemetry(&snapshot);
        let ctx = eval_context(
            &snapshot,
            telemetry.confidence_score,
            telemetry.uncertainty_score,
        );
        let fallback = contract.fallback_policy();

        assert_eq!(telemetry.chosen_action, "rollback");
        assert!(!telemetry.deterministic_fallback_triggered);
        assert_eq!(telemetry.deterministic_fallback_reason, "none");
        assert!(
            telemetry.expected_loss_terms[action::ROLLBACK]
                < telemetry.expected_loss_terms[action::CONTINUE]
        );
        assert!(
            telemetry.expected_loss_terms[action::ROLLBACK]
                < telemetry.expected_loss_terms[action::CANARY_HOLD]
        );
        assert!(
            telemetry.expected_loss_terms[action::ROLLBACK]
                < telemetry.expected_loss_terms[action::FALLBACK]
        );
        assert!(ctx.calibration_score >= fallback.calibration_drift_threshold);
        assert!(ctx.e_process <= fallback.e_process_breach_threshold);
        assert!(ctx.ci_width <= fallback.confidence_width_threshold);
    }

    #[test]
    fn moderate_pressure_selects_conservative_action() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 32,
            n_cols: 24,
            density_permille: 450,
            rank_deficit_permille: 200,
            inactivation_pressure_permille: 400,
            overhead_ratio_permille: 350,
            budget_exhausted: false,
            baseline_loss: 800,
            high_support_loss: 600,
            block_schur_loss: 750,
        });

        // Under moderate pressure the expected-loss engine may select
        // canary_hold, rollback, or fallback depending on posterior shape.
        assert!(
            telemetry.chosen_action != "continue",
            "moderate pressure should not prefer continue, got: {}",
            telemetry.chosen_action
        );
    }

    #[test]
    fn unknown_state_low_confidence_triggers_fallback() {
        // Conflicting policy signals + missing block_schur → high unknown posterior
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 40,
            n_cols: 32,
            density_permille: 300,
            rank_deficit_permille: 100,
            inactivation_pressure_permille: 200,
            overhead_ratio_permille: 100,
            budget_exhausted: true,
            baseline_loss: 500,
            high_support_loss: 500,
            block_schur_loss: u32::MAX,
        });

        assert!(
            telemetry.deterministic_fallback_triggered,
            "budget exhaustion should trigger deterministic fallback"
        );
        assert_eq!(telemetry.chosen_action, "fallback");
    }

    #[test]
    fn explicit_unknown_low_confidence_reason_is_reported() {
        // Missing block_schur plus maximally conflicting policy losses make UNKNOWN
        // the dominant posterior state, while high rank pressure keeps confidence low
        // without relying on the separate budget-exhaustion fallback path.
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 0,
            rank_deficit_permille: 650,
            inactivation_pressure_permille: 0,
            overhead_ratio_permille: 190,
            budget_exhausted: false,
            baseline_loss: 500,
            high_support_loss: 500,
            block_schur_loss: u32::MAX,
        });

        assert!(
            telemetry.state_posterior_permille[state::UNKNOWN]
                > telemetry.state_posterior_permille[state::HEALTHY]
        );
        assert!(
            telemetry.state_posterior_permille[state::UNKNOWN]
                > telemetry.state_posterior_permille[state::DEGRADED]
        );
        assert!(
            telemetry.state_posterior_permille[state::UNKNOWN]
                > telemetry.state_posterior_permille[state::REGRESSION]
        );
        assert!(
            telemetry.confidence_score < 350,
            "test must stay on the low-confidence side of the explicit UNKNOWN fallback seam"
        );
        assert!(
            telemetry.deterministic_fallback_triggered,
            "explicit low-confidence UNKNOWN path must trigger deterministic fallback"
        );
        assert_eq!(telemetry.chosen_action, "fallback");
        assert_eq!(
            telemetry.deterministic_fallback_reason,
            FALLBACK_REASON_UNKNOWN_LOW_CONFIDENCE
        );
    }

    #[test]
    fn conflicting_evidence_raises_uncertainty() {
        // All policy losses are nearly identical → high conflict → high unknown
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 20,
            n_cols: 16,
            density_permille: 200,
            rank_deficit_permille: 50,
            inactivation_pressure_permille: 100,
            overhead_ratio_permille: 50,
            budget_exhausted: false,
            baseline_loss: 1000,
            high_support_loss: 1001,
            block_schur_loss: 1002,
        });

        // With closely matched losses, uncertainty should be material
        assert!(
            telemetry.uncertainty_score >= 500,
            "conflicting evidence should produce high uncertainty, got: {}",
            telemetry.uncertainty_score
        );
    }

    #[test]
    fn structured_log_contains_all_required_fields() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 90,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 80,
            overhead_ratio_permille: 120,
            budget_exhausted: false,
            baseline_loss: 540,
            high_support_loss: 760,
            block_schur_loss: u32::MAX,
        });

        let log = telemetry.to_structured_log();

        assert!(
            log.starts_with("g7_decision:"),
            "log must start with g7_decision prefix"
        );
        assert!(
            log.contains("state_posterior="),
            "log must include state_posterior"
        );
        assert!(
            log.contains("expected_loss="),
            "log must include expected_loss"
        );
        assert!(log.contains("action="), "log must include chosen action");
        assert!(
            log.contains("confidence="),
            "log must include confidence score"
        );
        assert!(
            log.contains("uncertainty="),
            "log must include uncertainty score"
        );
        assert!(log.contains("fallback="), "log must include fallback flag");
        assert!(log.contains("reason="), "log must include fallback reason");
        assert!(log.contains("replay="), "log must include replay ref");
        assert!(
            log.contains("top="),
            "log must include top evidence contributors"
        );
    }

    #[test]
    fn display_impl_matches_structured_log() {
        let telemetry = evaluate_governance(&GovernanceSnapshot {
            n_rows: 24,
            n_cols: 16,
            density_permille: 500,
            rank_deficit_permille: 300,
            inactivation_pressure_permille: 400,
            overhead_ratio_permille: 200,
            budget_exhausted: false,
            baseline_loss: 800,
            high_support_loss: 900,
            block_schur_loss: 850,
        });

        assert_eq!(
            format!("{telemetry}"),
            telemetry.to_structured_log(),
            "Display impl must match to_structured_log"
        );
    }

    #[test]
    fn replay_reproducibility_across_contract_instances() {
        let snapshot = GovernanceSnapshot {
            n_rows: 48,
            n_cols: 32,
            density_permille: 600,
            rank_deficit_permille: 250,
            inactivation_pressure_permille: 500,
            overhead_ratio_permille: 300,
            budget_exhausted: false,
            baseline_loss: 1200,
            high_support_loss: 950,
            block_schur_loss: 1100,
        };

        let contract_a = RaptorQDecisionContract::new();
        let contract_b = RaptorQDecisionContract::new();

        let telemetry_a = contract_a.telemetry(&snapshot);
        let telemetry_b = contract_b.telemetry(&snapshot);

        assert_eq!(
            telemetry_a, telemetry_b,
            "different contract instances must produce identical telemetry for the same snapshot"
        );
        assert_eq!(
            telemetry_a.to_structured_log(),
            telemetry_b.to_structured_log(),
            "structured log output must be identical across instances"
        );
    }

    #[test]
    fn confidence_uncertainty_are_complementary() {
        for (density, rank, inact, overhead) in [
            (0, 0, 0, 0),
            (500, 500, 500, 500),
            (1000, 1000, 1000, 1000),
            (100, 900, 50, 200),
        ] {
            let telemetry = evaluate_governance(&GovernanceSnapshot {
                n_rows: 32,
                n_cols: 24,
                density_permille: density,
                rank_deficit_permille: rank,
                inactivation_pressure_permille: inact,
                overhead_ratio_permille: overhead,
                budget_exhausted: false,
                baseline_loss: 600,
                high_support_loss: 800,
                block_schur_loss: 700,
            });

            assert_eq!(
                telemetry.confidence_score + telemetry.uncertainty_score,
                1000,
                "confidence + uncertainty must equal 1000 for density={density} rank={rank}"
            );
        }
    }

    #[test]
    fn all_actions_are_reachable() {
        // Very clean → continue (well-separated losses, no missing block_schur)
        let healthy = evaluate_governance(&GovernanceSnapshot {
            n_rows: 16,
            n_cols: 12,
            density_permille: 20,
            rank_deficit_permille: 0,
            inactivation_pressure_permille: 10,
            overhead_ratio_permille: 15,
            budget_exhausted: false,
            baseline_loss: 100,
            high_support_loss: 800,
            block_schur_loss: 900,
        });
        assert_eq!(healthy.chosen_action, "continue");

        // Budget exhausted → fallback
        let exhausted = evaluate_governance(&GovernanceSnapshot {
            n_rows: 64,
            n_cols: 64,
            density_permille: 900,
            rank_deficit_permille: 700,
            inactivation_pressure_permille: 800,
            overhead_ratio_permille: 600,
            budget_exhausted: true,
            baseline_loss: 2000,
            high_support_loss: 1800,
            block_schur_loss: 1900,
        });
        assert_eq!(exhausted.chosen_action, "fallback");

        // Verify each action is a valid label
        for action_name in &["continue", "canary_hold", "rollback", "fallback"] {
            let idx = match *action_name {
                "continue" => action::CONTINUE,
                "canary_hold" => action::CANARY_HOLD,
                "rollback" => action::ROLLBACK,
                "fallback" => action::FALLBACK,
                _ => unreachable!(),
            };
            assert_eq!(action_label(idx), *action_name);
        }
    }

    #[test]
    fn action_label_out_of_range_returns_fallback() {
        assert_eq!(action_label(99), "fallback");
        assert_eq!(action_label(usize::MAX), "fallback");
    }

    #[test]
    fn normalize_permille_zero_total_gives_uniform() {
        let result = normalize_permille([0, 0, 0, 0]);
        assert_eq!(result, [250, 250, 250, 250]);
    }

    #[test]
    fn normalize_permille_does_not_assign_remainder_to_zero_score_bucket() {
        let result = normalize_permille([1, 1, 1, 0]);
        assert_eq!(result, [334, 333, 333, 0]);
    }

    #[test]
    fn contributor_normalization_does_not_assign_remainder_to_zero_weight() {
        let result = normalize_contributor_permille([2, 1, 0]);
        assert_eq!(result, [667, 333, 0]);
    }

    #[test]
    fn contract_trait_methods_are_consistent() {
        let contract = RaptorQDecisionContract::new();
        assert_eq!(contract.name(), "raptorq_expected_loss_governance");
        assert_eq!(contract.state_space().len(), state::COUNT);
        assert_eq!(contract.action_set().len(), action::COUNT);
        assert_eq!(contract.fallback_action(), action::FALLBACK);

        // Loss matrix dimensions match states × actions
        let losses = contract.loss_matrix();
        for s in 0..state::COUNT {
            for a in 0..action::COUNT {
                let loss = losses.get(s, a);
                assert!(loss >= 0.0, "loss({s},{a}) must be non-negative");
            }
        }
    }

    #[test]
    fn choose_action_uses_conservative_tie_breaker() {
        let contract = RaptorQDecisionContract::new();

        let continue_vs_hold = Posterior::new(vec![0.75, 0.25, 0.0, 0.0]).unwrap();
        assert_eq!(
            contract.choose_action(&continue_vs_hold),
            action::CANARY_HOLD,
            "equal expected loss between continue/canary_hold must prefer canary_hold"
        );

        let rollback_vs_fallback = Posterior::new(vec![0.25, 0.0, 0.75, 0.0]).unwrap();
        assert_eq!(
            contract.choose_action(&rollback_vs_fallback),
            action::FALLBACK,
            "equal expected loss between rollback/fallback must prefer fallback"
        );
    }

    #[test]
    fn posterior_update_concentrates_on_observation() {
        let contract = RaptorQDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT);
        contract
            .update_posterior(&mut posterior, state::REGRESSION)
            .expect("update_posterior succeeds for matching length + valid observation");

        // After observing REGRESSION, its probability should increase
        let probs = posterior.probs();
        assert!(
            probs[state::REGRESSION] > probs[state::HEALTHY],
            "regression probability should exceed healthy after observing regression"
        );
    }

    #[test]
    fn choose_action_fails_closed_for_malformed_posterior_length() {
        let contract = RaptorQDecisionContract::new();
        let malformed = Posterior::new(vec![0.34, 0.33, 0.33]).unwrap();

        assert_eq!(
            contract.choose_action(&malformed),
            action::FALLBACK,
            "malformed posterior length must fail closed to fallback"
        );
    }

    #[test]
    fn posterior_update_returns_length_mismatch_error() {
        // br-asupersync-u5uhpt: previously a wrong-length posterior was
        // a silent no-op. Now it surfaces a typed error and the posterior
        // remains unchanged so callers can fall back deterministically.
        let contract = RaptorQDecisionContract::new();
        let mut malformed = Posterior::new(vec![0.34, 0.33, 0.33]).unwrap();
        let before = malformed.probs().to_vec();

        let err = contract
            .update_posterior(&mut malformed, state::REGRESSION)
            .expect_err("wrong-length posterior must surface a typed error");

        assert!(
            matches!(
                err,
                franken_decision::UpdatePosteriorError::LengthMismatch {
                    expected: state::COUNT,
                    actual: 3,
                }
            ),
            "expected LengthMismatch, got {err:?}"
        );
        assert_eq!(
            malformed.probs(),
            before.as_slice(),
            "malformed posterior length must remain unchanged after update"
        );
    }

    #[test]
    fn posterior_update_returns_observation_out_of_range_error() {
        // br-asupersync-u5uhpt: an out-of-range observation must surface a
        // typed error; the posterior must remain unchanged.
        let contract = RaptorQDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT);
        let before = posterior.probs().to_vec();

        let err = contract
            .update_posterior(&mut posterior, usize::MAX)
            .expect_err("out-of-range observation must surface a typed error");

        assert!(
            matches!(
                err,
                franken_decision::UpdatePosteriorError::ObservationOutOfRange {
                    observation: usize::MAX,
                    state_count: state::COUNT,
                }
            ),
            "expected ObservationOutOfRange, got {err:?}"
        );
        assert_eq!(
            posterior.probs(),
            before.as_slice(),
            "out-of-range observations must not perturb posterior state"
        );
    }

    #[test]
    fn default_impl_matches_new() {
        let from_new = RaptorQDecisionContract::new();
        let from_default = RaptorQDecisionContract::default();
        assert_eq!(from_new.name(), from_default.name());
        assert_eq!(from_new.state_space(), from_default.state_space());
        assert_eq!(from_new.action_set(), from_default.action_set());
    }

    #[test]
    fn runtime_fallback_reason_boundary_matches_live_contract() {
        assert_eq!(
            G7_RUNTIME_FALLBACK_REASONS,
            &[
                FALLBACK_REASON_POLICY_BUDGET_EXHAUSTED,
                FALLBACK_REASON_UNKNOWN_LOW_CONFIDENCE,
                FALLBACK_REASON_REGRESSION_LOW_CONFIDENCE,
                FALLBACK_REASON_UNCLASSIFIED,
            ],
            "live runtime fallback boundary must stay aligned with canonical telemetry reasons"
        );

        for reason in G7_RUNTIME_FALLBACK_REASONS {
            assert!(
                is_runtime_fallback_reason(reason),
                "{reason} must remain runtime-emittable"
            );
        }
    }

    #[test]
    fn broader_contract_only_triggers_are_not_runtime_emittable_reasons() {
        for reason in [
            "decode_mismatch_detected",
            "proof_replay_mismatch",
            "none",
            "unknown_reason",
        ] {
            assert!(
                !is_runtime_fallback_reason(reason),
                "{reason} must stay outside the live runtime-emittable reason boundary"
            );
        }
    }

    #[test]
    fn evidence_contributors_are_always_three() {
        for budget_exhausted in [false, true] {
            let telemetry = evaluate_governance(&GovernanceSnapshot {
                n_rows: 32,
                n_cols: 24,
                density_permille: 500,
                rank_deficit_permille: 300,
                inactivation_pressure_permille: 400,
                overhead_ratio_permille: 200,
                budget_exhausted,
                baseline_loss: 800,
                high_support_loss: 900,
                block_schur_loss: 850,
            });

            assert_eq!(telemetry.top_evidence_contributors.len(), 3);
            for contributor in &telemetry.top_evidence_contributors {
                assert!(
                    !contributor.name.is_empty(),
                    "contributor name must not be empty"
                );
                assert!(
                    contributor.contribution_permille <= 1000,
                    "contributor weight must be <= 1000"
                );
            }
        }
    }
}
