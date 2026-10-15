//! RaptorQ G7 governance telemetry — structured-log serialization + posterior
//! and evidence-contributor structural conformance.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC5/AC6. The G7 decision contract emits a single
//! deterministic forensic line per decision via
//! `GovernanceTelemetry::to_structured_log()` (and its `Display` shim). SREs and
//! replay tooling key on that line's exact shape and on the numeric fields it
//! carries, yet `to_structured_log` / `Display` had ZERO integration coverage,
//! and the *structural* (as opposed to sum-normalization) behavior of
//! `state_posterior_permille` and `top_evidence_contributors` was likewise
//! unpinned — `tests/raptorq_governance_contract_conformance.rs` only proves the
//! posterior sums to 1000, is deterministic, equals the free-fn telemetry, and
//! that the confidence/uncertainty split + fallback-reason classification hold.
//!
//! This harness pins, oracle-free (everything recomputed from the public
//! `GovernanceTelemetry` fields the contract itself populates):
//!   - the exact structured-log format (field order, labels, separators,
//!     brackets) for a representative decision, plus `Display == to_structured_log`;
//!   - field-by-field correspondence between the parsed log tokens and the
//!     telemetry struct (posterior array order, expected-loss action order,
//!     top-contributor name:weight pairs, fallback flag/reason, replay ref) by
//!     PARSING the emitted string rather than re-stating the format;
//!   - the fallback flag <=> reason consistency, bridged to the runtime
//!     classifier `is_runtime_fallback_reason`;
//!   - single-line / deterministic emission;
//!   - metamorphic posterior mass-shift laws that the conformance suite omits:
//!       * `budget_exhausted` moves mass OUT of `healthy` and INTO
//!         `regression + unknown` (monotone, holding everything else fixed);
//!       * an unavailable block-Schur loss (`block_schur_loss == u32::MAX`)
//!         never decreases `unknown` mass when the policy-conflict inputs are
//!         held identical;
//!       * input pressures are clamped at 1000 permille — values above the cap
//!         produce a byte-identical posterior;
//!   - top-evidence-contributor structure: contributions are non-increasing,
//!     sum to exactly 1000 (or 0 in the all-zero-signal degenerate case),
//!     names are drawn from the canonical signal set and pairwise distinct,
//!     and the whole vector is deterministic.
//!
//! Repro: `cargo test --test raptorq_governance_telemetry_structured_log`

use asupersync::raptorq::decision_contract::{
    G7_DECISION_REPLAY_REF, GovernanceSnapshot, GovernanceTelemetry, RaptorQDecisionContract,
    action, evaluate_governance, is_runtime_fallback_reason, state,
};

/// A diverse grid of runtime snapshots covering the major posterior regimes:
/// clean, degraded, regression-dominant, unknown-dominant, budget-exhausted,
/// missing block-Schur, and clamp-saturating extremes.
fn snapshot_grid() -> Vec<GovernanceSnapshot> {
    vec![
        // Very clean — all losses present and well separated.
        GovernanceSnapshot {
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
        },
        // Moderately degraded.
        GovernanceSnapshot {
            n_rows: 48,
            n_cols: 40,
            density_permille: 420,
            rank_deficit_permille: 120,
            inactivation_pressure_permille: 260,
            overhead_ratio_permille: 300,
            budget_exhausted: false,
            baseline_loss: 540,
            high_support_loss: 600,
            block_schur_loss: 650,
        },
        // Regression-dominant — heavy rank deficit, low confidence.
        GovernanceSnapshot {
            n_rows: 96,
            n_cols: 80,
            density_permille: 500,
            rank_deficit_permille: 720,
            inactivation_pressure_permille: 300,
            overhead_ratio_permille: 400,
            budget_exhausted: false,
            baseline_loss: 900,
            high_support_loss: 905,
            block_schur_loss: 910,
        },
        // Unknown-dominant — missing block-Schur + tight policy conflict.
        GovernanceSnapshot {
            n_rows: 32,
            n_cols: 28,
            density_permille: 200,
            rank_deficit_permille: 80,
            inactivation_pressure_permille: 120,
            overhead_ratio_permille: 160,
            budget_exhausted: false,
            baseline_loss: 700,
            high_support_loss: 701,
            block_schur_loss: u32::MAX,
        },
        // Budget exhausted — forces the conservative fallback reason.
        GovernanceSnapshot {
            n_rows: 64,
            n_cols: 56,
            density_permille: 300,
            rank_deficit_permille: 200,
            inactivation_pressure_permille: 180,
            overhead_ratio_permille: 220,
            budget_exhausted: true,
            baseline_loss: 400,
            high_support_loss: 500,
            block_schur_loss: 600,
        },
        // Clamp-saturating extremes — every pressure above the 1000 cap.
        GovernanceSnapshot {
            n_rows: 1,
            n_cols: 1,
            density_permille: 5000,
            rank_deficit_permille: 9000,
            inactivation_pressure_permille: 7000,
            overhead_ratio_permille: 6000,
            budget_exhausted: false,
            baseline_loss: 0,
            high_support_loss: 0,
            block_schur_loss: 0,
        },
    ]
}

/// Parsed view of a single structured-log line, tokenized on whitespace. None of
/// the embedded values contain spaces (hex ids, snake_case labels, comma-packed
/// arrays), so whitespace splitting is lossless.
struct ParsedLog {
    fields: std::collections::HashMap<String, String>,
}

impl ParsedLog {
    fn parse(line: &str) -> Self {
        let mut fields = std::collections::HashMap::new();
        let mut tokens = line.split_whitespace();
        assert_eq!(
            tokens.next(),
            Some("g7_decision:"),
            "structured log must begin with the canonical record tag (line={line:?})"
        );
        for token in tokens {
            let (key, value) = token
                .split_once('=')
                .unwrap_or_else(|| panic!("token {token:?} is not key=value (line={line:?})"));
            assert!(
                fields.insert(key.to_string(), value.to_string()).is_none(),
                "duplicate field {key:?} in structured log (line={line:?})"
            );
        }
        Self { fields }
    }

    fn get(&self, key: &str) -> &str {
        self.fields
            .get(key)
            .unwrap_or_else(|| panic!("structured log missing field {key:?}"))
    }

    /// Parse a `[a,b,c,...]`-bracketed comma list into its raw element strings.
    fn bracket_list(&self, key: &str) -> Vec<String> {
        let raw = self.get(key);
        let inner = raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or_else(|| panic!("field {key:?}={raw:?} is not bracketed"));
        inner.split(',').map(str::to_string).collect()
    }
}

/// Build the exact expected structured-log string from the public telemetry
/// fields, mirroring the documented format. This is an independent restatement
/// of the format contract: a refactor that reorders fields, drops a label, or
/// changes a separator must update this golden alongside the production code.
fn expected_structured_log(t: &GovernanceTelemetry) -> String {
    format!(
        "g7_decision: decision_id={} trace_id={} \
         state_posterior=[{},{},{},{}] expected_loss=[{},{},{},{}] \
         action={} confidence={} uncertainty={} fallback={} reason={} \
         replay={} top=[{}:{},{}:{},{}:{}]",
        t.decision_id,
        t.trace_id,
        t.state_posterior_permille[state::HEALTHY],
        t.state_posterior_permille[state::DEGRADED],
        t.state_posterior_permille[state::REGRESSION],
        t.state_posterior_permille[state::UNKNOWN],
        t.expected_loss_terms[action::CONTINUE],
        t.expected_loss_terms[action::CANARY_HOLD],
        t.expected_loss_terms[action::ROLLBACK],
        t.expected_loss_terms[action::FALLBACK],
        t.chosen_action,
        t.confidence_score,
        t.uncertainty_score,
        t.deterministic_fallback_triggered,
        t.deterministic_fallback_reason,
        t.replay_ref,
        t.top_evidence_contributors[0].name,
        t.top_evidence_contributors[0].contribution_permille,
        t.top_evidence_contributors[1].name,
        t.top_evidence_contributors[1].contribution_permille,
        t.top_evidence_contributors[2].name,
        t.top_evidence_contributors[2].contribution_permille,
    )
}

/// The exact format contract holds for every snapshot in the grid, and `Display`
/// is a verbatim shim over `to_structured_log`.
#[test]
fn structured_log_matches_documented_format_and_display_shim() {
    for snapshot in snapshot_grid() {
        let t = evaluate_governance(&snapshot);
        let log = t.to_structured_log();
        assert_eq!(
            log,
            expected_structured_log(&t),
            "structured log diverged from documented format (snapshot={snapshot:?})"
        );
        assert_eq!(
            format!("{t}"),
            log,
            "Display must delegate verbatim to to_structured_log (snapshot={snapshot:?})"
        );
    }
}

/// Emission is single-line and deterministic across repeated calls.
#[test]
fn structured_log_is_single_line_and_deterministic() {
    for snapshot in snapshot_grid() {
        let t = evaluate_governance(&snapshot);
        let first = t.to_structured_log();
        let second = t.to_structured_log();
        assert_eq!(
            first, second,
            "structured log not deterministic ({snapshot:?})"
        );
        assert!(
            !first.contains('\n') && !first.contains('\r'),
            "structured log must be a single line ({snapshot:?}): {first:?}"
        );
        assert!(
            first.starts_with("g7_decision: "),
            "structured log must lead with the record tag ({snapshot:?})"
        );
    }
}

/// PARSE the emitted line and check every numeric/string field equals the
/// corresponding telemetry field — independent of `expected_structured_log`,
/// which restates the format; here we recover semantics from the wire form.
#[test]
fn parsed_structured_log_fields_match_telemetry() {
    for snapshot in snapshot_grid() {
        let t = evaluate_governance(&snapshot);
        let parsed = ParsedLog::parse(&t.to_structured_log());

        assert_eq!(
            parsed.get("decision_id"),
            format!("{}", t.decision_id).as_str()
        );
        assert_eq!(parsed.get("trace_id"), format!("{}", t.trace_id).as_str());
        assert_eq!(parsed.get("action"), t.chosen_action);
        assert_eq!(
            parsed.get("confidence").parse::<u16>().unwrap(),
            t.confidence_score
        );
        assert_eq!(
            parsed.get("uncertainty").parse::<u16>().unwrap(),
            t.uncertainty_score
        );
        assert_eq!(
            parsed.get("fallback").parse::<bool>().unwrap(),
            t.deterministic_fallback_triggered
        );
        assert_eq!(parsed.get("reason"), t.deterministic_fallback_reason);
        assert_eq!(parsed.get("replay"), t.replay_ref);
        assert_eq!(t.replay_ref, G7_DECISION_REPLAY_REF);

        // Posterior array in canonical [healthy, degraded, regression, unknown] order.
        let posterior: Vec<u16> = parsed
            .bracket_list("state_posterior")
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(posterior, t.state_posterior_permille.to_vec());

        // Expected-loss array in [continue, canary_hold, rollback, fallback] order.
        let losses: Vec<u32> = parsed
            .bracket_list("expected_loss")
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(losses, t.expected_loss_terms.to_vec());

        // top=[name:weight, ...] matches the three contributors in order.
        let top = parsed.bracket_list("top");
        assert_eq!(top.len(), 3, "top segment must carry three contributors");
        for (entry, contributor) in top.iter().zip(t.top_evidence_contributors.iter()) {
            let (name, weight) = entry
                .split_once(':')
                .unwrap_or_else(|| panic!("top entry {entry:?} not name:weight"));
            assert_eq!(name, contributor.name);
            assert_eq!(
                weight.parse::<u16>().unwrap(),
                contributor.contribution_permille
            );
        }
    }
}

/// The logged `fallback`/`reason` pair is internally consistent and bridges to
/// the runtime classifier: a triggered fallback always carries a canonical
/// runtime reason, and a non-triggered decision always reports `none`.
#[test]
fn structured_log_fallback_reason_is_classifier_consistent() {
    for snapshot in snapshot_grid() {
        let t = evaluate_governance(&snapshot);
        if t.deterministic_fallback_triggered {
            assert_ne!(t.deterministic_fallback_reason, "none");
            assert!(
                is_runtime_fallback_reason(t.deterministic_fallback_reason),
                "triggered fallback emitted a non-canonical reason {:?} ({snapshot:?})",
                t.deterministic_fallback_reason
            );
        } else {
            assert_eq!(
                t.deterministic_fallback_reason, "none",
                "non-triggered decision must report reason=none ({snapshot:?})"
            );
        }
    }
}

/// Metamorphic law: exhausting the strict feature budget moves probability mass
/// OUT of `healthy` and INTO `regression + unknown`, holding all other inputs
/// fixed. (The conformance suite only checks the posterior sums to 1000.)
#[test]
fn budget_exhaustion_shifts_mass_from_healthy_to_failure_states() {
    let base = GovernanceSnapshot {
        n_rows: 80,
        n_cols: 64,
        density_permille: 300,
        rank_deficit_permille: 250,
        inactivation_pressure_permille: 200,
        overhead_ratio_permille: 240,
        budget_exhausted: false,
        baseline_loss: 500,
        high_support_loss: 560,
        block_schur_loss: 620,
    };
    let exhausted = GovernanceSnapshot {
        budget_exhausted: true,
        ..base
    };

    let calm = RaptorQDecisionContract::state_posterior_permille(&base);
    let busted = RaptorQDecisionContract::state_posterior_permille(&exhausted);

    assert!(
        busted[state::HEALTHY] <= calm[state::HEALTHY],
        "budget exhaustion must not increase healthy mass: calm={calm:?} busted={busted:?}"
    );
    let calm_fail = u32::from(calm[state::REGRESSION]) + u32::from(calm[state::UNKNOWN]);
    let busted_fail = u32::from(busted[state::REGRESSION]) + u32::from(busted[state::UNKNOWN]);
    assert!(
        busted_fail >= calm_fail,
        "budget exhaustion must not decrease regression+unknown mass: \
         calm={calm:?} busted={busted:?}"
    );
    // The effect is non-trivial, not a rounding artifact.
    assert!(
        busted_fail > calm_fail,
        "budget exhaustion should meaningfully raise failure-state mass: \
         calm_fail={calm_fail} busted_fail={busted_fail}"
    );
}

/// Metamorphic law: an unavailable block-Schur loss (`u32::MAX`) never decreases
/// `unknown` mass. We hold the policy-conflict inputs fixed by keeping the finite
/// variant's block-Schur loss strictly above `high_support_loss` (so it never
/// enters the best/second margin computation), isolating the documented
/// "+unknown when block-Schur missing" behavior.
#[test]
fn missing_block_schur_does_not_lower_unknown_mass() {
    let present = GovernanceSnapshot {
        n_rows: 40,
        n_cols: 36,
        density_permille: 220,
        rank_deficit_permille: 100,
        inactivation_pressure_permille: 140,
        overhead_ratio_permille: 180,
        budget_exhausted: false,
        baseline_loss: 100,
        high_support_loss: 200,
        // Strictly above high_support_loss => does not change best/second,
        // so policy_conflict_permille is identical to the missing variant.
        block_schur_loss: 5_000,
    };
    let missing = GovernanceSnapshot {
        block_schur_loss: u32::MAX,
        ..present
    };

    let with = RaptorQDecisionContract::state_posterior_permille(&present);
    let without = RaptorQDecisionContract::state_posterior_permille(&missing);

    assert!(
        without[state::UNKNOWN] >= with[state::UNKNOWN],
        "missing block-Schur must not reduce unknown mass: with={with:?} without={without:?}"
    );
}

/// Input pressures are clamped at 1000 permille: values above the cap yield a
/// byte-identical posterior, so an out-of-range upstream feature cannot perturb
/// the decision beyond saturation.
#[test]
fn pressure_inputs_saturate_at_the_permille_cap() {
    let capped = GovernanceSnapshot {
        n_rows: 50,
        n_cols: 44,
        density_permille: 1_000,
        rank_deficit_permille: 1_000,
        inactivation_pressure_permille: 1_000,
        overhead_ratio_permille: 1_000,
        budget_exhausted: false,
        baseline_loss: 300,
        high_support_loss: 400,
        block_schur_loss: 500,
    };
    let over = GovernanceSnapshot {
        density_permille: 9_999,
        rank_deficit_permille: 50_000,
        inactivation_pressure_permille: 12_345,
        overhead_ratio_permille: 7_777,
        ..capped
    };

    assert_eq!(
        RaptorQDecisionContract::state_posterior_permille(&capped),
        RaptorQDecisionContract::state_posterior_permille(&over),
        "pressures above 1000 permille must saturate to the same posterior as the cap"
    );
}

/// Top evidence contributors are well-formed: non-increasing contribution order,
/// total of exactly 1000 permille (or 0 in the degenerate all-zero-signal case),
/// canonical pairwise-distinct names, and deterministic across re-evaluation.
#[test]
fn top_evidence_contributors_are_well_formed_and_deterministic() {
    const CANONICAL_SIGNALS: [&str; 5] = [
        "correctness_mismatch_signal",
        "performance_budget_signal",
        "instability_signal",
        "cache_policy_signal",
        "policy_conflict_signal",
    ];

    for snapshot in snapshot_grid() {
        let t = evaluate_governance(&snapshot);
        let again = evaluate_governance(&snapshot);
        let top = t.top_evidence_contributors;

        assert_eq!(
            top, again.top_evidence_contributors,
            "top contributors must be deterministic ({snapshot:?})"
        );

        // Non-increasing contribution order.
        assert!(
            top[0].contribution_permille >= top[1].contribution_permille
                && top[1].contribution_permille >= top[2].contribution_permille,
            "contributions must be non-increasing: {:?} ({snapshot:?})",
            top.map(|c| c.contribution_permille)
        );

        // Total is a normalized distribution (or the all-zero degenerate case).
        let total: u32 = top.iter().map(|c| u32::from(c.contribution_permille)).sum();
        assert!(
            total == 1000 || total == 0,
            "contributor permille must total 1000 or 0, got {total} ({snapshot:?})"
        );

        // Canonical, pairwise-distinct signal names.
        for contributor in &top {
            assert!(
                CANONICAL_SIGNALS.contains(&contributor.name),
                "non-canonical contributor name {:?} ({snapshot:?})",
                contributor.name
            );
        }
        assert!(
            top[0].name != top[1].name && top[1].name != top[2].name && top[0].name != top[2].name,
            "top contributors must be distinct signals: {:?} ({snapshot:?})",
            top.map(|c| c.name)
        );
    }
}
