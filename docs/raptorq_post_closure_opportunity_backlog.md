# RaptorQ Post-Closure Opportunity Backlog (H3 / bd-3gmf5)

This document defines the post-closure opportunity queue for H3:

- Bead: `asupersync-387as`
- Parent track: `asupersync-p8o9m`
- External ref: `bd-3gmf5`
- Canonical artifact: `artifacts/raptorq_post_closure_opportunity_backlog_v1.json`

## Purpose

H3 captures high-upside follow-on work so future execution can start from a
deterministic, evidence-linked queue instead of rediscovery.

Each backlog entry is required to include:

1. dependency anchors (beads + artifacts),
2. expected value and strategic fit scores,
3. explicit unit and deterministic E2E expectations,
4. structured logging/replay requirements,
5. measurable user-facing success metrics.

## Evidence Baseline

All opportunities are grounded in the closure-era governance/performance
artifacts:

1. `artifacts/raptorq_optimization_decision_records_v1.json`
2. `artifacts/raptorq_controlled_rollout_policy_v1.json`
3. `artifacts/raptorq_expected_loss_decision_contract_v1.json`
4. `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json`
5. `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json`
6. `artifacts/raptorq_track_f_factor_cache_p95p99_v3.json`
7. `artifacts/raptorq_track_f_wavefront_pipeline_v1.json`

For Track-E-derived opportunities, H3 keeps both current closure anchors visible:
`highconf_v1` remains the narrowed not-ready guardrail, while
`multiscenario_refresh_v5` is the broader favorable-but-not-closure-grade
successor packet surfaced by the live H2 closure contract.

## Scoring Model

The artifact uses deterministic ranking:

- `composite_score = round(0.6 * expected_value_score + 0.4 * strategic_fit_score)`
- tie-breaker: higher `strategic_fit_score`, then lexicographic
  `opportunity_id`

Score range: `[0, 100]`.

## Current Ranked Queue

1. `RQ-H3-001` Expand GF256 profile packs to AVX-512/SVE2.
2. `RQ-H3-003` Adaptive repair-budget controller driven by expected-loss.
3. `RQ-H3-002` Large-k wavefront scaling with memory-aware batching.
4. `RQ-H3-004` Automated replay minimizer for regression triage.
5. `RQ-H3-005` Interop-focused conformance extension corpus.

## Entry Contract for New Backlog Items

Every new H3 item must be execution-ready and include:

1. At least one bead prerequisite and one artifact prerequisite.
2. At least one user benefit hypothesis and two measurable success metrics.
3. Unit-test expectations that are deterministic and replayable.
4. Deterministic E2E expectations with fixed-seed campaign coverage.
5. Structured log requirements that include scenario/replay pointers.
6. At least one starter command that uses `rch exec --` for cargo-heavy steps.

## Operational Notes

- H3 is a planning/backlog lane, not a bypass for Track-G/H gates.
- Opportunities should be promoted into concrete beads only when dependencies
  are satisfiable and closure evidence remains reproducible.
- Track-E follow-on items must preserve the current `highconf_v1` plus
  `multiscenario_refresh_v5` gating story until `asupersync-36m6p` actually
  closes.
- Cargo-heavy commands in this queue must continue to run via `rch exec --`.
