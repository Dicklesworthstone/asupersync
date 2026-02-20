# RaptorQ Expected-Loss Decision Contract (G7 / bd-2bd8e)

This document defines the G7 decision contract for rollout, abort, and fallback
actions as a deterministic expected-loss policy.

- Bead: `asupersync-m7o6i`
- Parent track: `asupersync-2cyx5`
- External ref: `bd-2bd8e`
- Canonical artifact: `artifacts/raptorq_expected_loss_decision_contract_v1.json`

## Contract Model

The contract defines explicit decision states:

1. `healthy`
2. `degraded`
3. `regression`
4. `unknown`

The contract defines explicit actions:

1. `continue`
2. `canary_hold`
3. `rollback`
4. `fallback`

Action choice is `argmin_expected_loss` over the current state posterior with a
deterministic tie-breaker:

1. `fallback`
2. `rollback`
3. `canary_hold`
4. `continue`

## Asymmetric Loss Discipline

The loss matrix is intentionally asymmetric.

- In `regression`/`unknown`, `rollback` and `fallback` are lower loss than
  `continue`.
- In `healthy`, `continue` is lower loss than disruptive actions.

This prevents optimistic bias during uncertain or conflicting evidence windows.

## Runtime Control Surface Mapping

The contract is wired to in-scope runtime levers:

1. `E4`
2. `E5`
3. `C5`
4. `C6`
5. `F5`
6. `F6`
7. `F7`
8. `F8`

For each lever, the artifact maps concrete control fields (for example
`decode.stats.policy_mode`, `decode.stats.regime_state`,
`decode.stats.factor_cache_last_reason`) and expected action semantics.

## Required Decision Output

Each decision record must emit:

1. `state_posterior`
2. `expected_loss_terms`
3. `chosen_action`
4. `top_evidence_contributors`
5. `confidence_score`
6. `uncertainty_score`
7. `deterministic_fallback_trigger`
8. `replay_ref`

## Deterministic Fallback Trigger

Fallback is mandatory if any hard-trigger condition is true:

1. decode mismatch detected
2. proof replay mismatch
3. unknown state with low confidence
4. unclassified conservative fallback reason

## Logging and Reproducibility

Structured decision logs must include state posterior, loss terms, chosen action,
contributors, confidence/uncertainty, and replay pointer.

Cargo-heavy validation and replay commands must use `rch`:

- `rch exec -- cargo ...`

Primary replay anchor:

- `rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_schema_and_coverage -- --nocapture`

## Closure Notes

`asupersync-m7o6i` can close after:

1. final G3 decision-card closure refs are attached,
2. deterministic E2E decision-path scenarios are attached for conflicting evidence,
3. Track-G summary packet references this contract artifact as the canonical G7 source.
