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

The contract artifact also defines a deterministic decision replay bundle linked
to:

- `artifacts/raptorq_replay_catalog_v1.json`

The replay bundle must include fixed-input decision samples for:

1. `normal`
2. `edge`
3. `conflicting_evidence`

Each sample carries a full decision-output payload (`state_posterior`,
`expected_loss_terms`, `chosen_action`, `top_evidence_contributors`,
`confidence_score`, `uncertainty_score`, `deterministic_fallback_trigger`,
`replay_ref`) so outcomes are reproducible from artifact-only inputs.

Cargo-heavy validation and replay commands must use `rch`:

- `rch exec -- cargo ...`

Primary replay anchor:

- `rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_schema_and_coverage -- --nocapture`

## Closure Readiness Contract

The artifact includes a machine-checkable `closure_readiness` section to avoid
hand-off ambiguity while dependencies are still active.

Current dependency set in the artifact:

1. `asupersync-3ltrv` (G3 decision records) must be `closed`
2. `asupersync-36m6p` (E5 high-confidence p95/p99 corpus) must be `closed`
3. `asupersync-n5fk6` (F7 final closure evidence in G3 cards) must be `closed`
4. `asupersync-2zu9p` (F8 implementation + closure evidence) must be `closed`

Current closure-readiness status (2026-03-05 refresh):

- `asupersync-3ltrv`: `closed`
- `asupersync-n5fk6`: `closed`
- `asupersync-2zu9p`: `closed`
- `asupersync-36m6p`: still `in_progress`

`ready_to_close` remains `false` because `asupersync-36m6p` has not yet reached
`closed`.

Track-G handoff packet fields (`gate_verdict_table`, `artifact_replay_index`,
`residual_risk_register`, `go_no_go_decision`) are now attached in
`artifacts/raptorq_program_closure_signoff_packet_v1.json` and recorded under
`closure_readiness.track_g_handoff.attached_packet_fields`.

## Closure Notes

`asupersync-m7o6i` can close after:

1. `asupersync-36m6p` reaches `closed` (dependency status requirement),
2. Track-G summary packet for `asupersync-2cyx5` remains synchronized with this contract artifact as the canonical G7 source.
