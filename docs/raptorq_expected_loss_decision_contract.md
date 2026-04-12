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

1. `decode_mismatch_detected` (decode mismatch detected)
2. `proof_replay_mismatch` (proof replay mismatch)
3. `policy_budget_exhausted` (runtime policy budget exhausted before a safe higher-confidence decision)
4. `unknown_state_with_low_confidence`
5. `regression_state_with_low_confidence`
6. `conservative_fallback_reason_unclassified`

The live runtime reason set emitted by `src/raptorq/decision_contract.rs`
currently covers `policy_budget_exhausted`,
`unknown_state_with_low_confidence`,
`regression_state_with_low_confidence`, and
`conservative_fallback_reason_unclassified`. The decode/proof mismatch triggers
remain part of the broader contract because downstream validation and replay
surfaces can force the same deterministic fallback action.

## Logging and Reproducibility

Structured decision logs must include state posterior, loss terms, chosen action,
contributors, confidence/uncertainty, and replay pointer.

The contract artifact also defines a deterministic decision replay bundle linked
to:

- `artifacts/raptorq_replay_catalog_v1.json`

Track-E evidence consumed by the expected-loss gate stays anchored to:

- `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json`
  (`highconf_v1`, `narrowed closure-status guardrail`)
- `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json`
  (`short_window_directional_not_closure_grade`,
  `historical short-window directional packet`)
- `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json`
  (`longer_window_interval_proxy_negative_guardrail`,
  `historical broader interval-proxy negative guardrail`)
- `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json`
  (`raw_sample_mixed_signal_not_closure_grade`,
  `current mixed-signal raw-sample blocker`)

`highconf_v1` remains the narrowed closure-status guardrail, `v2` and `v3`
remain historical broader packets, and `v4` is the current broader blocker
consumed by G7 and the Track-G handoff.

The replay bundle must include fixed-input decision samples for:

1. `normal`
2. `edge`
3. `conflicting_evidence`

Each sample carries a full decision-output payload (`state_posterior`,
`expected_loss_terms`, `chosen_action`, `top_evidence_contributors`,
`confidence_score`, `uncertainty_score`, `deterministic_fallback_trigger`,
`replay_ref`) so outcomes are reproducible from artifact-only inputs.

Cargo-heavy validation and replay commands must use `rch`:

- `rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_schema_and_coverage -- --nocapture`
- `rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_replay_bundle_is_well_formed -- --nocapture`
- `rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_docs_are_cross_linked -- --nocapture`

Because those G7 checks compare `closure_readiness` status fields against live
Beads state, the artifact also defines a machine-checkable
`reproducibility.status_snapshot_contract`. On shared rch workers, export
`ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON` from the caller workspace snapshot of
`.beads/issues.jsonl` for `asupersync-2cyx5`, `asupersync-36m6p`,
`asupersync-3ltrv`, `asupersync-n5fk6`, and `asupersync-2zu9p`; shared workers
can otherwise observe stale Beads JSONL during multi-agent sync races.

## Closure Readiness Contract

The artifact includes a machine-checkable `closure_readiness` section to avoid
hand-off ambiguity while dependencies are still active.

Current dependency set in the artifact:

1. `asupersync-3ltrv` (G3 decision records) must be `closed`
2. `asupersync-36m6p` (E5 Track-E evidence lineage: `highconf_v1` + v2/v3
   history + v4 blocker) must be `closed`
3. `asupersync-n5fk6` (F7 final closure evidence in G3 cards) must be `closed`
4. `asupersync-2zu9p` (F8 implementation + closure evidence) must be `closed`

Dependency shorthand: `highconf_v1 + v2/v3 history + v4 blocker`.

Current closure-readiness status (2026-04-10 refresh):

- `asupersync-3ltrv`: `closed`
- `asupersync-n5fk6`: `closed`
- `asupersync-2zu9p`: `closed`
- `asupersync-36m6p`: still `in_progress`

`ready_to_close` remains `false` because `asupersync-36m6p` has not yet reached
`closed`.

The current unresolved broader blocker in that dependency lineage is
`artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json`; `highconf_v1`
stays the narrowed guardrail and `v2`/`v3` stay historical.

Track-G handoff packet fields (`gate_verdict_table`, `artifact_replay_index`,
`residual_risk_register`, `go_no_go_decision`) are now attached in
`artifacts/raptorq_program_closure_signoff_packet_v1.json` and recorded under
`closure_readiness.track_g_handoff.attached_packet_fields`. Track-G itself
remains `open` after stale-triage reopen, and that live state is now recorded
under `closure_readiness.track_g_handoff.current_status` so the G7 contract
does not rely on bead id alone.

The handoff remains machine-checkable through four explicit fields on
`closure_readiness.track_g_handoff`:

1. `required_packet_fields`
2. `attached_packet_fields`
3. `attachment_status`
4. `evidence_ref`

`required_packet_fields` and `attached_packet_fields` must match exactly while
the handoff stays blocked, `attachment_status` must remain
`complete_in_h2_packet_pending_track_g_closure`, and `evidence_ref` must stay
anchored to `artifacts/raptorq_program_closure_signoff_packet_v1.json`.

## Closure Notes

`asupersync-m7o6i` can close after:

1. `asupersync-36m6p` reaches `closed` (dependency status requirement),
2. Track-G summary packet for `asupersync-2cyx5` remains synchronized with this contract artifact as the canonical G7 source.
