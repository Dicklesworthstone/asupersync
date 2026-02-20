# RaptorQ Controlled Rollout Policy (G4 / bd-2frfp)

This document is the operator-facing reference for controlled rollout and rollback of
high-impact RaptorQ optimization levers.

- Bead: `asupersync-23kd4`
- Parent track: `asupersync-2cyx5`
- External ref: `bd-2frfp`
- Canonical artifact: `artifacts/raptorq_controlled_rollout_policy_v1.json`
- Decision-card baseline: `artifacts/raptorq_optimization_decision_records_v1.json`

## Scope

This policy applies to the high-impact levers required by G3/G4:

- `E4`
- `E5`
- `C5`
- `C6`
- `F5`
- `F6`
- `F7`
- `F8`

Each lever must have:

1. Approved or approved_guarded decision-card status for rollout entry.
2. Explicit conservative comparator mode.
3. Replayable rollback command and post-rollback checklist.

## Prerequisite Gates

Rollout progression requires all prerequisite beads and evidence gates:

1. `asupersync-3ltrv` (G3 decision records) is active and current.
2. `asupersync-3ec61` (G2 CI regression gates) is closed.
3. `asupersync-1xbzk` (G6 triage/report playbook) is closed.
4. Deterministic unit + deterministic E2E evidence bundles are attached.
5. Structured logs include scenario id, seed, outcome, and artifact pointers.

## Staged Rollout Model

Stages must execute in this exact order:

1. `shadow_observe`
2. `canary`
3. `guarded_ramp`
4. `broad_default`

At each stage:

1. Entry criteria must be explicitly marked complete.
2. Hold requirements must remain green for the stage window.
3. Any stop condition triggers rollback actions immediately.

## Stop and Rollback Triggers

Trigger classes:

1. `correctness_regression`
2. `performance_budget_breach`
3. `instability_signal`

Mandatory rollback action sequence:

1. Force conservative comparator mode for the affected lever.
2. Run deterministic replay bundle (`seed=424242`) and attach logs/artifacts.
3. Capture unit + deterministic E2E + benchmark evidence.
4. Publish incident update using required communication template fields.

## Cargo/Build Execution Policy

All CPU-intensive cargo commands must be offloaded with `rch`:

- Required pattern: `rch exec -- <cargo command>`
- This applies to check/test/bench/clippy used for rollout evidence.

## Operator Response Packet

Every rollback or stop event requires:

1. `symptom`
2. `exposure_scope`
3. `affected_levers`
4. `mitigation_executed`
5. `replay_command`
6. `artifact_path`
7. `eta`
8. `user_impact_message_template`

The user-impact message template must include:

1. Symptom
2. User scope
3. Mitigation in place
4. Current fallback mode
5. Next update ETA

## Notes for Closure

`asupersync-23kd4` can close once this policy is fully wired to final G3 decision-card
evidence and Track-E/F closure artifacts, with no missing replay pointers.
