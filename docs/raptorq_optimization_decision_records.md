# RaptorQ Optimization Decision Records (G3 / bd-7toum)

This document is the human-readable index for the optimization decision cards required by:

- Bead: `asupersync-3ltrv`
- External ref: `bd-7toum`
- Artifact: `artifacts/raptorq_optimization_decision_records_v1.json`

The decision-card artifact is the canonical source for:

1. Expected value and risk classification.
2. Proof-safety constraints.
3. Adoption wedge and conservative comparator.
4. Fallback and rollback rehearsal commands.
5. Validation evidence and deterministic replay commands.

## Decision Template (Required Fields)

Every card uses the same minimum schema:

- `decision_id`
- `lever_code`
- `lever_bead_id`
- `summary`
- `expected_value`
- `risk_class`
- `proof_safety_constraints`
- `adoption_wedge`
- `conservative_comparator`
- `fallback_plan`
- `rollback_rehearsal`
- `validation_evidence`
- `deterministic_replay`
- `owner`
- `status`

Status values:

- `approved`
- `approved_guarded`
- `proposed`
- `hold`

## High-Impact Lever Coverage

The G3 acceptance criteria require dedicated cards for:

- `E4` -> `asupersync-348uw`
- `E5` -> `asupersync-36m6p` and `asupersync-2ncba.1` (closed scalar optimization slice)
- `C5` -> `asupersync-zfn8v`
- `C6` -> `asupersync-2qfjd`
- `F5` -> `asupersync-324sc`
- `F6` -> `asupersync-j96j4`
- `F7` -> `asupersync-n5fk6`
- `F8` -> `asupersync-2zu9p`

## Comparator and Replay Policy

For each card, two deterministic commands are recorded:

1. `pre_change_command` (conservative baseline).
2. `post_change_command` (optimized mode under test).

Command policy:

- Use `rch exec -- ...` for all cargo/bench/test execution.
- Pin deterministic seed (`424242`) and scenario ID in each card.
- Keep conservative mode runnable even after optimization adoption.

## Rollback Rehearsal Contract

Each card includes:

1. A direct rollback rehearsal command.
2. A post-rollback verification checklist.

Minimum checklist requirements:

1. Conservative mode is actually active.
2. Deterministic replay artifacts are emitted.
3. Unit and deterministic E2E gates remain green.

## Current Program State

Current artifact summary (`coverage_summary` in JSON):

- `cards_total = 8`
- `cards_with_replay_commands = 8`
- `cards_with_measured_comparator_evidence = 3`
- `cards_pending_measured_evidence = 5`

Closure blockers for `asupersync-3ltrv` remain:

1. Fill measured comparator evidence for open/planned levers (`E5` offline pack, `F6`, `F7`, `F8`).
2. Record completed rollback rehearsal outcomes per card.
3. Link final passing comprehensive unit + deterministic E2E evidence for all approved cards.
