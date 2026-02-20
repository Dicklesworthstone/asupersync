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
- `cards_with_measured_comparator_evidence = 5`
- `cards_pending_measured_evidence = 3`

Closure blockers for `asupersync-3ltrv` remain:

1. Finalize high-confidence offline profile-pack comparator evidence for `E5` (`asupersync-36m6p`) with p95/p99 links (directional p95/p99 corpus now exists; high-confidence run has started targeting `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json` but publication/sign-off is still pending).
2. Promote `F7` from proposed to approved_guarded only after burst comparator evidence + rollback rehearsal outcomes are recorded.
3. Keep `F8` as proposed/template until implementation exists, then attach overlap-vs-sequential evidence and rollback outcomes.

Recent evidence alignment updates (2026-02-19):

- `F6` (`asupersync-j96j4`) moved from template/proposed to approved_guarded in the decision artifact based on closed-bead implementation evidence.
- `E5` card now points to active offline profile-pack bead (`asupersync-36m6p`) and uses deterministic profile-pack replay commands.
- Stale non-existent command flags (`--mode`, `--policy`, `--cache`, `--pipeline`) were replaced with valid deterministic `rch exec -- ...` commands.

Recent evidence alignment updates (2026-02-20):

- Added partial `E5` measured-comparator evidence anchors from latest Track-E execution (`agent-mail asupersync-3ltrv #1383`) and linked bead evidence comments (`asupersync-36m6p` comments `#1848` and `#1855`).
- Added deterministic bench repro commands for E5 comparator capture:
  - `rch exec -- cargo bench --bench raptorq_benchmark -- gf256_primitives`
  - `rch exec -- cargo bench --bench raptorq_benchmark -- gf256_dual_policy`
- Added follow-up E5 evidence from `asupersync-36m6p` comment `#1848` and coord thread updates (`#1408`, `#1410`): manifest snapshot determinism tests + `rch exec -- cargo check --all-targets` pass.
- Added follow-up E5 fifth-slice reproducibility evidence (`asupersync-36m6p` comment `#1855`, agent-mail `#1422/#1424`): deterministic environment metadata now included in manifest snapshots and Track-E policy/probe logs.
- Added sixth-slice comparator artifact `artifacts/raptorq_track_e_gf256_bench_v1.json`: baseline/auto/rollback Track-E capture with rollback rehearsal outcomes.
- Added sixth-slice confirmation references (`agent-mail asupersync-3ltrv #1441`, `coord thread #1443`) to tie the new comparator artifact and rollback capture into G3 evidence flow.
- Added seventh-slice p95/p99-oriented comparator corpus (`artifacts/raptorq_track_e_gf256_p95p99_v1.json`, bead comment `#1863`, agent-mail `#1461/#1465`) and updated blocker wording to reflect this as directional evidence pending final high-confidence corpus closure.
- Added in-progress high-confidence run reference (`coord thread #1487`) with planned closure artifact target `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json`.
- Added ninth-slice run-state note (`coord thread #1493/#1504`): high-confidence reruns temporarily hit unrelated `src/combinator/retry.rs` compile-frontier issues while remediation is active.
- Added follow-up compile verification note: `rch exec -- cargo check -p asupersync --lib` exits 0, so closure focus remains on publishing/signing off the high-confidence E5 artifact.
- Added G7 dependency-state note (`asupersync-m7o6i` comment `#1886`, `coord thread #1520`): targeted expected-loss contract reruns are all PASS; remaining G3 gating remains E5/F7/F8 closure evidence linkage.
- Added independent support refresh (`asupersync-3ltrv` comment `#1896`, agent-mail thread `asupersync-3ltrv` msg `#1555`): fresh `bv --robot-next` still ranks G3 top-impact; targeted `cargo test --test raptorq_perf_invariants g3_decision -- --nocapture` rerun is PASS (2/2), and cross-agent request for latest E5/F7/F8 closure anchors has been rebroadcast in-thread.
- Removed stale compile-mismatch blocker text; current E5 blocker is narrowed to missing final p95/p99 comparator corpus.
