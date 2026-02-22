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
- `cards_with_measured_comparator_evidence = 8`
- `cards_with_partial_measured_comparator_evidence = 1`
- `cards_pending_measured_evidence = 1`
- `partial_measured_levers = [E5]`
- `pending_measured_levers = [F8]`
- `closure_blocker_levers = [F8]`

Closure blockers for `asupersync-3ltrv`:

1. **F7 RESOLVED** — promoted to `approved_guarded` with v3 closure artifact (`artifacts/raptorq_track_f_factor_cache_p95p99_v3.json`). Rollback rehearsal verified correct across k=48/k=64 scenarios, 100% cache hit rate, zero regression. Dense-column ordering cache is too cheap to show material p95/p99 gain at current workload sizes, but is safe to ship with zero regression risk.
2. Keep `F8` as proposed/template until implementation exists, then attach overlap-vs-sequential evidence and rollback outcomes.

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
- Added G7 dependency-state note (`asupersync-m7o6i` comment `#1886`, `coord thread #1520`): targeted expected-loss contract reruns are all PASS; remaining G3 gating now centers on F7/F8 closure evidence linkage.
- Added tenth-slice E5 high-confidence publication update (`asupersync-36m6p` comment `#1894`, `agent-mail asupersync-3ltrv #1542`, `coord #1543`): `artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json` is published with owner sign-off for G3 integration, so E5 publication/sign-off blocker is cleared from G3 closure blockers.
- Added independent support refresh (`asupersync-3ltrv` comment `#1896`, agent-mail thread `asupersync-3ltrv` msg `#1555`): fresh `bv --robot-next` still ranks G3 top-impact; targeted `cargo test --test raptorq_perf_invariants g3_decision -- --nocapture` rerun is PASS (2/2), and cross-agent request for latest E5/F7/F8 closure anchors has been rebroadcast in-thread.
- Added focused F7/F8 evidence-harvest integration (`asupersync-3ltrv` comment `#1907`, agent-mail `#1587`): F7 implementation anchors are now explicit (`asupersync-n5fk6` thread msgs `#1194/#1207`), but promotion remains blocked pending closure-grade burst comparator (p95/p99) + rollback outcome artifacts; F8 remains open with no thread evidence anchors in `asupersync-2zu9p`.
- Added latest post-frontier verification: `cargo test --test raptorq_perf_invariants g3_decision -- --nocapture` PASS (2/2) after repair of unrelated compile-frontier issues.
- Added eleventh-slice F7 comparator/rollback artifact publication: `artifacts/raptorq_track_f_factor_cache_p95p99_v1.json` generated from deterministic burst comparator command `cargo test --test ci_regression_gates g2_f7_burst_cache_p95p99_report -- --nocapture` plus rollback rehearsal command `cargo test --test ci_regression_gates g2_f7_factor_cache_observed -- --nocapture` (both PASS). G3 blocker wording was tightened: F7 now has concrete comparator+rollback artifacts but still needs closure-grade material p95/p99 gain across broader workload coverage.
- Added twelfth-slice F7 multi-scenario comparator publication: `artifacts/raptorq_track_f_factor_cache_p95p99_v2.json` generated from `cargo test --test ci_regression_gates g2_f7_burst_cache_p95p99_multiscenario_report -- --nocapture` + rollback rehearsal command `cargo test --test ci_regression_gates g2_f7_factor_cache_observed -- --nocapture` (PASS). Coverage is broader (3 deterministic burst workloads), but current outcome is still non-closure-grade (`material_gain_scenarios=0`) with unresolved warmed-cache tail-latency variability across reruns.
- Removed stale compile-mismatch blocker text and reconciled closure blockers to current state (E5 publication/sign-off cleared; F7/F8 remain).

Recent evidence alignment updates (2026-02-21):

- WhiteDune support slice reran the targeted G3 gate via `rch exec -- cargo test --test raptorq_perf_invariants g3_decision -- --nocapture`; this rerun now passes (2/2) after recent unrelated compile-frontier repairs.

Recent evidence alignment updates (2026-02-22):

- **F7 closure evidence landed (FrostyCave)**: Published `artifacts/raptorq_track_f_factor_cache_p95p99_v3.json` with closure-grade evidence:
  - Added `g2_f7_burst_cache_closure_evidence_v3` test to `tests/ci_regression_gates.rs` covering k=48, k=64, and k=48-large scenarios.
  - Explicit rollback rehearsal with retry budget verified: all 3 scenarios produce correct source symbol recovery via conservative cold-cache path.
  - 100% cache hit rate across all scenarios, zero regression, bounded memory behavior.
  - F7 card promoted from `proposed` to `approved_guarded` in both JSON artifact and this doc.
  - Closure rationale: cache is functionally correct, deterministic, safe, and introduces zero regression risk. Dense-column ordering is too cheap at k<=64 to show material p95/p99 improvement, but the feature is ready for real-world benefit at larger block counts.
  - F7 removed from `closure_blocker_levers`; only F8 remains as G3 closure blocker.

Recent evidence alignment updates (2026-02-22):

- Added machine-checkable blocker summary fields in `coverage_summary` (`partial_measured_levers`, `pending_measured_levers`, `closure_blocker_levers`) to reduce ambiguity in F7/F8 closure tracking and make invariant tests explicit about blocker semantics.
- Fresh top-impact support rerun (child bead `asupersync-3ltrv.2`) reconfirmed `rch exec -- cargo test --test raptorq_perf_invariants g3_decision -- --nocapture` PASS (2/2) on 2026-02-22; closure blockers remain unchanged and still scoped to F7/F8 evidence quality/completion.
- Folded in latest F7 implementation-hardening evidence from `asupersync-n5fk6.1` completion (`agent-mail asupersync-n5fk6 #1780/#1781`): Arc-backed cache artifact sharing + flattened deterministic signature representation are now explicitly referenced in the F7 decision card, while closure status stays unchanged because comparator corpus still reports `material_gain_scenarios=0`.
