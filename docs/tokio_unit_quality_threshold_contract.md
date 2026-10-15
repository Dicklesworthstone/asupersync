# Cross-Track Unit-Test Quality Threshold Contract

**Bead**: `asupersync-2oh2u.10.11` ([T8.11])  
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])  
**Date**: 2026-03-03  
**Purpose**: define deterministic, machine-enforceable unit-test depth and quality
thresholds across Tokio-replacement tracks before cross-track closure gates can pass.

---

## 1. Scope

This contract governs unit-test quality policy for the following prerequisite beads:

- `asupersync-2oh2u.2.9` (Async I/O + codec unit matrix)
- `asupersync-2oh2u.3.9` (fs/process/signal unit matrix)
- `asupersync-2oh2u.4.10` (QUIC/H3 unit/protocol matrix)
- `asupersync-2oh2u.5.11` (web/middleware/gRPC unit matrix)
- `asupersync-2oh2u.6.12` (database/messaging unit matrix)
- `asupersync-2oh2u.7.10` (adapter boundary unit matrix)

This bead does not replace track-specific tests. It sets cross-track quality floors
and hard-fail CI policy.

---

## 2. Unit-Test Matrix Contract

Each track-level unit suite MUST publish and enforce all required categories:

| Category | Required | Notes |
|---|---|---|
| Happy path | yes | canonical success behavior |
| Edge cases | yes | bounds, empty inputs, max/min values |
| Error paths | yes | malformed input, protocol violations, transient failures |
| Cancellation race invariants | yes | loser-drain, cancellation checkpoints, cleanup order |
| Leak invariants | yes | no task leak, no obligation leak, region close quiescence |

Minimum per-track category coverage is `>= 1` test per category. In practice, each
track SHOULD exceed this baseline substantially.

### 2.1 Cross-Track Minimum Quality Thresholds

| Threshold ID | Requirement | Hard-Fail Condition |
|---|---|---|
| `TQ-01` | Per-track unit test count `>= 20` | count below 20 for any track |
| `TQ-02` | `(edge + error) / happy >= 0.50` | ratio below 0.50 for any track |
| `TQ-03` | `(cancel + leak) >= 4` | fewer than 4 cancellation/leak-focused tests |
| `TQ-04` | flaky retry pass rate = 0 tolerated | any retry-only pass in gated unit runs |

Thresholds are deterministic policy floors and cannot be waived silently.

---

## 3. Deterministic Quality Gates (Normative)

| Gate ID | Gate | Hard-Fail Conditions |
|---|---|---|
| `UQ-01` | Required category coverage | any missing category in a track matrix |
| `UQ-02` | Deterministic execution | non-deterministic/flaky unit test outcomes |
| `UQ-03` | Cancellation race assertions | missing cancellation-race invariant assertions |
| `UQ-04` | Leak-oracle enforcement | missing leak-oracle checks on concurrency-sensitive tests |
| `UQ-05` | Cross-track threshold regression | threshold drop vs. last accepted baseline |
| `UQ-06` | Artifact completeness | missing per-track manifest or triage pointers |

All `UQ-*` gates are hard-fail. No soft-pass mode exists for replacement closure.

---

## 4. Leak-Oracle Requirements

For concurrency-sensitive paths, unit suites MUST include explicit checks for:

- `no_task_leak`
- `no_obligation_leak`
- `region_close_quiescence`
- `loser_drain_complete`

When a track cannot run a given oracle due to surface limitations, it MUST emit
explicit `oracle_not_applicable` evidence with rationale and owner.

---

## 5. CI Enforcement and Commands

Heavy checks MUST be executed with `rch exec --` when run manually or in shared
agent environments.

Required command tokens:

- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo check --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo clippy --all-targets -- -D warnings`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo fmt --check`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo test --test tokio_unit_quality_threshold_contract -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo test --test tokio_io_parity_audit -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo test --test tokio_fs_process_signal_parity_matrix -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo test --test tokio_web_grpc_parity_map -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_unit_quality_docs cargo test --test tokio_ecosystem_capability_inventory -- --nocapture`

Track unit suites are expected to publish dedicated commands in their own contracts;
this gate validates their aggregated quality manifests and threshold outcomes.

---

## 6. Required Artifacts

Every T8.11 evaluation run MUST emit:

- `tokio_unit_quality_manifest.json`
- `tokio_unit_quality_report.md`
- `tokio_unit_quality_failures.json`
- `tokio_unit_quality_triage_pointers.txt`

Missing artifacts fail `UQ-06`.

---

## 7. Manifest Schema (Minimum)

Each track entry in `tokio_unit_quality_manifest.json` MUST include:

| Field | Required | Description |
|---|---|---|
| `track_id` | yes | source track (`T2`..`T7`) |
| `bead_id` | yes | owning unit-matrix bead id |
| `commit_sha` | yes | evaluated revision |
| `category_counts` | yes | counts for happy/edge/error/cancel/leak |
| `threshold_result` | yes | pass/fail for each `UQ-*` gate |
| `oracle_status` | yes | leak-oracle execution outcomes |
| `threshold_metrics` | yes | numeric values for `TQ-01`..`TQ-04` evaluation |
| `repro_commands` | yes | deterministic rerun commands for failures |
| `artifact_links` | yes | pointers to logs/traces/failure payloads |

---

## 8. Failure Routing and Triage

`tokio_unit_quality_failures.json` MUST classify each failure with:

- `gate_id` (`UQ-01`..`UQ-06`)
- `track_id`
- `bead_id`
- `severity`
- `owner`
- `repro_command`
- `first_failing_commit`

`tokio_unit_quality_triage_pointers.txt` MUST include one-command rerun entries for
every failing track and gate combination.

---

## 9. Downstream Binding

This contract is a blocker for:

- `asupersync-2oh2u.10.12` (cross-track e2e logging gates)
- `asupersync-2oh2u.10.9` (final replacement-readiness aggregator)

T8.11 is complete only when gates and artifacts are deterministic, hard-fail,
and reproducible from declared evidence.
