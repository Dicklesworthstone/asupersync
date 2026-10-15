# Runtime Workload Corpus Contract

Bead: `asupersync-1508v.1.5`

## Purpose

This contract defines the canonical replayable workload corpus used by the runtime-ascension baseline tracks. It keeps the corpus intentionally small, stable, and replayable: one core scenario per required workload family plus optional expansion packs that add coverage without changing the baseline denominator.

The contract is split into:

1. A versioned corpus artifact in `artifacts/runtime_workload_corpus_v1.json`
2. A local bundle runner in `scripts/run_runtime_workload_corpus.sh`
3. Invariant tests in `tests/runtime_workload_corpus_contract.rs`

## Corpus Shape

Each workload entry carries two commands:

1. `replay_command`: the one-command user-facing replay path that goes through the bundle runner
2. `entry_command`: the underlying bench or E2E command that the runner executes

The runner is the canonical path because it always emits a local bundle manifest, captures stdout or stderr to a stable log path, and preserves structured replay metadata even when the underlying entry point is a plain `cargo test`.

## Runtime Profiles

The corpus uses four stable runtime profiles:

| Profile | Meaning |
| --- | --- |
| `bench-release` | Native release-mode benchmark hot paths |
| `native-e2e` | Host integration suites that exercise runtime + protocol surfaces |
| `lab-deterministic` | Pure deterministic lab or oracle-driven replay workloads |
| `distributed-shadow` | Deterministic multi-node and fault-script preview runs |

## Core Set

The canonical core set must cover these workload families:

| Family | Core workload ID | Purpose |
| --- | --- | --- |
| `cpu-heavy` | `AA01-WL-CPU-001` | Throughput baseline for scheduler and phase-0 hot paths |
| `cancellation-heavy` | `AA01-WL-CANCEL-001` | Cancel storm and loser-drain pressure |
| `io-heavy` | `AA01-WL-IO-001` | Transport-heavy host I/O validation |
| `bursty` | `AA01-WL-BURST-001` | Scheduler burst and wakeup stress |
| `timer-heavy` | `AA01-WL-TIMER-001` | Timer wheel and timeout replay anchor |
| `fan-out/fan-in` | `AA01-WL-FANIO-001` | Messaging fan-out and aggregation pressure |
| `distributed-preview` | `AA01-WL-DIST-001` | Multi-node preview with distributed invariants |

The core set must include both:

1. Happy-path throughput workloads
2. Pathological tail or failure workloads

## Expansion Packs

Expansion packs are allowed, but they must remain outside the baseline denominator unless intentionally promoted into the core set. The v1 corpus includes these optional packs:

- `http-application-io`: adds `AA01-WL-IO-HTTP-EX1` for application-layer HTTP request or response coverage without changing the core set size
- `agent-swarm-coordination-pressure`: adds `ASWARM-WL-*` workloads synthesized from redacted coordination bundles. These workloads model real Agent Mail, Beads, bv, rch, git dirty-frontier, and proof-artifact pressure while preserving the seven-workload core denominator.

The coordination pack covers:

| Scenario family | Runtime workload | Semantic pressure | Provenance-only context |
| --- | --- | --- | --- |
| `tracker_lock_contention` | `ASWARM-WL-LOCK-001` | metadata lock waiters, serialized claim backlog, queue residency tail | hashed lock path, pseudonymized holder, bead/thread id |
| `concurrent_rch_proofs` | `ASWARM-WL-RCH-001` | validation fanout, remote proof queue depth, artifact retrieval tail | redacted worker pool, hashed proof command, bead id |
| `fail_closed_dirty_frontier` | `ASWARM-WL-DIRTY-001` | admission refusal, unsupported dirty-frontier count, operator retry pressure | path hashes, dirty path count, redaction verdict |
| `artifact_retrieval_tail` | `ASWARM-WL-ARTIFACT-001` | artifact fetch fanout, result materialization tail, summary index pressure | artifact kind, artifact path hash, source bead id |
| `proof_runner_fanout` | `ASWARM-WL-FANOUT-001` | parallel proof launch, ack-free notification burst, ready queue burst | message subject hash, pseudonymized sender, thread id |
| `stale_in_progress_reclaim` | `ASWARM-WL-STALE-001` | stale work requeue, tracker priority rebalance, operator recovery loop | pseudonymized assignee, updated-at bucket, dependency count |
| `coordination_latency_burst` | `ASWARM-WL-LATENCY-001` | ack-required message burst, coordination round-trip tail, operator latency amplification | message id, thread id, ack-required flag |

For `concurrent_rch_proofs`, synthesis also emits an `rch_pressure_summary`
inside the expansion pack, scheduler evidence input, and synthesis report. The
summary keeps only deterministic pressure classes: queue-depth bucket, maximum
queue depth, proof fanout count, artifact-retrieval-tail bucket, timeout or
refusal reasons, and command-class hashes. It never carries raw worker names,
hostnames, command text, or artifact paths.

## Reproducibility Bundle Format

Every runner-emitted bundle manifest must include:

- `workload_id`
- `family`
- `scenario_id`
- `runtime_profile`
- `seed`
- `workload_config_ref`
- `artifact_path`
- `run_log_path`
- `entry_command`
- `replay_command`
- `status`
- `exit_code`

Every workload entry in the artifact must also declare its expected artifact bundle with stable path globs so later controller, benchmark, and shadow-run tracks can consume the same evidence surfaces.

The coordination synthesis mode emits:

- `coordination-workload-expansion-pack.json`
- `coordination-scheduler-evidence-inputs.json`
- `coordination-workload-synthesis-report.json`
- `coordination-workload-expansion.jsonl`
- `coordination-workload-synthesis.summary.txt`

Focused fixture command:

```bash
bash scripts/run_runtime_workload_corpus.sh --synthesize-coordination-pack --coordination-fixture --output-root target/workload-corpus
```

Focused refusal fixture:

```bash
bash scripts/run_runtime_workload_corpus.sh --synthesize-coordination-pack --coordination-fixture-id refused-missing-scenario-dimensions --output-root target/workload-corpus
```

## Structured Log Requirements

The canonical structured replay surface is the runner-emitted bundle manifest at:

- `target/workload-corpus/run_*/<WORKLOAD_ID>/bundle_manifest.json`

That manifest is the minimum required structured log. Underlying suite or benchmark runners may emit richer JSON summaries, but the bundle manifest is the stable denominator and must include:

1. `workload_id`
2. `scenario_id`
3. `seed`
4. `runtime_profile`
5. `workload_config_ref`
6. `artifact_path`
7. `replay_command`

All heavy underlying cargo operations must be routed through `rch`, either directly in `entry_command` with `RCH_REQUIRE_REMOTE=1` or indirectly through an `RCH_BIN=rch` script runner.

## Validation

The invariant suite for this contract lives in `tests/runtime_workload_corpus_contract.rs`.

Focused reproduction:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-pearldog-aa012 cargo test --test runtime_workload_corpus_contract -- --nocapture
```

The validation checks:

1. The doc section structure stays stable.
2. The artifact retains the required family and runtime-profile coverage.
3. Every replay command resolves through the bundle runner.
4. Every underlying entry command stays `rch`-routed and references a real script or test file.
5. Core-set and expansion-pack IDs remain internally consistent.
6. Coordination expansion-pack synthesis keeps all `ASWARM-WL-*` workloads outside the core denominator.
7. Accepted coordination fixtures carry the rch proof-queue pressure summary through expansion packs, scheduler evidence inputs, and reports.
8. Accepted and refused coordination fixtures emit deterministic hashes, stable replay commands, valid artifact globs, and explicit `missing_scenario_dimensions` refusal reports.

## Cross-References

- `artifacts/runtime_workload_corpus_v1.json`
- `scripts/run_runtime_workload_corpus.sh`
- `tests/runtime_workload_corpus_contract.rs`
- `artifacts/agent_swarm_coordination_workload_contract_v1.json`
- `scripts/run_perf_e2e.sh`
- `scripts/test_transport_e2e.sh`
- `scripts/test_messaging_e2e.sh`
- `scripts/test_distributed_e2e.sh`
- `scripts/test_scheduler_wakeup_e2e.sh`
- `scripts/test_http_e2e.sh`
