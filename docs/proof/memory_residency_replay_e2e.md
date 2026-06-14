# Memory Residency Replay E2E

`scripts/run_memory_residency_replay_e2e.sh` is the M4 deterministic replay
lane for `asupersync-memory-residency-control-ho2itz.4`. The checked contract
is `artifacts/memory_residency_replay_e2e_contract_v1.json`, and the focused
verifier is `tests/memory_residency_replay_e2e_contract.rs`.

The replay fixture models the 64C/256G topology used by the memory-residency
policy and accounting contracts. It is deterministic fixture replay only: it
does not probe live hosts, run local Cargo, mutate scheduler state, change
runtime defaults, evict cache entries, migrate tasks, or start a continuous
control loop.

## Scenarios

The runner emits evidence for these scenario IDs:

| Scenario | Expected boundary |
| --- | --- |
| `fresh_topology_warm_evidence` | fresh topology selects warm retained evidence |
| `stale_topology_fallback` | stale topology fails closed to fallback |
| `no_win_locality` | balanced locality returns `no_win` |
| `critical_memory_pressure` | critical memory pressure returns `no_win` |
| `cold_evidence_budget_exhausted` | exhausted cold-evidence budget falls back |
| `artifact_cache_pressure_spill_available` | spill budget selects cold evidence |

Each scenario records the input fixture, expected tier, expected snapshot
status, required reason codes, and whether the outcome is fail-closed.

## Artifacts

The runner writes a timestamped directory below
`target/e2e-results/memory_residency_replay_e2e` containing:

| File | Purpose |
| --- | --- |
| `summary.json` | `e2e-suite-summary-v3` summary for `run_all_e2e.sh` |
| `events.ndjson` | One deterministic event per replayed scenario |
| `scenario_report.json` | Scenario matrix and no-claim boundary report |
| `operator_report.md` | Human-readable replay summary |

Failure output names the exact missing or stale input and includes this
copy-paste verifier:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_residency_replay_e2e_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test memory_residency_replay_e2e_contract -- --nocapture
```

## Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_residency_replay_e2e_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test memory_residency_replay_e2e_contract -- --nocapture
```

This proof covers the M4 replay/e2e contract, runner artifacts, orchestrator
registration, manifest/status rows, and no-claim boundaries only. It does not
prove live host throughput, p50/p95/p999 improvement, memory reduction, cache
hit-rate improvement, scheduler performance, production-on-by-default behavior,
broad workspace health, release readiness, live RCH fleet availability, or
source correctness outside this replay/e2e contract.
