# Proof Lane Admission Decision

`scripts/proof_lane_admission_decision.py` emits deterministic dry-run
admission receipts for proof lanes. It reads fixture-style admission inputs and
reports whether a lane should run now, queue, split, reject, or wait for a
handoff. The helper does not run Cargo, RCH, Git, Beads, Agent Mail, cache
writes, host probes, or file deletion.

## Topology Guidance

Inputs may include an optional `topology_guidance` object pointing at
`artifacts/large_host_topology_corpus_v1.json`. The helper loads the requested
profile and records topology fit, same-domain contention, degraded NUMA memory,
remote-worker preference, source refs, and the profile refresh command.

Topology guidance is operator advice only. It is not proof-lane correctness
evidence, not a live host measurement, not a throughput benchmark, and not RCH
fleet availability evidence. Dirty-tree blockers, active peer reservations, disk
pressure, scalar memory pressure, stale topology receipts, and malformed
topology profiles override topology warmth or placement advice.

Stable topology reason codes include:

| Reason code | Meaning |
| --- | --- |
| `topology-fit` | A fresh corpus profile matched the input lane context. |
| `topology-missing` | No topology input was supplied; scalar capacity remains the only basis. |
| `same-domain-contention` | The requested contention domain is already occupied by another lane. |
| `split-lane-recommended` | The lane should be split or routed by topology before admission. |
| `remote-worker-preferred` | The corpus profile recommends remote-worker queue/backoff handling. |
| `low-memory-numa-node` | Per-node or degraded-memory topology makes aggregate memory unsafe. |

## Deterministic E2E Receipt

Run the bounded E2E wrapper to generate JSON, Markdown, and line-oriented log
receipts under `target/proof-lane-admission-decision/`.

```bash
bash scripts/run_proof_lane_admission_decision_e2e.sh --run-id local-check
```

The wrapper covers:

| Fixture | Expected outcome |
| --- | --- |
| `high_core_admit` | admit with fresh topology fit and isolated target-dir command |
| `same_socket_contention_queue` | queue with same-domain contention and split advice |
| `low_memory_numa_node` | queue because degraded NUMA memory overrides scalar headroom |
| `stale_topology_input` | wait for refreshed topology telemetry |
| `unrelated_dirty_tree_blocker` | wait for dirty-tree handoff despite topology fit |

Focused Rust validation for the contract test must remain remote-required:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_admission_decision_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test proof_lane_admission_decision_contract -- --nocapture
```
