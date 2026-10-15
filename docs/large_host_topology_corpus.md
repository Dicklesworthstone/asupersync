# Large Host Topology Corpus

This document is the operator runbook for
`large-host-topology-corpus-v1`. The canonical contract is
`artifacts/large_host_topology_corpus_v1.json`, the helper is
`scripts/large_host_topology_corpus.py`, and the contract verifier is
`tests/large_host_topology_corpus_contract.rs`.

The corpus is intentionally deterministic. It models representative host
topologies used by swarm pressure planning, proof-lane admission, and future
resource-placement work. It is not live host measurement, not a benchmark report,
not proof of real-host throughput, and not evidence that any RCH worker is
currently available or healthy.

## Profile Catalog

| Profile | Planning use |
| --- | --- |
| `single-socket-64c-256g` | Flat 64-core, 256 GiB large-host reference |
| `dual-socket-64c-256g-numa` | Two-socket NUMA placement and cross-node memory risk |
| `high-memory-96c-512g` | Memory-heavy proof-lane planning without claiming live free memory |
| `cgroup-limited-32c-96g` | Conservative fallback when a large physical host has smaller effective limits |
| `memory-pressure-degraded-64c` | Brownout-style planning when memory pressure should queue broad lanes |
| `remote-worker-queue-contention-64c-256g` | RCH queue-slot pressure where worker warmth is advisory only |

Each row carries `profile_id`, `profile_family`, `topology`, `memory`,
`cgroup`, `rch_slot_model`, `contention_domains`, `fallback_policy`,
`operator_interpretation`, `proof_boundary`, `rch_refresh_command`, and
`source_refs`.

## Proof Boundary

The committed artifact is a topology contract. It turns machine-shape
assumptions into explicit input rows for later admission and scheduling logic,
but it does not claim fresh benchmark evidence or live hardware discovery.
Every row has `corpus_is_live_host_measurement = false`,
`corpus_is_fresh_benchmark = false`, and
`proves_real_host_throughput = false`.

The helper is non-mutating. It does not run Cargo, RCH, Git, Beads, Agent Mail,
host probes, profilers, cache writes, or file deletion. It only reads a bounded
fixture/contract and emits JSON or Markdown.

## RCH Refresh Commands

All heavy validation commands are remote-required and include an isolated
`CARGO_TARGET_DIR`. Local Cargo fallback is not admissible for topology-corpus
validation evidence.

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_topology_single_socket CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p asupersync --test large_host_topology_corpus_contract single_socket_profile_declares_flat_topology -- --nocapture
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_topology_dual_socket CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p asupersync --test large_host_topology_corpus_contract dual_socket_profile_declares_numa_domains -- --nocapture
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_topology_high_memory CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p asupersync --test large_host_topology_corpus_contract high_memory_profile_declares_large_memory_ceiling -- --nocapture
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_topology_cgroup_limited CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p asupersync --test large_host_topology_corpus_contract cgroup_limited_profile_declares_effective_limits -- --nocapture
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_topology_memory_degraded CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p asupersync --test large_host_topology_corpus_contract degraded_profile_declares_safe_fallback -- --nocapture
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_topology_remote_queue CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p asupersync --test large_host_topology_corpus_contract remote_worker_contention_profile_declares_queue_policy -- --nocapture
```

Use the focused RCH verifier for the whole contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_large_host_topology_corpus_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test large_host_topology_corpus_contract -- --nocapture
```

## Deterministic E2E Receipt

The bounded E2E wrapper writes a JSON receipt, Markdown receipt, and log file
under `target/large-host-topology-corpus/`.

```bash
bash scripts/run_large_host_topology_corpus_e2e.sh --run-id local-check
```

The log fields are stable: `bead_id`, `profile_id`, `profile_family`,
`status`, `physical_cores`, `memory_gib`, `numa_nodes`, `rch_slots`,
`fallback_action`, `artifact_path`, and `first_failure`.

Future topology-aware proof admission should consume this corpus as advisory
placement input. It must still let dirty-tree blockers, stale proof evidence,
zero-test proof lanes, and no-local-fallback policy override topology warmth.
