# Agent Swarm Coordination Workload Contract

Bead: `asupersync-qn8i0p.1`

## Purpose

This contract defines the v1 bundle shape for turning real agent-swarm
coordination evidence into deterministic workload inputs. The bridge normalizes
Agent Mail, Beads, `bv`, `rch`, git dirty-frontier observations, and proof
artifact references into one redacted event stream that later runtime workload,
lab replay, scheduler evidence, capacity, and profile planner beads can consume.

The bridge is intentionally outside the core runtime. The runtime crate must not
link MCP Agent Mail, Beads, `bv`, or `rch` libraries. Collectors and smoke
runners read explicit command output, fixture files, or checked artifacts and
emit a schema-versioned bundle.

## Contract Artifact

The canonical artifact is:

- `artifacts/agent_swarm_coordination_workload_contract_v1.json`

The artifact declares:

- bundle schema version
- required event fields
- deterministic ordering and duplicate handling rules
- allowed source, event, command, workload, redaction, and refusal taxonomies
- runtime workload corpus compatibility metadata
- accepted and refused sample bundles
- core-runtime dependency boundaries

## Required Event Fields

Every normalized event must include:

- `schema_version`
- `run_id`
- `source_kind`
- `source_agent`
- `source_thread_or_bead`
- `event_ts`
- `stable_sequence`
- `event_kind`
- `correlation_id`
- `command_class`
- `workload_family`
- `queue_depth_or_lock_state`
- `file_frontier`
- `artifact_refs`
- `redaction_verdict`
- `source_hash`
- `refusal_reason`

`queue_depth_or_lock_state`, `file_frontier`, and `artifact_refs` may be empty
objects or arrays, but the keys must be present so downstream replay code can
distinguish "known empty" from "not collected".

## Deterministic Ordering

Collectors must sort accepted and refused events lexically by:

1. `event_ts`
2. `stable_sequence`
3. `source_kind`
4. `source_thread_or_bead`
5. `event_kind`
6. `correlation_id`

Duplicate events are identified by `source_hash`, `correlation_id`, and
`event_kind`. The v1 action is `dedupe_then_sort`: keep one canonical event,
record a duplicate count in bundle metadata, and never let duplicates widen a
capacity or scheduler claim.

## Redaction And Refusal

The contract permits only redacted, pseudonymized, metadata-only, or refused
events. Raw secrets, raw home-directory paths, raw hostnames, raw worker names,
and raw message bodies are not valid bundle content.

Required refusal reasons include:

- `unsupported_source_kind`
- `missing_required_field`
- `stale_source`
- `unredacted_secret`
- `unknown_schema_version`
- `nondeterministic_order`
- `duplicate_event`

Refused events remain useful: they preserve deterministic provenance and explain
why the input could not become replayable workload pressure. They must not count
as production conformance or as evidence that a workload family was covered.

## Runtime Workload Corpus Compatibility

The bundle is compatible with `runtime-workload-corpus-v1` as an optional
expansion pack only. It must not change the core workload denominator in
`artifacts/runtime_workload_corpus_v1.json`.

The v1 scenario families are:

- `tracker_lock_contention`
- `concurrent_rch_proofs`
- `fail_closed_dirty_frontier`
- `artifact_retrieval_tail`
- `proof_runner_fanout`
- `stale_in_progress_reclaim`
- `coordination_latency_burst`

Each synthesized workload must say which source events produced the pressure
model and which fields were retained only as provenance. Missing or refused
scenario dimensions fail closed.

## Validation

The invariant suite for this contract lives in:

- `tests/agent_swarm_coordination_workload_contract.rs`

Focused reproduction:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_agent_swarm_coordination_contract cargo test -p asupersync --test agent_swarm_coordination_workload_contract -- --nocapture
```

The validation checks:

1. Documentation references the artifact and bead.
2. Required fields and allowed taxonomies are stable and duplicate-free.
3. Sample bundles contain all required fields.
4. Accepted samples have empty refusal reasons.
5. Refused samples cover unknown-source and stale-contract rejection.
6. Event ordering and duplicate handling rules are deterministic.
7. The runtime workload corpus compatibility metadata stays optional and
   fail-closed.
8. Core runtime dependency boundaries remain explicit.

## Cross-References

- `artifacts/agent_swarm_coordination_workload_contract_v1.json`
- `tests/agent_swarm_coordination_workload_contract.rs`
- `docs/runtime_workload_corpus_contract.md`
- `artifacts/runtime_workload_corpus_v1.json`
- `src/runtime/scheduler/swarm_evidence.rs`
