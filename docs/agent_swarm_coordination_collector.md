# Agent Swarm Coordination Collector

Bead: `asupersync-qn8i0p.2`

## Purpose

The collector turns explicit Agent Mail, Beads, `bv`, `rch`, git dirty-frontier,
and proof artifact exports into the redacted deterministic workload bundle from
`docs/agent_swarm_coordination_workload_contract.md`.

It is intentionally outside the core runtime. The collector does not link or
call MCP Agent Mail, Beads, `bv`, `rch`, or git by itself. Operators and agents
must pass checked fixture files or explicit exported command output with
`--source KIND:PATH`.

The collector contract pins this as a core-runtime dependency boundary: the
runtime manifest must not declare `mcp_agent_mail`, `agent-mail`, `beads`, `br`,
`bv`, or `rch` dependency keys or package names in production dependency
sections. Live swarm state reaches the collector only through explicit export
files, never through runtime crate linkage.

## Command

```bash
scripts/run_agent_swarm_coordination_collector.sh --list
scripts/run_agent_swarm_coordination_collector.sh --dry-run --source beads:br-ready.json
scripts/run_agent_swarm_coordination_collector.sh --fixture --output-root target/agent-swarm-coordination-collector
scripts/run_agent_swarm_coordination_collector.sh --execute --source agent_mail:mail.json --source beads:br.json --source bv:bv.json --source rch:rch.json --source git_dirty_frontier:dirty.json --output-root target/agent-swarm-coordination-collector
```

Supported source adapters:

- `agent_mail`
- `beads`
- `bv`
- `rch`
- `git_dirty_frontier`
- `artifact_store`

## Modes

- `--list`: prints supported adapters, modes, and output artifact kinds.
- `--dry-run`: prints planned source files and does not read them.
- `--fixture`: emits a checked synthetic bundle with duplicate suppression,
  tracker lock contention, `rch` queue pressure, dirty-frontier hashing, and
  proof artifact references.
- `--execute`: reads only explicit `--source KIND:PATH` files and emits a
  bundle, JSONL event log, machine report, and human summary.

The `rch` adapter models proof-queue pressure as redacted workload metadata,
not as runtime linkage. It records deterministic queue-depth buckets,
command-class hashes, artifact retrieval tail buckets, timeout/refusal reasons,
and proof fanout counts so planners can replay validation pressure without raw
commands, hostnames, or worker details. RCH local fallback markers fail closed
as refused proof events instead of being recorded as completed validation
pressure.

## Output Artifacts

Each execute or fixture run writes:

- `coordination-workload-bundle.json`
- `coordination-workload-events.jsonl`
- `coordination-collector-report.json`
- `coordination-collector.summary.txt`

The bundle uses schema version
`agent-swarm-coordination-workload-bundle-v1` and event schema version
`agent-swarm-coordination-event-v1`. Events are deduplicated by
`source_hash`, `correlation_id`, and `event_kind`, then sorted by the workload
contract sort key.

The machine report includes deterministic `e2e_log_rows` for every normalized
event. Each row records the source kind, pseudonymized agent, correlation id,
workload family, workload id, refusal reason, source hash, output bundle path,
and replay command needed to feed the bundle into
`scripts/run_runtime_workload_corpus.sh`. For `rch` proof-pressure events, rows
also include proof family, queue bucket, command-class hash, artifact tail
bucket, proof fanout count, and proof timeout/refusal reason.

## Redaction

The collector keeps message bodies out of bundle content by default. Agent
names, local paths, worker metadata, and artifact paths are pseudonymized or
hashed. Inputs that contain token-like material, malformed JSON, unknown source
kinds, missing required identifiers, RCH local fallback evidence, or source
events older than the deterministic freshness window fail closed with a refused
event and a nonzero exit code.

The redaction behavior is constrained by:

- `docs/agent_swarm_coordination_workload_contract.md`
- `artifacts/agent_swarm_coordination_workload_contract_v1.json`
- `docs/agent_swarm_coordination_redaction_contract.md`
- `artifacts/agent_swarm_coordination_redaction_contract_v1.json`

## Validation

Focused reproduction:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_agent_swarm_coordination_collector cargo test -p asupersync --test agent_swarm_coordination_collector_contract -- --nocapture
```

The validation checks:

1. The contract artifact names all modes, adapters, outputs, and fail-closed
   cases.
2. `--list` and `--dry-run` do not read source files.
3. Fixture execution emits deterministic bundle, JSONL, report, and summary
   artifacts.
4. Fixture events satisfy the workload contract required fields and ordering.
5. Duplicate message events are suppressed and counted.
6. Malformed JSON, unsupported sources, stale source events, and unredacted
   secrets fail closed.
7. Git dirty-frontier inputs retain only path hashes and counts.
8. Report `e2e_log_rows` expose the required smoke-log fields and replay
   command for every emitted event.
9. `rch` source rows expose queue-depth bucket, command-class hash, artifact
   retrieval tail bucket, timeout/refusal reason, and proof fanout count without
   retaining raw commands or worker details.
10. Unsupported nested worker data in `rch` sources fails closed with
   `unsupported_worker_data`.
11. RCH local fallback markers fail closed with `rch_local_fallback` without
   retaining raw fallback text or command details.
12. The collector artifact and root runtime manifest preserve the no-core-
   runtime-dependency boundary for Agent Mail, Beads, `bv`, and `rch`.
13. Repeated fixture runs produce identical bundle hashes.

## Cross-References

- `scripts/run_agent_swarm_coordination_collector.sh`
- `artifacts/agent_swarm_coordination_collector_contract_v1.json`
- `tests/agent_swarm_coordination_collector_contract.rs`
- `artifacts/agent_swarm_coordination_workload_contract_v1.json`
- `artifacts/agent_swarm_coordination_redaction_contract_v1.json`
