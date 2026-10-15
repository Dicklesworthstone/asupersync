# Coordination Workload Bridge Smoke Runbook

Bead: `asupersync-qn8i0p.7`

## Purpose

This runbook gives operators and agents one deterministic command for the
redacted coordination workload bridge. The smoke runner connects the checked
Agent Mail / Beads / `bv` / `rch` / dirty-frontier collector fixture to runtime
workload synthesis, lab replay handoff checks, redaction refusals, and
capacity/profile planner handoff rows without reading live control-plane state.

The runner is intentionally outside the core runtime. It does not call live MCP
Agent Mail, `br`, `bv`, `rch`, git, or home-directory inputs. Execute mode uses
checked fixtures and local dry-run planner handoffs, then writes all artifacts
under the operator-provided output root.

## Commands

```bash
bash scripts/run_coordination_workload_bridge_smoke.sh --list
bash scripts/run_coordination_workload_bridge_smoke.sh --dry-run --fixture --output-root target/coordination-workload-bridge-smoke-dry-run
bash scripts/run_coordination_workload_bridge_smoke.sh --execute --fixture --output-root target/coordination-workload-bridge-smoke --generated-at 2026-05-05T05:00:00Z
```

Use `--run-id` when comparing two roots or when preserving multiple runs under
the same output root:

```bash
bash scripts/run_coordination_workload_bridge_smoke.sh --execute --fixture --output-root target/coordination-workload-bridge-smoke-a --run-id stable-a --generated-at 2026-05-05T05:00:00Z
bash scripts/run_coordination_workload_bridge_smoke.sh --execute --fixture --output-root target/coordination-workload-bridge-smoke-b --run-id stable-b --generated-at 2026-05-05T05:00:00Z
```

`--extra-required-path` is a fail-closed prerequisite probe. A missing path makes
the runner write a report and exit nonzero instead of continuing with partial
evidence.

## Modes

- `--list`: prints row ids, consumers, expected statuses, and output names.
- `--dry-run`: writes a manifest, JSONL row plan, report, and summary without
  running child smoke scripts.
- `--execute --fixture`: runs checked fixture ingestion, refusal probes,
  workload-corpus synthesis, replay handoff checks, and planner dry-run handoff.
- `--output-root`: pins every generated artifact under an explicit root.

Execute mode without `--fixture` is refused because live Agent Mail, Beads,
`bv`, `rch`, and git reads are not supported by this bridge smoke.

## Smoke Rows

| Row | Consumer | What It Proves |
| --- | --- | --- |
| `missing_prerequisite_guard` | operator | Required tools, scripts, and contracts exist before any child runner is trusted. |
| `collector_fixture_accepts_redacted_inputs` | collector | The checked coordination fixture plus a checked ack-required latency source emits redacted events for all seven workload families and a stable source bundle hash. |
| `workload_expansion_accepts_collector_bundle` | synthesis | The collector bundle expands into all seven `ASWARM-WL-*` workload families. |
| `workload_expansion_refuses_missing_dimensions` | synthesis | A bundle missing six scenario families is refused with `missing_scenario_dimensions`. |
| `collector_refuses_malformed_source_schema` | redaction | Malformed JSON becomes a deterministic fail-closed collector report. |
| `collector_refuses_unredacted_secret` | redaction | Token-like source content is refused before message body retention. |
| `dirty_frontier_unsupported_paths_fail_closed` | collector | Absolute and home-directory dirty paths are treated as unsupported planner input. |
| `schema_mismatch_guard_fails_closed` | synthesis | Bundle schema drift is stopped before workload-corpus synthesis. |
| `replay_hook_handoff_validates_minimization_inputs` | replay | The accepted pack has the families and expected event totals required by `synthesize_coordination_pressure_replay` and `minimize_coordination_pressure_replay`. |
| `capacity_profile_planner_handoff_records_used_refused_absent` | capacity/profile | The planner handoff row records used, refused, and absent coordination pack states and dry-runs capacity, host-profile, and signed-profile smoke scripts. |

Expected fail-closed rows are successful smoke evidence. They only fail the
overall runner when the observed row status diverges from the contract.

## Artifacts

Each run writes:

- `coordination-workload-bridge-smoke-manifest.json`
- `coordination-workload-bridge-smoke.jsonl`
- `coordination-workload-bridge-smoke-report.json`
- `coordination-workload-bridge-smoke.summary.txt`
- child collector, workload-corpus, replay handoff, and planner dry-run logs

Stable fingerprints are computed from semantic fields such as source bundle
hashes, missing scenario families, expected refusal reasons, and the committed
planner handoff row. Output-root paths are kept out of those fingerprints so
two fixture runs can be compared across different roots.

## Consumer Mapping

- Collector rows map to `scripts/run_agent_swarm_coordination_collector.sh` and
  `artifacts/agent_swarm_coordination_collector_contract_v1.json`.
- Redaction rows map to
  `artifacts/agent_swarm_coordination_redaction_contract_v1.json`.
- Synthesis rows map to `scripts/run_runtime_workload_corpus.sh` and
  `artifacts/runtime_workload_corpus_v1.json`.
- Replay rows map to `src/lab/replay.rs` via the integration test that calls
  `synthesize_coordination_pressure_replay` and
  `minimize_coordination_pressure_replay`.
- Capacity/profile rows map to `scripts/run_capacity_envelope_planner_smoke.sh`,
  `scripts/run_host_profile_planner_smoke.sh`,
  `scripts/run_signed_profile_bundle_smoke.sh`, and the
  `coordination_workload_planner_handoff` row in
  `artifacts/massive_swarm_signoff_smoke_contract_v1.json`.

## Validation

Non-Rust syntax and schema checks may run directly:

```bash
bash -n scripts/run_coordination_workload_bridge_smoke.sh
jq empty artifacts/coordination_workload_bridge_smoke_contract_v1.json
bash scripts/run_coordination_workload_bridge_smoke.sh --list
bash scripts/run_coordination_workload_bridge_smoke.sh --dry-run --fixture --output-root target/coordination-workload-bridge-smoke-dry-run
bash scripts/run_coordination_workload_bridge_smoke.sh --execute --fixture --output-root target/coordination-workload-bridge-smoke --generated-at 2026-05-05T05:00:00Z
```

Cargo validation must go through `rch`:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_coordination_workload_bridge_smoke cargo test -p asupersync --test coordination_workload_bridge_smoke_contract --features test-internals -- --nocapture
```

The integration test checks the contract artifact, runbook references, list and
dry-run modes, fixture execution, expected fail-closed rows, deterministic
fingerprints across output roots, missing prerequisite failure, and real replay
hook synthesis/minimization from the emitted expansion pack.

## Cross-References

- `scripts/run_coordination_workload_bridge_smoke.sh`
- `artifacts/coordination_workload_bridge_smoke_contract_v1.json`
- `tests/coordination_workload_bridge_smoke_contract.rs`
- `docs/agent_swarm_coordination_collector.md`
- `docs/runtime_workload_corpus_contract.md`

## Failure Policy

The safe default is to refuse questionable inputs. The smoke runner exits
nonzero when a prerequisite is missing, live-input execution is requested,
schema versions drift, privacy proof fails, a dirty frontier contains
unsupported paths, or a planner handoff row no longer records used/refused/absent
coordination pack states.
