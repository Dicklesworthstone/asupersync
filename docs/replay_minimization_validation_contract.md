# Replay Minimization, Counterexample Quality, and Distributed Inconsistency Debugging Contract

Bead: `asupersync-1508v.6.6`

## Purpose

This contract validates that the trace-intelligence pipeline (canonicalization, minimization, DPOR, geodesic normalization) produces correct, smaller, and more useful counterexamples without sacrificing replay determinism. Every validation scenario must demonstrate equivalence preservation, size reduction, and structured diagnostic output.

## Contract Artifacts

1. Canonical artifact: `artifacts/replay_minimization_validation_contract_v1.json`
2. Comparator-smoke runner: `scripts/run_replay_minimization_validation_smoke.sh`
3. Invariant suite: `tests/replay_minimization_validation_contract.rs`

## Validation Dimensions

### Dimension 1: Replay Equivalence After Canonicalization

Canonical (Foata normal form) traces must be replay-equivalent to originals:

- Fingerprint stability: same events yield same fingerprint across runs
- Layer ordering: Foata layers respect the independence relation
- Round-trip: canonicalize then linearize produces a valid linear extension

Owner: `src/trace/canonicalize.rs`

### Dimension 2: Minimization Quality

Delta-debugging and scenario-level minimization must produce strictly smaller traces:

- Hierarchical pruning: region subtrees are removed before fine-grained ddmin
- Minimality: every event in the result is necessary (removing any one loses the failure)
- Budget compliance: minimization respects `max_evaluations` cap

Owner: `src/trace/delta_debug.rs`, `src/trace/minimizer.rs`

### Scenario Fault-List Minimization

`frankenlab minimize <scenario.yaml>` reduces the scenario fault list before
reporting a repro. The CLI keeps participant, lab, network, cancellation, and
oracle configuration fixed, maps each fault position to a stable synthetic
`ScenarioElement`, and runs the existing `TraceMinimizer` over that ordered
surface. Candidate subsets are translated back to fault indices, rerun through
`ScenarioRunner`, and accepted only when the reduced scenario still fails.

This is an equivalence-class search over the ordered fault schedule rather than
raw YAML text. For trace-level reducers the same rule applies at the Foata class
boundary: shrink representatives of the trace equivalence class
`M(Sigma,I) = Sigma* / equiv_I`, then linearize only after independence has been
accounted for. That avoids spending budget on permutations that differ only by
commuting independent events.

The CLI uses a logical minimizer clock for scenario YAML minimization, stable
index sorting, and deterministic JSON field construction. The same input and
budget must therefore produce identical minimized indices, reduction ratio, and
budget-exhaustion flag. Budget exhaustion is fail-closed: the command reports
the best verified still-failing subset it has found and marks the result
exhausted instead of claiming a fully minimal repro.

### Incident Replay Package / Crashpack-Family Minimization

`frankenlab minimize <package.json>` also accepts deterministic incident replay
package JSON. This is the supported crashpack-family input path for the CLI:
raw `CrashPack` artifacts remain repro artifacts, while
`IncidentReplayPackage` is the replay-minimizer-facing envelope that can carry
crashpack, trace-log, support-bundle, repro-note, and proof-failure sources.

For package JSON, the CLI uses the existing incident replay package minimizer
with a built-in stable oracle:

- require one retained `crash_pack` replay source;
- preserve the crashpack trace fingerprint when the package carries one;
- shrink non-required replay sources before feature flags;
- report the full `IncidentReplayMinimizationReport` under the
  `outcome` field.

The `--max-replays` flag maps to the incident minimizer's shrink-step budget
for this input kind; `0` means unbounded over the finite source and feature-flag
sets. A package that cannot satisfy the crashpack-preservation oracle emits a
typed blocked/inconclusive outcome and exits non-zero rather than pretending it
found a repro.

### Dimension 3: Geodesic Normalization Correctness

Normalized traces must be valid linear extensions with reduced switch cost:

- Validity: normalized schedule respects happens-before
- Optimality: switch count is less than or equal to the original
- Fallback soundness: every fallback tier produces a valid result

Owner: `src/trace/geodesic.rs`

### Dimension 4: Race Detection Soundness

DPOR race analysis must be sound (no false negatives on known racing traces):

- Independent events: events on different resources are correctly independent
- Dependent events: events on the same resource with conflicting access are detected
- Coverage: race report includes all racing event pairs

Owner: `src/trace/dpor.rs`

### Dimension 5: Crash Pack Integrity

Crash packs must be self-contained, deterministic, and replayable:

- Schema version stability
- Fingerprint matches canonical trace fingerprint
- Replay command is well-formed and references the correct seed/config

Owner: `src/trace/crashpack.rs`

### Dimension 6: Divergence Diagnostics Quality

Divergence reports must pinpoint the exact failure location with context:

- First-violation isolation: correct event index
- Affected entity analysis: tasks and regions are identified
- Context window: surrounding events are included
- Structured output: JSON-serializable for CI

Owner: `src/trace/divergence.rs`

## Equivalence Invariants

1. `canonicalize(events)` preserves the set of events (no drops, no duplicates)
2. `trace_fingerprint(events) == trace_fingerprint(events)` (deterministic)
3. `normalize_trace(events, config)` returns `events.len()` events
4. `trace_switch_cost(normalized) <= trace_switch_cost(original)`
5. `detect_races(independent_events).is_race_free()` for truly independent events
6. Crash pack fingerprint matches `trace_fingerprint` of the same events

## Structured Logging Contract

Validation logs MUST include:

- `dimension`: Which validation dimension is being tested
- `trace_length`: Number of events in the test trace
- `canonical_fingerprint`: Foata fingerprint of the trace
- `switch_count_before`: Switch cost before normalization
- `switch_count_after`: Switch cost after normalization
- `minimization_ratio`: Ratio of minimized to original trace length
- `race_count`: Number of races detected
- `algorithm`: Algorithm used (geodesic tier, minimizer variant)

## Comparator-Smoke Runner

Canonical runner: `scripts/run_replay_minimization_validation_smoke.sh`

The runner reads `artifacts/replay_minimization_validation_contract_v1.json`, supports deterministic dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `replay-minimization-validation-smoke-bundle-v1`
2. Aggregate run report with schema `replay-minimization-validation-smoke-run-report-v1`

Examples:

```bash
# List scenarios
bash ./scripts/run_replay_minimization_validation_smoke.sh --list

# Dry-run one scenario
bash ./scripts/run_replay_minimization_validation_smoke.sh --scenario AA06-VALID-CANONICALIZATION --dry-run

# Execute one scenario
bash ./scripts/run_replay_minimization_validation_smoke.sh --scenario AA06-VALID-CANONICALIZATION --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa063 cargo test --test replay_minimization_validation_contract -- --nocapture
```

Invariant coverage locks:

1. Doc section and cross-reference stability
2. Artifact schema/version invariants
3. Validation dimension catalog completeness
4. Canonicalization equivalence (fingerprint determinism, event preservation)
5. Normalization correctness (valid extension, switch cost reduction)
6. Race detection soundness (independent = no race, dependent = race)
7. Crash pack schema and fingerprint stability
8. Divergence report structure and context quality
9. Smoke command `rch` routing and report schema stability

## Cross-References

- `src/trace/canonicalize.rs` -- Foata canonicalization
- `src/trace/delta_debug.rs` -- Hierarchical delta debugging
- `src/trace/minimizer.rs` -- Scenario-level minimization
- `src/trace/geodesic.rs` -- Geodesic normalization
- `src/trace/dpor.rs` -- DPOR race detection
- `src/trace/crashpack.rs` -- Crash pack format
- `src/trace/divergence.rs` -- Divergence diagnostics
- `src/trace/replayer.rs` -- Trace replayer
- `src/trace/event_structure.rs` -- Trace poset
- `src/trace/independence.rs` -- Independence relation
- `artifacts/replay_minimization_validation_contract_v1.json`
- `scripts/run_replay_minimization_validation_smoke.sh`
- `tests/replay_minimization_validation_contract.rs`
- `docs/cost_capped_exploration_contract.md`
