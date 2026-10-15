# Cost-Capped Topology-Guided Exploration and Canonical Trace Artifacts Contract

Bead: `asupersync-1508v.6.5`

## Purpose

This contract defines the cost-capping, budgeting, and artifact-emission surface for trace exploration algorithms (DPOR, Foata canonicalization, geodesic normalization, topological scoring). Every expensive computation is budgeted, observable, and falls back deterministically when the math gets too expensive.

## Contract Artifacts

1. Canonical artifact: `artifacts/cost_capped_exploration_contract_v1.json`
2. Comparator-smoke runner: `scripts/run_cost_capped_exploration_smoke.sh`
3. Invariant suite: `tests/cost_capped_exploration_contract.rs`

## Exploration Algorithms and Their Budget Surfaces

### Algorithm 1: Geodesic Normalization

Minimizes owner switches in trace linearizations.

| Parameter | Default | Budget Behavior |
|-----------|---------|----------------|
| `exact_threshold` | 30 events | Traces beyond this fall to beam search |
| `beam_threshold` | 100 events | Traces beyond this fall to greedy |
| `beam_width` | 8 | Wider = more exploration, slower |
| `step_budget` | 100,000 | Absolute work-unit cap before fallback |

Fallback chain: ExactAStar → BeamSearch → Greedy → TopoSort

Owner: `src/trace/geodesic.rs`

### Algorithm 2: DPOR Race Detection

Identifies scheduling races for backtracking exploration.

| Parameter | Complexity | Budget Behavior |
|-----------|-----------|----------------|
| Pairwise independence | O(n²) | Bounded by trace length |
| Backtrack set | O(races) | Bounded by race count |

Budget concern: very long traces (>10K events) make O(n²) analysis expensive.

Owner: `src/trace/dpor.rs`

### Algorithm 3: Foata Canonicalization

Produces canonical Foata normal form for trace equivalence classes.

| Parameter | Complexity | Budget Behavior |
|-----------|-----------|----------------|
| Layer construction | O(n²) | Pairwise independence checks |
| Fingerprinting | O(n²) | Same algorithm, hash instead of clone |

Budget concern: same O(n²) as DPOR.

Owner: `src/trace/canonicalize.rs`

### Algorithm 4: Topological Scoring

Priorities exploration nodes by persistence homology novelty.

| Parameter | Behavior |
|-----------|---------|
| `novelty` | New homology classes not seen before |
| `persistence_sum` | Sum of death-birth intervals |
| `fingerprint` | Deterministic tie-break |

Owner: `src/trace/scoring.rs`

## Cost Cap Contract

### Time Caps

Every exploration call MUST respect a step or time budget:

1. `step_budget`: Maximum discrete work units (e.g., A* expansions, beam candidates evaluated)
2. When budget exhausted, algorithm MUST fall back to the next cheaper tier
3. Fallback MUST be logged with the reason ("budget_exhausted", "threshold_exceeded")

### Memory Caps

1. Working memory for A* search: bounded by `beam_width × trace_length`
2. Race analysis: bounded by `O(n²)` adjacency checks
3. Canonicalization: bounded by `O(n)` for layer storage

### Exhaustion Behavior

When a cap is hit:

1. Stop the expensive algorithm immediately
2. Record the partial result (if any)
3. Switch to the next fallback tier
4. Emit a structured log entry with: algorithm, budget consumed, reason, fallback chosen
5. The fallback result MUST be valid (correct linearization / sound race analysis)

## Artifact Emission Contract

Every exploration run MUST emit:

### Exploration Manifest

```json
{
  "schema": "cost-capped-exploration-manifest-v1",
  "trace_length": <n>,
  "algorithm_chosen": "<ExactAStar|BeamSearch|Greedy|TopoSort>",
  "algorithm_fallback_chain": ["ExactAStar", "Greedy"],
  "fallback_reason": "<budget_exhausted|threshold_exceeded|null>",
  "canonical_fingerprint": "<hex>",
  "switch_count": <n>,
  "race_count": <n>,
  "step_budget": <n>,
  "steps_consumed": <n>,
  "heuristic_path_explanation": "<human readable>"
}
```

### Canonical Fingerprint

The Foata normal form fingerprint uniquely identifies the trace equivalence class. Two traces are equivalent iff their fingerprints match.

## Structured Logging Contract

Exploration logs MUST include:

- `algorithm`: Which algorithm was used
- `fallback_reason`: Why a cheaper algorithm was chosen (or null)
- `step_budget`: Configured budget
- `steps_consumed`: Actual steps used
- `trace_length`: Number of events in the trace
- `switch_count`: Owner switches in the result
- `race_count`: Races detected (DPOR)
- `canonical_fingerprint`: Foata fingerprint
- `exploration_time_us`: Wall-clock microseconds for exploration
- `fallback_chain`: Ordered list of algorithms attempted

## Comparator-Smoke Runner

Canonical runner: `scripts/run_cost_capped_exploration_smoke.sh`

The runner reads `artifacts/cost_capped_exploration_contract_v1.json`, supports deterministic dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `cost-capped-exploration-smoke-bundle-v1`
2. Aggregate run report with schema `cost-capped-exploration-smoke-run-report-v1`

Examples:

```bash
# List scenarios
bash ./scripts/run_cost_capped_exploration_smoke.sh --list

# Dry-run one scenario
bash ./scripts/run_cost_capped_exploration_smoke.sh --scenario AA06-SMOKE-GEODESIC-BUDGET --dry-run

# Execute one scenario
bash ./scripts/run_cost_capped_exploration_smoke.sh --scenario AA06-SMOKE-GEODESIC-BUDGET --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa062 cargo test --test cost_capped_exploration_contract -- --nocapture
```

Invariant coverage locks:

1. Doc section and cross-reference stability
2. Artifact schema/version invariants
3. Algorithm catalog completeness (every algorithm listed with budget parameters)
4. Fallback chain ordering and validity
5. Exploration manifest schema stability
6. Structured log field completeness
7. Smoke command `rch` routing and report schema stability
8. Budget parameter defaults match source code

## Cross-References

- `src/trace/geodesic.rs` — Geodesic normalization algorithms
- `src/trace/dpor.rs` — DPOR race detection
- `src/trace/canonicalize.rs` — Foata canonicalization
- `src/trace/scoring.rs` — Topological novelty scoring
- `src/trace/event_structure.rs` — Trace poset and event structure
- `src/trace/independence.rs` — Independence relation
- `artifacts/cost_capped_exploration_contract_v1.json`
- `scripts/run_cost_capped_exploration_smoke.sh`
- `tests/cost_capped_exploration_contract.rs`
- `docs/hindsight_logging_nondeterminism_capture_contract.md`
