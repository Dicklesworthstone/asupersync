# Runtime Control-Seam Inventory Contract

Bead: `asupersync-1508v.1.6`

## Purpose

This contract publishes the AA-01.3 control-seam ledger for runtime ascension work. It gives later tracks one stable inventory of tunable seams, one explicit EV ranking model, and one conservative baseline comparator table with rollback surfaces.

The contract is intentionally split into:

1. A versioned inventory artifact in `artifacts/runtime_control_seam_inventory_v1.json`
2. A comparator-smoke runner in `scripts/run_runtime_control_seam_smoke.sh`
3. Invariant tests in `tests/runtime_control_seam_inventory_contract.rs`

## Inventory Scope

The v1 ledger covers seams across runtime scheduler policy, browser handoff behavior, deadline monitoring, admission and obligation safety policy, combinator retry or hedge controls, transport route selection, and RaptorQ decoder policy selection.

Each seam entry must include:

1. Stable seam ID and owner symbol/file
2. Baseline selector and conservative rollback surface
3. Comparator candidates
4. Comparator-smoke command routed through `rch`
5. Workload IDs and downstream bead links
6. EV scoring fields and explicit confidence note

## EV Ranking Model

The canonical model is `aa01-ev-ranking-v1` with 1-5 ordinal inputs.

`EV = 0.35*impact + 0.20*confidence + 0.15*(6-effort) + 0.15*(6-adoption_friction) + 0.15*user_visible_benefit`

Required EV fields per seam:

- `impact`
- `confidence`
- `effort`
- `adoption_friction`
- `user_visible_benefit`
- `expected_value_score`

Interpretation rules:

1. Higher effort/adoption friction lowers EV through inverse terms.
2. Confidence expresses evidence maturity, not optimism.
3. If confidence is weak, mark the seam exploratory; do not inflate EV.

## Baseline Comparator Table

| Seam ID | Baseline selector | Conservative rollback surface |
| --- | --- | --- |
| `AA01-SEAM-SCHED-CANCEL-STREAK` | `cancel_lane_max_streak = 16` | restore runtime default streak |
| `AA01-SEAM-SCHED-GOVERNOR` | governor disabled, interval 32 | disable governor |
| `AA01-SEAM-SCHED-ADAPTIVE-CANCEL` | adaptive on, epoch 128 | disable adaptive and pin static streak |
| `AA01-SEAM-BROWSER-HANDOFF` | browser handoff limit 0 | disable forced browser handoff |
| `AA01-SEAM-DEADLINE-MONITOR` | deadline monitor disabled | disable monitor and rely on budgets |
| `AA01-SEAM-ADMISSION-ROOT-LIMITS` | root limits unset | unbounded root admission |
| `AA01-SEAM-LEAK-ESCALATION` | leak response Log, no escalation | revert to Log-only leak handling |
| `AA01-SEAM-RETRY-BACKOFF` | default retry policy | fixed conservative retry delay |
| `AA01-SEAM-HEDGE-DELAY` | adaptive hedge default bounds | static hedge delay |
| `AA01-SEAM-TRANSPORT-ROUTER` | health/connection-count routing | single-path conservative routing |
| `AA01-SEAM-RAPTORQ-DECODER-POLICY` | conservative decoder mode | force conservative decode policy |

## Comparator-Smoke Runner

The canonical runner is `scripts/run_runtime_control_seam_smoke.sh`.

Runner behavior:

1. Reads seam inventory from `artifacts/runtime_control_seam_inventory_v1.json`
2. Executes one seam or all seams in deterministic order
3. Emits per-seam bundle manifests with command, status, exit code, and artifact paths
4. Emits an aggregate run report for operator and CI consumption

Default mode is `--dry-run` so schema and command surfaces can be validated without long execution. Use `--execute` for real smoke runs.

Examples:

```bash
# List seam IDs
bash ./scripts/run_runtime_control_seam_smoke.sh --list

# Dry-run one seam
bash ./scripts/run_runtime_control_seam_smoke.sh --seam AA01-SEAM-SCHED-CANCEL-STREAK --dry-run

# Execute one seam comparator smoke command
bash ./scripts/run_runtime_control_seam_smoke.sh --seam AA01-SEAM-SCHED-CANCEL-STREAK --execute
```

## Structured Artifact Contract

Per-seam bundle manifests must use schema `runtime-control-seam-smoke-bundle-v1` and include:

- `seam_id`
- `scenario_id`
- `workload_ids`
- `baseline_selector`
- `rollback_surface`
- `comparator_smoke_command`
- `artifact_path`
- `run_log_path`
- `status`
- `exit_code`

Aggregate run reports must use schema `runtime-control-seam-smoke-run-report-v1`.

## Validation

Invariant suite:

- `tests/runtime_control_seam_inventory_contract.rs`

Focused reproduction:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa013 cargo test --test runtime_control_seam_inventory_contract -- --nocapture
```

Optional smoke runner validation:

```bash
bash ./scripts/run_runtime_control_seam_smoke.sh --seam AA01-SEAM-SCHED-CANCEL-STREAK --dry-run
```

The invariant checks lock:

1. doc section stability and cross-references
2. artifact schema and EV-field shape
3. seam ID uniqueness and baseline-table completeness
4. owner-file existence and `rch` routing on smoke commands
5. workload-link integrity against `artifacts/runtime_workload_corpus_v1.json`

## Cross-References

- `artifacts/runtime_control_seam_inventory_v1.json`
- `scripts/run_runtime_control_seam_smoke.sh`
- `tests/runtime_control_seam_inventory_contract.rs`
- `docs/runtime_workload_corpus_contract.md`
- `docs/runtime_tail_latency_taxonomy_contract.md`
- `src/runtime/config.rs`
- `src/runtime/deadline_monitor.rs`
- `src/combinator/retry.rs`
- `src/combinator/adaptive_hedge.rs`
- `src/transport/router.rs`
- `src/raptorq/decoder.rs`
