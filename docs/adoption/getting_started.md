# Getting Started with FrankenLab

FrankenLab is a deterministic lab-runtime harness for async Rust. Its CLI loads
typed `Scenario` documents from YAML, validates them, and can run, explore, or
replay the current runner. The schema is broader than the behavior wired into
that runner, so this guide distinguishes accepted authoring syntax from active
runtime effects.

## Install

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adoption_getting_started_docs cargo install --path frankenlab
```

Or from the workspace root:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adoption_getting_started_docs cargo build -p frankenlab --release
# Binary at target/release/frankenlab
```

## 1. Validate a YAML scenario

Validation checks typed deserialization and semantic rules. It does not execute
the scenario or prove that every declared field has a runtime effect.

```bash
frankenlab validate frankenlab/examples/scenarios/01_race_condition.yaml
# => Scenario 'example-race-condition' is valid
```

## 2. Run the current runner

```bash
frankenlab run frankenlab/examples/scenarios/01_race_condition.yaml
```

Human-readable output has this shape:

```
Scenario: example-race-condition [PASS]
Seed: 42
Steps: 0
Faults injected: 0
Oracles: 17/17 passed
Certificate: event_hash=0, schedule_hash=0
```

`lab.seed` feeds the deterministic scheduler. The YAML schema itself does not
create application tasks, messages, leases, or saga work, so a narrative
scenario may legitimately report zero steps. Treat the result as evidence for
the current runner and binary, not as a cross-build or cross-platform promise.

Try a different seed:

```bash
frankenlab run frankenlab/examples/scenarios/01_race_condition.yaml --seed 99
```

## 3. Explore scheduler seeds

Sweep through seeds for the workload the runner actually has. Exploration does
not synthesize a workload from participant names or a scenario description.

```bash
frankenlab explore frankenlab/examples/scenarios/02_obligation_leak.yaml --seeds 200
```

Output:

```
Exploration: example-obligation-leak [PASS]
Seeds: 200/200 passed
Unique fingerprints: 200
```

If a seed fails, FrankenLab reports the first failing seed. Replay the exact
scenario with the same binary before treating the result as reproducible
evidence.

## 4. Check scoped replay determinism

Replay runs the loaded scenario twice and compares its event and schedule
fingerprints:

```bash
frankenlab replay frankenlab/examples/scenarios/01_race_condition.yaml
```

Output:

```
Replay verified: example-race-condition (seed=42, event_hash=0, schedule_hash=0)
```

If the two runs disagree, FrankenLab reports a divergence. A green replay is a
same-command, same-binary check; it is not a blanket checksum, platform, or
future-version guarantee.

## 5. Read fault declarations literally

The third fixture declares partition, clock-skew, heal, cancellation, network,
and participant data:

```bash
frankenlab run frankenlab/examples/scenarios/03_saga_partition.yaml
```

Today, every fault declaration produces a timed trace entry. Disk
pressure/recovery, delayed cleanup, and process stall/resume also affect a
synthetic effect summary. Partition/heal, host crash/restart, and clock
skew/reset are recorded but do not simulate those behaviors. Network and
cancellation sections are validation-only, participant names only validate
fault references, and participant roles/properties do not schedule work.

The fixture is therefore useful for schema and trace-shape authoring, but its
name and comments are not proof of a partitioned saga execution.

## JSON result output

Add `--json` for a machine-readable command result or report:

```bash
frankenlab run 01_race_condition.yaml --json | jq .passed
# => true
```

This flag does not make the CLI accept a JSON `Scenario`, and it does not emit
canonical Scenario JSON. Both application loaders take a YAML Scenario path.
The library-only `Scenario::from_json` and `Scenario::to_json` methods provide
typed JSON round trips for callers that already have a `Scenario` value.

## Run the built-in demo pipeline

Run all three stages (validate, run, explore) in sequence:

```bash
frankenlab demo all
```

The separate [`tools/demos/time_travel.yaml`](../../tools/demos/time_travel.yaml)
file is an adjacent human-readable parameter reference, not a typed `Scenario`
and not an input to `make demo-benchmark`. The benchmark uses compiled constants
and reads `artifacts/demo_golden_checksums.json`.

## Writing your own scenarios

A minimal scenario:

```yaml
schema_version: 1
id: my-test
description: My first FrankenLab scenario

lab:
  seed: 42
  worker_count: 2
  max_steps: 10000
  panic_on_obligation_leak: true

chaos:
  preset: "off"

oracles:
  - all
```

Current field-consumption boundaries:

| Field | Current behavior |
|-------|------------------|
| `lab.*` | Builds the lab configuration, including seed and step limit |
| `chaos.*` | Builds the current chaos policy |
| `oracles` | Selects registered runner checks; unknown names are rejected |
| `faults` | Produces timed trace entries; only a subset affects the synthetic effect summary |
| `resource_caps` | Partially consumed for post-parse/runtime artifact limits |
| `minimization` | Partially consumed by minimization/report paths |
| `include` | Paths are validated only; referenced files are not read or merged |
| `network` | Validated only; not consumed by `ScenarioRunner` |
| `cancellation` | Validated only; not consumed by `ScenarioRunner` |
| `participants` | Names validate fault references; roles/properties are otherwise unused |
| `expected_invariants` | Validated only; does not select or enforce runner checks |
| `golden_projection` | `format` is unused; `canonicalized` and `redacted` do not transform output |

The exact typed corpus is the ten files under `examples/scenarios/` and the
three files under `frankenlab/examples/scenarios/`. Use them as syntax and
validation examples, not as proof of the behavior named in a filename.

## YAML authoring boundaries

- Unknown keys at the root or another typed-struct boundary are accepted and
  discarded. A typo can therefore silently leave a default in effect.
- Invalid types, invalid enum values, duplicate mapping keys, and multiple YAML
  documents are rejected.
- Anchors and aliases are resolved by the incumbent parser. A `<<` merge key is
  not applied by either production loader; it is treated as an ignored unknown
  field in the target struct.
- Include path extension, length, and character rules are validated, but no
  include file is opened or merged.
- The loaders read the whole document before parsing and define no application
  byte, scalar, collection, nesting, or total-work budget.

Parser errors identify the input path and include parser text plus a line and
column when the parser supplies them. Semantic validation aggregates field-like
paths, but those errors do not carry YAML source spans. Unknown-oracle errors
are a separate runner failure class.

## Do not put secrets in scenarios

Every `faults[].args` key and value is copied into user-trace text, and JSON run
results include the fault log. `golden_projection.redacted: true` does not scrub
those values. Do not place credentials, tokens, personal data, or other private
values anywhere in a Scenario document.

For the full source-pinned inventory and no-claim boundaries, see the
[Scenario YAML capability inventory](../scenario_yaml_capability_inventory.md).

## Correctness-by-Construction Review Workflow

For changes touching runtime-critical paths (`src/runtime/`, `src/cx/`,
`src/cancel/`, `src/channel/`, `src/obligation/`, `src/trace/`, `src/lab/`,
`formal/lean/`), change reviews must include a completed **Proof + Conformance Impact
Declaration** in `.github/PULL_REQUEST_TEMPLATE.md`.

Required review artifact content:

- Change path classification (`none`, `local`, `cross-cutting`)
- Theorem touchpoints (theorem/helper/witness IDs)
- Refinement mapping touchpoints (`runtime_state_refinement_map` rows or
  constraint IDs)
- Executable conformance touchpoints and artifact links
- Reviewer routing for critical path owner groups

For deterministic evidence commands, run heavy checks via `rch`:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adoption_getting_started_docs cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adoption_getting_started_docs cargo clippy --all-targets -- -D warnings
```

Detailed routing and review rules are documented in
`docs/integration.md` under **Proof-Impact Classification and Routing**.

## Next steps

- Inspect the [partition_heal](../../examples/scenarios/partition_heal.yaml)
  fixture as a typed partition/heal declaration, while retaining the trace-only
  fault boundary above
- Read the [replay debugging guide](../replay-debugging.md) for trace
  analysis techniques
- Check the [cancellation testing guide](../cancellation-testing.md) for
  obligation protocol guidance
