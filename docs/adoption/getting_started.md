# Getting Started with FrankenLab

FrankenLab is a deterministic testing harness for async Rust. It finds
concurrency bugs reproducibly using virtual time, schedule exploration, and
fault injection.

## Install

```bash
cargo install --path frankenlab
```

Or from the workspace root:

```bash
cargo build -p frankenlab --release
# Binary at target/release/frankenlab
```

## 1. Validate a scenario (30 seconds)

Scenarios are YAML files that describe a test setup: participants, seed,
chaos level, faults, and oracles.

```bash
frankenlab validate frankenlab/examples/scenarios/01_race_condition.yaml
# => Scenario 'example-race-condition' is valid
```

## 2. Run a scenario (1 minute)

```bash
frankenlab run frankenlab/examples/scenarios/01_race_condition.yaml
```

Output:

```
Scenario: example-race-condition [PASS]
Seed: 42
Steps: 0
Faults injected: 0
Oracles: 17/17 passed
Certificate: event_hash=0, schedule_hash=0
```

The seed controls all scheduling decisions. Same seed = same execution,
every time, on every machine.

Try a different seed:

```bash
frankenlab run frankenlab/examples/scenarios/01_race_condition.yaml --seed 99
```

## 3. Explore seeds to find bugs (2 minutes)

Sweep through many seeds to discover scheduling orders that trigger
invariant violations:

```bash
frankenlab explore frankenlab/examples/scenarios/02_obligation_leak.yaml --seeds 200
```

Output:

```
Exploration: example-obligation-leak [PASS]
Seeds: 200/200 passed
Unique fingerprints: 200
```

If any seed fails, FrankenLab reports the first failing seed so you can
replay it deterministically.

## 4. Replay for determinism (30 seconds)

Verify that a scenario produces bit-identical results on re-execution:

```bash
frankenlab replay frankenlab/examples/scenarios/01_race_condition.yaml
```

Output:

```
Replay verified: example-race-condition (seed=42, event_hash=0, schedule_hash=0)
```

The event and schedule hashes are deterministic fingerprints. If replay
produces different hashes, FrankenLab reports a divergence with full
diagnostic context.

## 5. Fault injection (2 minutes)

The third example injects network partitions, clock skew, and heavy chaos
across 10 participants:

```bash
frankenlab run frankenlab/examples/scenarios/03_saga_partition.yaml
```

This exercises:

- **Network partitions**: 3 participants isolated at T=200ms, healed at T=800ms
- **Clock skew**: 50ms drift injected on one participant
- **Chaos**: random delays, I/O errors, and message loss (heavy preset)
- **Cancellation injection**: 2% probabilistic cancellation rate

All oracles verify that obligations are properly released and no tasks leak,
even under these failure conditions.

## JSON output

Add `--json` to any command for machine-readable output:

```bash
frankenlab run 01_race_condition.yaml --json | jq .passed
# => true
```

## Run the demo pipeline

Run all three stages (validate, run, explore) in sequence:

```bash
frankenlab demo all
```

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

Key fields:

| Field | Purpose |
|-------|---------|
| `lab.seed` | PRNG seed for deterministic scheduling |
| `lab.worker_count` | Number of virtual workers |
| `lab.max_steps` | Step limit (prevents infinite loops) |
| `chaos.preset` | off, light, heavy, or custom |
| `network.preset` | ideal, local, lan, wan, satellite, congested, lossy |
| `faults` | Timed fault injection events (partition, heal, clock_skew) |
| `participants` | Named actors in the scenario |
| `oracles` | Invariant checkers (obligation_leak, task_leak, quiescence, all) |
| `cancellation` | Injection strategy (random_sample or probabilistic) |

See `examples/scenarios/` for more examples.

## Next steps

- Explore the [partition_heal](../../examples/scenarios/partition_heal.yaml)
  scenario for saga compensation testing
- Read the [replay debugging guide](../replay-debugging.md) for trace
  analysis techniques
- Check the [cancellation testing guide](../cancellation-testing.md) for
  obligation protocol verification
