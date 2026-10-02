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

Human-readable output has this shape (`<N>` and `<u64>` stand for the values
your binary prints):

```
Scenario: example-race-condition [PASS]
Seed: 42
Steps: <N>
Participants: 2 bound (sender), 0 unbound
Faults injected: 0
Oracles: 24/24 passed (16 not fed by the lab runtime)
Certificate: event_hash=<u64>, schedule_hash=<u64>
```

The count in parentheses is the number of checked oracles that the lab
runtime never sends events to. They pass without having observed anything.
`asupersync::lab::oracle::LAB_RUNTIME_FED_ORACLE_NAMES` lists the oracles it
does feed.

`lab.seed` feeds the deterministic scheduler. The YAML schema itself does not
create application tasks, messages, leases, or saga work. The runner binds
only participants whose `role` is exactly `sender`, `receiver`, `swarm`,
`supervisor`, `worker`, `saga-coordinator`, `saga-participant`, `primary`,
`replica`, `lease-grantor` or `lease-holder` (the match is case-sensitive) and
spawns lab tasks for them:

- a receiver owns a bounded `mpsc` channel (`properties.capacity`, default 4,
  at most 4096) and drains it until every sender is gone;
- a sender sends `properties.messages` values (default 16, at most 1000000) to
  the receivers in round-robin order through the two-phase `reserve`/`send`
  API, so each value is a runtime-tracked `SendPermit` obligation that the
  obligation oracle sees;
- senders without any receiver, as in `01_race_condition.yaml`, race on one
  shared channel drained by an implicit sink task, and receivers without
  senders see a closed channel at once;
- a swarm spawns `properties.tasks` short tasks (default 100, from 1 to
  20000); each yields twice and bumps a counter all of them share;
- a supervisor runs a `ManagedSupervisor` from `asupersync::supervision`.
  Workers go to the supervisors round-robin in declaration order, and workers
  without a supervisor share an implicit one. Each worker is a transient
  one-for-one child that fails `properties.fail_times` times (default 1, at
  most 1000) and then succeeds. The supervisor allows
  `properties.max_restarts` restarts per minute across its workers, by
  default the sum of their `fail_times`, and stops a worker that exhausts it;
- a saga coordinator runs an `asupersync::remote::Saga` with one step per saga
  participant. Participants go to the coordinators round-robin in declaration
  order, and participants without a coordinator share an implicit one. Before
  each step the coordinator sleeps `properties.step_ms` of virtual time
  (default 50, from 1 to 60000), registers the step's compensation, asks the
  participant to apply the step over a bounded `mpsc` channel and waits at
  most `step_ms` for the reply. A refused, lost or late reply aborts the saga,
  which runs the registered compensations in reverse order: each undoes an
  applied step, or fences one that was never applied so that a late request
  is refused;
- a primary appends `properties.writes` entries (default 20, at most 10000),
  one per round of `properties.write_ms` virtual milliseconds (default 50).
  Replicas go to the primaries round-robin, and replicas without a primary
  share an implicit one. Each round the primary ships every lagging replica
  its log from that replica's acknowledged length and waits at most
  `write_ms` for the reply; a lost or late batch is shipped again the next
  round. After the last write it keeps shipping for up to 40 rounds until
  every replica has the whole log;
- a lease grantor grants one lease for `properties.initial_lease_ms` (default
  100, from 1 to 60000) by its own clock, to one holder at a time. Holders go
  to the grantors round-robin, and holders without a grantor share an implicit
  one. After `properties.start_ms` (default 0) a holder asks for the lease
  every `properties.renew_ms` (default 40) until it gets it, renews it
  `properties.renewals` times (default 4, at most 10000) and releases it. It
  believes it holds the lease until the grant's length less
  `properties.margin_ms` (default 10) after its request, by its own clock, and
  holds a runtime-tracked `Lease` obligation meanwhile. A `clock_skew` fault
  sets its `host`'s clock `skew_ms` ahead (or behind, when negative) and
  `clock_reset` puts it back; a grantor whose clock jumps further ahead than
  a holder's margin can grant the lease to a second holder. Lab chaos delays
  advance virtual time, so a holder delayed past its deadline also believes
  it holds the lease until it runs again, as a paused process would; heavy
  chaos can therefore report `double_holder`.

Saga, replication and lease messages cross a simulated network. The `network`
preset (`ideal`, `local`, `lan`, `wan`, `satellite`, `congested` or `lossy`)
sets every link's latency, jitter and packet loss, and a `links` entry keyed
`"from->to"` overrides one direction's `latency` and `packet_loss`; the other
link fields are not modeled. `partition` and `heal` faults whose `from` and
`to` name two participants cut and restore the link between them. A message
that the network drops or that is sent over a cut link is lost, and a
coordinator, primary or holder whose request or reply is lost times out. When
saga, replication or lease roles are bound, the runner fires due timers on its
way to each fault and advances virtual time to the next timer whenever the
lab is idle.

Lab chaos can cancel these tasks mid-protocol; a cancelled send, receive,
swarm task, worker generation, supervisor, saga, replication or lease task is
counted and stops, and a cancelled coordinator aborts its saga. A run fails
with a `workload:` invariant violation if a bound task cannot be spawned,
receives one sender's values out of order, drains its channel to close
without receiving every committed value, or meets an outcome its contract
rules out. It also fails if a swarm task neither completes nor ends
cancelled, a worker never succeeds or succeeds after a restart count other
than its `fail_times`, a supervisor exits with an error, a completed saga
left a step unapplied, an aborted saga left one applied or did not run each
compensation exactly once in reverse order, a replica's log is not a prefix
of its primary's log, or two holders believed they held one grantor's lease
at the same time (`double_holder`). A malformed `messages`, `capacity`,
`tasks`, `max_restarts`, `fail_times`, `step_ms`, `writes`, `write_ms`,
`initial_lease_ms`, `renewals`, `renew_ms`, `margin_ms` or `start_ms` value on
a bound participant is a run-time validation error.

Every other role is unbound and schedules no work. The `Participants:` line
(printed only when the scenario declares participants) shows the split, and a
run that executed nothing prints `Steps: 0 (no workload ran)`: its oracles had
nothing to observe. Treat the result as evidence for the current runner and
binary, not as a cross-build or cross-platform promise.

Try a different seed:

```bash
frankenlab run frankenlab/examples/scenarios/01_race_condition.yaml --seed 99
```

## 3. Explore scheduler seeds

Sweep through seeds for the workload the runner actually has: the tasks of the
bound participants, if any. Exploration does not synthesize work for unbound
roles or from a scenario description.

```bash
frankenlab explore frankenlab/examples/scenarios/02_obligation_leak.yaml --seeds 200
```

Output shape:

```
Exploration: example-obligation-leak [PASS]
Seeds: 200/200 passed
Unique fingerprints: <N>
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

Output shape:

```
Replay verified: example-race-condition (seed=42, event_hash=<u64>, schedule_hash=<u64>)
```

If the two runs disagree, FrankenLab reports a divergence. A green replay is a
same-command, same-binary check; it is not a blanket checksum, platform, or
future-version guarantee.

## 5. Read fault declarations literally

The third fixture declares a ten-participant saga, a partition of
participants 7-9 from 200 ms to 800 ms, clock skew, heavy chaos, and network
and cancellation data:

```bash
frankenlab run frankenlab/examples/scenarios/03_saga_partition.yaml
```

```text
Scenario: example-saga-partition [PASS]
Seed: 314159
Steps: 58
Participants: 11 bound (saga-coordinator, saga-participant), 0 unbound
Faults injected: 8
Oracles: 24/24 passed (16 not fed by the lab runtime)
```

The coordinator asks one participant every 50 ms of virtual time, plus the
LAN round trip of each step (2-10 ms). Without chaos it reaches participant-7
at about 440 ms, its request is lost on the cut link, the coordinator times
out 50 ms later, and the saga compensates participants 7 to 0 in reverse;
participants 8 and 9 are never asked. Heavy chaos can cancel
the coordinator earlier, which aborts the saga the same way. Either way the
run fails if a step stays applied after the abort.

Every fault declaration also produces a timed trace entry. Partition and heal
between two participants cut and restore saga, replication and lease links.
Clock skew/reset move the clock of the participant they name, which only
lease roles read; this fixture has none. Disk pressure/recovery, delayed
cleanup, and process stall/resume affect a synthetic effect summary. Host
crash/restart are recorded but do not simulate those behaviors. The network
section shapes saga, replication and lease messages, as described above. The
cancellation section is validation-only, and participant names validate fault
references.

## JSON result output

Add `--json` for a machine-readable command result or report:

```bash
frankenlab run 01_race_condition.yaml --json | jq .passed
# => true
```

The result also carries `workload_ran`, false when the run took no steps (a
pass then checked nothing), and, when the scenario declares participants,
`participant_bindings` with the bound and unbound lists. `asupersync lab run
--json` writes the same object.

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

participants:
  - name: producer
    role: sender
    properties:
      messages: 32
  - name: consumer
    role: receiver
    properties:
      capacity: 2

oracles:
  - all
```

Without the two bound participants, this scenario would run an empty lab and
print `Steps: 0 (no workload ran)`.

Current field-consumption boundaries:

| Field | Current behavior |
|-------|------------------|
| `lab.*` | Builds the lab configuration, including seed and step limit |
| `chaos.*` | Builds the current chaos policy |
| `oracles` | Selects registered runner checks; unknown names are rejected |
| `faults` | Produces timed trace entries; only a subset affects the synthetic effect summary; `partition`/`heal` between two participants cut and restore saga, replication and lease links; `clock_skew`/`clock_reset` move a lease role's clock |
| `resource_caps` | Partially consumed for post-parse/runtime artifact limits |
| `minimization` | Partially consumed by minimization/report paths |
| `include` | Paths are validated only; referenced files are not read or merged |
| `network` | The preset and per-link `latency`/`packet_loss` shape saga, replication and lease messages between participants; other link fields are not modeled |
| `cancellation` | Validated only; not consumed by `ScenarioRunner` |
| `participants` | Names validate fault references; `sender`/`receiver` (`messages`/`capacity`), `swarm` (`tasks`), `supervisor` (`max_restarts`), `worker` (`fail_times`), `saga-coordinator` (`step_ms`), `saga-participant`, `primary` (`writes`/`write_ms`), `replica`, `lease-grantor` (`initial_lease_ms`) and `lease-holder` (`renewals`/`renew_ms`/`margin_ms`/`start_ms`) roles run as lab tasks; other roles are unused |
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
  fixture, a two-participant saga with a partition on one participant's link
- Read the [replay debugging guide](../replay-debugging.md) for trace
  analysis techniques
- Check the [cancellation testing guide](../cancellation-testing.md) for
  obligation protocol guidance
