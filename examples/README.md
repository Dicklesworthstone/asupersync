# Asupersync Examples

Start with the four-level on-ramp. Each Rust entry below includes its exact run
command in [`metadata.json`](metadata.json), the machine-readable companion to
this index.

## Graduated on-ramp

- [`onramp_level0.rs`](onramp_level0.rs) — enter the production runtime with
  `#[asupersync::main]` and no runtime concepts.
- [`onramp_level1.rs`](onramp_level1.rs) — add the prelude, `Cx`, `Outcome`,
  and composable budgets.
- [`onramp_level2.rs`](onramp_level2.rs) — spawn and collect region-owned
  dynamic fan-out through a scoped `JoinSet`.
- [`onramp_level3.rs`](onramp_level3.rs) — commit a two-phase channel send and
  make the deterministic lab catch an obligation leak.
- [`production_service.rs`](production_service.rs) — run a production-style
  HTTP service with a SQLite-backed handler and request-aware graceful drain.

## Runtime, API, and structured-concurrency examples

- [`hello.rs`](hello.rs) — minimal async entry point with a `Cx` checkpoint.
- [`spawn_fanout.rs`](spawn_fanout.rs) — small `JoinSet` fan-out with joined
  child outcomes.
- [`external_consumer.rs`](external_consumer.rs) — public-API smoke program for
  runtime and lab entry points.
- [`appspec_reference_journey.rs`](appspec_reference_journey.rs) — production
  `AppSpec` journey with explicit capability ownership and fail-closed lowering.
- [`spork_minimal_supervised_app.rs`](spork_minimal_supervised_app.rs) — minimal
  supervised application with a named `GenServer` child.
- [`session_typed_channel.rs`](session_typed_channel.rs) — session facade for
  send permits, leases, and two-phase commit.
- [`test_manual.rs`](test_manual.rs) — manual buffered `read_line` smoke over
  split UTF-8 input.

## Macro examples

- [`macros_basic.rs`](macros_basic.rs) — `scope!`, `spawn!`, and `join!`
  fundamentals.
- [`macros_nested.rs`](macros_nested.rs) — nested macro scopes and tree-shaped
  ownership.
- [`macros_race.rs`](macros_race.rs) — winner selection with loser cleanup.
- [`macros_error_handling.rs`](macros_error_handling.rs) — structured macro
  error handling.

## Deterministic testing and forensics

- [`deterministic_test.rs`](deterministic_test.rs) — same-seed replay,
  quiescence, and invariant reporting.
- [`cancellation_injection.rs`](cancellation_injection.rs) — systematic
  cancellation at recorded await points.
- [`chaos_testing.rs`](chaos_testing.rs) — deterministic delay, fault, and
  budget injection.
- [`demo_record_nondeterministic.rs`](demo_record_nondeterministic.rs) — find
  and record an obligation leak for replay.
- [`demo_delta_debug.rs`](demo_delta_debug.rs) — minimize a structured failure
  trace hierarchically.
- [`demo_benchmark.rs`](demo_benchmark.rs) — reproducible time-travel benchmark
  with golden checksums.

## Services, protocols, and observability

- [`atp_daemon_basic.rs`](atp_daemon_basic.rs) — configure an ATP daemon with
  in-process peer and transfer state.
- [`channel_mpsc_select_e2e.rs`](channel_mpsc_select_e2e.rs) — thin target for
  the production MPSC/select E2E harness.
- [`prometheus_metrics.rs`](prometheus_metrics.rs) — metrics provider and
  Prometheus-style export.
- [`atp_dogfood_demo.sh`](atp_dogfood_demo.sh) — manual ATP operator workflow.
- [`atp_j5_cli_examples.md`](atp_j5_cli_examples.md) — ATP J5 CLI journeys and
  expected operator flows.
- [`grafana_dashboard.json`](grafana_dashboard.json) — importable observability
  dashboard.

## Scenario fixtures

These 13 YAML files are typed `Scenario` fixtures. Their filenames, comments,
and descriptions are authoring narratives, not evidence that the runner simulates
every declared network, cancellation, or fault effect or schedules the named
workload. Include paths are validated but not merged. Only participants whose
role is exactly `sender`, `receiver`, `swarm`, `supervisor`, `worker`,
`saga-coordinator` or `saga-participant` run: senders and receivers as lab
tasks on bounded two-phase `mpsc` channels, a swarm as many short lab tasks,
supervisors as managed supervisors that restart failing workers, and saga
coordinators as `remote::Saga` runs that compensate in reverse when a
participant refuses or a message is lost. The `network` preset and per-link
latency and loss delay or drop saga messages, and `partition` and `heal`
faults between two participants cut and restore saga links; no other fault
changes the workload. Other roles run nothing (`Steps: 0 (no workload ran)`).
See the [author guide](../docs/adoption/getting_started.md) for the field
boundaries.

- [`scenarios/smoke_happy_path.yaml`](scenarios/smoke_happy_path.yaml) — small
  typed smoke fixture.
- [`scenarios/cancellation_exhaustive.yaml`](scenarios/cancellation_exhaustive.yaml)
  — fixture declaring cancellation settings, which are currently
  validation-only.
- [`scenarios/chaos_sendpermit_ack.yaml`](scenarios/chaos_sendpermit_ack.yaml) —
  chaos fixture; its `sender` and `receiver` run as a real channel workload.
- [`scenarios/clock_skew_lease.yaml`](scenarios/clock_skew_lease.yaml) —
  clock-skew declaration fixture; the action is recorded rather than simulated.
- [`scenarios/composable_base.yaml`](scenarios/composable_base.yaml) — reusable
  base-shaped fixture; current loaders do not merge it into another document.
- [`scenarios/composed_partition_test.yaml`](scenarios/composed_partition_test.yaml)
  — include and partition declaration fixture; include resolution is not wired.
- [`scenarios/custom_latency_model.yaml`](scenarios/custom_latency_model.yaml) —
  network-latency fixture; its hub and peer roles are unbound, so its links
  shape no traffic.
- [`scenarios/host_crash_restart.yaml`](scenarios/host_crash_restart.yaml) —
  supervision fixture; its `supervisor` restarts each `worker` after one
  failure, while the crash and restart actions stay trace records.
- [`scenarios/partition_heal.yaml`](scenarios/partition_heal.yaml) — saga
  partition/heal fixture; its coordinator runs a saga over two participants
  while the declared partition cuts one of their links.
- [`scenarios/stress_10k_tasks.yaml`](scenarios/stress_10k_tasks.yaml) —
  stress fixture; one `swarm` participant runs 10,000 short lab tasks under
  chaos.

The standalone FrankenLab CLI also ships three typed scenario fixtures, all
covered by [`metadata.json`](metadata.json):

- [`01_race_condition.yaml`](../frankenlab/examples/scenarios/01_race_condition.yaml)
  — race-condition fixture; two `sender` tasks race on one implicit-sink channel.
- [`02_obligation_leak.yaml`](../frankenlab/examples/scenarios/02_obligation_leak.yaml)
  — obligation fixture; one `sender` and four `receiver` tasks under light chaos.
- [`03_saga_partition.yaml`](../frankenlab/examples/scenarios/03_saga_partition.yaml)
  — ten-participant saga under heavy chaos; without chaos, the partition of
  participants 7-9 makes the coordinator time out and compensate its steps.
