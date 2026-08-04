# Dependency failure-injection matrix

The VER A4 contract is
`artifacts/dependency_failure_injection_matrix_v1.json`. It turns the
replacement plans in `artifacts/dependency_verification_matrix_v1.json` into a
bounded, deterministic failure-injection obligation. The artifact is the
machine-readable source of truth; this page explains how replacement owners
instantiate it.

## What the contract proves

`tests/dependency_failure_injection_matrix_contract.rs` validates the live
replacement inventory against seven applicability families:

- every row receives success cleanup, cancellation-before-start, timeout or
  budget exhaustion, and panic-containment scenarios;
- concurrent rows add queued cancellation, retry/backoff cancellation, and
  shutdown races;
- parser or codec rows add cancellation during parse and encode plus malformed
  and truncated inputs;
- resource-sensitive rows add explicit resource caps, decompression bombs, and
  cardinality bombs;
- networked rows add network-I/O cancellation, peer disconnect, partial write,
  service restart, and rebalance/reconnect;
- persisted rows add disk-I/O cancellation, artifact corruption, and rollback
  after partial migration;
- user journeys add service recovery and rollback evidence.

The contract resolves every named oracle through the public
`OracleRegistry`. Its core set is `task_leak`, `obligation_leak`,
`cancellation_protocol`, `loser_drain`, `finalizer`, `region_tree`, and
`quiescence`. The deterministic model test reaches every injection phase under
success, error, cancellation, and panic, then checks that obligations, permits,
tasks, services, and cleanup accounting are quiescent.

The negative-fixture table fails closed on missing phases, unbounded step
budgets, sleeps, ambient randomness, mocks, log-substring assertions, missing
cleanup, missing or unknown oracles, absent operator error codes, missing replay
commands, incomplete receipts, and uncovered replacement rows.

## Replacement-owner contract

Each applicable replacement must instantiate its assigned scenario IDs with
`LabRuntime`, deterministic I/O or network drivers, explicit failpoints, or
real process control. A no-mock service scenario may control a real local
service process; it may not replace that process with an in-memory fake.

Each attempt emits a structured receipt with:

- stable scenario, phase, seed or fixture, and injection-driver identity;
- expected and observed `Outcome` class, plus a registered `ASUP-Exxx` code
  when the failure crosses an operator-facing boundary;
- retryability;
- obligations, permits, tasks, and service-process counts before and after;
- artifact state and partial-output validity before recovery;
- proof that the selected injection phase was reached;
- the first failing invariant, cleanup result, recovery instruction, and exact
  replay command.

Detailed logs are diagnostic artifacts. A log substring is never the pass
criterion. The structured outcome, resource counters, oracle results, artifact
state, and replay receipt decide the result.

All scenarios have explicit maximum step and virtual-time budgets. An
unbounded wait, wall-clock sleep used to create a race, or ambient entropy is a
contract failure. Success, error, cancellation, and panic all run the same
cleanup epilogue.

## Focused proof

List the stable dependency-sovereignty scenarios:

```bash
bash scripts/run_dependency_sovereignty_e2e.sh --list
```

Preview the focused VER A4 command and evidence paths:

```bash
bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario failure-injection-contract \
  --run-id ver-a4-preview \
  --dry-run
```

Execute the focused remote-only contract:

```bash
RCH_REQUIRE_REMOTE=1 \
  bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario failure-injection-contract \
  --run-id ver-a4-contract-001
```

The runner retains the normal dependency-sovereignty `summary.json`,
`events.ndjson`, `scenarios.ndjson`, `validation_stages.ndjson`,
`artifact_manifest.ndjson`, `environment.json`, `repro_manifest.json`, and
per-step logs. The stable E2E step ID is
`ver-a4-failure-injection-contract`. Its replay pointer repeats the same
remote-required command.

## No-claim boundary

A green VER A4 contract proves the matrix shape, live inventory mapping,
registered oracle names, deterministic model phase reachability, cleanup
accounting, runner registration, evidence fields, and negative-fixture
rejection. It does not prove that every replacement has already instantiated
its scenarios.

It also does not prove real-service interoperability, broad workspace health,
release readiness, performance improvement, dependency cutover, or live RCH
fleet availability. Replacement evidence remains non-green until the owning
unit, lab, property, fuzz, downstream, and real no-mock E2E rows have terminal
receipts.
