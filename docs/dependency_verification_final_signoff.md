# Dependency Verification Final Signoff

This document is the operator guide for VER A6,
`asupersync-dep-p1-foundations-upksjk.6.6`. The canonical machine contract is
`artifacts/dependency_verification_final_signoff_v1.json`, checked by
`tests/dependency_verification_final_signoff_contract.rs`.

The terminal verdict is `PASS_SCOPED_KEEP_DEFER`. It means the Phase-1
capability and verification artifacts join without an unowned validation
coordinate. It does not mean that planned tests have run, that a dependency
exit is allowed, or that a blocked service or platform became green.

## What the aggregate resolves

The signoff starts from the 50 stable capability IDs in
`artifacts/dependency_capability_registry_v1.json`. For each ID, the contract
resolves these columns:

- focused unit evidence;
- integration, downstream, E2E, scan, and audit evidence;
- scenario owner and fixture or seed;
- sparse-feature and platform cells;
- retained artifact schema and replay pointer;
- deterministic failure-injection applicability;
- a pinned real-service owner or
  `NOT_APPLICABLE_NON_SERVICE_CAPABILITY`;
- redaction policy;
- final cutover beads and the current cutover state.

Empty values and silent skips are invalid. N/A is allowed only for a
non-service capability under the explicit label
`NOT_APPLICABLE_NON_SERVICE_CAPABILITY`.

All 106 `role=implementation` rows in the VER A1 matrix must have a focused
unit plan. An implementation row also needs a direct E2E/downstream plan. When
that row is not itself a user-journey boundary, the only accepted alternative
is `N/A_ROW_LOCAL_AGGREGATE_CAPABILITY_COVERAGE`: every capability on the row
must have a checked E2E/downstream plan elsewhere in the same canonical
matrix. The contract computes this join; authors cannot assert it free-form.

## Prerequisite closure

The artifact names CAP A1 through CAP A4 and VER A1 through VER A5 as required
closed prerequisites. RCH excludes mutable tracker state, so the remote
focused test validates the checked VER A1 tracker-plan digest and CAP A4
`PASS_SCOPED` graph snapshot. Before closeout, the operator must also run the
exact `canonical_commands.live_prerequisite_audit` `br show` command from the
artifact against the live workspace. The contract requires the registry,
baseline, cutover, verification, failure-injection, real-service, and
feature/platform/consumer capability sets to agree exactly.

The joined cutover result is deliberately non-authorizing:

- 9 capabilities are `NOT_A_CUTOVER` guard rows;
- 23 are `KEEP_INCUMBENT`;
- 18 are `BLOCKED_PENDING_EVIDENCE`;
- all 50 have `dependency_exit_allowed=false`.

## Forensic runner contract

The stable scenario is `aggregate-signoff-contract`; its stable step is
`ver-a6-aggregate-signoff-contract`. Cargo execution is remote-only through
RCH clean-overlay mode. A local Cargo fallback is a failure.

The retained run directory must contain:

- `summary.json`;
- `events.ndjson`;
- `scenarios.ndjson`;
- `validation_stages.ndjson`;
- `artifact_manifest.ndjson`;
- `environment.json`;
- `repro_manifest.json`;
- per-step stdout and stderr logs.

Pass/fail comes from structured receipts, never a log substring alone. Each
validation-stage row carries capability IDs, stable scenario and step IDs,
fixture/seed, config snapshot, exact command, expected and observed outcomes,
exit/signal/timing, artifact pointers, RCH provenance, owner, redaction policy,
first failing invariant, cleanup result, and replay pointer. The suite keeps
the standard minimum log-quality score of 80.

The redaction policy is `metadata-and-secret-patterns-v1`. The canary
`VER_A2_CANARY_SECRET_DO_NOT_RETAIN` must never survive in retained output.
Every wait is bounded, cleanup is mandatory, and an orphan process is a
failure.

## Real-service interpretation

The aggregate binds service-sensitive capabilities to the VER A3 families:
Kafka, NATS/NKey, OTLP, SQLite/FrankenSQLite, HTTP compression, TLS/X.509, and
downstream consumers. It preserves their exact outcomes. Only the real-file
SQLite fixture is currently executable-complete; missing immutable external
identity remains `BLOCKED_EXTERNAL`, and unavailable downstream work remains
`UNSUPPORTED`.

Neither outcome is converted to pass. A mocked service, ambient service,
mutable image, missing version, or missing immutable identity fails closed.

## Negative fixtures

The focused contract mutates one valid gate at a time and requires all 14
acceptance failures:

1. no unit test;
2. no direct or aggregate E2E path;
3. incomplete artifact/log contract;
4. log-only assertion;
5. secret leakage;
6. missing replay pointer;
7. silent local fallback;
8. mocked external service;
9. missing sparse feature;
10. unsupported platform reported as pass;
11. unpinned service;
12. unbounded wait;
13. orphan process;
14. cutover preceding terminal evidence.

Each mutation must produce exactly its stable error label. The positive
fixture must produce no gaps.

## Canonical commands

Discover the stable scenario:

```bash
bash scripts/run_dependency_sovereignty_e2e.sh --list
```

Inspect the complete command and replay inventory without running Cargo:

```bash
bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario aggregate-signoff-contract \
  --dry-run \
  --run-id ver-a6-dry-run-001
```

Run the focused contract through remote RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_verification_final_signoff" \
  cargo test -p asupersync \
    --test dependency_verification_final_signoff_contract -- --nocapture
```

Run the retained canonical scenario:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario aggregate-signoff-contract \
  --run-id ver-a6-aggregate-signoff-001
```

Replay without the run ID to create a fresh retained attempt:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario aggregate-signoff-contract
```

## No-claim boundary

This signoff proves deterministic schema joins, ownership, plan coverage,
negative-fixture behavior, suite discovery, dry-run inventory, replay
coordinates, remote-routing policy, redaction, and cleanup contracts.

It does not execute every planned evidence row or prove broad runtime
correctness, performance, no regression, release readiness, broad workspace
health, live RCH fleet availability, unavailable service/platform execution,
or downstream-repository behavior. It does not authorize dependency, feature,
API, format, protocol, platform, diagnostic, user-journey, or file removal.
