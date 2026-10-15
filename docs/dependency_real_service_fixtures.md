# Dependency real-service fixtures

This document is the operator view of
`artifacts/dependency_real_service_fixture_matrix_v1.json`. It covers
`CAP-REAL-SERVICE-E2E` and `CAP-VERIFICATION-PROFILES` for VER A3. A green
contract test means the fixture catalog and lifecycle rules are internally
consistent; it is not real-service interoperability proof.

## Lifecycle harness

`TestEnvironment` remains the fixture orchestrator. It now releases held
loopback port reservations immediately before managed startup, rolls back a
partial startup in reverse order, retries failed teardown, and exposes
`orphaned_services()` plus `teardown_errors()`. Cleanup callbacks run once even
when service teardown needs a retry.

`PinnedProcessIdentity` requires all of the following before a process starts:

- an absolute executable path;
- the exact lowercase SHA-256 of the executable;
- an exact, non-empty version-probe result.

`ProcessFixtureService` clears the ambient environment, accepts only explicitly
declared environment keys, supports a loopback TCP readiness probe with a
bounded timeout, detects an early crash, captures stdout and stderr, and
redacts declared secret values from its public log view. Successful failure or
stop cleanup rewrites the captured files with the same redaction. Repeated stop
is idempotent.

`DockerFixtureService` rejects mutable tags at startup. Its image must use
`repository@sha256:<64 hex digits>`. Container names are unique per process,
container logs are captured and redacted before removal, and teardown checks
for a residual container. The harness does not remove an unknown stale
container during startup.

Focused lifecycle tests cover:

- unique port reservation;
- successful and failed readiness;
- readiness timeout and early process crash;
- pinned digest and version drift;
- sanitized log capture;
- reverse rollback and reverse teardown;
- repeated teardown;
- failed-stop retry and orphan reporting.

## Service-family status

Each required family has a stable `fixture-smoke-*` receipt in the canonical
`dependency-sovereignty` suite. Catalog-preflight receipts always set
`proof_admitted=false`; they describe whether a real execution is available
without pretending the preflight itself exercised a service.

| Family | Smoke scenario | Current state | Reason |
|---|---|---|---|
| Kafka | `fixture-smoke-kafka` | `BLOCKED_EXTERNAL` | Existing setup uses mutable Kafka/ZooKeeper tags, permits an ambient bootstrap server, and lacks an approved oldest/newest/security version matrix. |
| NATS/NKey | `fixture-smoke-nats-nkey` | `BLOCKED_EXTERNAL` | The runner names NATS v2.12.5 but does not verify the archive or binary SHA-256 and does not provision isolated NKey credentials. |
| OTLP | `fixture-smoke-otlp` | `BLOCKED_EXTERNAL` | No immutable managed collector or pinned reference metrics/traces/logs reader/provider exists. |
| SQLite | `fixture-smoke-sqlite-real-disk` | `EXECUTABLE_COMPLETE` | The real-file WAL cancellation/rollback test uses the Cargo.lock-pinned bundled engine and an isolated temporary directory. |
| FrankenSQLite | `fixture-smoke-frankensqlite` | `UNSUPPORTED` | FrankenSQLite is a reverse dependency; this fixture belongs in its repository or a neutral consumer with an independent lockfile. |
| HTTP compression | `fixture-smoke-http-compression` | `BLOCKED_EXTERNAL` | Internal negotiation/codec tests are not an independent gzip, deflate, and Brotli peer. |
| TLS/X.509 | `fixture-smoke-tls-x509` | `BLOCKED_EXTERNAL` | Current focused tests use in-process or virtual peers, not an independently pinned client/server process in both directions. |
| Downstream consumers | `fixture-smoke-downstream-consumers` | `UNSUPPORTED` | Exact downstream repositories, revisions, and owner commands are outside this workspace. |

`BLOCKED_EXTERNAL` and `UNSUPPORTED` are terminal evidence outcomes for the
current run, not passing skips. A blocked cell must leave zero managed
processes, containers, held ports, temporary directories, and credentials.

## Commands

Validate the matrix, source wiring, negative fixtures, and one catalog-preflight
receipt per family:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_real_service_fixture_contract" \
  cargo test -p asupersync --test dependency_real_service_fixture_contract -- --nocapture
```

Run the same contract through the canonical retained-evidence suite:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario real-service-fixture-contract
```

Run the currently executable real-service family smoke:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_fixture_smoke_sqlite" \
  cargo test -p asupersync --features sqlite,test-internals \
  --test sqlite_real_disk_cancel_rollback -- --nocapture --test-threads=1
```

No local Cargo fallback is admissible for any command above.

## No-claim boundary

This contract does not prove blocked or unsupported service cells, broad
workspace health, release readiness, performance, dependency cutover, or live
RCH fleet availability. Internal, virtual, scripted-protocol, and in-memory
peers do not satisfy external service rows. Mutable image tags, unverified
binaries, ambient developer services, mock substitution, silently skipped
tests, and unredacted credentials are never admitted as proof.
