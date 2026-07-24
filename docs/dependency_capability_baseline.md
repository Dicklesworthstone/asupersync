# Dependency capability baseline

`artifacts/dependency_capability_baseline_v1.json` is the canonical executable
baseline for CAP A2. It turns the CAP A1 inventory into replayable incumbent
evidence while preserving every gap as an explicit blocker. It is not cutover evidence
and it does not claim that any proposed replacement is equivalent.

## No feature loss

Dependency sovereignty is an implementation objective, not permission to make
asupersync smaller as a product. Public APIs, generic extension points,
features, binaries, formats, wire protocols, platform behavior, diagnostics,
security policy, cancellation semantics, downstream integrations, and user
journeys stay available unless an explicit owner decision changes product
scope. A missing test is `UNKNOWN` or blocked; it never means unused.

Every one of the 50 stable capability IDs classifies six case classes:

- `positive`: accepted use and normal output;
- `empty_boundary`: empty, minimum, maximum, Unicode, binary, or other edge
  values;
- `malformed_error`: invalid input, public error mapping, and fail-closed
  behavior;
- `resource_limit`: size, memory, queue, disk, work, timeout, or topology
  bounds;
- `cancellation_cleanup`: interruption, drain, quiescence, and residual
  resources;
- `recovery`: retry, reuse, restart, rollback, or next-operation behavior.

A case is backed by a named evidence entry, typed as
`BLOCKED_EXTERNAL`, `BLOCKED_PLATFORM`, or `BLOCKED_OWNER`, or explicitly
`NOT_APPLICABLE` with a reason. Silent skips are forbidden. In particular,
zero tests is a failure for every cataloged Cargo test command.

## What parity means

The artifact separates properties that are often incorrectly collapsed into
“the tests passed”:

- `EXACT_BYTES` applies only to accepted wire, persisted, and stable operator
  bytes;
- `SEMANTIC` preserves the meaning of inputs and outputs without demanding
  accidental implementation bytes;
- `PUBLIC_COMPILE` protects downstream naming, traits, bounds, and feature
  combinations;
- `ERROR_CONTRACT` protects variants, context, stable diagnostics, and
  fail-closed behavior;
- `SECURITY_POLICY` protects trust, redaction, downgrade resistance, and secret
  lifecycle;
- `RESOURCE_ENVELOPE` protects bounded work, memory, handles, queues, and
  latency;
- `LIFECYCLE` protects cancellation, drain, cleanup, quiescence, restart, and
  rollback;
- `PLATFORM_MATRIX`, `SERVICE_INTEROP`, and `OPERATOR_UX` retain behavior that a
  host-only unit test cannot establish.

`EXECUTABLE_COMPLETE` means only that all six baseline case classes are
classified with current incumbent evidence or a justified non-applicability.
It does not mean the surface is exhaustive, a replacement has parity, or a
cutover is allowed.

## Standalone downstream consumer

The fixture at
`tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml` is its own
workspace. It does not inherit root dev-dependencies and never enables
`test-internals`. Its committed `Cargo.lock` and exact direct versions pin the
standalone resolver state. This catches both public API narrowing that an
in-workspace test could accidentally hide and unreviewed dependency drift.

Two profiles are required:

- `consumer-default` runs at least seven tests for the pinned lockfile, an
  arbitrary downstream Serde enum/map/binary type, a downstream-defined Prost
  message with repeated/map and oneof fields, a downstream-authored pending
  Stream, configuration and public errors, and Base64 protocol helpers.
- `consumer-full` runs at least nine tests and adds the public metrics exporter
  lifecycle, custom regex and automatic PII redaction, the Tower Service
  adapter, and feature-graph coverage for config and compression.

Representative types do not cap the accepted generic surface. They prove that
downstream-defined types still work; finite in-repo schemas never justify
replacing arbitrary Serde or Protobuf capability.

## Replay and logging

Run the focused scenarios through RCH:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh contract
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh consumer-default
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh consumer-full
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh catalog
```

The script writes a retained run directory under
`target/e2e-results/dependency-capability-baseline/<run_id>/`. The fail-closed
execution floors are 26 contract tests, seven default-consumer
tests, nine full-consumer tests, and one static catalog assertion. A successful
command below its lane's floor is reported as `FAIL`. Each run includes:

- `summary.json` with normalized outcome, executed test count, timing, cleanup,
  source drift, and redaction status;
- `events.ndjson` with stable run, scenario, and step IDs;
- per-step `stdout.log` and `stderr.log`;
- `provenance.json` with the actual source and baseline revisions, Rust/Cargo
  versions, exact shell-escaped command, fixture ID, per-file SHA-256 manifest
  plus aggregate fixture digest, features, target, host, execution tree, and
  RCH worker context. The runner accepts either GNU `sha256sum` or the
  macOS-provided `shasum -a 256`;
- `replay.sh` containing the exact deterministic replay command.

Canonical Cargo scenarios use RCH's clean committed-`HEAD` mode
(`--base HEAD --clean-overlay --no-overlay`), so unrelated shared-worktree dirt
is recorded by the controller but excluded from the execution tree. During
implementation, agents use explicit `--overlay-path` proof commands; the
retained runner is the post-commit replay surface.

The runner filters stdout and stderr before either stream reaches retained
files or the controller terminal. A deterministic canary self-test verifies
that filter on every run, and a post-write scan fails if the raw canary is
still present. It rejects zero-test Cargo success, rejects a successful
remote-required command whose RCH worker cannot be identified, and records the
complete generated-path inventory plus child-process cleanup. It does not use
a local Cargo fallback. External or platform prerequisites produce a typed
blocked receipt rather than a passing skip.

The later VER A2 aggregate owns
`scripts/run_all_e2e.sh --suite dependency-sovereignty`, injected runner
failure, aggregate service lifecycle, and cross-scenario log packaging. CAP A2
does not overclaim that future work.

## High-risk boundaries

- SQLite uses the incumbent real-file/WAL corpus, but FrankenSQLite is
  currently a reverse dependency. It may be compared only from a neutral
  synthesized consumer or the downstream repository; adding it to asupersync
  would create a Cargo cycle.
- Kafka authentication fixtures are not a Kafka client. Produce/consume,
  transactions, groups, rebalance, coordinator, security, fault, and restart
  behavior stay blocked on pinned real brokers.
- X.509 incumbent tests do not authorize owning certificate validation or
  cryptography. rustls/webpki remains the delegated validator unless the
  complete security epic passes.
- Regex examples do not narrow the accepted regex language. Fixed scanners are
  not a substitute for arbitrary user patterns.
- Compression includes Brotli. DEFLATE evidence cannot silently remove it.
- Linux evidence does not stand in for macOS, Windows, BSD, browsers, kqueue,
  IOCP, control events, xattr variants, or host-introspection fields.
- Functional concurrency evidence does not establish performance. Apple
  Silicon and representative high-core-count Intel/AMD measurements remain
  separate acceptance gates.

## Generated summary

<!-- BEGIN GENERATED BASELINE SUMMARY -->
- Artifact: `dependency-capability-baseline-v1` (schema 1)
- Coverage: 50 capabilities; 40 evidence entries; 2 consumer profiles.
- States: BLOCKED_EXTERNAL=5, BLOCKED_PLATFORM=6, EXECUTABLE_COMPLETE=12, EXECUTABLE_PARTIAL_BLOCKING=27.

| Capability ID | Baseline state | Evidence | Blocked cases |
|---|---|---:|---:|
| `CAP-ATP-VERSION-SCANNER` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-AUTH-CREDENTIALS` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-BASE64-CODEC` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-BROWSER-RUNTIME` | BLOCKED_PLATFORM | 1 | 2 |
| `CAP-CACHE-LAYOUT` | BLOCKED_PLATFORM | 2 | 1 |
| `CAP-CLI-ASUPERSYNC` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 3 |
| `CAP-CLI-ATP` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-CLI-ATPD` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-CLI-OFFLINE-TUNER` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-CONCURRENT-QUEUES` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-CONFIG-TOML-JSON` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-DATABASE-WIRE` | BLOCKED_EXTERNAL | 2 | 2 |
| `CAP-DEPENDENCY-LEDGER` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-DIAGNOSTICS` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-DOWNSTREAM-CONSUMERS` | EXECUTABLE_COMPLETE | 3 | 0 |
| `CAP-FUTURES-STREAMS` | EXECUTABLE_COMPLETE | 2 | 0 |
| `CAP-HASH-MAPS` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-HEX-CODEC` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-HOST-BENCH-METADATA` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-HOST-INTROSPECTION` | BLOCKED_PLATFORM | 1 | 1 |
| `CAP-HTTP-COMPRESSION` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-KAFKA` | BLOCKED_EXTERNAL | 1 | 2 |
| `CAP-LAB-DETERMINISM` | EXECUTABLE_COMPLETE | 2 | 0 |
| `CAP-NATS-MESSAGING` | BLOCKED_EXTERNAL | 2 | 2 |
| `CAP-NKEY-AUTH` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 3 |
| `CAP-OTLP-ECOSYSTEM` | BLOCKED_EXTERNAL | 2 | 2 |
| `CAP-PERSISTED-TRACE-SNAPSHOT` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-POLLING-SOCKET` | BLOCKED_PLATFORM | 1 | 1 |
| `CAP-PROC-MACROS` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-PROTOBUF-GENERIC` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 2 |
| `CAP-PUBLIC-API-TOPOLOGY` | EXECUTABLE_PARTIAL_BLOCKING | 3 | 2 |
| `CAP-QUIC-HTTP3-ATP` | EXECUTABLE_PARTIAL_BLOCKING | 3 | 1 |
| `CAP-REAL-SERVICE-E2E` | BLOCKED_EXTERNAL | 5 | 3 |
| `CAP-REGEX-PRIVACY` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 3 |
| `CAP-SCENARIO-YAML-JSON` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-SERDE-GENERIC` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-SIGNALS` | BLOCKED_PLATFORM | 1 | 1 |
| `CAP-SIMD-RAPTORQ` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-SQLITE` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-STRUCTURED-CONCURRENCY` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-SYNC-LOCKS` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-TEMP-ARTIFACTS` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 2 |
| `CAP-TIME-UTC-RFC3339` | EXECUTABLE_PARTIAL_BLOCKING | 2 | 1 |
| `CAP-TLS-X509` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-TOKEN-SLAB` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-TOWER-COMPAT` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 4 |
| `CAP-TRACE-LZ4` | EXECUTABLE_COMPLETE | 1 | 0 |
| `CAP-VERIFICATION-PROFILES` | EXECUTABLE_COMPLETE | 2 | 0 |
| `CAP-VISIBILITY-MACRO` | EXECUTABLE_PARTIAL_BLOCKING | 1 | 1 |
| `CAP-XATTR` | BLOCKED_PLATFORM | 1 | 1 |
<!-- END GENERATED BASELINE SUMMARY -->

## No-claim boundary

This baseline does not prove replacement parity, broad workspace health,
release readiness, production correctness, performance improvement, live RCH
fleet availability, or permission to delete anything. Every cutover stays
serialized behind CAP A4, VER A1/A2, campaign-specific unit and no-mock E2E
evidence, graph/oracle/rollback disposition, security review, platform/service
matrices, and owner signoff.
