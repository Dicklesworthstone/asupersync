# Dependency Feature, Platform, Consumer, and Service Matrix

This is the operator guide for VER A5,
`asupersync-dep-p1-foundations-upksjk.6.5`. The machine-readable source is
[`artifacts/dependency_feature_platform_consumer_matrix_v1.json`](../artifacts/dependency_feature_platform_consumer_matrix_v1.json).
Its focused validator is
[`tests/dependency_feature_platform_consumer_matrix_contract.rs`](../tests/dependency_feature_platform_consumer_matrix_contract.rs).

The matrix is a fail-closed execution plan. It does not pre-label a compile,
runtime, service, platform, consumer, or performance coordinate as passing.
`RERUN_REQUIRED` means exactly that: run the named command again against the
source revision being evaluated and retain its terminal evidence.

## VER-A5-SPARSE-FEATURES

The artifact contains one direct sparse profile for every feature declared in
the root `Cargo.toml`. The contract joins those 57 profiles to the 57 feature
rows in `artifacts/dependency_capability_registry_v1.json`.

- `default-nightly` uses the pinned nightly toolchain and the default feature
  set.
- Every other sparse profile disables default features and selects exactly one
  root feature.
- The stable subset is a separate combination profile:
  `stable-no-default-proc-macros`. It runs
  `scripts/run_stable_lane_e2e.sh`; a nightly `proc-macros` compile cannot
  substitute for it.
- The relevant-combination rows preserve feature edges that matter at public or
  service boundaries: metrics plus tracing, both TLS root policies,
  QUIC/HTTP3/TLS, SQLite with test internals, Kafka with test internals, the two
  browser profiles, and the all-target lanes.
- Fuzz and workspace profiles are explicit quarantine rows. Feature unification
  in either row cannot satisfy a sparse production profile.

The validator compares the artifact to the live manifest. Adding, renaming, or
removing a Cargo feature without adding the corresponding sparse coordinate is
a contract failure. A profile that selects multiple direct features is also a
failure, even if Cargo resolves successfully.

## VER-A5-HOST-TARGET

Host and target are independent fields. `host_id` names the machine that
executes Cargo or a runtime; `target_id` names the code or service environment
being evaluated. A Linux RCH host compiling a wasm target is not a browser
runtime, and a Linux cross-check cannot be reported as macOS or Windows runtime
proof.

The compact matrix is a checked relational projection:

1. Each feature and capability names platform selectors in the capability
   registry.
2. `platform_selector_expansions` maps all 14 live selectors to concrete target
   coordinates.
3. Each concrete target names a host, target triple, execution kind, compile
   outcome, runtime outcome, exact command when executable, and blocker when it
   is not.
4. The contract expands every feature/capability selector and rejects missing
   selectors or target IDs.

Current target dispositions are intentionally conservative:

| Target coordinate | Compile | Runtime |
| --- | --- | --- |
| Linux x86_64 GNU | `RERUN_REQUIRED` | `RERUN_REQUIRED` |
| wasm32 browser | `RERUN_REQUIRED` | `BLOCKED_EXTERNAL` |
| Linux AArch64 | `BLOCKED_PLATFORM` | `BLOCKED_PLATFORM` |
| macOS AArch64 and x86_64 | `BLOCKED_PLATFORM` | `BLOCKED_PLATFORM` |
| Windows x86_64 MSVC | `BLOCKED_PLATFORM` | `BLOCKED_PLATFORM` |
| Android AArch64 and supported BSD | `BLOCKED_PLATFORM` | `BLOCKED_PLATFORM` |
| Other scalar target | `BLOCKED_PLATFORM` | `BLOCKED_PLATFORM` |

Apple Silicon, AMD x86_64, and Intel x86_64 performance coordinates are
separate from compile coordinates. They remain `NO_CLAIM` or
`BLOCKED_PLATFORM` until a fresh identified host produces retained benchmark
evidence. This artifact carries no performance result.

## VER-A5-CONSUMERS-SERVICES

The maintained consumer rows cover the public surfaces named by the bead:

- arbitrary downstream Serde and Protobuf types;
- downstream-authored `Stream` behavior;
- CLI/config/error workflows;
- external metrics exporter and privacy surfaces;
- the Tower adapter;
- HTTP compression feature resolution;
- real-file SQLite WAL cancellation and recovery;
- the NKey/JWT protocol boundary;
- Kafka and TLS real-service boundaries; and
- the external downstream portfolio.

An executable runtime row includes an exact remote-required command and a
pinned fixture, lockfile, crate checksum, or repository-source identity.
Compile-only commands cannot satisfy runtime rows. Kafka and TLS remain
`BLOCKED_EXTERNAL` because the repository lacks the approved immutable
oldest/current broker range or an independently pinned bidirectional TLS peer.

The capability registry lists 16 downstream repositories under `/dp`. The
canonical RCH workers do not mount that portfolio, and the registry does not
yet pin owner revisions plus runtime commands. The artifact therefore projects
all 16 as `BLOCKED_EXTERNAL`. Inventory presence on the controller does not turn
those cells green.

Service-version coordinates are joined from
`artifacts/dependency_real_service_fixture_matrix_v1.json`. The contract checks
all 16 cells, including Kafka oldest/current plaintext, Kafka SASL/TLS, NATS
NKey and JetStream reconnect, OTLP metrics/traces/logs, SQLite, FrankenSQLite,
gzip/deflate/Brotli, both TLS directions, and the downstream-consumer smoke
cell.

Only the SQLite fixture is currently executable. VER A5 maps that state back to
`RERUN_REQUIRED`; the retained VER A3 receipt is useful provenance but does not
waive a rerun for a new source revision. All other service cells stay
`BLOCKED_EXTERNAL` or `UNSUPPORTED` with their blocker and owner boundary.

## Running the contract

Run the focused validator through the remote compiler:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
  env CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS='-D warnings -C debuginfo=0' \
      CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_feature_platform_consumer_matrix" \
  cargo test -p asupersync \
    --test dependency_feature_platform_consumer_matrix_contract \
    -- --nocapture
```

Run the canonical retained scenario after committing the source revision:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario feature-platform-consumer-contract \
  --run-id ver-a5-feature-platform-consumer-001
```

The scenario retains its summary, events, scenario and validation-stage NDJSON,
environment snapshot, artifact manifest, replay manifest, and per-step logs
under:

```text
target/e2e-results/dependency-sovereignty/<run_id>/
```

The scenario proves the matrix and negative-fixture contract only. Operators
must run the individual sparse, combination, consumer, platform, and service
commands before changing a row from `RERUN_REQUIRED`.

## Negative fixtures

The validator mutates in-memory copies and proves that the gate rejects:

- a missing sparse feature profile;
- a sparse profile that relies on feature unification;
- a missing optional feature or platform edge;
- unknown or confused host/target IDs;
- an unsupported target reported as pass;
- a runtime consumer represented by compile-only evidence;
- a runtime consumer without pinned provenance;
- an executable service without immutable identity; and
- a missing oldest/current service range cell.

The canonical JSON also lists the full negative-fixture catalog required by the
aggregate VER A6 signoff.

## VER-A5-NO-CLAIMS

This contract does not prove that every planned lane has fresh evidence. It
does not infer runtime behavior from cross-compilation, infer one operating
system from another, substitute all-features for sparse profiles, substitute
mocks or ambient services for managed fixtures, or treat an absent downstream
repository as passing.

It also does not prove replacement parity, broad workspace health, release
readiness, performance improvement, real-service interoperability, live RCH
fleet availability, or permission to remove a dependency, feature, platform,
format, protocol, service, diagnostic, or user workflow.
