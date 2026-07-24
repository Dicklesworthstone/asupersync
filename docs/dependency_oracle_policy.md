# Dependency Differential-Oracle Policy

Bead: `asupersync-dep-p1-foundations-upksjk.3`

## Purpose

The canonical machine-readable registry is
`artifacts/dependency_oracle_policy_v1.json`. Its focused contract is
`tests/dependency_oracle_policy_contract.rs`.

Dependency sovereignty needs differential tests, but retaining every incumbent
inside the workspace would preserve the very trust, native-build, and package
cycle costs that the program is meant to remove. This policy separates:

1. an incumbent dependency that still provides production functionality;
2. a planned oracle that has not reached cutover;
3. an active, time-bounded oracle retained after cutover;
4. immutable fixtures that do not resolve or build the incumbent; and
5. a retired oracle whose package edge is gone.

The registry is the decision source for that lifecycle. A comment saying that a
crate is "test only" is not sufficient.

## Current incumbent is not retained oracle

Most registry rows are currently `planned`. Their package is still an
incumbent production or optional-production edge, so the policy does not
pretend it has already been removed. In particular, `rdkafka`, `rusqlite`, and
`sqlparser` remain conditional production dependencies until their complete
replacement campaigns reach a terminal SAME-or-BETTER decision.

The post-cutover restrictions become mandatory before a manifest cutover is
committed. At that point the owner must:

- change `lifecycle_state` from `planned` to `active`;
- replace `CUTOVER_RELEASE` with the concrete introduction release;
- replace `CUTOVER_RELEASE_PLUS_2_MAX` with a concrete expiry release;
- record an ISO-8601 `expiry_date_utc`;
- capture immutable fixture provenance and license information;
- prove the declared graph lane and feature-unification behavior; and
- retain the incumbent package only in the class-permitted harness.

If those fields cannot be completed, the production dependency stays in place.
The program uses KEEP rather than an ungoverned oracle.

## Oracle classes

### `PURE_RUST_IN_WORKSPACE_ORACLE`

A bounded pure-Rust reference may remain in a workspace dev or explicit fuzz
lane only when:

- the reference adds no prohibited native, runtime, or host-build surface;
- feature unification cannot contaminate minimal or production profiles;
- the comparison cannot create a package cycle;
- fixture source, license, reference version, and hashes are recorded;
- an owner and terminal retirement bead exist; and
- retention ends no later than two releases after cutover.

The class does not assert that an upstream crate is free of unsafe code. Each
row records an `unsafe_status`, and activation requires a fresh package graph
audit. A pure-Rust crate whose resolved features activate prohibited native or
host-build work must move to external quarantine instead.

The bounded candidates include hex, Base64, futures-lite, slab, visibility,
Bincode, MessagePack, TOML, YAML, clap, regex, nkeys, prost, chrono/time,
parking_lot, LZ4, DEFLATE, and sysinfo reference surfaces.

### `NATIVE_OR_C_ORACLE`

An oracle with active C, C++, assembly, bundled native libraries,
configure/make, or prohibited native host-build exposure must not remain in any
ordinary asupersync graph after cutover.

Allowed forms are:

- an `external-cargo-harness` with its own manifest, lockfile, target directory,
  and execution receipt; or
- `frozen-fixture-only` vectors and transcripts.

It is forbidden from `workspace-normal`, `workspace-dev`, `workspace-build`,
`workspace-release`, and `workspace-fuzz-quarantine`.

The initial native rows are:

- `rdkafka` / `rdkafka-sys` / librdkafka;
- `rusqlite` / `libsqlite3-sys` / SQLite; and
- `sqlparser` when its resolved `psm` / `stacker` path introduces native stack
  probing.

The current incumbent edges are allowed to exist only until their conditional
production cutover. They are not permission to add the same packages back as
dev dependencies afterward.

### `REVERSE_DEPENDENCY_ORACLE`

If project B already depends on asupersync, B cannot be added as an asupersync
dev dependency. Cargo would create a package cycle and normal workspace checks
would inherit B's graph.

The comparison must run in one of:

- the `downstream-project` itself;
- a `neutral-synthesized-consumer` with an independent lockfile; or
- immutable `frozen-fixture-only` inputs.

FrankenSQLite parity therefore belongs in FrankenSQLite or a neutral consumer
that depends on both engines. The registry's cycle rule is explicit:
`must-not-enter-asupersync-workspace`.

### `SECURITY_PROTOCOL_ORACLE`

Parser and protocol references handling certificates, credentials, telemetry,
or other security-sensitive data are quarantined even when their
implementation is pure Rust. They require:

- corpus source, license, byte hash, reference version, and expected result;
- strict secret and identifying-data redaction;
- explicit input and resource bounds;
- fuzz-only, external, or fixture-only placement;
- a two-release expiry; or
- a `permanent-keep-approved` owner receipt with nonempty justification.

The initial security rows cover the X.509 parser and the generated OTLP
protobuf/tonic reference graph. The OTLP row does not weaken the default and
metrics production no-Tokio guarantees.

## Registry fields

Every oracle row carries:

- stable oracle and replacement candidate IDs;
- replaced package IDs;
- oracle class and lifecycle state;
- current graph state;
- allowed and forbidden graph profiles;
- native and unsafe status;
- exact harness URI;
- fixture source and license policy;
- introduction and expiry release;
- expiry date and maximum release window;
- owner and retirement bead;
- feature-unification and cycle-safety checks;
- corpus provenance and secret-redaction policy;
- extension signoff; and
- a specific no-claim boundary.

Missing or unknown fields fail the contract. A planned harness URI identifies
the owning location; it is not evidence that the harness already exists.

## Activation procedure

Before removing a production dependency:

1. Re-read the current manifest, feature graph, package IDs, public API map,
   downstream consumers, and the owning replacement bead.
2. Generate a current marginal ledger for every affected feature, target, and
   host profile.
3. Freeze independent vectors and pre-cutover transcripts with source,
   license, version, hash, seed, and redaction receipts.
4. Build or identify the class-permitted harness.
5. Resolve the harness graph separately and prove the incumbent cannot enter a
   forbidden profile through feature unification.
6. For a downstream comparison, prove no reverse package cycle and preserve
   the neutral/downstream lockfile.
7. Update the registry row to `active` with concrete releases and date.
8. Run the focused contract and the owning campaign's unit, property,
   differential, fuzz, real-service E2E, and performance gates.
9. Serialize the production manifest cutover last.
10. If any proof is unavailable, KEEP the dependency.

## Expiry, extension, and retirement

`CUTOVER_RELEASE_PLUS_2_MAX` means that a planned pure-Rust, native, reverse,
or security oracle may be active for at most two subsequent releases. It is a
maximum, not a target.

At each release:

1. compare the policy date and release against every active row;
2. retire rows whose owning differential corpus is now frozen and sufficient;
3. close or update the linked retirement bead;
4. remove the package from every remaining harness when retired; and
5. capture fresh graph evidence.

An expired active oracle fails closed. An extension is valid only when
`extension_signoff.status` is `approved` and the row carries:

- approving owner;
- approval timestamp;
- new expiry release, copied into the row's `expiry_release`;
- a new valid ISO-8601 date in the row's `expiry_date_utc`;
- concrete reason; and
- updated graph and fixture evidence in the owning bead.

Only `SECURITY_PROTOCOL_ORACLE` may use `permanent_keep`, and only with
`permanent-keep-approved` owner signoff and a nonempty security justification.

## Test and E2E ownership

The focused contract contains positive schema/graph checks and negative
fixtures for:

- missing retirement disposition;
- native oracle in `workspace-dev`;
- reverse dependency in `workspace-dev`;
- expired active oracle without extension;
- approved extension with unchanged expiry release or stale expiry date;
- security oracle without redaction;
- missing feature-unification proof; and
- allowed/forbidden profile overlap;
- unknown graph-profile names; and
- duplicate registry, class, profile, or required-field IDs.

It also checks the current manifest truth: native incumbents remain production
edges until cutover, are not ordinary dev dependencies, and FrankenSQLite is
not an asupersync workspace dependency.

This policy does not change runtime behavior or contact an external service.
Its canonical no-mock aggregate execution and structured result packaging are
owned by `asupersync-dep-p1-foundations-upksjk.6.2`; aggregate negative-fixture
signoff is owned by `asupersync-dep-p1-foundations-upksjk.6.6`. Those beads
must include this scenario in:

```text
scripts/run_all_e2e.sh --suite dependency-sovereignty
```

and retain:

```text
target/e2e-results/dependency-sovereignty/<run_id>/summary.json
target/e2e-results/dependency-sovereignty/<run_id>/events.ndjson
target/e2e-results/dependency-sovereignty/<run_id>/<scenario>/stdout.log
target/e2e-results/dependency-sovereignty/<run_id>/<scenario>/stderr.log
```

The scenario ID is `dependency_oracle_policy_contract_v1`. Structured results
must include source revision, feature vector, target/host, RCH worker,
toolchain, stable step IDs, normalized outcome, elapsed time, redaction result,
and replay command. BLOCKED and UNSUPPORTED are explicit outcomes; neither is
green.

## Validation

Run the focused contract through RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_oracle_policy" cargo test -p asupersync --test dependency_oracle_policy_contract -- --nocapture
```

The artifact embeds the exact same proof command so documentation drift fails
the contract.

## No-claim boundaries

Passing this contract proves only that:

- all 24 initial oracle plans have complete governance rows;
- class placement and forbidden graph lanes are internally consistent;
- retirement beads and aggregate E2E owners exist;
- current native incumbency is not falsely reported as completed cutover;
- reverse-dependency placement is cycle-safe by policy; and
- negative fixtures fail for the prohibited states listed above.

It does not prove that either implementation is correct. It does not prove
that a planned harness exists, native code is safe, a production cutover is
ready, performance is equivalent, every downstream consumer was exercised, or
the broad workspace is healthy. Those claims require the owning replacement
campaign and terminal evidence.
