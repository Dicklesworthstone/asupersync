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

## Current manifest reconciliation

Bead `asupersync-mnotoo.4.1` adds the checked
`dependency-oracle-manifest-reconciliation-v1` block to the same canonical
artifact. It does not create a second registry and does not activate any of the
24 planned post-cutover rows.

The reconciliation inventories the reference edges that exist now:

- 10 active reference packages;
- 15 exact manifest edges;
- every root workspace member manifest;
- the excluded fuzz and WASM Cargo projects;
- five standalone conformance project manifests; and
- `Cargo.lock` package version, source, and checksum data.

Synthetic Cargo manifests under `tests/fixtures/` are excluded because they are
positive and negative contract inputs, not installed dependency edges. Every
other scoped manifest and the lockfile carries a SHA-256 and line-count pin.
Any drift is an unregistered state until the active registry is reconciled.

The active packages are `httparse`, `tokio-util`, `sqlx`, `redis`, `raptorq`,
`tokio`, `h2`, `prometheus-client`, `opentelemetry_sdk`, and
`opentelemetry-proto`. Each row records:

- exact Cargo package ID, requested and resolved version, registry source, and
  lockfile checksum;
- every admitted manifest path, dependency section, alias, feature set, and
  default-feature state;
- exact source paths and focused `cargo test` lanes;
- a production-exclusion command and its deliberately narrow no-claim scope;
- the Git revision and date that introduced the edge;
- concrete release/date expiry;
- independent corpus status and provenance;
- bead-backed owner, renewal authority, and removal bead; and
- a row-specific no-claim boundary.

The current deterministic class report is:

| Class | Active oracle edges | Interpretation |
| --- | ---: | --- |
| Production | 0 | A package may have a distinct production edge, but no oracle edge is production evidence. |
| Dev / conformance | 15 | Only the exact registered differential and conformance lanes are admitted. |
| Build | 0 | A build-dependency oracle is unregistered and fails closed. |
| Native | 0 active, 3 planned | Native incumbents remain planned external or fixture-only oracles. |
| Reverse-cycle | 0 active, 1 planned | FrankenSQLite remains outside the workspace. |

Some dependency declarations are explicitly non-oracle candidates. For
example, Tokio drives conformance binaries, prost supports generated messages,
and the excluded fuzz conformance member declares HTTP/1 packages that its
current H2-only sources do not import. The H2 edge in that excluded member is
`declared-reference-not-wired`; it cannot report PASS. The standalone RaptorQ
differential skeleton similarly has no RaptorQ or asupersync package edge and
remains blocked.

The reconciliation snapshot is current at release `0.4.9` on `2026-08-21`.
Renewal belongs to `asupersync-mnotoo.4` and requires a new expiry, owner
receipt, corpus status, production-exclusion evidence, and one decision for
every due active row. Removal and the initial retirement sweep belong to
`asupersync-mnotoo.4.3`. The machine state remains
`cutover_authorized = false`.

### Initial retirement sweep

The `asupersync-mnotoo.4.3` sweep reviewed all 10 active rows after their
original `0.3.11` release deadline had passed. It retired zero and renewed all
10 through release `0.4.11` or UTC date `2026-10-21`, whichever is reached
first. This is a bounded preservation decision, not a claim that indefinite
retention is acceptable. Removing any row now would discard live comparison
coverage without an independently sufficient replacement corpus.

| Active oracle | Disposition | Evidence still required before retirement |
| --- | --- | --- |
| `httparse` HTTP/1 | Renewed | Frozen request-head outcomes with provenance and seeded-parser mutation proof. |
| `tokio-util` codec | Renewed | Immutable frame transcripts covering bounds, truncation, and flush behavior, plus mutation proof. |
| `sqlx` MySQL | Renewed | Independently frozen packet transcripts for prepared-value, null-bitmap, signedness, and malformed cases. |
| `redis-rs` | Renewed | Independent RESP2/RESP3 semantic outputs and mutation proof across all seven registered families. |
| `raptorq` | Renewed | Independently generated source, repair, and decode vectors for every registered symbol regime. |
| Tokio semaphore | Renewed | Separation of non-oracle Tokio harness support plus independent wake-order transcripts. |
| `h2` | Renewed | Complete independent protocol vectors and resolution of the explicitly unwired fuzz copy. |
| `prometheus-client` | Renewed | Immutable exposition outputs covering escaping, ordering, buckets, and special numeric values. |
| `opentelemetry_sdk` | Renewed | Separation of exporter test support and completion of independent propagation/resource fixtures. |
| `opentelemetry-proto` | Renewed | Complete finite-schema vectors for every signal without resolving generated incumbent messages. |

Each machine-readable decision records its old and new deadline, retained
invariants, concrete missing evidence, production-exclusion status, approving
bead authority, and next action. Because no manifest edge was retired, profile
remeasurement is explicitly `not-applicable-no-manifest-edge-retired`; no
manifest, lockfile, public API, fixture, or runtime behavior changed.

The focused contract fails on:

- manifest or lockfile pin drift;
- an unregistered or unknown oracle edge;
- an expired active row;
- missing owner, exact test scope, independent corpus, or removal bead;
- package version, source, or checksum mismatch; and
- deterministic report count drift;
- a missing or unapproved retirement decision;
- drift in the scheduled expiry gate; and
- an active deadline reached by the live Cargo package version or UTC date.

Manifest and lockfile pins prove only that the reviewed graph text has not
drifted. They do not prove a package safe, a reference correct, a comparison
complete, or a production graph broadly healthy.

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

## Native and reverse-cycle quarantine proof

`asupersync-mnotoo.4.2` adds the machine-readable
`dependency-oracle-quarantine-proof-v1` packet under
`manifest_reconciliation.quarantine_proof`. It closes a subtle classification
gap: package presence in `Cargo.lock` is not proof that a native build is
active, and native build activity under an explicitly enabled production
feature is not proof that the same package is a live test oracle.

The contract classifies the exact Cargo `run-custom-build` units reached by an
explicit feature/profile/target/host unit graph. Only `absent` and `active` are
green-eligible classifications. A missing target or host, an unclassified
custom-build unit, a missing feature vector, or any `unknown` native state is a
hard failure.

The canonical Linux matrix is:

| Profile | Boundary | Reached build scripts | Active native compilation/link boundary | Oracle role |
|---|---|---|---|---|
| `default-check` | default normal/build graph | none of the governed candidates | none | absent |
| `default-all-targets-check` | default tests, examples, benches, and binaries | none of the governed candidates | none | absent |
| `default-release-check` | default release graph | none of the governed candidates | none | absent |
| `sqlite-feature-check` | optional `sqlite` production feature | `libsqlite3-sys`, `psm`, `stacker` | `libsqlite3-sys`, `psm`; `stacker` is declared inactive on Linux | incumbent production edges, not oracles |
| `kafka-feature-check` | optional `kafka` production feature | `rdkafka-sys` | `rdkafka-sys` | incumbent production edge, not oracle |
| `all-features-all-targets-check` | all features and all targets | all four governed build scripts | `libsqlite3-sys`, `psm`, `rdkafka-sys`; `stacker` is declared inactive on Linux | incumbent production edges, not oracles |
| `all-features-release-check` | all-features release graph | all four governed build scripts | `libsqlite3-sys`, `psm`, `rdkafka-sys`; `stacker` is declared inactive on Linux | incumbent production edges, not oracles |

Every row records `x86_64-unknown-linux-gnu` as both target and host and embeds
an exact `RCH_REQUIRE_REMOTE=1 rch exec -- ... cargo check --locked ... -Z
unstable-options --unit-graph` recipe. The unit graph identifies build-script
reachability. Target-specific source rules then distinguish active native work
from no-op build scripts: on Linux `stacker` returns without compiling C while
`psm` assembles the stack-switching source. Other targets and hosts need their
own receipts and may not inherit the Linux classification. The graph does not
claim that compilation or linking succeeded.

The three planned native rows have an explicit isolated-lane result:
`blocked-planned-no-external-manifest` / `BLOCKED`. Their
`external-harness://` values are ownership addresses, not installed manifests,
and therefore cannot report PASS. This is deliberate fail-closed evidence,
not an omission disguised as green:

- `rdkafka-librdkafka-external-reference` remains a planned external oracle;
  the root `kafka` feature still activates `rdkafka-sys` as an incumbent.
- `rusqlite-libsqlite-external-reference` remains a planned external oracle;
  the root `sqlite` feature still activates bundled `libsqlite3-sys` as an
  incumbent.
- `sqlparser-native-exposure-reference` remains a planned external oracle;
  the root `sqlite` feature still reaches `psm` and `stacker` build scripts,
  with native assembly active in `psm` and `stacker`'s own Linux build script
  declared inactive.

No command in this packet implicitly authorizes a broker, system package
manager, external service, service mutation, or non-Cargo build tool. Creating
or executing a future external harness requires the owning bead's separate
authorization and receipts.

The reverse-cycle row has a real neutral boundary at
`tests/fixtures/sqlite-parity-consumer/Cargo.toml`. That manifest declares its
own nested `[workspace]`, is non-publishable, and has the separately pinned
`tests/fixtures/sqlite-parity-consumer/Cargo.lock`. It depends on asupersync and
FrankenSQLite from outside the root workspace, so Cargo can resolve both sides
without making FrankenSQLite an asupersync dependency. The focused contract
pins both files, proves the root manifest and lock remain free of `fsqlite`,
and rejects loss of the nested-workspace boundary.

The permanent negative fixtures are:

- `native-build-unit-leakage`;
- `unknown-active-native-state`;
- `reverse-consumer-loses-workspace-boundary`; and
- `native-isolated-lane-falsely-green`.

These checks establish quarantine and role classification. They do not prove
native-code safety, successful linking, broker availability, SQL correctness,
performance parity, or permission to remove an incumbent dependency.

## Aggregate governance signoff

`asupersync-mnotoo.4.4` adds the
`dependency-oracle-aggregate-signoff-v1` packet under
`manifest_reconciliation.aggregate_signoff`. It is the terminal reconciliation
of the three child contracts, not a new registry and not a dependency-cutover
decision.

The aggregate covers all 34 governed rows without duplicating their authority:

| Population | Count | Terminal interpretation |
|---|---:|---|
| Planned registry rows | 24 | Incumbent or future-oracle plans remain governed but are not active retained oracles. |
| Active registry rows | 10 | All are exact dev/conformance references with bounded retirement decisions. |
| Pure-Rust rows | 26 | 18 planned plus 8 active. |
| Security/protocol rows | 4 | 2 planned plus 2 active; independent corpus, redaction, and resource-bound requirements remain normative. |
| Native/C rows | 3 | All remain planned external or fixture-only oracles; none is an ordinary active oracle. |
| Reverse-cycle rows | 1 | The FrankenSQLite comparison stays planned; its cycle-isolation evidence remains the independent neutral consumer. |

The aggregate report has zero unregistered edges, expired active rows, missing
required fields, pending retirement decisions, and unknown registry rows. It
preserves 15 active dev/conformance manifest edges, zero production oracle
edges, and zero build-dependency oracle edges. Cargo `mode=build` or
`run-custom-build` units are not automatically build-dependency oracle edges;
the manifest section and semantic registry row remain authoritative.

Four live Linux target/host unit-graph receipts make the ordinary graph split
explicit:

| Receipt | Governed packages resolved | Semantic oracle rows admitted |
|---|---:|---:|
| `root-default-normal` | 0 | 0 |
| `root-default-release` | 0 | 0 |
| `root-focused-dev` | 10 | 8 root rows; `h2` and `prometheus-client` are resolved support in this target, not promoted evidence. |
| `conformance-focused-normal` | 7 | 4 conformance rows; `httparse`, `tokio`, and `tokio-util` are resolved support only. |

Each receipt records the exact `RCH_REQUIRE_REMOTE=1 rch exec -- ... cargo
check --locked ... -Z unstable-options --unit-graph` command, target, host,
worker, exit status, unit count, observation date, resolved package IDs,
semantic row IDs, support-only package IDs, and a narrow no-claim boundary.
The aggregate contract derives the semantic sets from the registered manifest
edges, so transitive reachability cannot silently become oracle evidence.

The security/protocol projection covers all four registered rows:

- the planned X.509 and generated-OTLP rows remain blocked until their
  independent vectors, licenses, hashes, redaction, and resource limits are
  complete;
- the active OpenTelemetry SDK and protobuf rows remain partial, explicitly
  fail closed on XFAIL/unavailable surfaces, and expire at release `0.4.11` or
  UTC date `2026-10-21`; and
- each active row links to its concrete retirement-sweep missing evidence,
  retained invariants, owner, and next action.

The aggregate's required negative-fixture closure names native leakage,
unknown native state, stale release and date expiry, missing owner, reverse
dependency placement, and loss of the neutral-consumer workspace boundary.
The aggregate cannot be green if any child receipt is missing or any unknown,
unregistered, expired, incomplete, or pending count is nonzero.

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

1. compare the live root `Cargo.toml` package version and current UTC date
   against every active row;
2. retire rows whose owning differential corpus is now frozen and sufficient;
3. close or update the linked retirement bead;
4. remove the package from every remaining harness when retired; and
5. capture fresh graph evidence.

The same live version/date check runs every day in
`.github/workflows/nightly-differential-stress.yml` at `0 4 * * *` using the
full focused contract command. This prevents an unchanged policy snapshot from
silently carrying an active oracle beyond either deadline. Release and date
deadlines are independent: reaching either one fails closed.

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

- manifest or lockfile pin drift;
- unregistered active oracle edges;
- expired active manifest-oracle rows;
- live package-release or UTC-date expiry;
- missing active owner, test scope, corpus, or removal fields;
- missing retirement-sweep decisions;
- unapproved retirement renewals;
- scheduled expiry-gate drift;
- lock package identity drift;
- active report count drift;
- missing retirement disposition;
- native oracle in `workspace-dev`;
- reverse dependency in `workspace-dev`;
- expired active oracle without extension;
- approved extension with unchanged expiry release or stale expiry date;
- security oracle without redaction;
- missing feature-unification proof; and
- allowed/forbidden profile overlap;
- unknown graph-profile names; and
- duplicate registry, class, profile, or required-field IDs;
- aggregate child-evidence omission;
- aggregate unknown-state drift; and
- resolution-to-semantic-oracle role confusion.

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

- 10 current reference packages across 15 exact manifest edges are registered;
- all 19 scoped manifests and the lockfile match their reviewed pins;
- active rows carry package identity, lane, exclusion, expiry, corpus, renewal,
  removal, and no-claim fields;
- the initial retirement sweep has one approved, bounded decision for every
  active row and no pending disposition;
- the live package version and UTC date have not reached either active
  deadline, and the nightly schedule runs the same gate;
- the report separates Production | 0, Dev / conformance | 15, Build | 0,
  Native | 0 active, 3 planned, and Reverse-cycle | 0 active, 1 planned;
- all 24 initial oracle plans have complete governance rows;
- all 34 planned and active rows are present in the aggregate signoff with zero
  unknown or pending state;
- live root normal, root release, focused root dev, and focused conformance
  unit-graph receipts preserve package-resolution versus semantic-oracle roles;
- all four security/protocol rows preserve independent-corpus, redaction, and
  resource-bound requirements;
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
